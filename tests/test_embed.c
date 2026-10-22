#include "test.h"
#include "embed.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>

static Image *make_image(uint32_t w, uint32_t h, uint8_t fill) {
    Image *img = calloc(1, sizeof(Image));
    img->width    = w;
    img->height   = h;
    img->channels = 3;
    img->rows   = malloc(h * sizeof(uint8_t *));
    for (uint32_t y = 0; y < h; y++) {
        img->rows[y] = malloc((size_t)w * 3);
        memset(img->rows[y], fill, (size_t)w * 3);
    }
    return img;
}

/* One-step wrappers: record into a plan, then apply it */
static EmbedStats last_stats;

static int encode(Image *img, const uint32_t *idx, uint32_t count,
                  const uint8_t *data, uint32_t len) {
    EmbedPlan *plan = embed_plan_new();
    int r = embed_encode(img, idx, count, data, len, plan);
    if (r == 0 && embed_apply(plan, &last_stats) != 0) r = -2;
    embed_plan_free(plan);
    return r;
}

static int write_raw(Image *img, const uint32_t *idx, uint32_t count,
                     const uint8_t *data, uint32_t len) {
    EmbedPlan *plan = embed_plan_new();
    int r = embed_write_raw(img, idx, count, data, len, plan);
    if (r == 0 && embed_apply(plan, &last_stats) != 0) r = -2;
    embed_plan_free(plan);
    return r;
}

static uint32_t *identity(uint32_t count) {
    uint32_t *idx = malloc(count * sizeof(uint32_t));
    for (uint32_t i = 0; i < count; i++) idx[i] = i;
    return idx;
}

/* A fixed non-sequential order, so bugs that only work with identity
   indices still show up */
static uint32_t *reversed(uint32_t count) {
    uint32_t *idx = malloc(count * sizeof(uint32_t));
    for (uint32_t i = 0; i < count; i++) idx[i] = count - 1 - i;
    return idx;
}

static void test_roundtrip(void) {
    Image *img = make_image(16, 16, 0x5A);
    uint32_t count = 16 * 16;
    uint32_t *idx = reversed(count);
    const uint8_t msg[] = "hello, scattered world";

    CHECK(encode(img, idx, count, msg, sizeof(msg)) == 0);
    CHECK(embed_peek_len(img, idx, count) == sizeof(msg));

    uint8_t out[sizeof(msg)] = {0};
    embed_decode(img, idx, count, out, sizeof(out));
    CHECK(memcmp(out, msg, sizeof(msg)) == 0);

    free(idx);
    image_free(img);
}

static void test_changes_at_most_one(void) {
    Image *img = make_image(8, 8, 0xAA);
    Image *orig = make_image(8, 8, 0xAA);
    uint32_t *idx = identity(64);
    const uint8_t msg[] = {0xFF, 0x00, 0x81, 0x7E};

    CHECK(encode(img, idx, 64, msg, sizeof(msg)) == 0);
    int within_one = 1;
    for (uint32_t y = 0; y < 8; y++)
        for (uint32_t i = 0; i < 8 * 3; i++)
            if (abs(img->rows[y][i] - orig->rows[y][i]) > 1)
                within_one = 0;
    CHECK(within_one);

    free(idx);
    image_free(img);
    image_free(orig);
}

static void test_lsb_matching_goes_both_ways(void) {
    /* Every sample is 100 (LSB 0) and every bit is 1, so every sample
       changes. Overwriting the LSB would always give 101; matching must
       give 99 and 101 about equally often. */
    Image *img = make_image(100, 100, 100);
    uint32_t *idx = identity(10000);
    uint8_t ones[3746];  /* (10000 * 3 - 32) / 8 */
    memset(ones, 0xFF, sizeof(ones));
    uint32_t len = (10000 * 3 - 32) / 8;
    CHECK(encode(img, idx, 10000, ones, len) == 0);

    uint32_t up = 0, down = 0, other = 0;
    for (uint32_t y = 0; y < 100; y++)
        for (uint32_t i = 0; i < 300; i++) {
            uint8_t v = img->rows[y][i];
            if (v == 101) up++;
            else if (v == 99) down++;
            else if (v != 100) other++;
        }
    CHECK(other == 0);
    CHECK(up + down >= len * 8);
    /* ~24000 fair flips: 45-55% is over 15 standard deviations wide */
    CHECK(up * 100 > (up + down) * 45 && up * 100 < (up + down) * 55);
    free(idx);
    image_free(img);
}

static void test_matching_never_wraps(void) {
    /* 0 can only go up and 255 only down; neither may wrap around */
    for (int fill = 0; fill <= 255; fill += 255) {
        Image *img = make_image(40, 40, (uint8_t)fill);
        uint32_t *idx = identity(1600);
        uint8_t msg[590];
        for (size_t i = 0; i < sizeof(msg); i++) msg[i] = (uint8_t)(i * 37);
        CHECK(encode(img, idx, 1600, msg, sizeof(msg)) == 0);
        int ok = 1;
        for (uint32_t y = 0; y < 40; y++)
            for (uint32_t i = 0; i < 120; i++)
                if (abs(img->rows[y][i] - fill) > 1) ok = 0;
        CHECK(ok);
        uint8_t out[590];
        embed_decode(img, idx, 1600, out, sizeof(out));
        CHECK(memcmp(out, msg, sizeof(msg)) == 0);
        free(idx);
        image_free(img);
    }
}

static void test_only_scattered_pixels_touched(void) {
    /* An empty message is just the 32-bit length header, which fills the
       first 11 listed pixels; the pixels after them must be untouched. */
    Image *img = make_image(4, 4, 0xFF);
    uint32_t idx[] = {13, 2, 7, 11, 0, 9, 4, 15, 1, 3, 5, 6, 8, 10, 12, 14};

    CHECK(encode(img, idx, 16, NULL, 0) == 0);
    for (int k = 11; k < 16; k++) {
        uint32_t p = idx[k];
        uint8_t *px = &img->rows[p / 4][(p % 4) * 3];
        CHECK(px[0] == 0xFF && px[1] == 0xFF && px[2] == 0xFF);
    }
    image_free(img);
}

static void test_capacity_boundary(void) {
    /* 32-bit header + 8 bits per byte, 3 bits per pixel.
       24 pixels = 72 bits = header + exactly 5 bytes. */
    Image *img = make_image(24, 1, 0);
    uint32_t *idx = identity(24);
    uint8_t msg[6] = {1, 2, 3, 4, 5, 6};

    CHECK(encode(img, idx, 24, msg, 5) == 0);
    CHECK(encode(img, idx, 24, msg, 6) == -1);

    uint8_t out[5] = {0};
    embed_decode(img, idx, 24, out, 5);
    CHECK(memcmp(out, msg, 5) == 0);

    free(idx);
    image_free(img);
}

static void test_too_small_for_header(void) {
    /* 10 pixels = 30 bits, less than the 32-bit length header */
    Image *img = make_image(10, 1, 0);
    uint32_t *idx = identity(10);
    CHECK(encode(img, idx, 10, NULL, 0) == -1);
    CHECK(embed_peek_len(img, idx, 10) == 0);
    free(idx);
    image_free(img);
}

static void test_huge_len_rejected_without_overflow(void) {
    /* data_len * 8 overflows 32 bits; encode must still refuse */
    Image *img = make_image(4, 4, 0);
    uint32_t *idx = identity(16);
    uint8_t dummy = 0;
    CHECK(encode(img, idx, 16, &dummy, 0x20000000u) == -1);
    free(idx);
    image_free(img);
}

static void test_decode_clamps_to_out_size(void) {
    Image *img = make_image(32, 4, 0);
    uint32_t *idx = identity(128);
    const uint8_t msg[] = "0123456789";

    CHECK(encode(img, idx, 128, msg, 10) == 0);
    /* out has room for 4 bytes plus a canary; decode must stop at 4 */
    uint8_t out[5];
    memset(out, 0xEE, sizeof(out));
    embed_decode(img, idx, 128, out, 4);
    CHECK(memcmp(out, "0123", 4) == 0);
    CHECK(out[4] == 0xEE);

    free(idx);
    image_free(img);
}

static void test_decode_stops_at_count(void) {
    /* Header claims 100 bytes but only a few pixels are listed: decode
       must not read past indices[count - 1]. */
    Image *img = make_image(64, 8, 0);
    uint32_t *idx = identity(512);
    uint8_t msg[100];
    memset(msg, 0x33, sizeof(msg));
    CHECK(encode(img, idx, 512, msg, sizeof(msg)) == 0);

    uint8_t out[100] = {0};
    embed_decode(img, idx, 20, out, sizeof(out));  /* ASan catches over-reads */
    CHECK(out[0] == 0x33);  /* bits 32..39 are inside the first 20 pixels */
    free(idx);
    image_free(img);
}

static void test_empty_message(void) {
    Image *img = make_image(4, 4, 0x11);
    uint32_t *idx = identity(16);
    CHECK(encode(img, idx, 16, NULL, 0) == 0);
    CHECK(embed_peek_len(img, idx, 16) == 0);
    free(idx);
    image_free(img);
}

static void test_raw_roundtrip(void) {
    /* 16 bytes = 128 bits in 43 pixels (129 bits): the v2 salt layout */
    Image *img = make_image(10, 10, 0x80);
    Image *orig = make_image(10, 10, 0x80);
    uint32_t px[43];
    for (uint32_t i = 0; i < 43; i++) px[i] = (i * 37) % 100;
    uint8_t salt[16], back[16];
    for (int i = 0; i < 16; i++) salt[i] = (uint8_t)(i * 29 + 7);
    CHECK(write_raw(img, px, 43, salt, 16) == 0);
    CHECK(embed_read_raw(img, px, 43, back, 16) == 0);
    CHECK(memcmp(salt, back, 16) == 0);
    int within_one = 1;
    for (uint32_t y = 0; y < 10; y++)
        for (uint32_t i = 0; i < 30; i++)
            if (abs(img->rows[y][i] - orig->rows[y][i]) > 1) within_one = 0;
    CHECK(within_one);
    /* 17 bytes don't fit in 43 pixels */
    uint8_t big[17] = {0};
    CHECK(write_raw(img, px, 43, big, 17) == -1);
    CHECK(embed_read_raw(img, px, 43, big, 17) == -1);
    image_free(img);
    image_free(orig);
}

static void test_exchange_swaps_neighbours(void) {
    /* One byte over 3 pixels (8 samples). Bit 0 = 1 into a 10 and bit 1 = 0
       into an 11: both need flipping and they're one apart, so they swap. */
    Image *img = make_image(3, 1, 0);
    const uint8_t vals[9] = {10, 11, 50, 52, 52, 52, 52, 52, 52};
    memcpy(img->rows[0], vals, 9);
    uint32_t idx[3] = {0, 1, 2};
    uint8_t byte = 0x01;  /* every other bit 0, matching the even values */
    CHECK(write_raw(img, idx, 3, &byte, 1) == 0);
    CHECK(img->rows[0][0] == 11 && img->rows[0][1] == 10);
    CHECK(memcmp(img->rows[0] + 2, vals + 2, 7) == 0);
    CHECK(last_stats.changes == 2 && last_stats.exchanged == 2);
    image_free(img);
}

static void test_exchange_preserves_histogram(void) {
    /* A noisy cover filled with random data: nearly every change pairs up,
       and only the unpaired ones (nudged +-1) can move the histogram */
    uint32_t w = 200, h = 150, count = w * h;
    Image *img = make_image(w, h, 0);
    for (uint32_t y = 0; y < h; y++) randombytes_buf(img->rows[y], (size_t)w * 3);
    uint32_t before[256] = {0}, after[256] = {0};
    for (uint32_t y = 0; y < h; y++)
        for (uint32_t i = 0; i < w * 3; i++) before[img->rows[y][i]]++;

    uint32_t *idx = identity(count);
    uint32_t len = (count * 3 - 32) / 8;
    uint8_t *msg = malloc(len);
    randombytes_buf(msg, len);
    CHECK(encode(img, idx, count, msg, len) == 0);
    for (uint32_t y = 0; y < h; y++)
        for (uint32_t i = 0; i < w * 3; i++) after[img->rows[y][i]]++;

    uint64_t moved = 0;  /* half the L1 histogram distance */
    for (int v = 0; v < 256; v++) moved += before[v] > after[v] ? before[v] - after[v] : 0;
    size_t unpaired = last_stats.changes - last_stats.exchanged;
    CHECK(last_stats.changes > count);              /* ~half of 90,000 samples */
    CHECK(unpaired * 100 < last_stats.changes);     /* over 99% exchanged */
    CHECK(moved <= unpaired);                       /* only nudges move it */

    uint8_t *out = malloc(len);
    embed_decode(img, idx, count, out, len);
    CHECK(memcmp(out, msg, len) == 0);
    free(out);
    free(msg);
    free(idx);
    image_free(img);
}

static void test_recording_changes_nothing(void) {
    /* Nothing changes until embed_apply */
    Image *img = make_image(4, 4, 0x40);
    Image *orig = make_image(4, 4, 0x40);
    EmbedPlan *plan = embed_plan_new();
    uint32_t *idx = identity(16);
    uint8_t ones[2] = {0xFF, 0xFF};
    CHECK(embed_write_raw(img, idx, 16, ones, 2, plan) == 0);
    int same = 1;
    for (uint32_t y = 0; y < 4; y++) same &= memcmp(img->rows[y], orig->rows[y], 12) == 0;
    CHECK(same);
    EmbedStats st;
    CHECK(embed_apply(plan, &st) == 0 && st.changes == 16);
    embed_plan_free(plan);
    free(idx);
    image_free(img);
    image_free(orig);
}

int main(void) {
    if (sodium_init() < 0) return 1;
    RUN(test_roundtrip);
    RUN(test_changes_at_most_one);
    RUN(test_lsb_matching_goes_both_ways);
    RUN(test_matching_never_wraps);
    RUN(test_only_scattered_pixels_touched);
    RUN(test_capacity_boundary);
    RUN(test_too_small_for_header);
    RUN(test_huge_len_rejected_without_overflow);
    RUN(test_decode_clamps_to_out_size);
    RUN(test_decode_stops_at_count);
    RUN(test_empty_message);
    RUN(test_raw_roundtrip);
    RUN(test_exchange_swaps_neighbours);
    RUN(test_exchange_preserves_histogram);
    RUN(test_recording_changes_nothing);
    return TEST_SUMMARY();
}
