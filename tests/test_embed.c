#include "test.h"
#include "embed.h"
#include <stdlib.h>
#include <string.h>

static Image *make_image(uint32_t w, uint32_t h, uint8_t fill) {
    Image *img = malloc(sizeof(Image));
    img->width  = w;
    img->height = h;
    img->rows   = malloc(h * sizeof(uint8_t *));
    for (uint32_t y = 0; y < h; y++) {
        img->rows[y] = malloc((size_t)w * 3);
        memset(img->rows[y], fill, (size_t)w * 3);
    }
    return img;
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

    CHECK(embed_encode(img, idx, count, msg, sizeof(msg)) == 0);
    CHECK(embed_peek_len(img, idx, count) == sizeof(msg));

    uint8_t out[sizeof(msg)] = {0};
    embed_decode(img, idx, count, out, sizeof(out));
    CHECK(memcmp(out, msg, sizeof(msg)) == 0);

    free(idx);
    image_free(img);
}

static void test_only_lsbs_change(void) {
    Image *img = make_image(8, 8, 0xAA);
    Image *orig = make_image(8, 8, 0xAA);
    uint32_t *idx = identity(64);
    const uint8_t msg[] = {0xFF, 0x00, 0x81, 0x7E};

    CHECK(embed_encode(img, idx, 64, msg, sizeof(msg)) == 0);
    int high_bits_same = 1;
    for (uint32_t y = 0; y < 8; y++)
        for (uint32_t i = 0; i < 8 * 3; i++)
            if ((img->rows[y][i] & 0xFE) != (orig->rows[y][i] & 0xFE))
                high_bits_same = 0;
    CHECK(high_bits_same);

    free(idx);
    image_free(img);
    image_free(orig);
}

static void test_only_scattered_pixels_touched(void) {
    /* An empty message is just the 32-bit length header, which fills the
       first 11 listed pixels; the pixels after them must be untouched. */
    Image *img = make_image(4, 4, 0xFF);
    uint32_t idx[] = {13, 2, 7, 11, 0, 9, 4, 15, 1, 3, 5, 6, 8, 10, 12, 14};

    CHECK(embed_encode(img, idx, 16, NULL, 0) == 0);
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

    CHECK(embed_encode(img, idx, 24, msg, 5) == 0);
    CHECK(embed_encode(img, idx, 24, msg, 6) == -1);

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
    CHECK(embed_encode(img, idx, 10, NULL, 0) == -1);
    CHECK(embed_peek_len(img, idx, 10) == 0);
    free(idx);
    image_free(img);
}

static void test_huge_len_rejected_without_overflow(void) {
    /* data_len * 8 overflows 32 bits; encode must still refuse */
    Image *img = make_image(4, 4, 0);
    uint32_t *idx = identity(16);
    uint8_t dummy = 0;
    CHECK(embed_encode(img, idx, 16, &dummy, 0x20000000u) == -1);
    free(idx);
    image_free(img);
}

static void test_decode_clamps_to_out_size(void) {
    Image *img = make_image(32, 4, 0);
    uint32_t *idx = identity(128);
    const uint8_t msg[] = "0123456789";

    CHECK(embed_encode(img, idx, 128, msg, 10) == 0);
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
    CHECK(embed_encode(img, idx, 512, msg, sizeof(msg)) == 0);

    uint8_t out[100] = {0};
    embed_decode(img, idx, 20, out, sizeof(out));  /* ASan catches over-reads */
    CHECK(out[0] == 0x33);  /* bits 32..39 are inside the first 20 pixels */
    free(idx);
    image_free(img);
}

static void test_empty_message(void) {
    Image *img = make_image(4, 4, 0x11);
    uint32_t *idx = identity(16);
    CHECK(embed_encode(img, idx, 16, NULL, 0) == 0);
    CHECK(embed_peek_len(img, idx, 16) == 0);
    free(idx);
    image_free(img);
}

int main(void) {
    RUN(test_roundtrip);
    RUN(test_only_lsbs_change);
    RUN(test_only_scattered_pixels_touched);
    RUN(test_capacity_boundary);
    RUN(test_too_small_for_header);
    RUN(test_huge_len_rejected_without_overflow);
    RUN(test_decode_clamps_to_out_size);
    RUN(test_decode_stops_at_count);
    RUN(test_empty_message);
    return TEST_SUMMARY();
}
