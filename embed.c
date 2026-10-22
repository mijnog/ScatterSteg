#include "embed.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>

/* Samples whose LSB has to flip, recorded by embed_encode/embed_write_raw
   and changed together by embed_apply */
struct EmbedPlan {
    uint8_t **samples;
    size_t n, cap;
    int failed;  /* out of memory while recording */
};

/* Random coin flips, drawn from libsodium 64 at a time */
typedef struct {
    uint64_t bits;
    int left;
} Coins;

static int flip(Coins *c) {
    if (c->left == 0) {
        randombytes_buf(&c->bits, sizeof(c->bits));
        c->left = 64;
    }
    int heads = c->bits & 1;
    c->bits >>= 1;
    c->left--;
    return heads;
}

EmbedPlan *embed_plan_new(void) {
    return calloc(1, sizeof(EmbedPlan));
}

void embed_plan_free(EmbedPlan *plan) {
    if (!plan) return;
    free(plan->samples);
    free(plan);
}

/* Record that this sample's LSB must become `bit` (nothing to do if it is) */
static void write_bit(Image *img, uint32_t pixel_idx, int channel, uint8_t bit, EmbedPlan *plan) {
    uint32_t x = pixel_idx % img->width;
    uint32_t y = pixel_idx / img->width;
    uint8_t *ch = &img->rows[y][x * img->channels + channel];
    if ((*ch & 0x01) == (bit & 0x01) || plan->failed) return;
    if (plan->n == plan->cap) {
        size_t cap = plan->cap ? plan->cap * 2 : 1024;
        uint8_t **bigger = realloc(plan->samples, cap * sizeof(uint8_t *));
        if (!bigger) { plan->failed = 1; return; }
        plan->samples = bigger;
        plan->cap = cap;
    }
    plan->samples[plan->n++] = ch;
}

/* LSB matching: change the value by +-1 at random rather than overwriting
   the LSB. Overwriting only ever maps 2k <-> 2k+1, which leaves the pair
   statistics that chi-square, RS and sample pair analysis detect. */
static void nudge(uint8_t *s, Coins *coins) {
    if (*s == 0)        *s = 1;
    else if (*s == 255) *s = 254;
    else                *s = flip(coins) ? *s + 1 : *s - 1;
}

/* Exchange embedding (after Hetzl & Mutzel, "A Graph-Theoretic Approach to
   Steganography", 2005, the idea behind steghide). +-1 changes still smooth
   the histogram slightly, which histogram-based detectors of LSB matching
   look for. But two samples that both need flipping and hold values v and
   v+1 can swap values instead: both LSBs come out right, each still moves
   by just 1, and the histogram doesn't change at all.

   Only samples one value apart can pair, so the pairing graph is a chain of
   value buckets 0-1-2-...-255, where greedily pairing each bucket's leftovers
   with the next bucket gives a maximum matching. Shuffling first makes which
   samples pair up random. The few left unpaired get a +-1 nudge.

   Decoding only reads LSBs, so it can't tell how they were set. */
int embed_apply(EmbedPlan *plan, EmbedStats *stats) {
    if (plan->failed) return -1;
    size_t n = plan->n;
    uint8_t **sorted = malloc((n ? n : 1) * sizeof(uint8_t *));
    if (!sorted) return -1;

    /* Shuffle, then a stable counting sort by value: random order per bucket */
    for (size_t i = n; i > 1; i--) {
        size_t j = (size_t)randombytes_uniform((uint32_t)i);
        uint8_t *t = plan->samples[i - 1];
        plan->samples[i - 1] = plan->samples[j];
        plan->samples[j] = t;
    }
    size_t start[257] = {0};
    for (size_t i = 0; i < n; i++) start[*plan->samples[i] + 1]++;
    for (int v = 0; v < 256; v++) start[v + 1] += start[v];
    size_t fill[256];
    memcpy(fill, start, sizeof(fill));
    for (size_t i = 0; i < n; i++) sorted[fill[*plan->samples[i]]++] = plan->samples[i];

    /* Walk the chain: bucket v's leftovers pair with the start of bucket v+1.
       Values were only read for sorting, so they can be changed as we go. */
    size_t pairs = 0;
    size_t left_from = 0;  /* bucket v's samples from here on are unpaired */
    Coins coins = {0, 0};
    for (int v = 0; v < 256; v++) {
        size_t leftovers = start[v + 1] - left_from;
        size_t next = v < 255 ? start[v + 2] - start[v + 1] : 0;
        size_t k = leftovers < next ? leftovers : next;
        for (size_t i = 0; i < k; i++) {
            *sorted[left_from + i]   = (uint8_t)(v + 1);
            *sorted[start[v + 1] + i] = (uint8_t)v;
        }
        pairs += k;
        for (size_t i = k; i < leftovers; i++)
            nudge(sorted[left_from + i], &coins);
        left_from = start[v + 1] + k;
    }

    if (stats) {
        stats->changes = n;
        stats->exchanged = 2 * pairs;
    }
    sodium_memzero(&coins, sizeof(coins));
    free(sorted);
    plan->n = 0;
    return 0;
}

static uint8_t read_bit(const Image *img, uint32_t pixel_idx, int channel) {
    uint32_t x = pixel_idx % img->width;
    uint32_t y = pixel_idx / img->width;
    return img->rows[y][x * img->channels + channel] & 0x01;
}

int embed_encode(Image *img, const uint32_t *indices, uint32_t count,
                 const uint8_t *data, uint32_t data_len, EmbedPlan *plan) {
    uint64_t bits_needed = 32 + (uint64_t)data_len * 8;
    if (bits_needed > (uint64_t)count * img->channels)
        return -1;

    uint32_t bit_pos = 0;

    for (int b = 0; b < 32; b++) {
        uint8_t bit = (data_len >> b) & 0x01;
        write_bit(img, indices[bit_pos / img->channels], bit_pos % img->channels, bit, plan);
        bit_pos++;
    }

    for (uint32_t i = 0; i < data_len; i++) {
        for (int b = 0; b < 8; b++) {
            uint8_t bit = (data[i] >> b) & 0x01;
            write_bit(img, indices[bit_pos / img->channels], bit_pos % img->channels, bit, plan);
            bit_pos++;
        }
    }
    return 0;
}

void embed_decode(const Image *img, const uint32_t *indices,
                  uint32_t count, uint8_t *out, uint32_t out_size) {
    uint32_t bit_pos = 0;

    uint32_t data_len = 0;
    for (int b = 0; b < 32; b++) {
        if (bit_pos / img->channels >= count) return;
        uint8_t bit = read_bit(img, indices[bit_pos / img->channels], bit_pos % img->channels);
        data_len |= ((uint32_t)bit << b);
        bit_pos++;
    }

    if (data_len > out_size) data_len = out_size;

    for (uint32_t i = 0; i < data_len; i++) {
        uint8_t byte = 0;
        for (int b = 0; b < 8; b++) {
            if (bit_pos / img->channels >= count) break;
            uint8_t bit = read_bit(img, indices[bit_pos / img->channels], bit_pos % img->channels);
            byte |= (bit << b);
            bit_pos++;
        }
        out[i] = byte;
    }
}

uint32_t embed_peek_len(const Image *img, const uint32_t *indices, uint32_t count) {
    uint32_t data_len = 0;
    for (int b = 0; b < 32; b++) {
        if ((uint32_t)b / img->channels >= count) return 0;
        uint8_t bit = read_bit(img, indices[b / img->channels], b % img->channels);
        data_len |= ((uint32_t)bit << b);
    }
    return data_len;
}

int embed_write_raw(Image *img, const uint32_t *indices, uint32_t count,
                    const uint8_t *data, uint32_t len, EmbedPlan *plan) {
    if ((uint64_t)len * 8 > (uint64_t)count * img->channels) return -1;
    for (uint32_t pos = 0; pos < len * 8; pos++)
        write_bit(img, indices[pos / img->channels], pos % img->channels, (data[pos / 8] >> (pos % 8)) & 0x01, plan);
    return 0;
}

int embed_read_raw(const Image *img, const uint32_t *indices, uint32_t count,
                   uint8_t *out, uint32_t len) {
    if ((uint64_t)len * 8 > (uint64_t)count * img->channels) return -1;
    memset(out, 0, len);
    for (uint32_t pos = 0; pos < len * 8; pos++)
        out[pos / 8] |= (uint8_t)(read_bit(img, indices[pos / img->channels], pos % img->channels) << (pos % 8));
    return 0;
}
