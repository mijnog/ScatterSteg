/* SPDX-License-Identifier: AGPL-3.0-or-later
   Copyright (C) 2026 Maxime de Montbron */
#include "embed.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>

enum { KIND_NONE, KIND_U8, KIND_COEF };

/* Samples whose LSB has to flip, recorded by embed_encode/embed_write_raw
   and changed together by embed_apply */
struct EmbedPlan {
    void **samples;  /* uint8_t * (PNG) or int16_t * (JPEG), per kind */
    size_t n, cap;
    int kind;
    int failed;      /* out of memory while recording */
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

uint32_t carrier_positions(const Carrier *c) {
    return c->img ? c->img->width * c->img->height : c->n_coefs;
}

uint32_t carrier_channels(const Carrier *c) {
    return c->img ? c->img->channels : 1;
}

/* The sample holding bit `pos` of the data written in `indices` order */
static void *sample_at(const Carrier *c, const uint32_t *indices, uint32_t pos) {
    if (!c->img) return c->coefs[indices[pos]];
    uint32_t ch = c->img->channels, pixel = indices[pos / ch];
    return &c->img->rows[pixel / c->img->width][(pixel % c->img->width) * ch + pos % ch];
}

static int value_of(int kind, const void *s) {
    return kind == KIND_U8 ? *(const uint8_t *)s : *(const int16_t *)s;
}

static void set_value(int kind, void *s, int v) {
    if (kind == KIND_U8) *(uint8_t *)s = (uint8_t)v;
    else                 *(int16_t *)s = (int16_t)v;
}

static uint8_t read_bit(const Carrier *c, const uint32_t *indices, uint32_t pos) {
    return value_of(c->img ? KIND_U8 : KIND_COEF, sample_at(c, indices, pos)) & 0x01;
}

EmbedPlan *embed_plan_new(void) {
    return calloc(1, sizeof(EmbedPlan));
}

void embed_plan_free(EmbedPlan *plan) {
    if (!plan) return;
    free(plan->samples);
    free(plan);
}

/* Record that bit `pos`'s sample must have LSB `bit` (nothing to do if it has) */
static void write_bit(const Carrier *c, const uint32_t *indices, uint32_t pos,
                      uint8_t bit, EmbedPlan *plan) {
    int kind = c->img ? KIND_U8 : KIND_COEF;
    void *s = sample_at(c, indices, pos);
    if ((value_of(kind, s) & 0x01) == (bit & 0x01) || plan->failed) return;
    if (plan->kind != kind && plan->kind != KIND_NONE) { plan->failed = 1; return; }
    plan->kind = kind;
    if (plan->n == plan->cap) {
        size_t cap = plan->cap ? plan->cap * 2 : 1024;
        void **bigger = realloc(plan->samples, cap * sizeof(void *));
        if (!bigger) { plan->failed = 1; return; }
        plan->samples = bigger;
        plan->cap = cap;
    }
    plan->samples[plan->n++] = s;
}

/* LSB matching: change the value by +-1 at random rather than overwriting
   the LSB. Overwriting only ever maps 2k <-> 2k+1, which leaves the pair
   statistics that chi-square, RS and sample pair analysis detect.
   Pixel values stay in 0..255. JPEG coefficients must keep |c| >= 2 so the
   decoder finds the same carriers: +-2 can only move outwards. */
static int nudged(int kind, int v, Coins *coins) {
    if (kind == KIND_U8) {
        if (v == 0)   return 1;
        if (v == 255) return 254;
    } else {
        /* Stay within what a JPEG encoder can write (|AC| <= 1023) */
        if (v == 2)      return 3;
        if (v == -2)     return -3;
        if (v >= 1023)   return v - 1;
        if (v <= -1023)  return v + 1;
    }
    return flip(coins) ? v + 1 : v - 1;
}

/* Exchange embedding (after Hetzl & Mutzel, "A Graph-Theoretic Approach to
   Steganography", 2005, the idea behind steghide). +-1 changes still smooth
   the histogram slightly, which histogram-based detectors of LSB matching
   look for. But two samples that both need flipping and hold values v and
   v+1 can swap values instead: both LSBs come out right, each still moves
   by just 1, and the histogram doesn't change at all.

   Only samples one value apart can pair, so the pairing graph is a chain of
   value buckets, where greedily pairing each bucket's leftovers with the
   next bucket gives a maximum matching. Shuffling first makes which
   samples pair up random. The rest get a +-1 nudge. For JPEG, buckets -1,
   0 and 1 hold no carriers, so no swap ever breaks |c| >= 2.

   Every pair flips one even and one odd value, so the leftovers are mostly
   the cover's parity imbalance among the carriers, which random message
   bits erase whatever the method.

   Decoding only reads LSBs, so it can't tell how they were set. */
int embed_apply(EmbedPlan *plan, EmbedStats *stats) {
    if (plan->failed) return -1;
    size_t n = plan->n;
    int kind = plan->kind;
    int lo = kind == KIND_COEF ? -32768 : 0;
    size_t buckets = kind == KIND_COEF ? 65536 : 256;
    void **sorted = malloc((n ? n : 1) * sizeof(void *));
    size_t *start = calloc(buckets + 1, sizeof(size_t));
    size_t *fill = malloc(buckets * sizeof(size_t));
    if (!sorted || !start || !fill) {
        free(sorted); free(start); free(fill);
        return -1;
    }

    /* Shuffle, then a stable counting sort by value: random order per bucket */
    for (size_t i = n; i > 1; i--) {
        size_t j = (size_t)randombytes_uniform((uint32_t)i);
        void *t = plan->samples[i - 1];
        plan->samples[i - 1] = plan->samples[j];
        plan->samples[j] = t;
    }
    for (size_t i = 0; i < n; i++) start[value_of(kind, plan->samples[i]) - lo + 1]++;
    for (size_t b = 0; b < buckets; b++) start[b + 1] += start[b];
    memcpy(fill, start, buckets * sizeof(size_t));
    for (size_t i = 0; i < n; i++)
        sorted[fill[value_of(kind, plan->samples[i]) - lo]++] = plan->samples[i];

    /* Walk the chain: bucket b's leftovers pair with the start of bucket b+1.
       Values were only read for sorting, so they can be changed as we go. */
    size_t pairs = 0;
    size_t left_from = 0;  /* bucket b's samples from here on are unpaired */
    Coins coins = {0, 0};
    for (size_t b = 0; b < buckets; b++) {
        int v = (int)b + lo;
        size_t leftovers = start[b + 1] - left_from;
        size_t next = b + 1 < buckets ? start[b + 2] - start[b + 1] : 0;
        size_t k = leftovers < next ? leftovers : next;
        for (size_t i = 0; i < k; i++) {
            set_value(kind, sorted[left_from + i], v + 1);
            set_value(kind, sorted[start[b + 1] + i], v);
        }
        pairs += k;
        for (size_t i = k; i < leftovers; i++)
            set_value(kind, sorted[left_from + i], nudged(kind, v, &coins));
        left_from = start[b + 1] + k;
    }

    if (stats) {
        stats->changes = n;
        stats->exchanged = 2 * pairs;
    }
    sodium_memzero(&coins, sizeof(coins));
    free(sorted);
    free(start);
    free(fill);
    plan->n = 0;
    return 0;
}

int embed_encode(const Carrier *c, const uint32_t *indices, uint32_t count,
                 const uint8_t *data, uint32_t data_len, EmbedPlan *plan) {
    uint64_t bits_needed = 32 + (uint64_t)data_len * 8;
    if (bits_needed > (uint64_t)count * carrier_channels(c))
        return -1;

    uint32_t bit_pos = 0;
    for (int b = 0; b < 32; b++)
        write_bit(c, indices, bit_pos++, (data_len >> b) & 0x01, plan);
    for (uint32_t i = 0; i < data_len; i++)
        for (int b = 0; b < 8; b++)
            write_bit(c, indices, bit_pos++, (data[i] >> b) & 0x01, plan);
    return 0;
}

void embed_decode(const Carrier *c, const uint32_t *indices,
                  uint32_t count, uint8_t *out, uint32_t out_size) {
    uint32_t ch = carrier_channels(c);
    uint32_t bit_pos = 0;

    uint32_t data_len = 0;
    for (int b = 0; b < 32; b++) {
        if (bit_pos / ch >= count) return;
        data_len |= ((uint32_t)read_bit(c, indices, bit_pos++) << b);
    }

    if (data_len > out_size) data_len = out_size;

    for (uint32_t i = 0; i < data_len; i++) {
        uint8_t byte = 0;
        for (int b = 0; b < 8; b++) {
            if (bit_pos / ch >= count) break;
            byte |= (uint8_t)(read_bit(c, indices, bit_pos++) << b);
        }
        out[i] = byte;
    }
}

uint32_t embed_peek_len(const Carrier *c, const uint32_t *indices, uint32_t count) {
    uint32_t ch = carrier_channels(c);
    uint32_t data_len = 0;
    for (uint32_t b = 0; b < 32; b++) {
        if (b / ch >= count) return 0;
        data_len |= ((uint32_t)read_bit(c, indices, b) << b);
    }
    return data_len;
}

int embed_write_raw(const Carrier *c, const uint32_t *indices, uint32_t count,
                    const uint8_t *data, uint32_t len, EmbedPlan *plan) {
    if ((uint64_t)len * 8 > (uint64_t)count * carrier_channels(c)) return -1;
    for (uint32_t pos = 0; pos < len * 8; pos++)
        write_bit(c, indices, pos, (data[pos / 8] >> (pos % 8)) & 0x01, plan);
    return 0;
}

int embed_read_raw(const Carrier *c, const uint32_t *indices, uint32_t count,
                   uint8_t *out, uint32_t len) {
    if ((uint64_t)len * 8 > (uint64_t)count * carrier_channels(c)) return -1;
    memset(out, 0, len);
    for (uint32_t pos = 0; pos < len * 8; pos++)
        out[pos / 8] |= (uint8_t)(read_bit(c, indices, pos) << (pos % 8));
    return 0;
}

void embed_get_bits(const Carrier *c, const uint32_t *indices, size_t start,
                    size_t n, uint8_t *bits) {
    for (size_t i = 0; i < n; i++)
        bits[i] = read_bit(c, indices, (uint32_t)(start + i));
}

void embed_set_bits(const Carrier *c, const uint32_t *indices, size_t start,
                    size_t n, const uint8_t *bits, EmbedPlan *plan) {
    for (size_t i = 0; i < n; i++)
        write_bit(c, indices, (uint32_t)(start + i), bits[i], plan);
}

/* PNG: uniform. Content-adaptive costs (cheap in texture, dear in flat
   areas, like HILL) were tried: on the detectors available here (HCF-COM,
   and Ker's adjacency HCF-COM, which looks at neighbouring pixels) they did
   worse than uniform, since they buy cheaper locations with more changes.
   They aim at machine-learning detectors, which weren't available to test.

   JPEG: a change of 1 to a coefficient changes its block's pixels in
   proportion to the quantization step, so that is the cost (precomputed
   per carrier by jpeg_io, which also makes changes to |value| == 2 dearer:
   2 can only go to 3, which shifts the 2:3 ratio JPEG detectors watch). */
void embed_costs(const Carrier *c, const uint32_t *indices, size_t start,
                 size_t n, float *costs) {
    for (size_t i = 0; i < n; i++)
        costs[i] = c->img ? 1.0f : c->coef_costs[indices[start + i]];
}
