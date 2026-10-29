/* SPDX-License-Identifier: AGPL-3.0-or-later
   Copyright (C) 2026 Maxime de Montbron */
#include "prng.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define STREAM_CHUNK 4096  /* keystream bytes generated at a time (64 blocks) */

typedef struct {
    const uint8_t *key;
    uint32_t block;  /* next ChaCha20-IETF block counter */
    uint32_t pos;    /* read position in buf */
    uint8_t buf[STREAM_CHUNK];
} Stream;

static void stream_init(Stream *s, const uint8_t *key) {
    s->key = key;
    s->block = 0;
    s->pos = STREAM_CHUNK;
}

/* Next 4 keystream bytes as a little-endian uint32. Chunks are contiguous,
   so this reads one long keystream starting at block 0. */
static uint32_t next_u32(Stream *s) {
    if (s->pos == STREAM_CHUNK) {
        static const uint8_t nonce[crypto_stream_chacha20_ietf_NONCEBYTES] = {0};
        memset(s->buf, 0, STREAM_CHUNK);
        crypto_stream_chacha20_ietf_xor_ic(s->buf, s->buf, STREAM_CHUNK, nonce, s->block, s->key);
        s->block += STREAM_CHUNK / 64;
        s->pos = 0;
    }
    const uint8_t *b = s->buf + s->pos;
    s->pos += 4;
    return (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
}

/* Uniform in [0, bound) by rejection: values below 2^32 mod bound are
   redrawn, so every result has exactly floor(2^32 / bound) preimages */
static uint32_t uniform(Stream *s, uint32_t bound) {
    uint32_t min = (uint32_t)(0u - bound) % bound;
    uint32_t r;
    do r = next_u32(s); while (r < min);
    return r % bound;
}

uint32_t *prng_permutation(const uint8_t *key, uint32_t count) {
    if (count == 0) return NULL;
#if SIZE_MAX / 4 < UINT32_MAX  /* 32-bit size_t: the byte count can overflow */
    if (count > SIZE_MAX / sizeof(uint32_t)) return NULL;
#endif
    uint32_t *a = malloc((size_t)count * sizeof(uint32_t));
    if (!a) return NULL;
    for (uint32_t i = 0; i < count; i++) a[i] = i;

    Stream s;
    stream_init(&s, key);
    /* Forward Fisher-Yates: slot i is final after step i, which is what
       lets prng_sample produce a prefix without the whole array */
    for (uint32_t i = 0; i + 1 < count; i++) {
        uint32_t j = i + uniform(&s, count - i);
        uint32_t t = a[i]; a[i] = a[j]; a[j] = t;
    }
    sodium_memzero(&s, sizeof(s));
    return a;
}

int prng_sample(const uint8_t *key, uint32_t count, uint32_t k, uint32_t *out) {
    if (k > count) return -1;
    /* The same shuffle, keeping only the slots it has touched: at most
       2k (slot, value) pairs; every other slot still holds its index */
    uint32_t *slot = malloc((size_t)2 * k * sizeof(uint32_t) + 1);
    uint32_t *val  = malloc((size_t)2 * k * sizeof(uint32_t) + 1);
    if (!slot || !val) { free(slot); free(val); return -1; }
    uint32_t n = 0;

    Stream s;
    stream_init(&s, key);
    for (uint32_t i = 0; i < k; i++) {
        uint32_t j = i + 1 < count ? i + uniform(&s, count - i) : i;
        uint32_t vi = i, vj = j, *pi = NULL, *pj = NULL;
        for (uint32_t m = 0; m < n; m++) {
            if (slot[m] == i) { vi = val[m]; pi = &val[m]; }
            if (slot[m] == j) { vj = val[m]; pj = &val[m]; }
        }
        if (!pi) { slot[n] = i; val[n] = vi; pi = &val[n++]; }
        if (!pj && j != i) { slot[n] = j; val[n] = vj; pj = &val[n++]; }
        *pi = vj;
        if (pj) *pj = vi;
        out[i] = vj;
    }
    sodium_memzero(&s, sizeof(s));
    free(slot);
    free(val);
    return 0;
}
