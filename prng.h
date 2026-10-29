/* SPDX-License-Identifier: MIT OR Apache-2.0
   Copyright (C) 2026 Maxime de Montbron */
#ifndef PRNG_H
#define PRNG_H

#include <stdint.h>

/* A permutation of [0, count), from an unbiased forward
   Fisher-Yates shuffle driven by the ChaCha20-IETF keystream of `key`
   (32 bytes, zero nonce), read as little-endian uint32s whatever the
   host byte order. NULL on allocation failure or count == 0. */
uint32_t *prng_permutation(const uint8_t *key, uint32_t count);

/* The first k entries of prng_permutation(key, count), in O(k^2) time
   without the full array. Returns 0, or -1 if k > count. */
int prng_sample(const uint8_t *key, uint32_t count, uint32_t k, uint32_t *out);

#endif /* PRNG_H */
