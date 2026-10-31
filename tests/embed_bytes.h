/* SPDX-License-Identifier: MIT OR Apache-2.0
   Copyright (C) 2026 Maxime de Montbron */
#ifndef EMBED_BYTES_H
#define EMBED_BYTES_H

/* Bytes written straight into sample LSBs, one bit per sample in indices
   order: what the format did before syndrome coding, kept for the tests
   and fuzz_embed, which drive the plan and its value swaps through them.
   Built on embed_get_bits and embed_set_bits. */

#include "embed.h"
#include <string.h>

static inline uint8_t bytes_bit(const Carrier *c, const uint32_t *indices, uint32_t pos) {
    uint8_t b;
    embed_get_bits(c, indices, pos, 1, &b);
    return b;
}

static inline void bytes_set(const Carrier *c, const uint32_t *indices, uint32_t pos, uint8_t bit,
                             EmbedPlan *plan) {
    embed_set_bits(c, indices, pos, 1, &bit, plan);
}

/* A 32-bit length, then the data. Returns 0, or -1 if it doesn't fit in
   count positions. */
static inline int embed_encode(const Carrier *c, const uint32_t *indices, uint32_t count,
                               const uint8_t *data, uint32_t data_len, EmbedPlan *plan) {
    uint64_t bits_needed = 32 + (uint64_t)data_len * 8;
    if (bits_needed > (uint64_t)count * carrier_channels(c)) return -1;
    uint32_t pos = 0;
    for (int b = 0; b < 32; b++) bytes_set(c, indices, pos++, (data_len >> b) & 1, plan);
    for (uint32_t i = 0; i < data_len; i++)
        for (int b = 0; b < 8; b++) bytes_set(c, indices, pos++, (data[i] >> b) & 1, plan);
    return 0;
}

/* What embed_encode wrote, up to out_size bytes; stops where the positions
   run out */
static inline void embed_decode(const Carrier *c, const uint32_t *indices, uint32_t count,
                                uint8_t *out, uint32_t out_size) {
    uint32_t ch = carrier_channels(c), pos = 0, data_len = 0;
    for (int b = 0; b < 32; b++) {
        if (pos / ch >= count) return;
        data_len |= (uint32_t)bytes_bit(c, indices, pos++) << b;
    }
    if (data_len > out_size) data_len = out_size;
    for (uint32_t i = 0; i < data_len; i++) {
        uint8_t byte = 0;
        for (int b = 0; b < 8; b++) {
            if (pos / ch >= count) break;
            byte |= (uint8_t)(bytes_bit(c, indices, pos++) << b);
        }
        out[i] = byte;
    }
}

/* embed_encode's length, or 0 if the positions can't hold one */
static inline uint32_t embed_peek_len(const Carrier *c, const uint32_t *indices, uint32_t count) {
    uint32_t ch = carrier_channels(c), data_len = 0;
    for (uint32_t b = 0; b < 32; b++) {
        if (b / ch >= count) return 0;
        data_len |= (uint32_t)bytes_bit(c, indices, b) << b;
    }
    return data_len;
}

/* Raw bytes with no length. 0, or -1 if len bytes don't fit in count positions. */
static inline int embed_write_raw(const Carrier *c, const uint32_t *indices, uint32_t count,
                                  const uint8_t *data, uint32_t len, EmbedPlan *plan) {
    if ((uint64_t)len * 8 > (uint64_t)count * carrier_channels(c)) return -1;
    for (uint32_t pos = 0; pos < len * 8; pos++)
        bytes_set(c, indices, pos, (data[pos / 8] >> (pos % 8)) & 1, plan);
    return 0;
}

static inline int embed_read_raw(const Carrier *c, const uint32_t *indices, uint32_t count,
                                 uint8_t *out, uint32_t len) {
    if ((uint64_t)len * 8 > (uint64_t)count * carrier_channels(c)) return -1;
    memset(out, 0, len);
    for (uint32_t pos = 0; pos < len * 8; pos++)
        out[pos / 8] |= (uint8_t)(bytes_bit(c, indices, pos) << (pos % 8));
    return 0;
}

#endif /* EMBED_BYTES_H */
