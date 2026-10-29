/* SPDX-License-Identifier: AGPL-3.0-or-later
   Copyright (C) 2026 Maxime de Montbron */
/* libFuzzer target: the file format (codec.c) on hostile carriers, past key
   derivation, which this build makes cheap (FUZZING_BUILD_MODE_UNSAFE_FOR_
   PRODUCTION swaps Argon2id for BLAKE2b). Decodes the fuzzer's carrier as
   decode would with any passphrase: every format's length and size
   handling then runs on whatever the samples hold. Then encodes a message
   into it and checks the right passphrase gets it back and a wrong one
   finds nothing. */
#include "codec.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>

#define PASSPHRASE "correct horse battery"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    return sodium_init() < 0;
}

/* A fresh copy of the carrier described by data, so each pass starts from
   the same samples */
typedef struct {
    Image img;
    int16_t *values;
    int16_t **coefs;
    float *costs;
    Carrier carrier;
} Cover;

static void cover_make(Cover *c, int kind, uint32_t w, uint32_t h,
                       const uint8_t *data, size_t size) {
    memset(c, 0, sizeof(*c));
    if (kind < 2) {  /* PNG: gray or RGB */
        uint32_t ch = kind ? 3 : 1;
        c->img = (Image){.width = w, .height = h, .channels = ch,
                         .rows = malloc(h * sizeof(uint8_t *))};
        for (uint32_t y = 0; y < h; y++) {
            c->img.rows[y] = malloc((size_t)w * ch);
            for (uint32_t i = 0; i < w * ch; i++)
                c->img.rows[y][i] = size ? data[(y * w * ch + i) % size] : 0;
        }
        c->carrier = carrier_of_image(&c->img);
    } else {  /* JPEG: carrier coefficients, |v| from 2 to 129 as jpeg_carrier gives */
        uint32_t n = w * h;
        c->values = malloc(n * sizeof(int16_t));
        c->coefs = malloc(n * sizeof(int16_t *));
        c->costs = malloc(n * sizeof(float));
        for (uint32_t i = 0; i < n; i++) {
            uint8_t b = size ? data[i % size] : 0;
            c->values[i] = (int16_t)((b & 0x7F) + 2) * (b & 0x80 ? -1 : 1);
            c->coefs[i] = &c->values[i];
            c->costs[i] = 1.0f + (float)(b & 0x0F);
        }
        c->carrier = (Carrier){NULL, c->coefs, n, c->costs};
    }
}

static void cover_free(Cover *c) {
    if (c->img.rows)
        for (uint32_t y = 0; y < c->img.height; y++) free(c->img.rows[y]);
    free(c->img.rows);
    free(c->values);
    free(c->coefs);
    free(c->costs);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Layout: kind (1) | w (1) | h (1) | samples, then the message: the rest */
    if (size < 3) return 0;
    int kind = data[0] % 3;
    uint32_t w = data[1] % 64 + 1, h = data[2] % 64 + 1;
    data += 3;
    size -= 3;

    Cover cover;
    cover_make(&cover, kind, w, h, data, size);

    /* Hostile decode: never FAILED, and no crash or overread */
    uint8_t *plaintext = NULL;
    uint32_t pt_len = 0;
    char name[CODEC_NAME_MAX + 1];
    int r = codec_decode(&cover.carrier, PASSPHRASE, &plaintext, &pt_len, name);
    if (r == FAILED) abort();
    if (r == DECODED) sodium_free(plaintext);

    /* Round trip */
    CodecPrepared *prep = codec_prepare(&cover.carrier, PASSPHRASE);
    if (prep) {
        size_t max = codec_max_message(prep);
        uint32_t len = (uint32_t)(size < max ? size : max);
        if (len == 0) {
            codec_prepared_free(prep);
        } else {
            /* With or without a name, at every compression level */
            const char *stored = size & 1 ? "fuzz.txt" : NULL;
            if (codec_embed(prep, &cover.carrier, stored, data, len, (int)(size % 10), NULL) != 0) {
                if (!stored) abort();  /* with no name, within the limit, it fits */
            } else {
                r = codec_decode(&cover.carrier, PASSPHRASE, &plaintext, &pt_len, name);
                if (r != DECODED || pt_len != len || memcmp(plaintext, data, len) != 0 ||
                    strcmp(name, stored ? stored : "") != 0)
                    abort();
                sodium_free(plaintext);
                if (codec_decode(&cover.carrier, "wrong horse battery", &plaintext, &pt_len, name) != NO_MATCH)
                    abort();
            }
        }
    }
    cover_free(&cover);
    return 0;
}
