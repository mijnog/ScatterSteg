/* SPDX-License-Identifier: AGPL-3.0-or-later
   Copyright (C) 2026 Maxime de Montbron */
#include "codec.h"
#include "embed.h"
#include "prng.h"
#include "stc.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The file format: how a message is keyed, laid out in a cover's carriers,
   and found again.

   v4 (written by encode): as v3, except for where the salt goes.
     salt     16 random bytes, as the STC syndrome (see stc.h) of the
              samples of a public salt region: the first salt_region_pixels
              pixels of the public permutation below. v3 wrote them straight
              into 128 samples at those public positions, about 64 changes at
              places anyone can look; spread over ~8192 samples, the salt
              takes ~18 changes, as sparse as the payload's.

   v3 (decode only):
     salt     16 random bytes, in the first 43 pixels (RGB; 128 for gray)
              of a public permutation (prng_permutation keyed with BLAKE2b
              of V2_SALT_LABEL), so it is spread over the image
     keys     master = Argon2id(passphrase, salt, "moderate": 3 passes,
              256 MiB); scatter and encryption keys = crypto_kdf subkeys 1
              and 2 of master, context V2_KDF_CONTEXT
     order    prng_permutation(scatter key) with the salt pixels removed
     payload  [nonce 24 | secretbox]: its 32-bit little-endian length in
              the first 32 samples in that order, then its bits as the STC
              syndrome of the samples after them (see v3_carriers, stc.h)

   v2 (decode only): salt, keys and order as v3; the length, then the
     payload's bits written straight into the samples in order.

   v1 (decode only): scatter key = keyed BLAKE2b of the passphrase alone,
     which let a wrong passphrase be rejected without Argon2id; payload =
     length, then [salt 16 | nonce 24 | secretbox] in prng_scatter order;
     encryption key = Argon2id(passphrase, salt, "interactive").

   Every pixel carries one bit per sample (R, G, B, or gray LSBs), written
   by LSB matching (a JPEG: one per carrier coefficient). There is no
   version marker, which would itself give the image away: decode tries
   v4, then v3 and v2 (which share a salt layout), then v1 (RGB PNG only). */

#define SALT_BYTES      crypto_pwhash_SALTBYTES             /* 16 */
#define V4_SALT_SAMPLES 8192  /* the v4 salt region, when the image allows */
#define V2_SALT_LABEL   "ScatterSteg v2 salt positions"
#define V2_KDF_CONTEXT  "ScatStg2"                          /* exactly 8 chars */
#define V2_OVERHEAD     (crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)
#define V1_OVERHEAD     (SALT_BYTES + V2_OVERHEAD)

/* Pixels holding the v2/v3 salt, and the 32-bit length header */
static uint32_t salt_pixel_count(uint32_t channels) {
    return (SALT_BYTES * 8 + channels - 1) / channels;
}

/* Pixels in the v4 salt region: V4_SALT_SAMPLES samples' worth, but at most
   1/16 of the image, and never fewer than one sample per salt bit */
static uint32_t salt_region_pixels(uint32_t count, uint32_t channels) {
    uint32_t want = (V4_SALT_SAMPLES + channels - 1) / channels;
    uint32_t k = want < count / 16 ? want : count / 16;
    uint32_t least = salt_pixel_count(channels);
    return k > least ? k : least;
}

/* The v4 salt's carriers: all of the region's samples, up to STC's cap */
static size_t salt_carriers(uint32_t k, uint32_t channels) {
    return stc_carriers((size_t)k * channels, SALT_BYTES * 8);
}

/* The v4 salt, read from the region's sample bits. 0, or -1 if out of memory. */
static int read_salt_v4(const Carrier *c, const uint32_t *salt_px, uint32_t k,
                        uint8_t salt[SALT_BYTES]) {
    size_t used = salt_carriers(k, carrier_channels(c));
    uint8_t *y = malloc(used), m[SALT_BYTES * 8];
    if (!y) return -1;
    embed_get_bits(c, salt_px, 0, used, y);
    stc_extract(y, SALT_BYTES * 8, used, m);
    memset(salt, 0, SALT_BYTES);
    for (unsigned i = 0; i < SALT_BYTES * 8; i++) salt[i / 8] |= (uint8_t)(m[i] << (i % 8));
    free(y);
    return 0;
}

/* Records the changes that make the region carry the salt. 0, or -1 if out
   of memory. */
static int write_salt_v4(const Carrier *c, const uint32_t *salt_px, uint32_t k,
                         const uint8_t salt[SALT_BYTES], EmbedPlan *plan) {
    size_t used = salt_carriers(k, carrier_channels(c));
    uint8_t *x = malloc(used), *y = malloc(used), m[SALT_BYTES * 8];
    float *costs = malloc(used * sizeof(float));
    int r = -1;
    if (x && y && costs) {
        for (unsigned i = 0; i < SALT_BYTES * 8; i++) m[i] = (salt[i / 8] >> (i % 8)) & 1;
        embed_get_bits(c, salt_px, 0, used, x);
        embed_costs(c, salt_px, 0, used, costs);
        if (stc_embed(x, costs, m, SALT_BYTES * 8, used, y) == 0) {
            embed_set_bits(c, salt_px, 0, used, y, plan);
            r = 0;
        }
    }
    free(x); free(y); free(costs);
    return r;
}

static uint32_t header_pixels(uint32_t channels) {
    return (32 + channels - 1) / channels;
}

/* Argon2id. A fuzzing build (FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION, set
   only where the fuzz targets are built) swaps in keyed BLAKE2b, so the
   fuzzer gets past key derivation in microseconds; such a build must never
   handle a real secret. The Rust fuzz builds swap in the same. */
static int pwhash(uint8_t *out, size_t out_len, const char *passphrase,
                  const uint8_t salt[SALT_BYTES], unsigned long long ops, size_t mem) {
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    (void)ops; (void)mem;
    return crypto_generichash(out, out_len, (const uint8_t *)passphrase, strlen(passphrase),
                              salt, SALT_BYTES);
#else
    return crypto_pwhash(out, out_len, passphrase, strlen(passphrase), salt, ops, mem,
                         crypto_pwhash_ALG_ARGON2ID13);
#endif
}

typedef struct {
    uint8_t scatter[crypto_stream_chacha20_ietf_KEYBYTES];
    uint8_t enc[crypto_secretbox_KEYBYTES];
} Keys;

/* v2: both keys from one Argon2id run, so every passphrase guess costs one.
   Returns them for sodium_free, or prints why and returns NULL. */
static Keys *derive_keys_v2(const char *passphrase, const uint8_t salt[SALT_BYTES]) {
    Keys *keys = sodium_malloc(sizeof(Keys));
    uint8_t *master = sodium_malloc(crypto_kdf_KEYBYTES);
    fprintf(stderr, "Deriving keys...\n");
    if (!keys || !master ||
        pwhash(master, crypto_kdf_KEYBYTES, passphrase, salt,
               crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE) != 0) {
        sodium_free(keys);
        sodium_free(master);
        fprintf(stderr, "Error: key derivation failed (out of memory)\n");
        return NULL;
    }
    crypto_kdf_derive_from_key(keys->scatter, sizeof(keys->scatter), 1, V2_KDF_CONTEXT, master);
    crypto_kdf_derive_from_key(keys->enc, sizeof(keys->enc), 2, V2_KDF_CONTEXT, master);
    sodium_free(master);
    return keys;
}

/* The first k pixels of the public permutation, where the salt goes:
   public, so the decoder can find it before it has any key. Returns 0, or
   -1 on allocation failure. */
static int salt_pixels(uint32_t count, uint32_t k, uint32_t *out) {
    uint8_t key[crypto_stream_chacha20_ietf_KEYBYTES];
    crypto_generichash(key, sizeof(key), (const uint8_t *)V2_SALT_LABEL,
                       strlen(V2_SALT_LABEL), NULL, 0);
    return prng_sample(key, count, k, out);
}

static int cmp_u32(const void *a, const void *b) {
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return (x > y) - (x < y);
}

/* The secret order says where the message is: wipe it before freeing.
   count is what payload_order or prng_scatter allocated. */
static void free_order(uint32_t *order, uint32_t count) {
    if (order) sodium_memzero(order, (size_t)count * sizeof(uint32_t));
    free(order);
}

/* The message order: the secret permutation with the k salt pixels taken
   out, count - k entries. NULL on allocation failure. */
static uint32_t *payload_order(const uint8_t *scatter_key, uint32_t count,
                               const uint32_t *salt_px, uint32_t k) {
    uint32_t *sorted = malloc((size_t)k * sizeof(uint32_t));
    if (!sorted) return NULL;
    memcpy(sorted, salt_px, k * sizeof(uint32_t));
    qsort(sorted, k, sizeof(uint32_t), cmp_u32);

    uint32_t *order = prng_permutation(scatter_key, count);
    if (order) {
        uint32_t n = 0;
        for (uint32_t i = 0; i < count; i++)
            if (!bsearch(&order[i], sorted, k, sizeof(uint32_t), cmp_u32))
                order[n++] = order[i];
    }
    free(sorted);
    return order;
}

/* v1 (decode only). The scatter key comes from the passphrase alone, so
   guesses can be checked against the length header without Argon2id. */
static void derive_scatter_key_v1(const char *passphrase,
                                  uint8_t scatter_key[crypto_stream_chacha20_KEYBYTES]) {
    crypto_generichash(scatter_key, crypto_stream_chacha20_KEYBYTES,
                       (const uint8_t *)passphrase, strlen(passphrase),
                       (const uint8_t *)"scatter", 7);
}

static int derive_enc_key_v1(const char *passphrase, const uint8_t salt[SALT_BYTES],
                             uint8_t enc_key[crypto_secretbox_KEYBYTES]) {
    return pwhash(enc_key, crypto_secretbox_KEYBYTES, passphrase, salt,
                  crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE);
}

/* Read the length-prefixed payload in `order` (n pixels). NO_MATCH if the
   length is out of range, as it is for a wrong passphrase or format;
   FAILED (with a message) if out of memory. */
static int read_payload(const Carrier *c, const uint32_t *order, uint32_t n,
                        uint32_t min_len, uint8_t **payload, uint32_t *len) {
    if (n < header_pixels(carrier_channels(c))) return NO_MATCH;
    uint32_t max_len = (uint32_t)(((uint64_t)n * carrier_channels(c) - 32) / 8);
    *len = embed_peek_len(c, order, n);
    if (*len < min_len || *len > max_len) return NO_MATCH;
    *payload = malloc(*len);
    if (!*payload) {
        fprintf(stderr, "Error: allocation failed\n");
        return FAILED;
    }
    embed_decode(c, order, n, *payload, *len);
    return DECODED;
}

/* The v3 layout over n positions of ch samples, shared by encode and
   decode so it can't drift between them: the 32-bit length goes straight
   into the first 32 samples, and the payload's bits are the STC syndrome
   of samples from 32 on. */

/* Samples after the length header; 0 if the header doesn't fit */
static size_t v3_samples(uint32_t n, uint32_t ch) {
    return n < header_pixels(ch) ? 0 : (size_t)n * ch - 32;
}

/* How many samples from 32 on carry a len-byte payload's syndrome (*mlen
   = 8 * len message bits); 0 if it doesn't fit */
static size_t v3_carriers(uint32_t n, uint32_t ch, uint32_t len, size_t *mlen) {
    *mlen = (size_t)len * 8;
    return stc_carriers(v3_samples(n, ch), *mlen);
}

/* v3 (see v3_samples). NO_MATCH if the length doesn't fit. */
static int read_payload_v3(const Carrier *c, const uint32_t *order, uint32_t n,
                           uint8_t **payload, uint32_t *len) {
    if (n < header_pixels(carrier_channels(c))) return NO_MATCH;
    *len = embed_peek_len(c, order, n);
    size_t mlen;
    size_t used = *len < V2_OVERHEAD ? 0 : v3_carriers(n, carrier_channels(c), *len, &mlen);
    if (!used) return NO_MATCH;

    uint8_t *y = malloc(used), *m = malloc(mlen);
    *payload = calloc(*len, 1);
    if (!y || !m || !*payload) {
        free(y); free(m); free(*payload);
        *payload = NULL;
        fprintf(stderr, "Error: allocation failed\n");
        return FAILED;
    }
    embed_get_bits(c, order, 32, used, y);
    stc_extract(y, mlen, used, m);
    for (size_t i = 0; i < mlen; i++) (*payload)[i / 8] |= (uint8_t)(m[i] << (i % 8));
    free(y);
    free(m);
    return DECODED;
}

/* Records the v3 changes for payload (see v3_samples) in plan: the
   STC picks, among all sample bits with the right syndrome, the set
   cheapest to reach under embed_costs. Returns 0, -1 if it doesn't fit,
   or -2 if out of memory. */
static int embed_payload_v3(const Carrier *c, const uint32_t *order, uint32_t n,
                            const uint8_t *payload, uint32_t len, EmbedPlan *plan) {
    size_t mlen;
    size_t used = v3_carriers(n, carrier_channels(c), len, &mlen);
    if (!used) return -1;

    uint8_t header[4] = {(uint8_t)len, (uint8_t)(len >> 8), (uint8_t)(len >> 16), (uint8_t)(len >> 24)};
    embed_write_raw(c, order, n, header, sizeof(header), plan);

    uint8_t *x = malloc(used), *y = malloc(used), *m = malloc(mlen);
    float *costs = malloc(used * sizeof(float));
    int r = -2;
    if (x && y && m && costs) {
        for (size_t i = 0; i < mlen; i++) m[i] = (payload[i / 8] >> (i % 8)) & 1;
        embed_get_bits(c, order, 32, used, x);
        embed_costs(c, order, 32, used, costs);
        if (stc_embed(x, costs, m, mlen, used, y) == 0) {
            embed_set_bits(c, order, 32, used, y, plan);
            r = 0;
        }
    }
    free(x); free(y); free(m); free(costs);
    return r;
}

/* Open [nonce | secretbox] with key. NO_MATCH if it doesn't authenticate. */
static int open_box(const uint8_t *box, uint32_t box_len, const uint8_t *key,
                    uint8_t **plaintext, uint32_t *pt_len) {
    *pt_len = box_len - V2_OVERHEAD;
    *plaintext = sodium_malloc(*pt_len + 1);
    if (!*plaintext) {
        fprintf(stderr, "Error: allocation failed\n");
        return FAILED;
    }
    const uint8_t *nonce = box, *ct = box + crypto_secretbox_NONCEBYTES;
    if (crypto_secretbox_open_easy(*plaintext, ct, box_len - crypto_secretbox_NONCEBYTES,
                                   nonce, key) != 0) {
        sodium_free(*plaintext);
        *plaintext = NULL;
        return NO_MATCH;
    }
    (*plaintext)[*pt_len] = '\0';
    return DECODED;
}

/* Decodes with one salt layout: v4's (an STC-coded salt region), or the
   one v3 and v2 share (the salt written straight into 43 pixels). Each
   costs an Argon2id run. */
static int decode_keyed(const Carrier *c, int v4, const char *passphrase,
                        uint8_t **plaintext, uint32_t *pt_len) {
    uint32_t count = carrier_positions(c), ch = carrier_channels(c);
    uint32_t k = v4 ? salt_region_pixels(count, ch) : salt_pixel_count(ch);
    if (count < k + header_pixels(ch)) return NO_MATCH;
    uint32_t *salt_px = malloc((size_t)k * sizeof(uint32_t));
    uint8_t salt[SALT_BYTES];
    if (!salt_px || salt_pixels(count, k, salt_px) != 0 ||
        (v4 ? read_salt_v4(c, salt_px, k, salt)
            : embed_read_raw(c, salt_px, k, salt, SALT_BYTES)) != 0) {
        free(salt_px);
        fprintf(stderr, "Error: allocation failed\n");
        return FAILED;
    }

    Keys *keys = derive_keys_v2(passphrase, salt);
    uint32_t *order = keys ? payload_order(keys->scatter, count, salt_px, k) : NULL;
    free(salt_px);
    if (!keys) return FAILED;
    if (!order) {
        sodium_free(keys);
        fprintf(stderr, "Error: allocation failed\n");
        return FAILED;
    }

    /* v4 and v3 lay the payload out alike; v2 shares v3's salt and keys but
       writes the payload straight in. */
    int r = NO_MATCH;
    for (int v3 = 1; v3 >= v4 && r == NO_MATCH; v3--) {  /* v4: v3 layout only */
        uint8_t *payload = NULL;
        uint32_t len = 0;
        r = v3 ? read_payload_v3(c, order, count - k, &payload, &len)
               : read_payload(c, order, count - k, V2_OVERHEAD, &payload, &len);
        if (r == DECODED)
            r = open_box(payload, len, keys->enc, plaintext, pt_len);
        if (payload) sodium_memzero(payload, len);
        free(payload);
    }
    free_order(order, count);
    sodium_free(keys);
    return r;
}

static int decode_v1(const Carrier *c, const char *passphrase,
                     uint8_t **plaintext, uint32_t *pt_len) {
    if (!c->img || c->img->channels != 3) return NO_MATCH;  /* v1 only ever wrote RGB PNG */
    uint32_t count = carrier_positions(c);
    uint8_t scatter_key[crypto_stream_chacha20_KEYBYTES];
    derive_scatter_key_v1(passphrase, scatter_key);
    uint32_t *order = prng_scatter(scatter_key, count);
    sodium_memzero(scatter_key, sizeof(scatter_key));
    if (!order) {
        fprintf(stderr, "Error: allocation failed\n");
        return FAILED;
    }

    uint8_t *payload = NULL;
    uint32_t len = 0;
    int r = read_payload(c, order, count, V1_OVERHEAD, &payload, &len);
    free_order(order, count);
    if (r != DECODED) return r;

    /* v1 payload = [salt | nonce | secretbox] */
    uint8_t *enc_key = sodium_malloc(crypto_secretbox_KEYBYTES);
    if (!enc_key || derive_enc_key_v1(passphrase, payload, enc_key) != 0) {
        fprintf(stderr, "Error: key derivation failed (out of memory)\n");
        r = FAILED;
    } else {
        r = open_box(payload + SALT_BYTES, len - SALT_BYTES, enc_key, plaintext, pt_len);
    }
    sodium_free(enc_key);
    sodium_memzero(payload, len);
    free(payload);
    return r;
}

uint32_t codec_header_pixels(uint32_t channels) {
    return header_pixels(channels);
}

int codec_decode(const Carrier *c, const char *passphrase,
                 uint8_t **plaintext, uint32_t *pt_len, int *v1) {
    *v1 = 0;
    int r = decode_keyed(c, 1, passphrase, plaintext, pt_len);      /* v4 */
    if (r == NO_MATCH)
        r = decode_keyed(c, 0, passphrase, plaintext, pt_len);     /* v3, v2 */
    if (r == NO_MATCH) {
        r = decode_v1(c, passphrase, plaintext, pt_len);
        *v1 = r == DECODED;
    }
    return r;
}

struct CodecPrepared {
    Keys *keys;
    uint32_t *salt_px;  /* the salt region, k pixels */
    uint32_t *order;    /* the message's, count - k pixels */
    uint32_t count, k;
    uint8_t salt[SALT_BYTES];
    size_t max_msg;
};

int codec_too_small(const Carrier *c) {
    uint32_t count = carrier_positions(c), ch = carrier_channels(c);
    return count < salt_region_pixels(count, ch) + header_pixels(ch);
}

/* The most the v3 layout holds after the k salt pixels: one payload bit
   per sample after the 32-bit header. Under 2^32, as positions are 32-bit
   and 3 samples each at most. */
static size_t max_message(uint32_t count, uint32_t k, uint32_t ch) {
    size_t samples = v3_samples(count - k, ch);
    return samples / 8 > V2_OVERHEAD ? samples / 8 - V2_OVERHEAD : 0;
}

size_t codec_capacity(const Carrier *c) {
    if (codec_too_small(c)) return 0;
    uint32_t count = carrier_positions(c), ch = carrier_channels(c);
    return max_message(count, salt_region_pixels(count, ch), ch);
}

CodecPrepared *codec_prepare(const Carrier *c, const char *passphrase) {
    uint32_t count = carrier_positions(c), ch = carrier_channels(c);
    uint32_t k = salt_region_pixels(count, ch);
    if (codec_too_small(c)) {
        fprintf(stderr, "Error: image too small to hide a message\n");
        return NULL;
    }
    CodecPrepared *p = calloc(1, sizeof(*p));
    if (!p) {
        fprintf(stderr, "Error: allocation failed\n");
        return NULL;
    }
    p->count = count;
    p->k = k;
    randombytes_buf(p->salt, sizeof(p->salt));
    p->keys = derive_keys_v2(passphrase, p->salt);
    if (!p->keys) {
        free(p);
        return NULL;
    }

    p->salt_px = malloc((size_t)k * sizeof(uint32_t));
    if (p->salt_px && salt_pixels(count, k, p->salt_px) == 0)
        p->order = payload_order(p->keys->scatter, count, p->salt_px, k);
    if (!p->order) {
        codec_prepared_free(p);
        fprintf(stderr, "Error: allocation failed\n");
        return NULL;
    }

    p->max_msg = max_message(count, k, ch);
    return p;
}

size_t codec_max_message(const CodecPrepared *p) {
    return p->max_msg;
}

void codec_prepared_free(CodecPrepared *p) {
    if (!p) return;
    sodium_free(p->keys);
    free_order(p->order, p->count);
    free(p->salt_px);
    free(p);
}

int codec_embed(CodecPrepared *p, const Carrier *c, const uint8_t *message, uint32_t msg_len) {
    /* payload = [nonce | secretbox(message)] */
    uint32_t payload_len = V2_OVERHEAD + msg_len;
    uint8_t *payload = malloc(payload_len);
    if (!payload) {
        codec_prepared_free(p);
        return -2;
    }
    randombytes_buf(payload, crypto_secretbox_NONCEBYTES);
    crypto_secretbox_easy(payload + crypto_secretbox_NONCEBYTES, message, msg_len,
                          payload, p->keys->enc);
    sodium_free(p->keys);  /* not needed past here */
    p->keys = NULL;

    /* PNG: HILL costs (see embed_costs) */
    Carrier costed = *c;
    float *hill = NULL;
    if (c->img) {
        hill = embed_hill_costs(c->img);
        if (!hill) {
            sodium_memzero(payload, payload_len);
            free(payload);
            codec_prepared_free(p);
            return -2;
        }
        costed.coef_costs = hill;
    }
    c = &costed;

    /* Record every change (payload and salt), then make them together so
       they can be paired up to keep the histogram (see embed_apply) */
    EmbedPlan *plan = embed_plan_new();
    int r = plan ? embed_payload_v3(c, p->order, p->count - p->k, payload, payload_len, plan) : -2;
    sodium_memzero(payload, payload_len);
    free(payload);
    if (r == 0 && (write_salt_v4(c, p->salt_px, p->k, p->salt, plan) != 0 ||
                   embed_apply(plan, NULL) != 0))
        r = -2;
    embed_plan_free(plan);
    free(hill);
    codec_prepared_free(p);
    return r;
}
