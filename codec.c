/* SPDX-License-Identifier: MIT OR Apache-2.0
   Copyright (C) 2026 Maxime de Montbron */
#include "codec.h"
#include "embed.h"
#include "prng.h"
#include "stc.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

/* The file format (FORMAT.md): how a message is keyed, laid out in a
   cover's carriers, and found again.

     salt     16 random bytes, as the STC syndrome (see stc.h) of the
              samples of a public salt region: the first salt_region_pixels
              pixels of a public permutation (prng_permutation keyed with
              BLAKE2b of SALT_LABEL). Public, so the decoder can find it
              before it has a key; syndrome-coded, so its ~18 changes are as
              sparse as the payload's.
     keys     master = Argon2id(passphrase, salt, "moderate": 3 passes,
              256 MiB); scatter and encryption keys = crypto_kdf subkeys 1
              and 2 of master, context KDF_CONTEXT
     order    prng_permutation(scatter key) with the salt pixels removed
     payload  [nonce 24 | secretbox]: its 32-bit little-endian length in
              the first 32 samples in that order, then its bits as the STC
              syndrome of the samples after them (see payload_carriers)
     message  the secretbox's plaintext: [encoding 1 | body], the body raw
              DEFLATE (encoding 1) of the record if that made it shorter,
              else the record as is (0); the record is [name length 1 |
              file name | message] (see pack_message, name_ok)

   Every pixel carries one bit per sample (R, G, B, or gray LSBs); a JPEG,
   one per carrier coefficient. There is no header or version marker,
   which would itself give the image away. */

#define SALT_BYTES      crypto_pwhash_SALTBYTES             /* 16 */
#define SALT_SAMPLES    8192  /* the salt region, when the image allows */
/* The labels are part of the format; "v2" is history, not a version */
#define SALT_LABEL      "ScatterSteg v2 salt positions"
#define KDF_CONTEXT     "ScatStg2"                          /* exactly 8 chars */
#define BOX_OVERHEAD    (crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)

/* Pixels in the salt region: SALT_SAMPLES samples' worth, but at most 1/16
   of the image, and never fewer than one sample per salt bit */
static uint32_t salt_region_pixels(uint32_t count, uint32_t channels) {
    uint32_t want = (SALT_SAMPLES + channels - 1) / channels;
    uint32_t k = want < count / 16 ? want : count / 16;
    uint32_t least = (SALT_BYTES * 8 + channels - 1) / channels;
    return k > least ? k : least;
}

/* The salt's carriers: all of the region's samples, up to STC's cap */
static size_t salt_carriers(uint32_t k, uint32_t channels) {
    return stc_carriers((size_t)k * channels, SALT_BYTES * 8);
}

/* The salt, read from the region's sample bits. 0, or -1 if out of memory. */
static int read_salt(const Carrier *c, const uint32_t *salt_px, uint32_t k,
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
static int write_salt(const Carrier *c, const uint32_t *salt_px, uint32_t k,
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

/* Both keys from one Argon2id run, so every passphrase guess costs one.
   Returns them for sodium_free, or prints why and returns NULL. */
static Keys *derive_keys(const char *passphrase, const uint8_t salt[SALT_BYTES]) {
    Keys *keys = sodium_malloc(sizeof(Keys));
    uint8_t *master = sodium_malloc(crypto_kdf_KEYBYTES);
    if (!keys || !master ||
        pwhash(master, crypto_kdf_KEYBYTES, passphrase, salt,
               crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE) != 0) {
        sodium_free(keys);
        sodium_free(master);
        fprintf(stderr, "Error: key derivation failed (out of memory)\n");
        return NULL;
    }
    crypto_kdf_derive_from_key(keys->scatter, sizeof(keys->scatter), 1, KDF_CONTEXT, master);
    crypto_kdf_derive_from_key(keys->enc, sizeof(keys->enc), 2, KDF_CONTEXT, master);
    sodium_free(master);
    return keys;
}

/* The first k pixels of the public permutation, where the salt goes:
   public, so the decoder can find it before it has any key. Returns 0, or
   -1 on allocation failure. */
static int salt_pixels(uint32_t count, uint32_t k, uint32_t *out) {
    uint8_t key[crypto_stream_chacha20_ietf_KEYBYTES];
    crypto_generichash(key, sizeof(key), (const uint8_t *)SALT_LABEL,
                       strlen(SALT_LABEL), NULL, 0);
    return prng_sample(key, count, k, out);
}

static int cmp_u32(const void *a, const void *b) {
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return (x > y) - (x < y);
}

/* The secret order says where the message is: wipe it before freeing.
   count is what payload_order allocated. */
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

/* The payload's layout over n positions of ch samples, shared by encode
   and decode so it can't drift between them: the 32-bit length goes straight
   into the first 32 samples, and the payload's bits are the STC syndrome
   of samples from 32 on. */

/* Samples after the length header; 0 if the header doesn't fit */
static size_t payload_samples(uint32_t n, uint32_t ch) {
    return n < header_pixels(ch) ? 0 : (size_t)n * ch - 32;
}

/* How many samples from 32 on carry a len-byte payload's syndrome (*mlen
   = 8 * len message bits); 0 if it doesn't fit */
static size_t payload_carriers(uint32_t n, uint32_t ch, uint32_t len, size_t *mlen) {
    *mlen = (size_t)len * 8;
    return stc_carriers(payload_samples(n, ch), *mlen);
}

/* The payload (see payload_samples). NO_MATCH if the length doesn't fit,
   as for a wrong passphrase. */
static int read_payload(const Carrier *c, const uint32_t *order, uint32_t n,
                        uint8_t **payload, uint32_t *len) {
    if (n < header_pixels(carrier_channels(c))) return NO_MATCH;
    *len = embed_peek_len(c, order, n);
    size_t mlen;
    size_t used = *len < BOX_OVERHEAD ? 0 : payload_carriers(n, carrier_channels(c), *len, &mlen);
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

/* Records the changes for payload (see payload_samples) in plan: the
   STC picks, among all sample bits with the right syndrome, the set
   cheapest to reach under embed_costs. Returns 0, -1 if it doesn't fit,
   or -2 if out of memory. */
static int embed_payload(const Carrier *c, const uint32_t *order, uint32_t n,
                         const uint8_t *payload, uint32_t len, EmbedPlan *plan) {
    size_t mlen;
    size_t used = payload_carriers(n, carrier_channels(c), len, &mlen);
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

/* The message is compressed when that makes it shorter: fewer bits to
   hide, so fewer changes. zlib's buffers hold the message, so they come
   from sodium_malloc, locked and wiped like the rest. */
enum { STORED = 0, DEFLATED = 1 };

static voidpf secret_alloc(voidpf opaque, uInt items, uInt size) {
    (void)opaque;
    if (size && items > SIZE_MAX / size) return Z_NULL;
    return sodium_malloc((size_t)items * size);
}

static void secret_free(voidpf opaque, voidpf p) {
    (void)opaque;
    sodium_free(p);
}

/* Most bytes a record inflates to: a decompression bomb stops there */
#define RECORD_MAX ((size_t)CODEC_MESSAGE_MAX + 1 + CODEC_NAME_MAX)

/* A file name a record may carry: a bare name, which extract can create in
   the current directory and print safely. 1 to CODEC_NAME_MAX bytes, no
   '/' or control characters, not "." or "..". */
static int name_ok(const uint8_t *s, size_t n) {
    if (n == 0 || n > CODEC_NAME_MAX) return 0;
    if ((n == 1 && s[0] == '.') || (n == 2 && s[0] == '.' && s[1] == '.')) return 0;
    for (size_t i = 0; i < n; i++)
        if (s[i] == '/' || s[i] < 0x20 || s[i] == 0x7f) return 0;
    return 1;
}

int codec_name_ok(const char *name) {
    return name_ok((const uint8_t *)name, strlen(name));
}

/* The secretbox's plaintext for a message: [encoding | body] (see the top
   of this file), in sodium_malloc memory. level 1-9 compresses at that
   level if that makes it shorter; 0 never does. NULL if out of memory. */
static uint8_t *pack_message(const char *name, const uint8_t *msg, uint32_t len, int level,
                             uint32_t *packed_len) {
    uint8_t head[1 + CODEC_NAME_MAX];  /* the record's name length and name */
    size_t name_len = name ? strlen(name) : 0, head_len = 1 + name_len;
    size_t record = head_len + len;
    head[0] = (uint8_t)name_len;
    if (name_len) memcpy(head + 1, name, name_len);

    z_stream z = {.zalloc = secret_alloc, .zfree = secret_free};
    if (level > 0 && deflateInit2(&z, level, Z_DEFLATED, -MAX_WBITS, 9, Z_DEFAULT_STRATEGY) != Z_OK)
        return NULL;
    uLong bound = level > 0 ? deflateBound(&z, record) : 0;
    size_t cap = 1 + (bound > record ? bound : record);
    uint8_t *packed = sodium_malloc(cap);
    int deflated = 0;
    if (packed && level > 0) {
        z.next_in = head;
        z.avail_in = (uInt)head_len;
        z.next_out = packed + 1;
        z.avail_out = (uInt)(cap - 1);
        int r = deflate(&z, Z_NO_FLUSH);
        z.next_in = (Bytef *)msg;
        z.avail_in = len;
        deflated = r == Z_OK && deflate(&z, Z_FINISH) == Z_STREAM_END && z.total_out < record;
    }
    if (packed && deflated) {
        packed[0] = DEFLATED;
        *packed_len = 1 + (uint32_t)z.total_out;
    } else if (packed) {
        packed[0] = STORED;
        memcpy(packed + 1, head, head_len);
        memcpy(packed + 1 + head_len, msg, len);
        *packed_len = (uint32_t)(1 + record);
    }
    if (level > 0) deflateEnd(&z);
    sodium_memzero(head, sizeof(head));
    return packed;
}

/* Inflates src, which must be exactly one raw DEFLATE stream, into out
   (out_cap bytes); or, if out is NULL, only measures it into *total.
   Returns 0, -1 if it is malformed or inflates past RECORD_MAX (a sender
   could make it a decompression bomb), or -2 if out of memory. */
static int inflate_record(const uint8_t *src, size_t src_len, uint8_t *out, size_t out_cap,
                          size_t *total) {
    z_stream z = {.zalloc = secret_alloc, .zfree = secret_free};
    if (inflateInit2(&z, -MAX_WBITS) != Z_OK) return -2;
    uint8_t *scratch = out ? NULL : sodium_malloc(65536);
    if (!out && !scratch) {
        inflateEnd(&z);
        return -2;
    }
    z.next_in = (Bytef *)src;
    z.avail_in = (uInt)src_len;
    if (out) {
        z.next_out = out;
        z.avail_out = (uInt)out_cap;
    }
    int r;
    do {
        if (scratch) {
            z.next_out = scratch;
            z.avail_out = 65536;
        }
        r = inflate(&z, Z_NO_FLUSH);
    } while (r == Z_OK && z.total_out <= RECORD_MAX);
    *total = z.total_out;
    int ok = r == Z_STREAM_END && z.avail_in == 0 && z.total_out <= RECORD_MAX;
    inflateEnd(&z);
    sodium_free(scratch);
    return ok ? 0 : r == Z_MEM_ERROR ? -2 : -1;
}

/* Replaces the secretbox's plaintext (*pt, *len bytes) with the message
   it holds, and copies out the file name stored with it ("" if none).
   FAILED, with a message, if it is malformed: only a faulty encoder, or a
   sender who knows the passphrase, could make one that authenticates. */
static int unpack_message(uint8_t **pt, uint32_t *len, char name[CODEC_NAME_MAX + 1]) {
    const uint8_t *body = *pt + 1;
    size_t body_len = *len ? *len - 1 : 0, size = 0;
    uint8_t *rec = NULL;  /* the record, in *pt or a buffer of its own */
    int r = *len == 0 || (**pt != STORED && **pt != DEFLATED) ? -1 : 0;
    if (r == 0 && **pt == STORED) {
        rec = *pt;
        size = body_len;
        memmove(rec, body, size);
    } else if (r == 0) {
        r = inflate_record(body, body_len, NULL, 0, &size);
        rec = r == 0 ? sodium_malloc(size + 1) : NULL;
        if (r == 0 && !rec) r = -2;
        if (r == 0) r = inflate_record(body, body_len, rec, size + 1, &size);
    }
    size_t name_len = r == 0 && size ? rec[0] : 0;
    if (r == 0 && (size == 0 || 1 + name_len > size || (name_len && !name_ok(rec + 1, name_len))))
        r = -1;
    if (r != 0) {
        if (rec != *pt) sodium_free(rec);
        fprintf(stderr, r == -2 ? "Error: allocation failed\n"
                                : "Error: the message is malformed; it authenticated, so "
                                  "whoever made the image knew the passphrase\n");
        return FAILED;
    }
    memcpy(name, rec + 1, name_len);
    name[name_len] = '\0';
    memmove(rec, rec + 1 + name_len, size - 1 - name_len);
    if (rec != *pt) {
        sodium_free(*pt);
        *pt = rec;
    }
    *len = (uint32_t)(size - 1 - name_len);
    return DECODED;
}

/* Open [nonce | secretbox] with key. NO_MATCH if it doesn't authenticate. */
static int open_box(const uint8_t *box, uint32_t box_len, const uint8_t *key,
                    uint8_t **plaintext, uint32_t *pt_len) {
    *pt_len = box_len - BOX_OVERHEAD;
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

uint32_t codec_header_pixels(uint32_t channels) {
    return header_pixels(channels);
}

int codec_decode(const Carrier *c, const char *passphrase,
                 uint8_t **plaintext, uint32_t *pt_len, char name[CODEC_NAME_MAX + 1]) {
    uint32_t count = carrier_positions(c), ch = carrier_channels(c);
    uint32_t k = salt_region_pixels(count, ch);
    if (count < k + header_pixels(ch)) return NO_MATCH;
    uint32_t *salt_px = malloc((size_t)k * sizeof(uint32_t));
    uint8_t salt[SALT_BYTES];
    if (!salt_px || salt_pixels(count, k, salt_px) != 0 || read_salt(c, salt_px, k, salt) != 0) {
        free(salt_px);
        fprintf(stderr, "Error: allocation failed\n");
        return FAILED;
    }

    Keys *keys = derive_keys(passphrase, salt);
    uint32_t *order = keys ? payload_order(keys->scatter, count, salt_px, k) : NULL;
    free(salt_px);
    if (!keys) return FAILED;
    if (!order) {
        sodium_free(keys);
        fprintf(stderr, "Error: allocation failed\n");
        return FAILED;
    }

    uint8_t *payload = NULL;
    uint32_t len = 0;
    int r = read_payload(c, order, count - k, &payload, &len);
    if (r == DECODED)
        r = open_box(payload, len, keys->enc, plaintext, pt_len);
    if (r == DECODED && (r = unpack_message(plaintext, pt_len, name)) != DECODED) {
        sodium_free(*plaintext);
        *plaintext = NULL;
    }
    if (payload) sodium_memzero(payload, len);
    free(payload);
    free_order(order, count);
    sodium_free(keys);
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

/* The longest message that fits stored as is, with no file name, after the
   k salt pixels: one payload bit per sample after the 32-bit header, less
   the box, the encoding byte and the name length. Under 2^32, as
   positions are 32-bit and 3 samples each at most. */
static size_t max_message(uint32_t count, uint32_t k, uint32_t ch) {
    size_t samples = payload_samples(count - k, ch);
    return samples / 8 > BOX_OVERHEAD + 2 ? samples / 8 - BOX_OVERHEAD - 2 : 0;
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
    p->keys = derive_keys(passphrase, p->salt);
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

int codec_embed(CodecPrepared *p, const Carrier *c, const char *name,
                const uint8_t *message, uint32_t msg_len, int level, CodecEmbedded *info) {
    /* payload = [nonce | secretbox([encoding | body])] */
    uint32_t packed_len = 0;
    uint8_t *packed = pack_message(name, message, msg_len, level, &packed_len);
    if (packed && info) {
        info->hidden = packed_len - 1;
        info->compressed = packed[0] == DEFLATED;
    }
    uint32_t payload_len = BOX_OVERHEAD + packed_len;
    uint8_t *payload = packed && packed_len <= p->max_msg + 2 ? malloc(payload_len) : NULL;
    if (!payload) {
        int too_long = packed && packed_len > p->max_msg + 2;
        sodium_free(packed);
        codec_prepared_free(p);
        return too_long ? -1 : -2;
    }
    randombytes_buf(payload, crypto_secretbox_NONCEBYTES);
    crypto_secretbox_easy(payload + crypto_secretbox_NONCEBYTES, packed, packed_len,
                          payload, p->keys->enc);
    sodium_free(packed);
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
    int r = plan ? embed_payload(c, p->order, p->count - p->k, payload, payload_len, plan) : -2;
    sodium_memzero(payload, payload_len);
    free(payload);
    if (r == 0 && (write_salt(c, p->salt_px, p->k, p->salt, plan) != 0 ||
                   embed_apply(plan, NULL) != 0))
        r = -2;
    embed_plan_free(plan);
    free(hill);
    codec_prepared_free(p);
    return r;
}
