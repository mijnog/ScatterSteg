/* SPDX-License-Identifier: MIT OR Apache-2.0
   Copyright (C) 2026 Maxime de Montbron */
#ifndef CODEC_H
#define CODEC_H

#include <stddef.h>
#include <stdint.h>
#include "embed.h"

/* The file format (see codec.c): keying a passphrase, hiding an encrypted
   message in a carrier, and finding it again. Failures print why. */

/* Outcome of trying to decode */
enum { DECODED, NO_MATCH, FAILED };

/* The longest message encode takes, before compression; decode refuses
   one that inflates past it (with its file name) */
#define CODEC_MESSAGE_MAX ((uint32_t)64 << 20)
/* The longest file name stored with a message */
#define CODEC_NAME_MAX 255
/* The suggested most to store (advice, not a limit; README, "Keep the
   message small"). By the square root law, what an image hides at a given
   risk grows with the square root of its size: everything stored, the fixed
   overhead included, is at most this many bytes per square root of the
   pixels (PNG) or non-zero AC coefficients (JPEG). Anchored on the lightest
   payloads the benchmarks measured on BOSSbase (256x256): about 0.1 bits per
   pixel and 0.08 bits per non-zero AC coefficient, overhead included. */
#define CODEC_SUGGESTED_PNG_BYTES  3
#define CODEC_SUGGESTED_JPEG_BYTES 1
/* What every message stores besides its text and file name: salt 16,
   length region 8 (the length, and layer A's share), MAC 16, encoding 1,
   name length 1 */
#define CODEC_FIXED_BYTES 42
/* A cover this smooth gets no suggestion, as a trained detector finds
   almost any message in it: a mean prediction residual (|4x - the four
   neighbours| / 4 per sample) under 1.7 (PNG: the smoothest fifth of
   BOSSbase, caught 84% of the time at 0.1 bits per pixel, 94% at 0.2), or
   under 14% of AC coefficients non-zero (JPEG: the smoothest third, caught
   93-98% of the time at any payload measured). */
#define CODEC_SMOOTH_PNG_RESIDUAL_X10 17
#define CODEC_SMOOTH_JPEG_PERCENT     14
/* The suggestion for a cover of `units` pixels (PNG) or non-zero AC
   coefficients (JPEG), before the smoothness check: 0 if the fixed overhead
   alone is over it */
uint64_t codec_suggested(uint64_t units, int jpeg);

/* Whether name can be stored with a message, and so created by extract: a
   bare file name of 1 to CODEC_NAME_MAX bytes of UTF-8, not starting with
   '.', with no '/', control characters or bidi controls (see name_ok) */
int codec_name_ok(const char *name);

/* The fewest positions a payload order needs, one sample per bit of the
   32-bit length: fewer, and no message fits */
uint32_t codec_header_pixels(uint32_t channels);

/* DECODED gives the message in *plaintext (sodium_malloc memory, pt_len
   bytes) and the file name stored with it in name ("" if none); NO_MATCH
   means a wrong passphrase or no message. Costs one Argon2id run. */
int codec_decode(const Carrier *c, const char *passphrase,
                 uint8_t **plaintext, uint32_t *pt_len, char name[CODEC_NAME_MAX + 1]);

/* Encode, in two steps: codec_prepare keys the passphrase (one Argon2id
   run) and finds the order, NULL if it fails or the carrier is too small;
   codec_embed stores the message (1 to CODEC_MESSAGE_MAX bytes) with its
   file name (NULL for none; codec_name_ok), compressed at level 1-9 if
   that makes it shorter (0: never), encrypts it, and records and makes the
   changes. It frees p, and returns 0, -1 if the message doesn't fit even
   compressed, or -2 if out of memory (the carrier then unchanged). info,
   if not NULL, says how it was stored. */
typedef struct CodecPrepared CodecPrepared;
typedef struct {
    uint32_t hidden;  /* bytes stored: the record, compressed or not */
    int compressed;
} CodecEmbedded;
/* Whether the carrier can't hold the salt and length, whatever the message:
   cheap, so encode checks it before slower work on the cover */
int codec_too_small(const Carrier *c);
/* The longest message the carrier holds stored as is, with no file name (a
   compressible one can be longer, a name takes its length), which needs no
   passphrase: what codec_max_message gives
   once prepared. 0 if codec_too_small. */
size_t codec_capacity(const Carrier *c);
CodecPrepared *codec_prepare(const Carrier *c, const char *passphrase);
size_t codec_max_message(const CodecPrepared *p);
int  codec_embed(CodecPrepared *p, const Carrier *c, const char *name,
                 const uint8_t *message, uint32_t msg_len, int level, CodecEmbedded *info);
/* codec_embed in two steps, so the caller can see how the message will be
   stored before the cover is changed: codec_pack compresses it (as
   codec_embed would) into k, 0 or -2 if out of memory; codec_packed_fits
   says whether it fits; codec_embed_packed stores it, frees p and k's
   data, and returns as codec_embed does. codec_packed_free frees k's data
   if it isn't stored after all. */
typedef struct {
    uint8_t *data;  /* sodium_malloc memory */
    uint32_t len;
    CodecEmbedded stored;
} CodecPacked;
int  codec_pack(const char *name, const uint8_t *message, uint32_t msg_len, int level,
                CodecPacked *k);
int  codec_packed_fits(const CodecPrepared *p, const CodecPacked *k);
int  codec_embed_packed(CodecPrepared *p, const Carrier *c, CodecPacked *k);
void codec_packed_free(CodecPacked *k);
void codec_prepared_free(CodecPrepared *p);  /* NULL is fine */

#endif /* CODEC_H */
