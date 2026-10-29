/* SPDX-License-Identifier: AGPL-3.0-or-later
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
/* The suggested most to store: 1 byte per this many pixels (PNG) or
   non-zero AC coefficients (JPEG), i.e. 0.05 bits each, the lightest
   payload the benchmarks measured (README, "Steganalysis results").
   Lighter is harder to detect; it is advice, not a limit. */
#define CODEC_SUGGESTED_UNITS_PER_BYTE 160

/* Whether name can be stored with a message, and so created by extract: a
   bare file name of 1 to CODEC_NAME_MAX bytes, no '/' or control
   characters, not "." or ".." */
int codec_name_ok(const char *name);

/* Positions the 32-bit length header takes: fewer, and no message fits */
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
void codec_prepared_free(CodecPrepared *p);  /* NULL is fine */

#endif /* CODEC_H */
