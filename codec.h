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
   one that inflates past it */
#define CODEC_MESSAGE_MAX ((uint32_t)64 << 20)

/* Positions the 32-bit length header takes: fewer, and no message fits */
uint32_t codec_header_pixels(uint32_t channels);

/* DECODED gives the message in *plaintext (sodium_malloc memory, pt_len
   bytes and one more to spare); NO_MATCH means a wrong passphrase or no
   message. Costs one Argon2id run. */
int codec_decode(const Carrier *c, const char *passphrase,
                 uint8_t **plaintext, uint32_t *pt_len);

/* Encode, in two steps: codec_prepare keys the passphrase (one Argon2id
   run) and finds the order, NULL if it fails or the carrier is too small;
   codec_embed compresses the message (1 to CODEC_MESSAGE_MAX bytes) if
   that makes it shorter, encrypts it, and records and makes the changes.
   It frees p, and returns 0, -1 if the message doesn't fit even
   compressed, or -2 if out of memory (the carrier then unchanged). */
typedef struct CodecPrepared CodecPrepared;
/* Whether the carrier can't hold the salt and length, whatever the message:
   cheap, so encode checks it before slower work on the cover */
int codec_too_small(const Carrier *c);
/* The longest message the carrier holds stored as is (a compressible one
   can be longer), which needs no passphrase: what codec_max_message gives
   once prepared. 0 if codec_too_small. */
size_t codec_capacity(const Carrier *c);
CodecPrepared *codec_prepare(const Carrier *c, const char *passphrase);
size_t codec_max_message(const CodecPrepared *p);
int  codec_embed(CodecPrepared *p, const Carrier *c, const uint8_t *message, uint32_t msg_len);
void codec_prepared_free(CodecPrepared *p);  /* NULL is fine */

#endif /* CODEC_H */
