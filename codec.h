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

/* Positions the 32-bit length header takes: fewer, and no message fits */
uint32_t codec_header_pixels(uint32_t channels);

/* Tries v4, then v3 and v2, then v1 (setting *v1). DECODED gives the
   message in *plaintext (sodium_malloc memory, pt_len bytes and one more
   to spare); NO_MATCH means a wrong passphrase or no message. */
int codec_decode(const Carrier *c, const char *passphrase,
                 uint8_t **plaintext, uint32_t *pt_len, int *v1);

/* Encode, in two steps so the message limit is known before the message
   is read: codec_prepare keys the passphrase (one Argon2id run) and finds
   the order, NULL if it fails or the carrier is too small; codec_embed
   encrypts the message (1 to codec_max_message bytes) and records and
   makes the changes. It frees p, and returns 0, -1 if the message doesn't
   fit, or -2 if out of memory (the carrier then unchanged). */
typedef struct CodecPrepared CodecPrepared;
CodecPrepared *codec_prepare(const Carrier *c, const char *passphrase);
size_t codec_max_message(const CodecPrepared *p);
int  codec_embed(CodecPrepared *p, const Carrier *c, const uint8_t *message, uint32_t msg_len);
void codec_prepared_free(CodecPrepared *p);  /* NULL is fine */

#endif /* CODEC_H */
