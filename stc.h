/* SPDX-License-Identifier: MIT OR Apache-2.0
   Copyright (C) 2026 Maxime de Montbron */
#ifndef STC_CODES_H
#define STC_CODES_H

#include <stddef.h>
#include <stdint.h>

/* Syndrome-trellis codes (Filler, Judas & Fridrich, "Minimizing Additive
   Distortion in Steganography Using Syndrome-Trellis Codes", 2011).

   The message is not written into the carriers' bits y directly: it is
   their syndrome m = H y, for a band matrix H made of copies of a small
   public submatrix. Many y have the same syndrome, so the encoder picks the
   one cheapest to reach from the cover's bits x (Viterbi over the trellis
   of partial syndromes), given a cost per carrier. At low payloads that
   takes several times fewer changes, and it leaves the cover's own bits,
   parity skew included, almost as they were.

   Message bit i is the syndrome of a block of carriers starting at
   floor(i * n / mlen), so blocks are w or w+1 wide and any payload uses
   all n carriers. Decoding is the matrix product. Bits are stored one per
   byte (0 or 1). */

/* How many carriers to use for mlen message bits when n_avail are there:
   all of them, up to a cap that bounds the work. 0 if they don't fit, or
   mlen is 2^32 or more. */
size_t stc_carriers(size_t n_avail, size_t mlen);

/* Finds stego bits y (n of them, from stc_carriers) with syndrome m,
   minimizing the sum of costs[i] over the i where y[i] != x[i]. Costs must
   be positive. Returns 0, or -1 if out of memory. */
int stc_embed(const uint8_t *x, const float *costs, const uint8_t *m,
              size_t mlen, size_t n, uint8_t *y);

/* The syndrome of y (n carriers): the mlen message bits */
void stc_extract(const uint8_t *y, size_t mlen, size_t n, uint8_t *m);

#endif /* STC_CODES_H */
