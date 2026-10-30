/* SPDX-License-Identifier: MIT OR Apache-2.0
   Copyright (C) 2026 Maxime de Montbron */
#ifndef DISTORTION_H
#define DISTORTION_H

#include <stdint.h>
#include "png_io.h"

/* Distortion models beyond the defaults (HILL for PNG, embed_hill_costs;
   UERD for JPEG, in jpeg_io.c): the wavelet-based models of Holub and
   Fridrich. Each gives the cost of a +-1 change to every sample, which
   only the encoder uses: the decoder reads LSBs, so a message embedded
   with any model reads back with any build.

   They follow the authors' reference implementations (Binghamton DDE lab:
   WOW v1.0, S-UNIWARD v1.0, J-UNIWARD v1.1) and are checked against them
   (tests/test_distortion.c; benchmark/README.md, "Distortion models").
   Where ScatterSteg differs from those (more than one channel or
   component, images smaller than the filters, the binary coder), the
   comments below say so. */

/* Which model a build uses: PNG_COSTS / JPEG_COSTS in the Makefile. The
   defaults are the ones the benchmarks measured best so far. Macros, not
   an enum: #if treats an enum constant as 0, so every test would match. */
#define COSTS_HILL     1
#define COSTS_WOW      2
#define COSTS_SUNIWARD 3
#define COSTS_UERD     1
#define COSTS_JUNIWARD 2
#ifndef SCATTERSTEG_PNG_COSTS
#define SCATTERSTEG_PNG_COSTS COSTS_HILL
#endif
#ifndef SCATTERSTEG_JPEG_COSTS
#define SCATTERSTEG_JPEG_COSTS COSTS_UERD
#endif
#if SCATTERSTEG_PNG_COSTS != COSTS_HILL && SCATTERSTEG_PNG_COSTS != COSTS_WOW && \
    SCATTERSTEG_PNG_COSTS != COSTS_SUNIWARD
#error "PNG_COSTS must be hill, wow or suniward"
#endif
#if SCATTERSTEG_JPEG_COSTS != COSTS_UERD && SCATTERSTEG_JPEG_COSTS != COSTS_JUNIWARD
#error "JPEG_COSTS must be uerd or juniward"
#endif

/* Costs above this are capped, as the references cap theirs ("wet" costs:
   the coder all but never changes such a sample) */
#define DISTORTION_WET_SPATIAL 1e10f
#define DISTORTION_WET_JPEG    1e13f

/* WOW (Holub and Fridrich, "Designing Steganographic Distortion Using
   Directional Filters", WIFS 2012) and S-UNIWARD (Holub, Fridrich and
   Denemark, "Universal Distortion Function for Steganography in an
   Arbitrary Domain", EURASIP JIS 2014), for every sample of img in
   rows[y][x * channels + c] order, like embed_hill_costs: each channel is
   costed on its own, as the references cost a grayscale image. NULL if out
   of memory. */
float *distortion_wow(const Image *img);
float *distortion_suniward(const Image *img);

/* J-UNIWARD (same paper), for one JPEG component at a time.

   Made from the component's decompressed plane: w x h pixels, both
   multiples of 8 (whole blocks), row by row, as decompression rounds and
   clamps them (distortion_idct_block). The reference costs only
   luminance; ScatterSteg costs every component on its own plane, at its
   own resolution and with its own quantization table, before colour
   conversion and upsampling. quant is in natural (row-major) order. NULL
   if out of memory. */
typedef struct JUniward JUniward;
/* Its planes take about 28 bytes per pixel of the component, so J-UNIWARD
   builds refuse a component larger than this (about 1.9 GB): the JPEG
   loader's own limits allow far more, which is fine for UERD's one value
   per block but not here */
#define JUNIWARD_MAX_PIXELS ((uint64_t)1 << 26)
JUniward *juniward_new(const float *pixels, uint32_t w, uint32_t h, const uint16_t quant[64]);
/* The cost of changing coefficient k (natural order, 1-63) of block
   (bx, by) by 1 */
float juniward_cost(const JUniward *j, uint32_t bx, uint32_t by, int k);
void  juniward_free(JUniward *j);  /* NULL is fine */

/* One block's pixels as decompression gives them: the inverse DCT of
   coef[k] * quant[k], plus 128, rounded and clamped to 0..255. A float
   inverse DCT, so a pixel can differ by 1 from libjpeg's integer one. */
void distortion_idct_block(const int16_t coef[64], const uint16_t quant[64], float out[64]);

#endif /* DISTORTION_H */
