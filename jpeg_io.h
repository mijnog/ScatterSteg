/* SPDX-License-Identifier: AGPL-3.0-or-later
   Copyright (C) 2026 Maxime de Montbron */
#ifndef JPEG_IO_H
#define JPEG_IO_H

#include <stdint.h>
#include <stdio.h>
#include "embed.h"

/* A JPEG's quantized DCT coefficients and markers, read and written
   losslessly: nothing is decoded to pixels and re-compressed, so only the
   coefficients we change differ in the output. */
typedef struct JpegImage JpegImage;

int is_jpeg_file(const char *path);  /* starts with the JPEG SOI marker */

/* Loads an 8-bit DCT JPEG (baseline or progressive, Huffman or arithmetic
   coded). NULL if it can't be read, is lossless or not 8-bit, or would
   need more than 1 GiB of coefficients, or of memory for its carriers. */
JpegImage *jpeg_load(const char *path);
void jpeg_free(JpegImage *j);

/* The carriers: every AC coefficient with |value| >= 2, in component,
   block-row, block, coefficient order. DC coefficients, zeros and +-1 are
   never used: changing them shows (blocking, and the count of zeros that
   JPEG steganalysis watches). Embedding keeps |value| >= 2, so a decoder
   finds the same carriers. Valid until jpeg_free. */
Carrier jpeg_carrier(JpegImage *j);
void jpeg_size(const JpegImage *j, uint32_t *width, uint32_t *height);

/* How much dearer a change to a coefficient of |value| 2 is than its UERD
   cost: 2 can only go to 3, which shifts the 2:3 ratio JPEG detectors
   watch. Tuned on the benchmark covers: 1.75 keeps the ratio within 0.17
   of the covers' spread at 0.05-0.2 bits per non-zero AC coefficient
   (1.5: 0.43, 2.0: 0.22), with the same DCTR detection to within noise. */
#ifndef JPEG_TWO_COST
#define JPEG_TWO_COST 1.75f
#endif

/* Why a cover this way would come out visibly changed, or NULL. Data
   after the EOI marker (MPF secondary images, Ultra HDR gain maps, depth
   maps) isn't kept, while the markers indexing it would be. */
const char *jpeg_unsuitable(const JpegImage *j);

/* Some JPEGs decode fine but libjpeg won't write their coefficients back
   (a quantization table redefined between scans, sampling factors too big
   for the scans it would generate, ...: each found by fuzzing). Encodes to
   nowhere to find out. Returns 0 if jpeg_save would succeed (barring I/O). */
int jpeg_check_writable(JpegImage *j);

/* Writes the coefficients and markers as a JPEG, atomically (see
   atomic_write). Returns 0, or -1 with errno set (0 if libjpeg failed). */
int jpeg_save(const JpegImage *j, const char *path);
/* The same on a stream, not atomically. jpeg_read closes fp; fp must not
   be NULL. */
JpegImage *jpeg_read(FILE *fp);
int jpeg_write(JpegImage *j, FILE *fp);

#endif /* JPEG_IO_H */
