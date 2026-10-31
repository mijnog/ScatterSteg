/* SPDX-License-Identifier: MIT OR Apache-2.0
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

/* The carriers: every AC coefficient, zeros included, in component,
   block-row, block, coefficient order, as UED, UERD and J-UNIWARD use
   them; the costs keep changes out of smooth blocks. DC coefficients are
   never used: changing them shows as blocking. Valid until jpeg_free. */
Carrier jpeg_carrier(JpegImage *j);
void jpeg_size(const JpegImage *j, uint32_t *width, uint32_t *height);
/* How many AC coefficients aren't 0: what JPEG payloads are measured in */
uint64_t jpeg_nonzero_ac(const JpegImage *j);

/* Why a cover this way would come out visibly changed, or NULL. Data
   after the EOI marker (MPF secondary images, Ultra HDR gain maps, depth
   maps) isn't kept, while the markers indexing it would be. A content
   credential (C2PA) would be kept, but no longer match the pixels. */
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
