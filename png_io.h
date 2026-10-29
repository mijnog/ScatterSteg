/* SPDX-License-Identifier: AGPL-3.0-or-later
   Copyright (C) 2026 Maxime de Montbron */
#ifndef PNG_IO_H
#define PNG_IO_H

#include <stdint.h>
#include <stdio.h>

/* The cover's ancillary chunks, kept by png_load for png_save to write back */
typedef struct PngMeta PngMeta;

typedef struct {
    uint32_t width;
    uint32_t height;
    uint32_t channels;   /* samples per pixel: 1 (gray) or 3 (RGB) */
    uint8_t **rows;      /* rows[y][x * channels + channel] */
    const char *unsuitable;  /* why a cover this way would come out visibly
                                changed, or give its changes away, e.g.
                                "transparency"; NULL for 8-bit RGB or gray
                                without transparency, sBIT < 8, animation
                                or RGB that is all gray */
    PngMeta *meta;       /* NULL if none */
} Image;

/* The reasons for unsuitable that are about the content (pixels, chunks)
   rather than the format: what png_save writes can still have them */
#define PNG_LOW_SBIT    "fewer than 8 significant bits (an sBIT chunk)"
#define PNG_GRAY_AS_RGB "only gray pixels, stored as RGB (save it as grayscale)"

Image *png_load(const char *path);
void   image_free(Image *img);

int  png_save(const Image *img, const char *path);  /* returns 0 on success, -1 on failure with errno set (0 if libpng failed internally) */
/* The same on a stream, not atomically. png_read closes fp. */
Image *png_read(FILE *fp);
int    png_write(const Image *img, FILE *fp);

#endif /* PNG_IO_H */