#ifndef PNG_IO_H
#define PNG_IO_H

#include <stdint.h>

/* The cover's ancillary chunks, kept by png_load for png_save to write back */
typedef struct PngMeta PngMeta;

typedef struct {
    uint32_t width;
    uint32_t height;
    uint32_t channels;   /* samples per pixel: 1 (gray) or 3 (RGB) */
    uint8_t **rows;      /* rows[y][x * channels + channel] */
    const char *unsuitable;  /* why a cover this way would come out visibly
                                changed, e.g. "transparency"; NULL for 8-bit
                                RGB or gray without transparency */
    PngMeta *meta;       /* NULL if none */
} Image;

Image *png_load(const char *path);
void   image_free(Image *img);

int  png_save(const Image *img, const char *path);  /* returns 0 on success, -1 on failure with errno set (0 if libpng failed internally) */

#endif /* PNG_IO_H */