#ifndef PNG_IO_H
#define PNG_IO_H

#include <stdint.h>

typedef struct {
    uint32_t width;
    uint32_t height;
    uint8_t **rows;   /* row_pointers[y][x * 3 + channel] */
    const char *dropped;  /* what png_load's conversion to 8-bit RGB lost,
                             e.g. "transparency"; NULL if nothing */
} Image;

Image *png_load(const char *path);
void   image_free(Image *img);

int  png_save(const Image *img, const char *path);  /* returns 0 on success, -1 on failure with errno set (0 if libpng failed internally) */

#endif /* PNG_IO_H */