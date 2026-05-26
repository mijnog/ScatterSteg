#ifndef PNG_IO_H
#define PNG_IO_H

#include <stdint.h>

typedef struct {
    uint32_t width;
    uint32_t height;
    uint8_t **rows;   /* row_pointers[y][x * 3 + channel] */
} Image;

Image *png_load(const char *path);
void   image_free(Image *img);

void png_save(const Image *img, const char *path);

#endif /* PNG_IO_H */