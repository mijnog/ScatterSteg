#include "png_io.h"
#include <png.h>
#include <stdlib.h>
#include <stdio.h>

/*




  10.
*/

Image *png_load(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;

    png_structp png = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png) { fclose(fp); return NULL; }
    png_infop info = png_create_info_struct(png);
    if (!info) { png_destroy_read_struct(&png, NULL, NULL); fclose(fp); return NULL; }

    /* libpng uses longjmp for errors — if anything goes wrong it jumps here */
    if (setjmp(png_jmpbuf(png))) {
        png_destroy_read_struct(&png, &info, NULL);
        fclose(fp);
        return NULL;
    }

    // Tell libpng to read from FILE* fp
    png_init_io(png, fp);
    // Read the image header (png_read_info) — this fills width, height, bit depth, color type
    png_read_info(png, info);

    // Get width and height
    uint32_t width  = png_get_image_width(png, info);
    uint32_t height = png_get_image_height(png, info);

    /* Force any PNG variant into 8-bit RGB */
    png_set_strip_alpha(png);     /* drop alpha channel if present */
    png_set_gray_to_rgb(png);     /* expand grayscale to RGB       */
    png_set_strip_16(png);        /* 16-bit channels → 8-bit       */
    png_set_palette_to_rgb(png);  /* indexed color → RGB           */
    png_read_update_info(png, info);    /* apply the transforms          */

    // Allocate the Image struct and its row pointers
    Image *img = malloc(sizeof(Image));
    if (!img) {
        png_destroy_read_struct(&png, &info, NULL);
        fclose(fp);
        return NULL;
    }
    img->width  = width;
    img->height = height;
    img->rows   = malloc(height * sizeof(uint8_t *));
    if (!img->rows) {
        free(img);
        png_destroy_read_struct(&png, &info, NULL);
        fclose(fp);
        return NULL;
    }
    for (uint32_t y = 0; y < height; y++) {
        img->rows[y] = malloc(width * 3);  /* 3 bytes per pixel: R G B */
        if (!img->rows[y]) {
            for (uint32_t i = 0; i < y; i++)
                free(img->rows[i]);
            free(img->rows);
            free(img);
            png_destroy_read_struct(&png, &info, NULL);
            fclose(fp);
            return NULL;
        }
    }

    // Read the pixel data (png_read_image)
    png_read_image(png, img->rows);

    // Clean up
    png_destroy_read_struct(&png, &info, NULL);
    fclose(fp);
    return img;
}

int png_save(const Image *img, const char *path) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;

    png_structp png = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png) { fclose(fp); remove(path); return -1; }
    png_infop info = png_create_info_struct(png);
    if (!info) { png_destroy_write_struct(&png, NULL); fclose(fp); remove(path); return -1; }

    // error handling
    if (setjmp(png_jmpbuf(png))) {
        png_destroy_write_struct(&png, &info);
        fclose(fp);
        remove(path);
        return -1;
    }

    // file to write to
    png_init_io(png, fp);

    // declare pixel data format
    png_set_IHDR(png, info,
        img->width, img->height,
        8,
        PNG_COLOR_TYPE_RGB,
        PNG_INTERLACE_NONE,
        PNG_COMPRESSION_TYPE_DEFAULT,
        PNG_FILTER_TYPE_DEFAULT);

    //  write the PNG header
    png_write_info(png, info);
    // write the pixel rows
    png_write_image(png, img->rows);
    // finalize the file
    png_write_end(png, NULL);

    // cleanup
    png_destroy_write_struct(&png, &info);
    fclose(fp);
    return 0;
}


void image_free(Image *img) {
    if (!img) return;
    for (uint32_t y = 0; y < img->height; y++)
        free(img->rows[y]);
    free(img->rows);
    free(img);
}