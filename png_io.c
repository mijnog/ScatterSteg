#include "png_io.h"
#include "atomic_write.h"
#include <png.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*




  10.
*/

/* Largest decoded pixel buffer png_load will allocate (1 GiB) */
#define PNG_MAX_PIXEL_BYTES ((size_t)1 << 30)
/* Largest single chunk (or decompressed text/profile) libpng may allocate */
#define PNG_MAX_CHUNK_BYTES ((png_alloc_size_t)16 << 20)
/* Largest single allocation libpng itself may make. Its biggest legitimate
   one is a row buffer: at most ~8 MB at its 1,000,000-pixel width limit.
   The chunk limit above isn't enough on its own: how libpng honours it
   depends on the version and build, and Ubuntu's 1.6.43 still allocated
   a 1.3 GB tEXt buffer from a 290-byte file (found by CI's fuzzer). */
#define PNG_MAX_LIB_ALLOC ((png_alloc_size_t)64 << 20)

static png_voidp capped_malloc(png_structp png, png_alloc_size_t size) {
    (void)png;
    return size <= PNG_MAX_LIB_ALLOC ? malloc(size) : NULL;  /* NULL: png_error */
}

static void capped_free(png_structp png, png_voidp p) {
    (void)png;
    free(p);
}

/* The read struct and info png_load parsed, kept so png_save can copy the
   ancillary chunks out of it with libpng's own getters */
struct PngMeta {
    png_structp png;
    png_infop info;
};

Image *png_load(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;

    png_structp png = png_create_read_struct_2(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL,
                                               NULL, capped_malloc, capped_free);
    if (!png) { fclose(fp); return NULL; }
    png_infop info = png_create_info_struct(png);
    if (!info) { png_destroy_read_struct(&png, NULL, NULL); fclose(fp); return NULL; }

    /* volatile: assigned after setjmp, so must survive the longjmp intact */
    Image *volatile img = NULL;

    /* libpng uses longjmp for errors — if anything goes wrong it jumps here */
    if (setjmp(png_jmpbuf(png))) {
        image_free(img);  /* NULL for the size checks below; fully allocated
                             by the time png_read_image can fail */
        png_destroy_read_struct(&png, &info, NULL);
        fclose(fp);
        return NULL;
    }

    // Tell libpng to read from FILE* fp
    png_init_io(png, fp);
    png_set_chunk_malloc_max(png, PNG_MAX_CHUNK_BYTES);
    png_set_chunk_cache_max(png, 1000);  /* at most this many ancillary chunks */
    /* Keep chunks libpng doesn't know, so safe-to-copy ones can be written back */
    png_set_keep_unknown_chunks(png, PNG_HANDLE_CHUNK_ALWAYS, NULL, 0);
    // Read the image header (png_read_info) — this fills width, height, bit depth, color type
    png_read_info(png, info);

    // Get width and height
    uint32_t width  = png_get_image_width(png, info);
    uint32_t height = png_get_image_height(png, info);

    /* Everything loads as 8-bit gray or 8-bit RGB. Only those two, without
       transparency, come back out of png_save in the same format; anything
       else would visibly change as a cover. Note why. */
    int color_type = png_get_color_type(png, info);
    int bit_depth  = png_get_bit_depth(png, info);
    const char *unsuitable = NULL;
    if ((color_type & PNG_COLOR_MASK_ALPHA) || png_get_valid(png, info, PNG_INFO_tRNS))
        unsuitable = "transparency";
    else if (bit_depth == 16)
        unsuitable = "16-bit color";
    else if (color_type == PNG_COLOR_TYPE_PALETTE)
        unsuitable = "a color palette";
    else if (bit_depth < 8)
        unsuitable = "fewer than 8 bits per sample";
    uint32_t channels = (color_type & PNG_COLOR_MASK_COLOR) ? 3 : 1;

    png_set_strip_alpha(png);     /* drop alpha channel if present */
    png_set_strip_16(png);        /* 16-bit samples → 8-bit        */
    png_set_palette_to_rgb(png);  /* indexed color → RGB           */
    png_set_expand_gray_1_2_4_to_8(png);  /* low-bit gray → 8-bit  */
    png_set_interlace_handling(png);    /* de-interlace Adam7 images     */
    png_read_update_info(png, info);    /* apply the transforms          */

    /* Rows are allocated as row_size below; refuse anything the transforms
       didn't turn into exactly that, rather than let libpng overrun them.
       row_size is computed once in size_t so the check and malloc agree.
       png_error reports the cause and jumps to the cleanup handler above. */
    size_t row_size = (size_t)width * channels;
    if (row_size / channels != width || png_get_rowbytes(png, info) != row_size)
        png_error(png, "unexpected decoded row size");

    /* The header's dimensions are untrusted: cap the total allocation before
       making it, so a tiny file can't request terabytes. This also bounds
       height, so the row-pointer array below can't overflow. libpng rejects
       a zero height in png_read_info, so the division is safe. */
    if (row_size > PNG_MAX_PIXEL_BYTES / height)
        png_error(png, "image dimensions too large");

    // Allocate the Image struct and its row pointers
    img = malloc(sizeof(Image));
    if (!img) {
        png_destroy_read_struct(&png, &info, NULL);
        fclose(fp);
        return NULL;
    }
    img->width      = width;
    img->height     = height;
    img->channels   = channels;
    img->unsuitable = unsuitable;
    img->meta       = NULL;
    img->rows       = malloc(height * sizeof(uint8_t *));
    if (!img->rows) {
        free(img);
        png_destroy_read_struct(&png, &info, NULL);
        fclose(fp);
        return NULL;
    }
    for (uint32_t y = 0; y < height; y++) {
        img->rows[y] = malloc(row_size);
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
    fclose(fp);

    /* Keep the parsed chunks (those before the image data) for png_save */
    PngMeta *meta = malloc(sizeof(PngMeta));
    if (!meta) {
        png_destroy_read_struct(&png, &info, NULL);
        image_free(img);
        return NULL;
    }
    meta->png  = png;
    meta->info = info;
    img->meta  = meta;
    return img;
}

/* Give the new PNG the cover's ancillary chunks, so the output looks like
   the same file: color space (gAMA, cHRM, sRGB, iCCP), pHYs, text, tIME,
   eXIf, and unknown chunks marked safe to copy. Unknown chunks not marked
   safe must, per the PNG spec, be dropped once the pixels change. */
/* png_write_tEXt and friends png_error on a keyword with no character from
   the PNG keyword set (Latin-1 printable, other than space) */
static int writable_keyword(png_const_charp key) {
    for (const unsigned char *k = (const unsigned char *)key; k && *k; k++)
        if ((*k > 32 && *k < 127) || *k > 160) return 1;
    return 0;
}

static void copy_metadata(png_structp w, png_infop wi, const PngMeta *m) {
    png_structp r = m->png;
    png_infop ri = m->info;
    /* Odd but readable metadata shouldn't make the save fail */
    png_set_benign_errors(w, 1);

    png_fixed_point gamma, wx, wy, rx, ry, gx, gy, bx, by;
    if (png_get_gAMA_fixed(r, ri, &gamma)) png_set_gAMA_fixed(w, wi, gamma);
    if (png_get_cHRM_fixed(r, ri, &wx, &wy, &rx, &ry, &gx, &gy, &bx, &by))
        png_set_cHRM_fixed(w, wi, wx, wy, rx, ry, gx, gy, bx, by);
    int intent;
    if (png_get_sRGB(r, ri, &intent)) png_set_sRGB(w, wi, intent);
    png_charp name;
    int compression;
    png_bytep profile;
    png_uint_32 len;
    if (png_get_iCCP(r, ri, &name, &compression, &profile, &len))
        png_set_iCCP(w, wi, name, compression, profile, len);
    png_uint_32 res_x, res_y;
    int unit;
    if (png_get_pHYs(r, ri, &res_x, &res_y, &unit)) png_set_pHYs(w, wi, res_x, res_y, unit);
    /* libpng reads text whose keyword it will then refuse to write (one with
       no printable character), so skip those rather than fail the save */
    png_textp text;
    int n_text = png_get_text(r, ri, &text, NULL);
    for (int i = 0; i < n_text; i++)
        if (writable_keyword(text[i].key)) png_set_text(w, wi, &text[i], 1);
    png_timep mod_time;
    if (png_get_tIME(r, ri, &mod_time)) png_set_tIME(w, wi, mod_time);
    png_bytep exif;
    png_uint_32 exif_len;
    if (png_get_eXIf_1(r, ri, &exif_len, &exif)) png_set_eXIf_1(w, wi, exif_len, exif);

    png_unknown_chunkp chunks;
    int n_chunks = png_get_unknown_chunks(r, ri, &chunks);
    for (int i = 0; i < n_chunks; i++)
        if (chunks[i].name[3] & 0x20) {  /* lowercase 4th letter: safe to copy */
            png_set_keep_unknown_chunks(w, PNG_HANDLE_CHUNK_ALWAYS, chunks[i].name, 1);
            png_set_unknown_chunks(w, wi, &chunks[i], 1);
        }
}

/* Writes the image as a PNG stream. Called by atomic_write, which leaves
   errno at 0 so a libpng error reports as such. */
static int write_png(FILE *fp, const void *ctx) {
    const Image *img = ctx;
    png_structp png = png_create_write_struct_2(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL,
                                                NULL, capped_malloc, capped_free);
    if (!png) return -1;
    png_infop info = png_create_info_struct(png);
    if (!info) {
        png_destroy_write_struct(&png, NULL);
        return -1;
    }
    if (setjmp(png_jmpbuf(png))) {
        png_destroy_write_struct(&png, &info);
        return -1;
    }

    png_init_io(png, fp);
    png_set_IHDR(png, info,
        img->width, img->height,
        8,
        img->channels == 1 ? PNG_COLOR_TYPE_GRAY : PNG_COLOR_TYPE_RGB,
        PNG_INTERLACE_NONE,
        PNG_COMPRESSION_TYPE_DEFAULT,
        PNG_FILTER_TYPE_DEFAULT);
    if (img->meta) copy_metadata(png, info, img->meta);
    png_write_info(png, info);
    png_write_image(png, img->rows);
    png_write_end(png, NULL);
    png_destroy_write_struct(&png, &info);
    return 0;
}

int png_save(const Image *img, const char *path) {
    return atomic_write(path, write_png, img);
}


void image_free(Image *img) {
    if (!img) return;
    if (img->meta) {
        png_destroy_read_struct(&img->meta->png, &img->meta->info, NULL);
        free(img->meta);
    }
    for (uint32_t y = 0; y < img->height; y++)
        free(img->rows[y]);
    free(img->rows);
    free(img);
}