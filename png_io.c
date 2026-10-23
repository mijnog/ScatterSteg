#include "png_io.h"
#include "atomic_write.h"
#include <png.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*




  10.
*/

/* Largest decoded pixel buffer png_load will allocate (1 GiB) */
#define PNG_MAX_PIXEL_BYTES ((size_t)1 << 30)
/* Most pixels png_load will take: each also has a 4-byte slot in the
   message permutation, so this keeps that to 1 GiB too. Without it a gray
   image within the byte cap needed a 4 GiB permutation. */
#define PNG_MAX_PIXELS ((uint64_t)1 << 28)
/* Largest single chunk (or decompressed text/profile) libpng may allocate */
#define PNG_MAX_CHUNK_BYTES ((png_alloc_size_t)16 << 20)
/* Largest single allocation libpng itself may make. Its biggest legitimate
   one is a row buffer: at most ~8 MB at its 1,000,000-pixel width limit.
   The chunk limit above isn't enough on its own: how libpng honours it
   depends on the version and build, and Ubuntu's 1.6.43 still allocated
   a 1.3 GB tEXt buffer from a 290-byte file (found by CI's fuzzer). */
#define PNG_MAX_LIB_ALLOC ((png_alloc_size_t)64 << 20)

/* Largest total libpng may hold at once. The per-chunk and per-allocation
   caps don't bound the sum: up to 1000 text chunks are kept, and a zTXt of
   a few KiB can inflate to nearly 16 MiB, so a 16 MB file could otherwise
   make libpng hold 16 GiB (and did hold 498 MiB for a 490 KB one). Past this, libpng drops the chunk it was
   reading (a benign error on read). */
#define PNG_MAX_LIB_TOTAL ((size_t)128 << 20)

/* What one libpng struct has allocated and not yet freed. Each block has a
   header recording its size, so capped_free can take it off. */
typedef struct {
    size_t live;
} AllocBudget;

typedef union {
    size_t size;
    max_align_t align;
} AllocHeader;

static png_voidp capped_malloc(png_structp png, png_alloc_size_t size) {
    AllocBudget *budget = png_get_mem_ptr(png);
    if (size > PNG_MAX_LIB_ALLOC || size > PNG_MAX_LIB_TOTAL - budget->live)
        return NULL;  /* NULL: png_error, or a benign error for a chunk */
    AllocHeader *h = malloc(sizeof(AllocHeader) + size);
    if (!h) return NULL;
    h->size = size;
    budget->live += size;
    return h + 1;
}

static void capped_free(png_structp png, png_voidp p) {
    if (!p) return;
    AllocHeader *h = (AllocHeader *)p - 1;
    ((AllocBudget *)png_get_mem_ptr(png))->live -= h->size;
    free(h);
}

/* The read struct and info png_load parsed, kept so png_save can copy the
   ancillary chunks out of it. The budget must
   outlive the struct, which frees through it. */
struct PngMeta {
    png_structp png;
    png_infop info;
    AllocBudget *budget;
};

/* Read the chunks after the image data. The pixels are already in, so a
   damaged tail only loses what comes after the damage. */
static void read_end(png_structp png, png_infop info) {
    jmp_buf saved;  /* png_load's handler, for after */
    memcpy(saved, png_jmpbuf(png), sizeof(saved));
    if (!setjmp(png_jmpbuf(png)))
        png_read_end(png, info);
    memcpy(png_jmpbuf(png), saved, sizeof(saved));
}

Image *png_load(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    AllocBudget *budget = calloc(1, sizeof(AllocBudget));
    if (!budget) { fclose(fp); return NULL; }

    png_structp png = png_create_read_struct_2(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL,
                                               budget, capped_malloc, capped_free);
    if (!png) { free(budget); fclose(fp); return NULL; }
    png_infop info = png_create_info_struct(png);
    if (!info) { png_destroy_read_struct(&png, NULL, NULL); free(budget); fclose(fp); return NULL; }

    /* volatile: assigned after setjmp, so must survive the longjmp intact */
    Image *volatile img = NULL;

    /* libpng uses longjmp for errors — if anything goes wrong it jumps here */
    if (setjmp(png_jmpbuf(png))) {
        image_free(img);  /* NULL for the size checks below; fully allocated
                             by the time png_read_image can fail */
        png_destroy_read_struct(&png, &info, NULL);
        free(budget);
        fclose(fp);
        return NULL;
    }

    // Tell libpng to read from FILE* fp
    png_init_io(png, fp);
    png_set_chunk_malloc_max(png, PNG_MAX_CHUNK_BYTES);
    png_set_chunk_cache_max(png, 1000);  /* at most this many ancillary chunks */
    /* Keep every ancillary chunk as raw bytes, known to libpng or not (all
       but IHDR, PLTE, tRNS, IDAT and IEND), for png_save to write back as
       they were. libpng doesn't parse them, so text isn't decompressed. */
    png_set_keep_unknown_chunks(png, PNG_HANDLE_CHUNK_ALWAYS, NULL, -1);
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
    if (row_size > PNG_MAX_PIXEL_BYTES / height || (uint64_t)width * height > PNG_MAX_PIXELS)
        png_error(png, "image dimensions too large");

    // Allocate the Image struct and its row pointers
    img = malloc(sizeof(Image));
    if (!img) {
        png_destroy_read_struct(&png, &info, NULL);
        free(budget);
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
        free(budget);
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
            free(budget);
            fclose(fp);
            return NULL;
        }
    }

    // Read the pixel data (png_read_image)
    png_read_image(png, img->rows);
    read_end(png, info);
    fclose(fp);

    /* Keep the chunks for png_save */
    PngMeta *meta = malloc(sizeof(PngMeta));
    if (!meta) {
        png_destroy_read_struct(&png, &info, NULL);
        free(budget);
        image_free(img);
        return NULL;
    }
    meta->png    = png;
    meta->info   = info;
    meta->budget = budget;
    img->meta  = meta;
    return img;
}

/* Ancillary chunks the PNG spec defines whose meaning doesn't depend on
   the exact pixel values, so they stay true once LSBs change: color space,
   physical layout, text, time, Exif... Many are marked unsafe to copy
   (uppercase 4th letter), but that rule is for editors that don't know
   the chunk. */
static const char *const kept_chunks[] = {
    "cHRM", "cICP", "cLLI", "gAMA", "iCCP", "mDCV", "sBIT", "sRGB", "bKGD", "pHYs",
    "sPLT", "eXIf", "tIME", "tEXt", "zTXt", "iTXt", "oFFs", "pCAL", "sCAL", "sTER",
};

static int keep_chunk(const png_byte *name) {
    if (name[3] & 0x20) return 1;  /* lowercase 4th letter: safe to copy */
    for (size_t i = 0; i < sizeof(kept_chunks) / sizeof(kept_chunks[0]); i++)
        if (memcmp(name, kept_chunks[i], 4) == 0) return 1;
    return 0;
}

/* Give the new PNG the cover's ancillary chunks, byte for byte and where
   they were (before or after the image data), so the output looks like
   the same file. Unknown chunks not marked safe to copy must, per the PNG
   spec, be dropped once the pixels change. */
static void copy_metadata(png_structp w, png_infop wi, const PngMeta *m) {
    png_unknown_chunkp chunks;
    int n_chunks = png_get_unknown_chunks(m->png, m->info, &chunks);
    for (int i = 0; i < n_chunks; i++)
        if (keep_chunk(chunks[i].name)) {
            png_set_keep_unknown_chunks(w, PNG_HANDLE_CHUNK_ALWAYS, chunks[i].name, 1);
            png_set_unknown_chunks(w, wi, &chunks[i], 1);
        }
}

/* Writes the image as a PNG stream. Called by atomic_write, which leaves
   errno at 0 so a libpng error reports as such. */
static int write_png(FILE *fp, const void *ctx) {
    const Image *img = ctx;
    AllocBudget budget = {0};
    png_structp png = png_create_write_struct_2(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL,
                                                &budget, capped_malloc, capped_free);
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
    /* Interlaced like the cover, so the format doesn't change */
    int interlace = img->meta ? png_get_interlace_type(img->meta->png, img->meta->info)
                              : PNG_INTERLACE_NONE;
    png_set_IHDR(png, info,
        img->width, img->height,
        8,
        img->channels == 1 ? PNG_COLOR_TYPE_GRAY : PNG_COLOR_TYPE_RGB,
        interlace == PNG_INTERLACE_ADAM7 ? PNG_INTERLACE_ADAM7 : PNG_INTERLACE_NONE,
        PNG_COMPRESSION_TYPE_DEFAULT,
        PNG_FILTER_TYPE_DEFAULT);
    if (img->meta) copy_metadata(png, info, img->meta);
    png_write_info(png, info);
    if (interlace == PNG_INTERLACE_ADAM7) png_set_interlace_handling(png);
    png_write_image(png, img->rows);
    png_write_end(png, info);  /* with info: the chunks after the image data */
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
        free(img->meta->budget);
        free(img->meta);
    }
    for (uint32_t y = 0; y < img->height; y++)
        free(img->rows[y]);
    free(img->rows);
    free(img);
}