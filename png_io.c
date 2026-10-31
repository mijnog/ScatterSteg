/* SPDX-License-Identifier: MIT OR Apache-2.0
   Copyright (C) 2026 Maxime de Montbron */
#include "png_io.h"
#include "atomic_write.h"
#include <png.h>
#include <zlib.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

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
    /* The cover's compressed image data (its first run of IDAT chunks,
       joined), for png_write to compress the new pixels the same way; NULL
       unless the cover is 8-bit gray or RGB, the only kind it writes */
    uint8_t *idat;
    size_t idat_len;
    uint32_t idat_first;  /* the first IDAT's size */
    uint32_t idat_count;  /* how many there were */
};

/* Everything libpng reads, kept so png_read can find the cover's
   compressed image data, which libpng doesn't hand out */
typedef struct {
    FILE *fp;
    uint8_t *buf;
    size_t len, cap;
    int lost;  /* out of memory: the copy is incomplete */
} Tee;

static void tee_read(png_structp png, png_bytep out, size_t n) {
    Tee *t = png_get_io_ptr(png);
    if (fread(out, 1, n, t->fp) != n) png_error(png, "Read Error");
    if (t->lost) return;
    if (n > t->cap - t->len) {
        size_t cap = t->cap ? t->cap : 1 << 16;
        while (cap < t->len + n && cap <= SIZE_MAX / 2) cap *= 2;
        uint8_t *buf = cap >= t->len + n ? realloc(t->buf, cap) : NULL;
        if (!buf) { t->lost = 1; return; }
        t->buf = buf;
        t->cap = cap;
    }
    memcpy(t->buf + t->len, out, n);
    t->len += n;
}

static uint32_t be32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

/* Moves the file's first run of IDAT chunks' data to the start of buf,
   joined, and notes the run's chunk sizes. Stops at a chunk that doesn't
   fit in the file. As rust/src/png_io.rs's idat_run. */
static void take_idat(PngMeta *m, uint8_t *buf, size_t len) {
    size_t pos = 8, out = 0;
    uint32_t count = 0, first = 0;
    while (pos + 12 <= len) {
        uint32_t n = be32(buf + pos);
        if (n > INT32_MAX || n > len - pos - 12) break;
        int idat = memcmp(buf + pos + 4, "IDAT", 4) == 0;
        if (!idat && count > 0) break;
        if (memcmp(buf + pos + 4, "IEND", 4) == 0) break;
        if (idat) {
            if (count++ == 0) first = n;
            memmove(buf + out, buf + pos + 8, n);
            out += n;
        }
        pos += 12 + (size_t)n;
    }
    m->idat = buf;
    m->idat_len = out;
    m->idat_first = first;
    m->idat_count = count;
}

/* An sBIT chunk (kept raw, like every ancillary chunk) saying a channel
   has fewer than 8 significant bits: such images have structured low bits
   (zeros, or the high bits repeated), which +-1 changes break, and the
   chunk itself, kept in the output, tells a warden to look */
static int low_sbit(png_structp png, png_infop info) {
    png_unknown_chunkp chunks;
    int n = png_get_unknown_chunks(png, info, &chunks);
    for (int i = 0; i < n; i++)
        if (memcmp(chunks[i].name, "sBIT", 4) == 0)
            for (size_t k = 0; k < chunks[i].size; k++)
                if (chunks[i].data[k] < 8) return 1;
    return 0;
}

/* An animated PNG (APNG): libpng reads only its first frame, and the
   output drops the chunks that hold the rest (acTL, fcTL, fdAT), so the
   animation would visibly stop. Only a well-formed acTL (8 bytes, at
   least one frame) counts: viewers show a malformed one's still image. */
static int animated(png_structp png, png_infop info) {
    png_unknown_chunkp chunks;
    int n = png_get_unknown_chunks(png, info, &chunks);
    for (int i = 0; i < n; i++)
        if (memcmp(chunks[i].name, "acTL", 4) == 0 && chunks[i].size == 8 &&
            (chunks[i].data[0] | chunks[i].data[1] | chunks[i].data[2] | chunks[i].data[3]))
            return 1;
    return 0;
}

/* Gray stored as RGB: R = G = B in every pixel. Changing the channels
   independently breaks that, which a one-line check finds. */
static int all_gray(const Image *img) {
    if (img->channels != 3) return 0;
    for (uint32_t y = 0; y < img->height; y++) {
        const uint8_t *p = img->rows[y];
        for (uint32_t x = 0; x < img->width; x++, p += 3)
            if (p[0] != p[1] || p[1] != p[2]) return 0;
    }
    return 1;
}

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
    return fp ? png_read(fp) : NULL;
}

Image *png_read(FILE *fp) {
    AllocBudget *budget = calloc(1, sizeof(AllocBudget));
    if (!budget) { fclose(fp); return NULL; }

    Tee *tee = calloc(1, sizeof(Tee));
    if (!tee) { free(budget); fclose(fp); return NULL; }
    tee->fp = fp;

    png_structp png = png_create_read_struct_2(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL,
                                               budget, capped_malloc, capped_free);
    if (!png) { free(tee); free(budget); fclose(fp); return NULL; }
    png_infop info = png_create_info_struct(png);
    if (!info) { png_destroy_read_struct(&png, NULL, NULL); free(tee); free(budget); fclose(fp); return NULL; }

    /* volatile: assigned after setjmp, so must survive the longjmp intact */
    Image *volatile img = NULL;

    /* libpng uses longjmp for errors — if anything goes wrong it jumps here */
    if (setjmp(png_jmpbuf(png))) {
        image_free(img);  /* NULL for the size checks below; fully allocated
                             by the time png_read_image can fail */
        png_destroy_read_struct(&png, &info, NULL);
        free(tee->buf);
        free(tee);
        free(budget);
        fclose(fp);
        return NULL;
    }

    // Tell libpng to read from FILE* fp, through tee
    png_set_read_fn(png, tee, tee_read);
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
        free(tee->buf);
        free(tee);
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
        free(tee->buf);
        free(tee);
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
            free(tee->buf);
            free(tee);
            free(budget);
            fclose(fp);
            return NULL;
        }
    }

    // Read the pixel data (png_read_image)
    png_read_image(png, img->rows);
    read_end(png, info);
    fclose(fp);

    /* Covers the output would give away: an animation it would stop, or
       low bits visibly structured, where the changes would stand out.
       Checked once the pixels and every chunk are in. */
    if (!img->unsuitable && animated(png, info))
        img->unsuitable = "an animation (APNG)";
    else if (!img->unsuitable && low_sbit(png, info))
        img->unsuitable = PNG_LOW_SBIT;
    else if (!img->unsuitable && all_gray(img))
        img->unsuitable = PNG_GRAY_AS_RGB;

    /* Keep the chunks for png_save */
    PngMeta *meta = calloc(1, sizeof(PngMeta));
    if (!meta) {
        png_destroy_read_struct(&png, &info, NULL);
        free(tee->buf);
        free(tee);
        free(budget);
        image_free(img);
        return NULL;
    }
    meta->png    = png;
    meta->info   = info;
    meta->budget = budget;
    /* The cover's compressed image data, if png_write can use it */
    if (!tee->lost && bit_depth == 8 &&
        (color_type == PNG_COLOR_TYPE_GRAY || color_type == PNG_COLOR_TYPE_RGB))
        take_idat(meta, tee->buf, tee->len);
    else
        free(tee->buf);
    free(tee);
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
    /* Lowercase 3rd letter: reserved. Older libpng reads such a chunk,
       newer refuses the file, so writing one back would make an image
       built here unreadable elsewhere. */
    if (name[2] & 0x20) return 0;
    /* Uppercase 1st letter: critical. libpng reads an unknown one (it keeps
       them all), but a viewer must understand it to show the image, so it
       can't be copied; Rust's parse_chunks drops it too. */
    if (!(name[0] & 0x20)) return 0;
    if (name[3] & 0x20) return 1;  /* lowercase 4th letter: safe to copy */
    for (size_t i = 0; i < sizeof(kept_chunks) / sizeof(kept_chunks[0]); i++)
        if (memcmp(name, kept_chunks[i], 4) == 0) return 1;
    return 0;
}

/* How png_write compresses the image data: each row's filter, zlib's
   settings and the IDAT chunks' size. Copied from the cover, so the output
   is written the way the cover was: its encoder's choices, not ours.
   rust/src/png_io.rs's Layout is the same, step for step, so both builds
   write the same bytes. */
typedef struct {
    uint8_t *filters;  /* one per row (Adam7: pass by pass); NULL: choose */
    uint32_t chunk;    /* bytes per IDAT, the last one shorter; 0: one IDAT */
    int level, window, mem, strategy;  /* deflateInit2's */
    uint8_t header[2];  /* the cover's zlib header, written if have_header */
    int have_header;
} Layout;

/* The rows of an image as written: one per row, or Adam7's seven passes */
typedef struct {
    uint32_t x0[7], y0[7], dx[7], dy[7];
    int passes;
} Passes;

static Passes passes_of(int interlaced) {
    Passes p = {{0, 4, 0, 2, 0, 1, 0}, {0, 0, 4, 0, 2, 0, 1},
                {8, 8, 4, 4, 2, 2, 1}, {8, 8, 8, 4, 4, 2, 2}, 7};
    if (!interlaced) p = (Passes){{0}, {0}, {1}, {1}, 1};
    return p;
}

/* Pixels across and rows in pass p: 0 if the image is too small for it,
   as then it has no rows at all */
static void pass_size(const Passes *p, int i, uint32_t w, uint32_t h, uint32_t *pw, uint32_t *ph) {
    *pw = w > p->x0[i] ? (w - p->x0[i] + p->dx[i] - 1) / p->dx[i] : 0;
    *ph = h > p->y0[i] ? (h - p->y0[i] + p->dy[i] - 1) / p->dy[i] : 0;
    if (!*pw || !*ph) *pw = *ph = 0;
}

/* One zlib configuration being tried on the cover's image data */
typedef struct {
    z_stream z;
    size_t out;  /* bytes it has produced */
    int live;
} Trial;

/* The configurations tried, most common first: libpng's default (6,
   Z_FILTERED), then the other levels, memLevel 8 (zlib's default) and 9
   (Pillow's), then Z_RLE and Z_HUFFMAN_ONLY (which optipng tries; their
   output doesn't depend on the level) and no compression. The first that
   reproduces the cover's data wins. */
#define N_TRIALS 41
static void trial_params(int i, int *level, int *mem, int *strategy) {
    static const int levels[9] = {6, 9, 1, 2, 3, 4, 5, 7, 8};
    if (i == N_TRIALS - 1) { *level = 0; *mem = 8; *strategy = Z_DEFAULT_STRATEGY; return; }
    if (i >= 36) { *level = 6; *mem = i % 2 ? 9 : 8; *strategy = i < 38 ? Z_RLE : Z_HUFFMAN_ONLY; return; }
    *level = levels[i / 4];
    *mem = i % 4 < 2 ? 8 : 9;
    *strategy = i % 2 ? Z_DEFAULT_STRATEGY : Z_FILTERED;
}

/* Inflated data piece by piece, and how much of it the trials see: past
   that, the first still matching is taken */
#define PIECE ((size_t)1 << 16)
#define TRIAL_BYTES ((size_t)8 << 20)

/* Compresses in with t, flushing as told, and checks the output against
   want, the cover's data (the 2-byte header aside, as the trial's own
   may differ). Clears t->live on a mismatch. */
static void trial_feed(Trial *t, const uint8_t *in, size_t n, int flush,
                       const uint8_t *want, size_t want_len, uint8_t *scratch) {
    t->z.next_in = (Bytef *)in;
    t->z.avail_in = (uInt)n;
    int r;
    do {
        t->z.next_out = scratch;
        t->z.avail_out = PIECE;
        r = deflate(&t->z, flush);
        size_t got = PIECE - t->z.avail_out;
        for (size_t i = 0; i < got; i++, t->out++)
            if (t->out >= 2 && (t->out >= want_len || scratch[i] != want[t->out])) {
                t->live = 0;
                return;
            }
    } while (t->z.avail_out == 0);
    if (r == Z_STREAM_ERROR || (flush == Z_FINISH && r != Z_STREAM_END)) t->live = 0;
}

/* Reads the cover's layout from its compressed data: the zlib header, the
   filter at the start of every row, and which configuration reproduces
   the data. Out of memory, it keeps what it found so far. */
static void read_layout(Layout *L, const PngMeta *m, uint32_t w, uint32_t h, uint32_t ch, int interlaced) {
    const uint8_t *data = m->idat;
    size_t len = m->idat_len;
    L->chunk = m->idat_count >= 2 && m->idat_first > 0 ? m->idat_first : 0;
    if (len < 2 || (data[0] & 0x0f) != 8 || data[0] >> 4 > 7 || (data[1] & 0x20) ||
        ((unsigned)data[0] << 8 | data[1]) % 31 != 0)
        return;
    /* zlib takes no window under 2^9; nor, then, the header saying so */
    L->window = (data[0] >> 4) + 8;
    if (L->window >= 9) {
        memcpy(L->header, data, 2);
        L->have_header = 1;
    } else {
        L->window = 9;
    }
    static const int flevel[4] = {1, 5, 6, 9};
    L->level = flevel[data[1] >> 6];
    L->mem = 8;
    L->strategy = Z_DEFAULT_STRATEGY;

    Passes p = passes_of(interlaced);
    uint64_t rows = 0;
    for (int i = 0; i < p.passes; i++) {
        uint32_t pw, ph;
        pass_size(&p, i, w, h, &pw, &ph);
        rows += ph;
    }
    uint8_t *filters = malloc(rows ? rows : 1);
    uint8_t *piece = malloc(PIECE), *scratch = malloc(PIECE);
    Trial *trials = calloc(N_TRIALS, sizeof(Trial));
    z_stream in = {0};
    if (!filters || !piece || !scratch || !trials || inflateInit(&in) != Z_OK) {
        free(filters); free(piece); free(scratch); free(trials);
        return;
    }
    for (int i = 0; i < N_TRIALS; i++) {
        int level, mem, strategy;
        trial_params(i, &level, &mem, &strategy);
        trials[i].live = deflateInit2(&trials[i].z, level, Z_DEFLATED, L->window, mem, strategy) == Z_OK;
    }

    /* Where the next row starts in the inflated data, which it is, and
       the rows left in its pass */
    uint64_t row = 0, row_at = 0, pos = 0;
    int pass = -1;
    uint32_t pw = 0, left = 0;
    int bad = 0, trying = 1;
    size_t fed = 0;
    in.next_in = (Bytef *)data;
    in.avail_in = len > UINT_MAX ? UINT_MAX : (uInt)len;
    for (;;) {
        in.next_out = piece;
        in.avail_out = PIECE;
        int r = inflate(&in, Z_NO_FLUSH);
        size_t got = PIECE - in.avail_out;
        while (!bad && row < rows && row_at < pos + got) {
            while (left == 0) pass_size(&p, ++pass, w, h, &pw, &left);
            left--;
            uint8_t f = piece[row_at - pos];
            if (f > 4) bad = 1;
            filters[row++] = f;
            row_at += 1 + (uint64_t)pw * ch;
        }
        pos += got;
        if (trying && got > 0) {
            for (int i = 0; i < N_TRIALS; i++)
                if (trials[i].live) trial_feed(&trials[i], piece, got, Z_NO_FLUSH, data, len, scratch);
            fed += got;
            if (fed >= TRIAL_BYTES) trying = 0;
        }
        if (r == Z_STREAM_END && trying)
            for (int i = 0; i < N_TRIALS; i++) {
                if (trials[i].live) trial_feed(&trials[i], NULL, 0, Z_FINISH, data, len, scratch);
                if (trials[i].out != in.total_in) trials[i].live = 0;
            }
        if (r != Z_OK || (!trying && (bad || row == rows))) break;
    }
    inflateEnd(&in);

    int found = 0;
    for (int i = 0; i < N_TRIALS; i++) {
        if (trials[i].live && !found++) trial_params(i, &L->level, &L->mem, &L->strategy);
        deflateEnd(&trials[i].z);
    }
    if (!bad && row == rows) L->filters = filters;
    else free(filters);
    free(piece);
    free(scratch);
    free(trials);
}
/* Filters a row (n bytes, bpp per pixel; prev is the row above, zeros for
   the first) with PNG filter type t, into out[0] = t and the bytes after */
static void filter_row(const uint8_t *row, const uint8_t *prev, size_t n, size_t bpp, int t, uint8_t *out) {
    out[0] = (uint8_t)t;
    for (size_t i = 0; i < n; i++) {
        int a = i >= bpp ? row[i - bpp] : 0, b = prev[i], c = i >= bpp ? prev[i - bpp] : 0;
        int pred = 0;
        switch (t) {
        case 1: pred = a; break;
        case 2: pred = b; break;
        case 3: pred = (a + b) / 2; break;
        case 4: {
            int q = a + b - c, pa = abs(q - a), pb = abs(q - b), pc = abs(q - c);
            pred = pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
            break;
        }
        }
        out[1 + i] = (uint8_t)(row[i] - pred);
    }
}

/* For an image with no cover to copy: the filter giving the smallest sum
   of absolute (signed) bytes, libpng's heuristic; ties to the lower type */
static int choose_filter(const uint8_t *row, const uint8_t *prev, size_t n, size_t bpp, uint8_t *tmp) {
    int best = 0;
    uint64_t best_sum = 0;
    for (int t = 0; t < 5; t++) {
        filter_row(row, prev, n, bpp, t, tmp);
        uint64_t sum = 0;
        for (size_t i = 0; i < n; i++) sum += (uint64_t)abs((int8_t)tmp[1 + i]);
        if (t == 0 || sum < best_sum) { best = t; best_sum = sum; }
    }
    return best;
}

typedef struct {
    uint8_t *buf;
    size_t len, cap;
} Buf;

/* Compresses n bytes of in onto out; 0, or -1 out of memory */
static int deflate_onto(z_stream *z, Buf *out, const uint8_t *in, size_t n, int flush) {
    z->next_in = (Bytef *)in;
    z->avail_in = (uInt)n;
    int r;
    do {
        if (out->cap - out->len < PIECE) {
            size_t cap = out->cap ? out->cap * 2 : PIECE * 4;
            uint8_t *buf = cap > out->cap ? realloc(out->buf, cap) : NULL;
            if (!buf) return -1;
            out->buf = buf;
            out->cap = cap;
        }
        z->next_out = out->buf + out->len;
        z->avail_out = PIECE;
        r = deflate(z, flush);
        out->len += PIECE - z->avail_out;
    } while (z->avail_out == 0);
    return r == Z_STREAM_ERROR || (flush == Z_FINISH && r != Z_STREAM_END) ? -1 : 0;
}

/* The image data as one zlib stream, laid out as L says; 0, or -1 out of
   memory */
static int compress_image(const Image *img, const Layout *L, int interlaced, Buf *out) {
    uint32_t w = img->width, h = img->height, ch = img->channels;
    size_t n = (size_t)w * ch;
    uint8_t *row = malloc(n), *prev = calloc(n, 1), *f = malloc(n + 1), *tmp = malloc(n + 1);
    z_stream z = {0};
    int ok = row && prev && f && tmp &&
             deflateInit2(&z, L->level, Z_DEFLATED, L->window, L->mem, L->strategy) == Z_OK;
    int inited = ok;
    Passes p = passes_of(interlaced);
    uint64_t r = 0;
    for (int i = 0; ok && i < p.passes; i++) {
        uint32_t pw, ph;
        pass_size(&p, i, w, h, &pw, &ph);
        size_t pn = (size_t)pw * ch;
        memset(prev, 0, pn);
        for (uint32_t k = 0; ok && k < ph; k++, r++) {
            const uint8_t *src = img->rows[p.y0[i] + k * p.dy[i]];
            for (uint32_t x = 0; x < pw; x++)
                memcpy(row + (size_t)x * ch, src + ((size_t)p.x0[i] + (size_t)x * p.dx[i]) * ch, ch);
            int t = L->filters ? L->filters[r] : choose_filter(row, prev, pn, ch, tmp);
            filter_row(row, prev, pn, ch, t, f);
            ok = deflate_onto(&z, out, f, pn + 1, Z_NO_FLUSH) == 0;
            memcpy(prev, row, pn);
        }
    }
    ok = ok && deflate_onto(&z, out, NULL, 0, Z_FINISH) == 0;
    if (inited) deflateEnd(&z);
    free(row); free(prev); free(f); free(tmp);
    return ok ? 0 : -1;
}

static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

static int write_chunk(FILE *fp, const void *name, const uint8_t *data, size_t n) {
    uint8_t head[8], crc[4];
    put32(head, (uint32_t)n);
    memcpy(head + 4, name, 4);
    uLong c = crc32(0, head + 4, 4);
    if (n) c = crc32(c, data, (uInt)n);  /* with no data, zlib's crc32 restarts */
    put32(crc, (uint32_t)c);
    return fwrite(head, 1, 8, fp) == 8 && (n == 0 || fwrite(data, 1, n, fp) == n) &&
           fwrite(crc, 1, 4, fp) == 4 ? 0 : -1;
}

/* The cover's ancillary chunks that come before the image data, or after
   it, byte for byte, so the output looks like the same file. Unknown
   chunks not marked safe to copy must, per the PNG spec, be dropped once
   the pixels change. */
static int write_kept(FILE *fp, const PngMeta *m, int after_idat) {
    png_unknown_chunkp chunks;
    int n_chunks = png_get_unknown_chunks(m->png, m->info, &chunks);
    for (int i = 0; i < n_chunks; i++)
        if (keep_chunk(chunks[i].name) && !!(chunks[i].location & PNG_AFTER_IDAT) == after_idat &&
            write_chunk(fp, chunks[i].name, chunks[i].data, chunks[i].size) != 0)
            return -1;
    return 0;
}

int png_write(const Image *img, FILE *fp) {
    uint32_t w = img->width, h = img->height;
    if (w == 0 || h == 0 || w > INT32_MAX || h > INT32_MAX) {
        errno = 0;
        return -1;
    }
    /* Interlaced like the cover, so the format doesn't change */
    int interlaced = img->meta &&
        png_get_interlace_type(img->meta->png, img->meta->info) == PNG_INTERLACE_ADAM7;
    /* libpng's defaults, for an image with no cover data to copy */
    Layout L = {NULL, 8192, 6, 15, 8, Z_FILTERED, {0}, 0};
    if (img->meta && img->meta->idat) read_layout(&L, img->meta, w, h, img->channels, interlaced);
    Buf z = {0};
    int r = compress_image(img, &L, interlaced, &z);
    free(L.filters);
    if (r != 0) {
        free(z.buf);
        errno = ENOMEM;
        return -1;
    }
    if (L.have_header) memcpy(z.buf, L.header, 2);

    static const uint8_t sig[8] = {0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a};
    uint8_t ihdr[13];
    put32(ihdr, w);
    put32(ihdr + 4, h);
    ihdr[8] = 8;
    ihdr[9] = img->channels == 1 ? PNG_COLOR_TYPE_GRAY : PNG_COLOR_TYPE_RGB;
    ihdr[10] = ihdr[11] = 0;
    ihdr[12] = interlaced ? PNG_INTERLACE_ADAM7 : PNG_INTERLACE_NONE;
    errno = 0;
    r = fwrite(sig, 1, 8, fp) == 8 && write_chunk(fp, "IHDR", ihdr, 13) == 0 ? 0 : -1;
    if (r == 0 && img->meta) r = write_kept(fp, img->meta, 0);
    size_t step = L.chunk ? L.chunk : z.len;
    for (size_t at = 0; r == 0 && at < z.len; at += step)
        r = write_chunk(fp, "IDAT", z.buf + at, z.len - at < step ? z.len - at : step);
    if (r == 0 && img->meta) r = write_kept(fp, img->meta, 1);
    if (r == 0) r = write_chunk(fp, "IEND", NULL, 0);
    free(z.buf);
    return r;
}

/* Called by atomic_write, which leaves errno at 0 so a libpng error
   reports as such */
static int write_png(FILE *fp, const void *ctx) {
    return png_write(ctx, fp);
}

int png_save(const Image *img, const char *path) {
    return atomic_write(path, write_png, img);
}


void image_free(Image *img) {
    if (!img) return;
    if (img->meta) {
        png_destroy_read_struct(&img->meta->png, &img->meta->info, NULL);
        free(img->meta->budget);
        free(img->meta->idat);
        free(img->meta);
    }
    for (uint32_t y = 0; y < img->height; y++)
        free(img->rows[y]);
    free(img->rows);
    free(img);
}