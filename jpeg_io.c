/* SPDX-License-Identifier: AGPL-3.0-or-later
   Copyright (C) 2026 Maxime de Montbron */
#define _POSIX_C_SOURCE 200809L  /* open_memstream, fmemopen */
#include "jpeg_io.h"
#include "atomic_write.h"
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jpeglib.h>

/* Largest coefficient storage jpeg_load will allocate (1 GiB) */
#define JPEG_MAX_COEF_BYTES ((size_t)1 << 30)
/* Most carriers jpeg_load will take. Each costs memory of its own beyond its
   2-byte coefficient: its pointer and cost here, its slot in the message
   permutation, and the bits and cost STC works on. A file of all-±2 AC
   coefficients near the coefficient cap would otherwise need ~9 GiB on top;
   this keeps that to 1 GiB. */
#define JPEG_CARRIER_BYTES (sizeof(int16_t *) + sizeof(float) + sizeof(uint32_t) + 2 + sizeof(float))
#define JPEG_MAX_CARRIERS (JPEG_MAX_COEF_BYTES / JPEG_CARRIER_BYTES)
/* Progressive JPEGs can have any number of scans, each a full pass over the
   coefficients; a crafted file with thousands of tiny scans takes minutes to
   read. Real files have a few dozen at most (djpeg suggests the same cap). */
#define JPEG_MAX_SCANS 500
/* Nor is the scan cap enough on its own, as each scan costs in proportion
   to the frame: 500 empty scans of a 23000x23000 frame, 5 KB in all, took
   16 s to read. So the blocks the scans visit are capped too. Real files
   visit each block about ten times (the largest image allowed here, some
   84 million visits); past this, one costs about a second. */
#define JPEG_MAX_SCAN_BLOCKS ((uint64_t)1 << 28)
/* And a frame's size is only what its header claims: a 330-byte file can
   declare 15144x32800 with no entropy data, which libjpeg fills with zeros,
   at 1.5 s and ~1 GB. Huffman coding spends at least 1 bit on every block
   (its DC code), so a frame of more blocks than the file has bits is
   refused before anything is allocated. Arithmetic coding can spend far
   less than a bit on a block, so it isn't bound this way. */
static int hollow_frame(const struct jpeg_decompress_struct *s, uint64_t bytes_left) {
    if (s->arith_code) return 0;
    uint64_t blocks = 0;
    for (int ci = 0; ci < s->num_components; ci++)
        blocks += (uint64_t)s->comp_info[ci].width_in_blocks * s->comp_info[ci].height_in_blocks;
    return bytes_left * 8 < blocks;
}

/* Bytes of fp from here to its end, or UINT64_MAX if it can't seek */
static uint64_t bytes_to_end(FILE *fp) {
    long here = ftell(fp), end;
    if (here < 0 || fseek(fp, 0, SEEK_END) != 0) return UINT64_MAX;
    end = ftell(fp);
    if (fseek(fp, here, SEEK_SET) != 0 || end < here) return UINT64_MAX;
    return (uint64_t)(end - here);
}
/* What an 8-bit encoder can write: DC in [-1024, 1023] (an all-black block
   at quality 100 is -1024), so block-to-block differences fit its 11 bits;
   AC values that fit 10 bits */
#define JPEG_MIN_DC (-1024)
#define JPEG_MAX_DC 1023
#define JPEG_MAX_AC 1023

/* libjpeg's default error handler calls exit(); jump back instead */
typedef struct {
    struct jpeg_error_mgr pub;
    jmp_buf jump;
} ErrorJump;

static void error_exit(j_common_ptr cinfo) {
    longjmp(((ErrorJump *)cinfo->err)->jump, 1);
}

/* After jpeg_load returns, nothing should make libjpeg fail on the source
   struct (only reads and jpeg_destroy follow); if it does, stop loudly
   rather than jump to a stale target */
static void unexpected_error(j_common_ptr cinfo) {
    (void)cinfo;
    abort();
}

struct JpegImage {
    struct jpeg_decompress_struct src;
    ErrorJump err;
    jvirt_barray_ptr *coefs;
    int16_t **carriers;
    float *costs;  /* per carrier, see collect_carriers */
    uint32_t n_carriers;
    int trailing_data;  /* bytes after the EOI marker */
};

static void silent(j_common_ptr cinfo) {
    (void)cinfo;  /* warnings about recoverable corruption: keep going */
}

/* The progress monitor, with what limit_scans has counted */
typedef struct {
    struct jpeg_progress_mgr pub;
    int scan;         /* the scan last counted */
    uint64_t blocks;  /* blocks the scans so far visit */
} Progress;

/* Called before each step of reading, so at least once per scan, after
   its header is read */
static void limit_scans(j_common_ptr cinfo) {
    if (!cinfo->is_decompressor) return;
    j_decompress_ptr d = (j_decompress_ptr)cinfo;
    Progress *p = (Progress *)cinfo->progress;
    if (d->input_scan_number > JPEG_MAX_SCANS) cinfo->err->error_exit(cinfo);
    if (d->input_scan_number != p->scan) {
        p->scan = d->input_scan_number;
        for (int i = 0; i < d->comps_in_scan; i++)
            p->blocks += (uint64_t)d->cur_comp_info[i]->width_in_blocks *
                         d->cur_comp_info[i]->height_in_blocks;
        if (p->blocks > JPEG_MAX_SCAN_BLOCKS) cinfo->err->error_exit(cinfo);
    }
}

int is_jpeg_file(const char *path) {
    unsigned char sig[3];
    FILE *fp = fopen(path, "rb");
    if (!fp) return 0;
    size_t n = fread(sig, 1, sizeof(sig), fp);
    fclose(fp);
    return n == 3 && sig[0] == 0xFF && sig[1] == 0xD8 && sig[2] == 0xFF;
}

/* Collect pointers to the carrier coefficients. libjpeg-turbo keeps virtual
   arrays wholly in memory (it has no backing store, and jpeg_load caps the
   size), so these pointers stay valid as long as the arrays do.

   Also checks every coefficient is one the encoder can write back: corrupt
   entropy data can decode to values beyond its 11-bit DC / 10-bit AC
   range, and then saving would fail (found by fuzzing). Returns -1 if one
   is out of range, there are too many carriers, or out of memory. */
static int collect_carriers(JpegImage *j) {
    struct jpeg_decompress_struct *s = &j->src;
    /* UERD (Guo, Ni, Su, Chen and Shi, 2015): a block's energy is the sum
       of its dequantized AC magnitudes, and a change costs the
       coefficient's quantization step over the energy of the block and,
       at a quarter weight, its 8 neighbours: cheap in busy blocks and
       low frequencies, dear in smooth ones. Pass 0 checks the values and
       sums the energies, pass 1 sets the costs. */
    size_t blocks = 0;
    for (int ci = 0; ci < s->num_components; ci++)
        blocks += (size_t)s->comp_info[ci].width_in_blocks * s->comp_info[ci].height_in_blocks;
    float *energy = malloc((blocks ? blocks : 1) * sizeof(float));
    if (!energy) return -1;
    int r = -1;
    for (int pass = 0; pass < 2; pass++) {
        uint32_t n = 0;
        size_t base = 0;  /* this component's first block in energy[] */
        for (int ci = 0; ci < s->num_components; ci++) {
            jpeg_component_info *comp = &s->comp_info[ci];
            JDIMENSION w = comp->width_in_blocks, h = comp->height_in_blocks;
            for (JDIMENSION by = 0; by < h; by++) {
                JBLOCKARRAY row = s->mem->access_virt_barray((j_common_ptr)s, j->coefs[ci], by, 1, TRUE);
                for (JDIMENSION bx = 0; bx < w; bx++) {
                    JCOEF dc = row[0][bx][0];
                    if (!pass && (dc < JPEG_MIN_DC || dc > JPEG_MAX_DC)) goto out;
                    float around = 0;  /* the block's energy plus a quarter of its neighbours' */
                    if (pass) {
                        for (int dy = -1; dy <= 1; dy++)
                            for (int dx = -1; dx <= 1; dx++) {
                                long y = (long)by + dy, x = (long)bx + dx;
                                if (y < 0 || x < 0 || y >= (long)h || x >= (long)w) continue;
                                float e = energy[base + (size_t)y * w + (size_t)x];
                                around += dy || dx ? 0.25f * e : e;
                            }
                    }
                    float e = 0;
                    for (int k = 1; k < DCTSIZE2; k++) {
                        JCOEF *c = &row[0][bx][k];
                        if (!pass && (*c < -JPEG_MAX_AC || *c > JPEG_MAX_AC)) goto out;
                        /* (a corrupt file's component may lack a table) */
                        float q = comp->quant_table ? comp->quant_table->quantval[k] : 1;
                        if (q <= 0) q = 1;
                        if (!pass) e += (float)abs(*c) * q;
                        if (*c >= 2 || *c <= -2) {
                            if (pass) {
                                /* And 2 can only go to 3, shifting the 2:3
                                   ratio detectors watch (see JPEG_TWO_COST) */
                                j->carriers[n] = c;
                                j->costs[n] = q / around * (*c == 2 || *c == -2 ? JPEG_TWO_COST : 1.0f);
                            }
                            n++;
                        }
                    }
                    if (!pass) energy[base + (size_t)by * w + bx] = e;
                }
            }
            base += (size_t)w * h;
        }
        if (!pass) {
            if (n > JPEG_MAX_CARRIERS) goto out;
            j->n_carriers = n;
            j->carriers = malloc((n ? n : 1) * sizeof(int16_t *));
            j->costs = malloc((n ? n : 1) * sizeof(float));
            if (!j->carriers || !j->costs) goto out;
        }
    }
    r = 0;
out:
    free(energy);
    return r;
}

JpegImage *jpeg_read(FILE *fp) {
    JpegImage *volatile j = calloc(1, sizeof(JpegImage));  /* survives the longjmp */
    if (!j) {
        fclose(fp);
        return NULL;
    }

    Progress progress = {.pub.progress_monitor = limit_scans};
    j->src.err = jpeg_std_error(&j->err.pub);
    j->err.pub.error_exit = error_exit;
    j->err.pub.output_message = silent;
    if (setjmp(j->err.jump)) {
        jpeg_destroy_decompress(&j->src);
        free(j->carriers);
        free(j->costs);
        free(j);
        fclose(fp);
        return NULL;
    }
    jpeg_create_decompress(&j->src);
    j->src.progress = &progress.pub;
    j->src.mem->max_memory_to_use = JPEG_MAX_COEF_BYTES + (16 << 20);
    jpeg_stdio_src(&j->src, fp);
    /* Keep comments and every APPn (EXIF, ICC profile, XMP...) to write back */
    jpeg_save_markers(&j->src, JPEG_COM, 0xFFFF);
    for (int m = 0; m < 16; m++) jpeg_save_markers(&j->src, JPEG_APP0 + m, 0xFFFF);
    jpeg_read_header(&j->src, TRUE);

    /* 2 bytes per coefficient, one coefficient per sample: an upper bound
       even before subsampling, checked before anything is allocated */
    if (j->src.data_precision != 8 ||
        (uint64_t)j->src.image_width * j->src.image_height * j->src.num_components * 2 >
            JPEG_MAX_COEF_BYTES)
        error_exit((j_common_ptr)&j->src);
    uint64_t rest = bytes_to_end(fp);
    if (rest != UINT64_MAX && hollow_frame(&j->src, j->src.src->bytes_in_buffer + rest))
        error_exit((j_common_ptr)&j->src);

    j->coefs = jpeg_read_coefficients(&j->src);
    if (!j->coefs || collect_carriers(j) != 0)
        error_exit((j_common_ptr)&j->src);
    /* Reading stops at EOI: anything left, buffered or not, comes after */
    j->trailing_data = j->src.src->bytes_in_buffer > 0 || fgetc(fp) != EOF;
    fclose(fp);
    j->err.pub.error_exit = unexpected_error;
    j->src.progress = NULL;
    return j;
}

JpegImage *jpeg_load(const char *path) {
    FILE *fp = fopen(path, "rb");
    return fp ? jpeg_read(fp) : NULL;
}

void jpeg_free(JpegImage *j) {
    if (!j) return;
    jpeg_destroy_decompress(&j->src);
    free(j->carriers);
    free(j->costs);
    free(j);
}

const char *jpeg_unsuitable(const JpegImage *j) {
    return j->trailing_data ? "data after the end of the image (such as a second "
                              "image or an HDR gain map)" : NULL;
}

Carrier jpeg_carrier(JpegImage *j) {
    Carrier c = {NULL, j->carriers, j->n_carriers, j->costs};
    return c;
}

/* Did the cover use the standard Huffman tables (as most cameras do)?
   Compared against the defaults jpeg_copy_critical_parameters set up. */
static int standard_tables(const struct jpeg_decompress_struct *s,
                           const struct jpeg_compress_struct *d) {
    for (int i = 0; i < NUM_HUFF_TBLS; i++) {
        const JHUFF_TBL *pairs[2][2] = {{s->dc_huff_tbl_ptrs[i], d->dc_huff_tbl_ptrs[i]},
                                        {s->ac_huff_tbl_ptrs[i], d->ac_huff_tbl_ptrs[i]}};
        for (int t = 0; t < 2; t++) {
            const JHUFF_TBL *a = pairs[t][0], *b = pairs[t][1];
            if (!a) continue;
            if (!b || memcmp(a->bits, b->bits, sizeof(a->bits)) != 0 ||
                memcmp(a->huffval, b->huffval, sizeof(a->huffval)) != 0)
                return 0;
        }
    }
    return 1;
}

static int is_marker(const jpeg_saved_marker_ptr m, int code, const char *tag, unsigned len) {
    return m->marker == code && m->data_length >= len && memcmp(m->data, tag, len) == 0;
}

/* Encodes the coefficients and markers to fp */
static int write_coefficients(JpegImage *j, FILE *fp) {
    struct jpeg_compress_struct dst;
    ErrorJump err;
    dst.err = jpeg_std_error(&err.pub);
    err.pub.error_exit = error_exit;
    err.pub.output_message = silent;
    if (setjmp(err.jump)) {
        jpeg_destroy_compress(&dst);
        return -1;
    }
    jpeg_create_compress(&dst);
    jpeg_stdio_dest(&dst, fp);

    /* Same quantization, sampling, color space and coding as the cover */
    jpeg_copy_critical_parameters(&j->src, &dst);
    /* It turns on the JFIF (or Adobe) header for the color space; write
       one only if the cover had one, as a camera's Exif-only file doesn't */
    dst.write_JFIF_header = j->src.saw_JFIF_marker;
    dst.write_Adobe_marker = j->src.saw_Adobe_marker;
    dst.arith_code = j->src.arith_code;
    dst.restart_interval = j->src.restart_interval;
    if (j->src.progressive_mode) jpeg_simple_progression(&dst);
    /* A changed coefficient may need a Huffman code an optimized table
       lacks, so the cover's own tables can't be reused. Keep the standard
       tables if it had them, else optimize like its encoder did. */
    dst.optimize_coding = !dst.arith_code && !standard_tables(&j->src, &dst);

    jpeg_write_coefficients(&dst, j->coefs);

    /* Markers, as jpegtran copies them: libjpeg writes the JFIF and Adobe
       headers itself when the cover had them, so skip the cover's copies */
    for (jpeg_saved_marker_ptr m = j->src.marker_list; m; m = m->next) {
        if (dst.write_JFIF_header && is_marker(m, JPEG_APP0, "JFIF", 5)) continue;
        if (dst.write_Adobe_marker && is_marker(m, JPEG_APP0 + 14, "Adobe", 5)) continue;
        jpeg_write_marker(&dst, m->marker, m->data, m->data_length);
    }

    jpeg_finish_compress(&dst);
    jpeg_destroy_compress(&dst);
    return 0;
}

int jpeg_write(JpegImage *j, FILE *fp) {
    return write_coefficients(j, fp);
}

static int write_jpeg(FILE *fp, const void *ctx) {
    return write_coefficients((JpegImage *)ctx, fp);  /* libjpeg isn't const-correct */
}

int jpeg_save(const JpegImage *j, const char *path) {
    return atomic_write(path, write_jpeg, j);
}

/* Are a's coefficients exactly b's, every one of them? */
static int same_coefficients(JpegImage *a, JpegImage *b) {
    if (a->src.num_components != b->src.num_components) return 0;
    for (int ci = 0; ci < a->src.num_components; ci++) {
        jpeg_component_info *ca = &a->src.comp_info[ci], *cb = &b->src.comp_info[ci];
        if (ca->width_in_blocks != cb->width_in_blocks || ca->height_in_blocks != cb->height_in_blocks)
            return 0;
        for (JDIMENSION by = 0; by < ca->height_in_blocks; by++) {
            JBLOCKARRAY ra = a->src.mem->access_virt_barray((j_common_ptr)&a->src, a->coefs[ci], by, 1, FALSE);
            JBLOCKARRAY rb = b->src.mem->access_virt_barray((j_common_ptr)&b->src, b->coefs[ci], by, 1, FALSE);
            if (memcmp(ra[0], rb[0], ca->width_in_blocks * sizeof(JBLOCK)) != 0) return 0;
        }
    }
    return 1;
}

int jpeg_check_writable(JpegImage *j) {
    /* Encode it, then read that back: some files (a truncated progressive
       one with a first AC scan at Al=1 and no refinement, found by fuzzing)
       are written with different coefficients, which would corrupt a
       message hidden in them. */
    char *buf = NULL;
    size_t len = 0;
    FILE *out = open_memstream(&buf, &len);
    if (!out) return -1;
    int rc = write_coefficients(j, out);
    if (fclose(out) != 0) rc = -1;  /* also sets buf and len */
    if (rc != 0) {
        free(buf);
        return -1;
    }
    FILE *in = fmemopen(buf, len, "rb");
    JpegImage *back = in ? jpeg_read(in) : NULL;
    free(buf);
    if (!back) return -1;
    int same = same_coefficients(j, back);
    jpeg_free(back);
    return same ? 0 : -1;
}
