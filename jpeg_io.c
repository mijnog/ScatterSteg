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

static void limit_scans(j_common_ptr cinfo) {
    if (cinfo->is_decompressor &&
        ((j_decompress_ptr)cinfo)->input_scan_number > JPEG_MAX_SCANS)
        cinfo->err->error_exit(cinfo);
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
    for (int pass = 0; pass < 2; pass++) {
        uint32_t n = 0;
        for (int ci = 0; ci < s->num_components; ci++) {
            jpeg_component_info *comp = &s->comp_info[ci];
            for (JDIMENSION by = 0; by < comp->height_in_blocks; by++) {
                JBLOCKARRAY row = s->mem->access_virt_barray((j_common_ptr)s, j->coefs[ci], by, 1, TRUE);
                for (JDIMENSION bx = 0; bx < comp->width_in_blocks; bx++) {
                    JCOEF dc = row[0][bx][0];
                    if (!pass && (dc < JPEG_MIN_DC || dc > JPEG_MAX_DC)) return -1;
                    for (int k = 1; k < DCTSIZE2; k++) {
                        JCOEF *c = &row[0][bx][k];
                        if (!pass && (*c < -JPEG_MAX_AC || *c > JPEG_MAX_AC)) return -1;
                        if (*c >= 2 || *c <= -2) {
                            if (pass) {
                                /* A change of 1 moves the block's pixels in
                                   proportion to the quantization step. And
                                   2 can only go to 3, shifting the 2:3 ratio
                                   detectors watch: 1.5x keeps the ratio
                                   within ~0.5% of the cover's in testing
                                   (1x lets it fall, 2-3x pushes it up) */
                                j->carriers[n] = c;
                                /* (a corrupt file's component may lack a table) */
                                float q = comp->quant_table ? comp->quant_table->quantval[k] : 1;
                                j->costs[n] = (q > 0 ? q : 1) *
                                              (*c == 2 || *c == -2 ? 1.5f : 1.0f);
                            }
                            n++;
                        }
                    }
                }
            }
        }
        if (!pass) {
            if (n > JPEG_MAX_CARRIERS) return -1;
            j->n_carriers = n;
            j->carriers = malloc((n ? n : 1) * sizeof(int16_t *));
            j->costs = malloc((n ? n : 1) * sizeof(float));
            if (!j->carriers || !j->costs) return -1;
        }
    }
    return 0;
}

JpegImage *jpeg_load(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    JpegImage *j = calloc(1, sizeof(JpegImage));
    if (!j) {
        fclose(fp);
        return NULL;
    }

    struct jpeg_progress_mgr progress = {.progress_monitor = limit_scans};
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
    j->src.progress = &progress;
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

/* A destination that throws the output away, for jpeg_check_writable */
static JOCTET discard_buf[4096];
static void discard_init(j_compress_ptr c) {
    c->dest->next_output_byte = discard_buf;
    c->dest->free_in_buffer = sizeof(discard_buf);
}
static boolean discard_empty(j_compress_ptr c) {
    discard_init(c);
    return TRUE;
}
static void discard_term(j_compress_ptr c) {
    (void)c;
}

/* Encodes the coefficients and markers to fp, or nowhere if fp is NULL */
static int write_coefficients(JpegImage *j, FILE *fp) {
    struct jpeg_compress_struct dst;
    struct jpeg_destination_mgr discard = {
        .init_destination = discard_init,
        .empty_output_buffer = discard_empty,
        .term_destination = discard_term,
    };
    ErrorJump err;
    dst.err = jpeg_std_error(&err.pub);
    err.pub.error_exit = error_exit;
    err.pub.output_message = silent;
    if (setjmp(err.jump)) {
        jpeg_destroy_compress(&dst);
        return -1;
    }
    jpeg_create_compress(&dst);
    if (fp) jpeg_stdio_dest(&dst, fp);
    else    dst.dest = &discard;

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

static int write_jpeg(FILE *fp, const void *ctx) {
    return write_coefficients((JpegImage *)ctx, fp);  /* libjpeg isn't const-correct */
}

int jpeg_save(const JpegImage *j, const char *path) {
    return atomic_write(path, write_jpeg, j);
}

int jpeg_check_writable(JpegImage *j) {
    return write_coefficients(j, NULL);
}
