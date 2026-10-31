/* SPDX-License-Identifier: MIT OR Apache-2.0
   Copyright (C) 2026 Maxime de Montbron */
#define _POSIX_C_SOURCE 200809L  /* open_memstream, fmemopen */
#include "jpeg_io.h"
#include "atomic_write.h"
#include "distortion.h"
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <jpeglib.h>

/* Largest coefficient storage jpeg_load will allocate (1 GiB) */
#define JPEG_MAX_COEF_BYTES ((size_t)1 << 30)
/* Most carriers jpeg_load will take. Each costs memory of its own beyond its
   2-byte coefficient: its cost here, its slot in the message permutation,
   and the bits and cost STC works on (each block's pointer adds an eighth
   of a byte). A file near the coefficient cap would otherwise need ~7 GiB
   on top; this keeps that to 1 GiB, about 50 megapixels of a 4:2:0 JPEG
   (63 carriers per block, 1.5 blocks per 64 pixels). rust/src/jpeg_io.rs's
   MAX_CARRIERS must equal it. */
#define JPEG_CARRIER_BYTES (sizeof(float) + sizeof(uint32_t) + 2 + sizeof(float))
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
/* UERD's cost where the block and its neighbours have no AC energy at all
   (every AC coefficient 0): q / 0. A large finite "wet" cost instead, as
   UERD implementations use, so the trellis can still pass through such
   carriers when it must. rust/src/jpeg_io.rs's WET_COST must equal it. */
#define JPEG_WET_COST 1e13f

/* Largest header (everything before the first scan's data) kept to copy
   into the output; past it, the output gets libjpeg's own */
#define JPEG_MAX_HEADER ((size_t)16 << 20)

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
    int16_t **blocks;  /* every 8x8 block's coefficients, see Carrier */
    float *costs;  /* per carrier, see collect_carriers */
    uint32_t n_carriers;
    uint64_t nonzero_ac;  /* AC coefficients that aren't 0 */
    int trailing_data;    /* bytes after the EOI marker */
    /* The cover's header, from SOI to the end of its first SOS segment,
       for write_like_cover; NULL if it couldn't be kept */
    uint8_t *header;
    size_t header_len;
    int scans;            /* how many the cover has */
};

static uint16_t be16(const uint8_t *p) {
    return (uint16_t)(p[0] << 8 | p[1]);
}

/* Where the SOS segment starts in a JPEG's first len bytes, which must
   be whole segments from SOI on; 0 if there's none */
static size_t find_sos(const uint8_t *d, size_t len) {
    size_t pos = 2;
    if (len < 2 || d[0] != 0xFF || d[1] != 0xD8) return 0;
    while (pos + 4 <= len && d[pos] == 0xFF) {
        if (d[pos + 1] == 0xDA) return pos;
        pos += 2 + (size_t)be16(d + pos + 2);
    }
    return 0;
}

/* Keeps the cover's header: the bytes libjpeg read up to the first scan's
   data, read again from fp (which must seek) without moving it */
static void keep_header(JpegImage *j, FILE *fp, long start) {
    long here = ftell(fp);
    if (start < 0 || here < start) return;
    size_t len = (size_t)(here - start) - j->src.src->bytes_in_buffer;
    if (len > JPEG_MAX_HEADER || !(j->header = malloc(len ? len : 1))) return;
    int ok = fseek(fp, start, SEEK_SET) == 0 && fread(j->header, 1, len, fp) == len;
    /* Back where libjpeg left it, or reading on would go wrong */
    if (fseek(fp, here, SEEK_SET) != 0) error_exit((j_common_ptr)&j->src);
    /* Whole segments ending with the SOS */
    size_t sos = ok ? find_sos(j->header, len) : 0;
    if (!sos || sos + 2 + be16(j->header + sos + 2) != len) {
        free(j->header);
        j->header = NULL;
        return;
    }
    j->header_len = len;
}

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

#if SCATTERSTEG_JPEG_COSTS == COSTS_JUNIWARD
/* J-UNIWARD for component ci (see distortion.h), from its decompressed plane */
static JUniward *juniward_component(JpegImage *j, int ci) {
    struct jpeg_decompress_struct *s = &j->src;
    jpeg_component_info *comp = &s->comp_info[ci];
    JDIMENSION w = comp->width_in_blocks, h = comp->height_in_blocks;
    uint16_t quant[64];
    for (int k = 0; k < 64; k++) {
        /* (a corrupt file's component may lack a table) */
        quant[k] = comp->quant_table && comp->quant_table->quantval[k] ? comp->quant_table->quantval[k] : 1;
    }
    size_t pw = (size_t)w * 8;
    if ((uint64_t)w * h * 64 > JUNIWARD_MAX_PIXELS) return NULL;
    float *pixels = pw ? malloc(pw * h * 8 * sizeof(float)) : NULL;
    if (!pixels) return NULL;
    for (JDIMENSION by = 0; by < h; by++) {
        JBLOCKARRAY row = s->mem->access_virt_barray((j_common_ptr)s, j->coefs[ci], by, 1, FALSE);
        for (JDIMENSION bx = 0; bx < w; bx++) {
            float block[64];
            distortion_idct_block(row[0][bx], quant, block);
            for (int y = 0; y < 8; y++)
                memcpy(pixels + ((size_t)by * 8 + y) * pw + (size_t)bx * 8, block + y * 8, 8 * sizeof(float));
        }
    }
    JUniward *ju = juniward_new(pixels, (uint32_t)pw, h * 8, quant);
    free(pixels);
    return ju;
}
#endif

/* Collect pointers to the blocks, whose AC coefficients are the carriers.
   libjpeg-turbo keeps virtual arrays wholly in memory (it has no backing
   store, and jpeg_load caps the size), so these pointers stay valid as
   long as the arrays do.

   Also checks every coefficient is one the encoder can write back: corrupt
   entropy data can decode to values beyond its 11-bit DC / 10-bit AC
   range, and then saving would fail (found by fuzzing). Returns -1 if one
   is out of range, there are too many carriers, or out of memory. */
static int collect_carriers(JpegImage *j) {
    struct jpeg_decompress_struct *s = &j->src;
    /* UERD (Guo, Ni, Su, Tang and Shi, 2015): a block's energy is the sum
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
    JUniward *ju = NULL;  /* J-UNIWARD builds: the component's costs */
    for (int pass = 0; pass < 2; pass++) {
        uint32_t n = 0, b = 0;  /* carriers, blocks */
        size_t base = 0;  /* this component's first block in energy[] */
        for (int ci = 0; ci < s->num_components; ci++) {
            jpeg_component_info *comp = &s->comp_info[ci];
            JDIMENSION w = comp->width_in_blocks, h = comp->height_in_blocks;
#if SCATTERSTEG_JPEG_COSTS == COSTS_JUNIWARD
            if (pass && !(ju = juniward_component(j, ci))) goto out;
#endif
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
                    if (pass) j->blocks[b] = row[0][bx];
                    b++;
                    for (int k = 1; k < DCTSIZE2; k++) {
                        JCOEF *c = &row[0][bx][k];
                        if (!pass && (*c < -JPEG_MAX_AC || *c > JPEG_MAX_AC)) goto out;
                        /* (a corrupt file's component may lack a table) */
                        float q = comp->quant_table ? comp->quant_table->quantval[k] : 1;
                        if (q <= 0) q = 1;
                        if (!pass) e += (float)abs(*c) * q;
                        if (!pass && *c) j->nonzero_ac++;
                        if (pass) j->costs[n] = ju ? juniward_cost(ju, bx, by, k)
                                                : around > 0 ? q / around : JPEG_WET_COST;
                        n++;
                    }
                    if (!pass) energy[base + (size_t)by * w + bx] = e;
                }
            }
            juniward_free(ju);
            ju = NULL;
            base += (size_t)w * h;
        }
        if (!pass) {
            if (n > JPEG_MAX_CARRIERS) goto out;
            j->n_carriers = n;
            j->blocks = malloc((b ? b : 1) * sizeof(int16_t *));
            j->costs = malloc((n ? n : 1) * sizeof(float));
            if (!j->blocks || !j->costs) goto out;
        }
    }
    r = 0;
out:
    juniward_free(ju);
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
        free(j->blocks);
        free(j->costs);
        free(j->header);
        free(j);
        fclose(fp);
        return NULL;
    }
    jpeg_create_decompress(&j->src);
    j->src.progress = &progress.pub;
    long start = ftell(fp);
    j->src.mem->max_memory_to_use = JPEG_MAX_COEF_BYTES + (16 << 20);
    jpeg_stdio_src(&j->src, fp);
    /* Keep comments and every APPn (EXIF, ICC profile, XMP...) to write back */
    jpeg_save_markers(&j->src, JPEG_COM, 0xFFFF);
    for (int m = 0; m < 16; m++) jpeg_save_markers(&j->src, JPEG_APP0 + m, 0xFFFF);
    jpeg_read_header(&j->src, TRUE);
    keep_header(j, fp, start);

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
    j->scans = j->src.input_scan_number;
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
    free(j->blocks);
    free(j->costs);
    free(j->header);
    free(j);
}

uint64_t jpeg_nonzero_ac(const JpegImage *j) {
    return j->nonzero_ac;
}

void jpeg_size(const JpegImage *j, uint32_t *width, uint32_t *height) {
    *width = j->src.image_width;
    *height = j->src.image_height;
}

/* A C2PA manifest (content credentials, which some phones and cameras now
   sign their photos with): JUMBF boxes in APP11 segments, the first one
   labelled "c2pa". It signs a hash of the image data, so any change to the
   coefficients shows as tampering to anyone who checks it. */
static int c2pa_manifest(const JpegImage *j) {
    for (jpeg_saved_marker_ptr m = j->src.marker_list; m; m = m->next) {
        if (m->marker != JPEG_APP0 + 11 || m->data_length < 2 || memcmp(m->data, "JP", 2) != 0)
            continue;
        for (unsigned i = 0; i + 4 <= m->data_length; i++)
            if (memcmp(m->data + i, "c2pa", 4) == 0) return 1;
    }
    return 0;
}

const char *jpeg_unsuitable(const JpegImage *j) {
    if (j->trailing_data)
        return "data after the end of the image (such as a second image or an HDR gain map)";
    if (c2pa_manifest(j)) return "a content credential (C2PA) signing its pixels";
    return NULL;
}

Carrier jpeg_carrier(JpegImage *j) {
    Carrier c = {NULL, j->blocks, j->n_carriers, j->costs};
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

/* How encode picks the Huffman tables: libjpeg's way (the standard ones
   if the cover had them, else optimized); the cover's own; or optimized,
   in the cover's table slots (see write_like_cover) */
enum { TABLES_LIBJPEG, TABLES_COVER, TABLES_OPTIMIZED };

/* Encodes the coefficients and markers to fp, with the tables `tables`
   says. With the cover's tables it doesn't fail if they lack a code the
   coefficients now need: libjpeg-turbo writes a code of no bits. */
static int encode(JpegImage *j, FILE *fp, int tables) {
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
    if (tables != TABLES_LIBJPEG) {
        dst.optimize_coding = tables == TABLES_OPTIMIZED;
        for (int i = 0; i < NUM_HUFF_TBLS && tables == TABLES_COVER; i++) {
            JHUFF_TBL **from[2] = {&j->src.dc_huff_tbl_ptrs[i], &j->src.ac_huff_tbl_ptrs[i]};
            JHUFF_TBL **to[2] = {&dst.dc_huff_tbl_ptrs[i], &dst.ac_huff_tbl_ptrs[i]};
            for (int t = 0; t < 2; t++) {
                if (!*from[t]) continue;
                if (!*to[t]) *to[t] = jpeg_alloc_huff_table((j_common_ptr)&dst);
                memcpy((*to[t])->bits, (*from[t])->bits, sizeof((*from[t])->bits));
                memcpy((*to[t])->huffval, (*from[t])->huffval, sizeof((*from[t])->huffval));
            }
        }
        for (int ci = 0; ci < dst.num_components; ci++) {
            dst.comp_info[ci].dc_tbl_no = j->src.comp_info[ci].dc_tbl_no;
            dst.comp_info[ci].ac_tbl_no = j->src.comp_info[ci].ac_tbl_no;
        }
    }

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

/* Are a's coefficients exactly those b decoded, every one of them? */
static int same_as_decoded(JpegImage *a, j_decompress_ptr b, jvirt_barray_ptr *bc) {
    if (a->src.num_components != b->num_components) return 0;
    for (int ci = 0; ci < a->src.num_components; ci++) {
        jpeg_component_info *ca = &a->src.comp_info[ci], *cb = &b->comp_info[ci];
        if (ca->width_in_blocks != cb->width_in_blocks || ca->height_in_blocks != cb->height_in_blocks)
            return 0;
        for (JDIMENSION by = 0; by < ca->height_in_blocks; by++) {
            JBLOCKARRAY ra = a->src.mem->access_virt_barray((j_common_ptr)&a->src, a->coefs[ci], by, 1, FALSE);
            JBLOCKARRAY rb = b->mem->access_virt_barray((j_common_ptr)b, bc[ci], by, 1, FALSE);
            if (memcmp(ra[0], rb[0], ca->width_in_blocks * sizeof(JBLOCK)) != 0) return 0;
        }
    }
    return 1;
}

static int same_coefficients(JpegImage *a, JpegImage *b) {
    return same_as_decoded(a, &b->src, b->coefs);
}

/* Does the JPEG in buf decode cleanly, with no warning, to j's
   coefficients? */
static int decodes_to(JpegImage *j, const uint8_t *buf, size_t len) {
    struct jpeg_decompress_struct d;
    ErrorJump err;
    d.err = jpeg_std_error(&err.pub);
    err.pub.error_exit = error_exit;
    err.pub.output_message = silent;
    if (setjmp(err.jump)) {
        jpeg_destroy_decompress(&d);
        return 0;
    }
    jpeg_create_decompress(&d);
    jpeg_mem_src(&d, buf, (unsigned long)len);
    jpeg_read_header(&d, TRUE);
    jvirt_barray_ptr *c = jpeg_read_coefficients(&d);
    int same = c && err.pub.num_warnings == 0 && same_as_decoded(j, &d, c);
    jpeg_destroy_decompress(&d);
    return same;
}

/* Each Huffman table slot's table (from its Tc/Th byte, then 16 counts
   and the values) in the DHT segments of a JPEG's first len bytes, whole
   segments from SOI on; NULL where there's none. Slot: Tc * 4 + Th. */
static void dht_tables(const uint8_t *d, size_t len, const uint8_t *slots[8], size_t sizes[8]) {
    for (int i = 0; i < 8; i++) slots[i] = NULL;
    for (size_t pos = 2; pos + 4 <= len && d[pos] == 0xFF && d[pos + 1] != 0xDA;) {
        size_t end = pos + 2 + be16(d + pos + 2);
        if (end > len) return;
        if (d[pos + 1] == 0xC4)
            for (size_t t = pos + 4; t + 17 <= end;) {
                size_t n = 17;
                for (int k = 1; k <= 16; k++) n += d[t + k];
                int slot = (d[t] >> 4) * 4 + (d[t] & 15);
                if (t + n > end || (d[t] >> 4) > 1 || (d[t] & 15) > 3) return;
                slots[slot] = d + t;
                sizes[slot] = n;
                t += n;
            }
        pos = end;
    }
}

/* The cover's header with each of its Huffman tables replaced by the one
   libjpeg wrote for that slot (in out's header), where it wrote one: the
   same segments in the same order, only the tables' contents new. Into h
   if not NULL; returns the length either way. */
static size_t new_tables_into(const JpegImage *j, const uint8_t *const fresh[8],
                              const size_t fresh_n[8], uint8_t *h) {
    size_t at = 2;  /* SOI */
    if (h) memcpy(h, j->header, 2);
    for (size_t pos = 2; pos < j->header_len;) {
        const uint8_t *seg = j->header + pos;
        size_t seg_len = 2 + (size_t)be16(seg + 2);
        if (seg[1] != 0xC4) {
            if (h) memcpy(h + at, seg, seg_len);
            at += seg_len;
        } else {
            size_t start = at;
            if (h) memcpy(h + at, seg, 4);
            at += 4;
            for (size_t t = 4; t + 17 <= seg_len;) {
                size_t n = 17;
                for (int k = 1; k <= 16; k++) n += seg[t + k];
                int slot = (seg[t] >> 4) * 4 + (seg[t] & 15);
                const uint8_t *use = fresh[slot] ? fresh[slot] : seg + t;
                size_t use_n = fresh[slot] ? fresh_n[slot] : n;
                if (h) memcpy(h + at, use, use_n);
                at += use_n;
                t += n;
            }
            if (h) {
                h[start + 2] = (uint8_t)((at - start - 2) >> 8);
                h[start + 3] = (uint8_t)(at - start - 2);
            }
        }
        pos += seg_len;
    }
    return at;
}

/* The same, allocated; NULL if out of memory */
static uint8_t *with_new_tables(const JpegImage *j, const uint8_t *out, size_t out_len, size_t *len) {
    const uint8_t *fresh[8];
    size_t fresh_n[8];
    dht_tables(out, out_len, fresh, fresh_n);
    *len = new_tables_into(j, fresh, fresh_n, NULL);
    uint8_t *h = malloc(*len);
    if (h) new_tables_into(j, fresh, fresh_n, h);
    return h;
}

/* A cover with one sequential, Huffman-coded scan (as cameras and phones
   write them) keeps its whole header: its markers in their order, its
   tables packed into segments its encoder's way, which libjpeg would
   write its own way. Only the scan's data is new, coded with the cover's
   own tables (TABLES_COVER: the header byte for byte) or, if those lack a
   code the changed coefficients need, with optimized ones in the same
   slots (TABLES_OPTIMIZED: the header with those tables swapped in), as
   such a cover's encoder optimizes them per image. libjpeg-turbo doesn't
   say when a table lacks a code (it writes a code of no bits), so the
   result is decoded and checked. If that fails, or libjpeg's scan header
   doesn't match the cover's, returns -1 having written nothing; -2 if
   writing to fp failed. */
static int write_like_cover(JpegImage *j, FILE *fp, int tables) {
    if (!j->header || j->scans != 1 || j->src.progressive_mode || j->src.arith_code ||
        j->src.comps_in_scan != j->src.num_components)
        return -1;
    char *buf = NULL;
    size_t len = 0;
    FILE *mem = open_memstream(&buf, &len);
    if (!mem) return -1;
    int r = encode(j, mem, tables);
    if (fclose(mem) != 0) r = -1;  /* also sets buf and len */
    size_t sos = r == 0 ? find_sos((uint8_t *)buf, len) : 0;
    size_t cover_sos = find_sos(j->header, j->header_len);
    size_t sos_len = 2 + (size_t)be16(j->header + cover_sos + 2);
    /* The same scan header: the same components, tables and spectral range */
    if (!sos || sos + sos_len > len || memcmp(buf + sos, j->header + cover_sos, sos_len) != 0) {
        free(buf);
        return -1;
    }
    size_t data = sos + sos_len, head_len = j->header_len;
    uint8_t *head = tables == TABLES_COVER ? j->header : with_new_tables(j, (uint8_t *)buf, sos, &head_len);
    /* What it decodes to */
    uint8_t *joined = head ? malloc(head_len + len - data) : NULL;
    int ok = joined != NULL;
    if (ok) {
        memcpy(joined, head, head_len);
        memcpy(joined + head_len, buf + data, len - data);
        ok = decodes_to(j, joined, head_len + len - data);
    }
    free(joined);
    errno = 0;
    r = !ok ? -1 :
        fwrite(head, 1, head_len, fp) == head_len && fwrite(buf + data, 1, len - data, fp) == len - data ? 0 : -2;
    if (head != j->header) free(head);
    free(buf);
    return r;
}

/* Like the cover if it can be, else libjpeg's way. -1 on failure. */
static int write_coefficients(JpegImage *j, FILE *fp) {
    int r = write_like_cover(j, fp, TABLES_COVER);
    if (r == -1) r = write_like_cover(j, fp, TABLES_OPTIMIZED);
    if (r == -2) return -1;  /* a write failed part way */
    return r == 0 ? 0 : encode(j, fp, TABLES_LIBJPEG);
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
