/* SPDX-License-Identifier: AGPL-3.0-or-later
   Copyright (C) 2026 Maxime de Montbron */
#define _POSIX_C_SOURCE 200809L  /* mkdtemp */
#include "test.h"
#include "jpeg_io.h"
#include <jpeglib.h>
#include <math.h>
#include <setjmp.h>
#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#define FIXTURE "tests/build/jpeg_fixture"

static char dir[256];

static const char *path_in_dir(const char *name) {
    static char buf[2][512];
    static int which;
    which ^= 1;
    snprintf(buf[which], sizeof(buf[which]), "%s/%s", dir, name);
    return buf[which];
}

static int make_fixture(const char *path, const char *args) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "%s %s %s", FIXTURE, path, args);
    return system(cmd);
}

static unsigned char *read_file(const char *path, size_t *len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    *len = (size_t)ftell(fp);
    rewind(fp);
    unsigned char *buf = malloc(*len ? *len : 1);
    if (fread(buf, 1, *len, fp) != *len) { free(buf); buf = NULL; }
    fclose(fp);
    return buf;
}

/* ---- an independent look at a JPEG, through libjpeg directly ------------- */

typedef struct {
    int ok, progressive, arith, restart, components, h_samp0, width, height;
    unsigned char *pixels;     /* decoded, width * height * components */
    int n_markers;
    struct { int code; unsigned len; unsigned char data[256]; } markers[8];
} Info;

typedef struct { struct jpeg_error_mgr pub; jmp_buf jump; } Jump;
static void jump_exit(j_common_ptr c) { longjmp(((Jump *)c->err)->jump, 1); }
static void quiet(j_common_ptr c) { (void)c; }

static Info inspect(const char *path) {
    Info info = {0};
    FILE *fp = fopen(path, "rb");
    if (!fp) return info;
    struct jpeg_decompress_struct d;
    Jump err;
    d.err = jpeg_std_error(&err.pub);
    err.pub.error_exit = jump_exit;
    err.pub.output_message = quiet;
    if (setjmp(err.jump)) {
        jpeg_destroy_decompress(&d);
        fclose(fp);
        free(info.pixels);
        info.pixels = NULL;
        info.ok = 0;
        return info;
    }
    jpeg_create_decompress(&d);
    jpeg_stdio_src(&d, fp);
    jpeg_save_markers(&d, JPEG_COM, 0xFFFF);
    for (int m = 1; m < 16; m++) jpeg_save_markers(&d, JPEG_APP0 + m, 0xFFFF);
    jpeg_read_header(&d, TRUE);
    info.progressive = d.progressive_mode;
    info.arith = d.arith_code;
    info.restart = d.restart_interval;
    info.components = d.num_components;
    info.h_samp0 = d.comp_info[0].h_samp_factor;
    for (jpeg_saved_marker_ptr m = d.marker_list; m && info.n_markers < 8; m = m->next) {
        info.markers[info.n_markers].code = m->marker;
        info.markers[info.n_markers].len = m->data_length;
        memcpy(info.markers[info.n_markers].data, m->data, m->data_length < 256 ? m->data_length : 256);
        info.n_markers++;
    }
    jpeg_start_decompress(&d);
    info.width = d.output_width;
    info.height = d.output_height;
    size_t stride = (size_t)d.output_width * d.output_components;
    info.pixels = malloc(stride * d.output_height);
    while (d.output_scanline < d.output_height) {
        JSAMPROW row = info.pixels + stride * d.output_scanline;
        jpeg_read_scanlines(&d, &row, 1);
    }
    jpeg_finish_decompress(&d);
    jpeg_destroy_decompress(&d);
    fclose(fp);
    info.ok = 1;
    return info;
}

static int same_pixels(const Info *a, const Info *b) {
    return a->ok && b->ok && a->width == b->width && a->height == b->height &&
           a->components == b->components &&
           memcmp(a->pixels, b->pixels, (size_t)a->width * a->height * a->components) == 0;
}

/* ---- lossless round trip ---------------------------------------------------- */

static const char *variants[] = {
    "96 64 3 85",                      /* baseline 4:2:0, standard tables */
    "96 64 1 85",                      /* grayscale */
    "96 64 3 85 444",                  /* no subsampling */
    "96 64 3 85 progressive",
    "96 64 3 85 optimize",
    "96 64 3 85 arith",
    "96 64 3 85 restart",
    "100 70 3 60 progressive markers", /* odd size: partial MCUs */
};

static void test_roundtrip_unchanged(void) {
    /* Load and save with nothing embedded: same coefficients (so the same
       decoded pixels), and the same coding format */
    for (size_t v = 0; v < sizeof(variants) / sizeof(variants[0]); v++) {
        const char *in = path_in_dir("in.jpg"), *out = path_in_dir("out.jpg");
        CHECK(make_fixture(in, variants[v]) == 0);
        JpegImage *j = jpeg_load(in);
        CHECK(j != NULL);
        if (!j) continue;
        CHECK(jpeg_save(j, out) == 0);
        jpeg_free(j);
        Info a = inspect(in), b = inspect(out);
        int ok = same_pixels(&a, &b) && a.progressive == b.progressive && a.arith == b.arith &&
                 a.restart == b.restart && a.h_samp0 == b.h_samp0;
        CHECK(ok);
        if (!ok) fprintf(stderr, "    (variant: %s)\n", variants[v]);
        free(a.pixels);
        free(b.pixels);
    }
}

static void test_standard_tables_byte_identical(void) {
    /* A camera-style JPEG (standard Huffman tables) comes back byte for byte */
    const char *in = path_in_dir("std.jpg"), *out = path_in_dir("std-out.jpg");
    CHECK(make_fixture(in, "128 96 3 90") == 0);
    JpegImage *j = jpeg_load(in);
    CHECK(j && jpeg_save(j, out) == 0);
    jpeg_free(j);
    size_t la, lb;
    unsigned char *a = read_file(in, &la), *b = read_file(out, &lb);
    CHECK(a && b && la == lb && memcmp(a, b, la) == 0);
    free(a);
    free(b);
}

static void test_markers_kept(void) {
    const char *in = path_in_dir("m.jpg"), *out = path_in_dir("m-out.jpg");
    CHECK(make_fixture(in, "64 64 3 80 markers") == 0);
    JpegImage *j = jpeg_load(in);
    CHECK(j && jpeg_save(j, out) == 0);
    jpeg_free(j);
    Info a = inspect(in), b = inspect(out);
    CHECK(a.n_markers == 3 && b.n_markers == a.n_markers);
    for (int i = 0; i < a.n_markers && i < b.n_markers; i++)
        CHECK(a.markers[i].code == b.markers[i].code && a.markers[i].len == b.markers[i].len &&
              memcmp(a.markers[i].data, b.markers[i].data,
                     a.markers[i].len < 256 ? a.markers[i].len : 256) == 0);
    free(a.pixels);
    free(b.pixels);
}

/* ---- carriers and embedding ----------------------------------------------- */

static void test_carriers_and_embedding(void) {
    const char *in = path_in_dir("c.jpg"), *out = path_in_dir("c-out.jpg");
    CHECK(make_fixture(in, "160 120 3 85") == 0);
    JpegImage *j = jpeg_load(in);
    CHECK(j != NULL);
    if (!j) return;
    Carrier c = jpeg_carrier(j);
    CHECK(c.n_coefs > 2000);
    int all_big = 1;
    for (uint32_t i = 0; i < c.n_coefs; i++)
        if (*c.coefs[i] > -2 && *c.coefs[i] < 2) all_big = 0;
    CHECK(all_big);

    /* Fill every carrier with random bits, exchange-embedded */
    uint32_t n = c.n_coefs, len = n / 8;
    uint32_t *idx = malloc(n * sizeof(uint32_t));
    for (uint32_t i = 0; i < n; i++) idx[i] = i;
    uint8_t *data = malloc(len), *back = malloc(len);
    randombytes_buf(data, len);
    int16_t *before = malloc(n * sizeof(int16_t));
    for (uint32_t i = 0; i < n; i++) before[i] = *c.coefs[i];
    EmbedPlan *plan = embed_plan_new();
    EmbedStats st;
    CHECK(embed_write_raw(&c, idx, n, data, len, plan) == 0);
    CHECK(embed_apply(plan, &st) == 0);
    embed_plan_free(plan);
    /* Most changes swap in pairs. Fewer than on PNG photos: coefficient
       magnitudes fall off steeply (many more 2s than 3s), and the random
       bits must even out that parity skew with nudges (68% pair here, about
       80% on real photos). */
    CHECK(st.exchanged * 10 > st.changes * 6);

    int kept = 1, within_one = 1;
    for (uint32_t i = 0; i < n; i++) {
        if (*c.coefs[i] > -2 && *c.coefs[i] < 2) kept = 0;
        if (abs(*c.coefs[i] - before[i]) > 1) within_one = 0;
    }
    CHECK(kept);        /* every carrier is still a carrier */
    CHECK(within_one);

    /* Through a file and back: the same carriers, holding the data */
    CHECK(jpeg_save(j, out) == 0);
    jpeg_free(j);
    JpegImage *k = jpeg_load(out);
    CHECK(k != NULL);
    if (k) {
        Carrier c2 = jpeg_carrier(k);
        CHECK(c2.n_coefs == n);
        if (c2.n_coefs == n) {
            CHECK(embed_read_raw(&c2, idx, n, back, len) == 0);
            CHECK(memcmp(back, data, len) == 0);
        }
        jpeg_free(k);
    }
    free(idx); free(data); free(back); free(before);
}

/* ---- bad input -------------------------------------------------------------- */

static void test_bad_input(void) {
    CHECK(jpeg_load(path_in_dir("missing.jpg")) == NULL);

    const char *p = path_in_dir("junk.jpg");
    FILE *fp = fopen(p, "wb");
    static const char junk[] = "\xFF\xD8\xFF not really a jpeg at all";
    fwrite(junk, 1, sizeof(junk) - 1, fp);
    fclose(fp);
    CHECK(is_jpeg_file(p));
    CHECK(jpeg_load(p) == NULL);

    /* Truncated mid-scan: libjpeg pads it out with a warning; it may load,
       but must not crash or leak (ASan watches) */
    const char *t = path_in_dir("trunc.jpg");
    CHECK(make_fixture(t, "96 64 3 85") == 0);
    struct stat st;
    stat(t, &st);
    CHECK(truncate(t, st.st_size / 2) == 0);
    jpeg_free(jpeg_load(t));
}

static void test_huge_dimensions_refused(void) {
    /* A small file whose frame header claims 65000 x 65000: refused before
       any coefficient memory (about 12 GB) is allocated */
    const char *p = path_in_dir("huge.jpg");
    CHECK(make_fixture(p, "16 16 3 85") == 0);
    size_t len;
    unsigned char *b = read_file(p, &len);
    for (size_t i = 0; b && i + 8 < len; i++)
        if (b[i] == 0xFF && b[i + 1] == 0xC0) {  /* SOF0: length, precision, height, width */
            b[i + 5] = b[i + 7] = 0xFD;
            b[i + 6] = b[i + 8] = 0xE8;
            break;
        }
    FILE *fp = fopen(p, "wb");
    fwrite(b, 1, len, fp);
    fclose(fp);
    free(b);
    alarm(10);
    CHECK(jpeg_load(p) == NULL);
    alarm(0);
}

static void test_scan_limit(void) {
    /* Reading every scan is a pass over the coefficients; a file can have
       thousands. 568 valid scans: refused. A normal progressive file has ~10. */
    const char *p = path_in_dir("scans.jpg");
    CHECK(make_fixture(p, "64 64 3 85 manyscans") == 0);
    Info info = inspect(p);
    CHECK(info.ok);  /* libjpeg itself reads it: it is valid */
    free(info.pixels);
    CHECK(jpeg_load(p) == NULL);
    CHECK(make_fixture(p, "64 64 3 85 progressive") == 0);
    JpegImage *j = jpeg_load(p);
    CHECK(j != NULL);
    jpeg_free(j);
}

static void test_extreme_dc_accepted(void) {
    /* An all-black block at quality 100 has DC -1024, the most negative an
       8-bit JPEG can hold: valid, so it must load and save */
    const char *p = path_in_dir("black.jpg"), *out = path_in_dir("black-out.jpg");
    FILE *fp = fopen(p, "wb");
    struct jpeg_compress_struct c;
    struct jpeg_error_mgr err;
    c.err = jpeg_std_error(&err);
    jpeg_create_compress(&c);
    jpeg_stdio_dest(&c, fp);
    c.image_width = c.image_height = 16;
    c.input_components = 1;
    c.in_color_space = JCS_GRAYSCALE;
    jpeg_set_defaults(&c);
    jpeg_set_quality(&c, 100, TRUE);
    jpeg_start_compress(&c, TRUE);
    unsigned char row[16] = {0};
    while (c.next_scanline < 16) {
        JSAMPROW r = row;
        jpeg_write_scanlines(&c, &r, 1);
    }
    jpeg_finish_compress(&c);
    jpeg_destroy_compress(&c);
    fclose(fp);
    JpegImage *j = jpeg_load(p);
    CHECK(j != NULL);
    CHECK(j && jpeg_save(j, out) == 0);
    jpeg_free(j);
}

static void test_many_scans_refused(void) {
    /* 500 empty scans of an 8192x8192 frame, 5 KB: each scan is a pass over
       the frame, so it took seconds to read (at 23000x23000, 16 s). Past
       the cap on blocks visited, it is refused. */
    CHECK(jpeg_load("tests/fuzz/regressions/jpeg_load/many-scans-large-frame.jpg") == NULL);
}

/* 330 bytes declaring a 15144x32800 gray frame with no entropy data:
   libjpeg filled it with zeros, 1.5 s and ~1 GB. Fewer bits than blocks,
   so refused before reading. */
static void test_hollow_frame_refused(void) {
    CHECK(jpeg_load("tests/fuzz/regressions/jpeg_load/hollow-huge-frame.jpg") == NULL);
}

static void test_unrewritable_refused(void) {
    /* Each decodes, but libjpeg writes it back wrong or not at all (found
       by fuzzing): the rewrite check refuses it. Encode now refuses these
       as too small first, so the CLI tests can't see this. */
    static const char *const files[] = {
        "oversampled-progressive.jpg", "redefined-quant-table.jpg", "truncated-progressive-al1.jpg",
    };
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        char in[200];
        snprintf(in, sizeof(in), "tests/fuzz/regressions/jpeg_load/%s", files[i]);
        JpegImage *j = jpeg_load(in);
        CHECK(j != NULL);
        if (j) CHECK(jpeg_check_writable(j) != 0);
        jpeg_free(j);
    }
}

/* UERD costs, recomputed here from the coefficients through libjpeg: a
   carrier costs its quantization step over its block's energy plus a
   quarter of each neighbour's (energy: the sum of |coefficient| x step
   over the AC terms), JPEG_TWO_COST times that for |value| 2 */
static void check_uerd(const char *path) {
    JpegImage *j = jpeg_load(path);
    CHECK(j != NULL);
    if (!j) return;
    Carrier c = jpeg_carrier(j);

    FILE *fp = fopen(path, "rb");
    struct jpeg_decompress_struct d;
    struct jpeg_error_mgr err;
    d.err = jpeg_std_error(&err);
    jpeg_create_decompress(&d);
    jpeg_stdio_src(&d, fp);
    jpeg_read_header(&d, TRUE);
    jvirt_barray_ptr *coefs = jpeg_read_coefficients(&d);
    uint32_t n = 0, bad = 0;
    for (int ci = 0; ci < d.num_components; ci++) {
        jpeg_component_info *comp = &d.comp_info[ci];
        int w = (int)comp->width_in_blocks, h = (int)comp->height_in_blocks;
        const UINT16 *q = comp->quant_table->quantval;
        double *energy = calloc((size_t)w * h, sizeof(double));
        for (int by = 0; by < h; by++) {
            JBLOCKARRAY row = d.mem->access_virt_barray((j_common_ptr)&d, coefs[ci], by, 1, FALSE);
            for (int bx = 0; bx < w; bx++)
                for (int k = 1; k < DCTSIZE2; k++) energy[by * w + bx] += abs(row[0][bx][k]) * q[k];
        }
        for (int by = 0; by < h; by++) {
            JBLOCKARRAY row = d.mem->access_virt_barray((j_common_ptr)&d, coefs[ci], by, 1, FALSE);
            for (int bx = 0; bx < w; bx++) {
                double around = 0;
                for (int y = by - 1; y <= by + 1; y++)
                    for (int x = bx - 1; x <= bx + 1; x++)
                        if (y >= 0 && x >= 0 && y < h && x < w)
                            around += (y == by && x == bx ? 1 : 0.25) * energy[y * w + x];
                for (int k = 1; k < DCTSIZE2; k++) {
                    int v = row[0][bx][k];
                    if (v > -2 && v < 2) continue;
                    double want = q[k] / around * (v == 2 || v == -2 ? JPEG_TWO_COST : 1);
                    if (n >= c.n_coefs || *c.coefs[n] != v || fabs(c.coef_costs[n] - want) > 1e-5 * want) bad++;
                    n++;
                }
            }
        }
        free(energy);
    }
    CHECK(n == c.n_coefs);
    CHECK(bad == 0);
    jpeg_destroy_decompress(&d);
    fclose(fp);
    jpeg_free(j);
}

static void test_uerd_costs(void) {
    const char *gray = path_in_dir("uerd-gray.jpg"), *color = path_in_dir("uerd-color.jpg");
    CHECK(make_fixture(gray, "64 48 1 85") == 0);
    check_uerd(gray);
    CHECK(make_fixture(color, "40 32 3 75") == 0);
    check_uerd(color);
}

static void test_fuzz_regressions(void) {
    /* Inputs the fuzzer once broke jpeg_load or jpeg_save with. Each must
       fail to load, be refused by jpeg_check_writable, or save and reload
       with the same carriers. */
    DIR *d = opendir("tests/fuzz/regressions/jpeg_load");
    CHECK(d != NULL);
    if (!d) return;
    struct dirent *e;
    int n = 0;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char in[600];
        snprintf(in, sizeof(in), "tests/fuzz/regressions/jpeg_load/%s", e->d_name);
        JpegImage *j = jpeg_load(in);
        if (j && jpeg_check_writable(j) != 0) {  /* encode refuses it: fine */
            jpeg_free(j);
            j = NULL;
        }
        if (j) {
            const char *out = path_in_dir("regression.jpg");
            CHECK(jpeg_save(j, out) == 0);
            JpegImage *k = jpeg_load(out);
            Carrier a = jpeg_carrier(j);
            CHECK(k && jpeg_carrier(k).n_coefs == a.n_coefs);
            if (k && jpeg_carrier(k).n_coefs == a.n_coefs) {
                Carrier b = jpeg_carrier(k);
                for (uint32_t i = 0; i < a.n_coefs; i++) CHECK(*a.coefs[i] == *b.coefs[i]);
            }
            jpeg_free(k);
            jpeg_free(j);
        }
        n++;
    }
    closedir(d);
    CHECK(n >= 1);
}

int main(void) {
    if (sodium_init() < 0) return 1;
    const char *base = getenv("TMPDIR");
    snprintf(dir, sizeof(dir), "%s/scattersteg-jpeg-XXXXXX", base ? base : "/tmp");
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }

    RUN(test_roundtrip_unchanged);
    RUN(test_standard_tables_byte_identical);
    RUN(test_markers_kept);
    RUN(test_carriers_and_embedding);
    RUN(test_bad_input);
    RUN(test_huge_dimensions_refused);
    RUN(test_scan_limit);
    RUN(test_extreme_dc_accepted);
    RUN(test_many_scans_refused);
    RUN(test_hollow_frame_refused);
    RUN(test_unrewritable_refused);
    RUN(test_uerd_costs);
    RUN(test_fuzz_regressions);

    char cmd[300];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    if (system(cmd) != 0) fprintf(stderr, "could not remove %s\n", dir);
    return TEST_SUMMARY();
}
