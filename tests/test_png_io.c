#define _POSIX_C_SOURCE 200809L  /* mkdtemp */
#include "test.h"
#include "png_io.h"
#include <png.h>
#include <zlib.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char dir[256];

static const char *path_in_dir(const char *name) {
    static char buf[512];
    snprintf(buf, sizeof(buf), "%s/%s", dir, name);
    return buf;
}

static int count_dir_entries(void) {
    DIR *d = opendir(dir);
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)))
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) n++;
    closedir(d);
    return n;
}

static void write_bytes(const char *path, const void *data, size_t len) {
    FILE *fp = fopen(path, "wb");
    fwrite(data, 1, len, fp);
    fclose(fp);
}

/* ---- fixture writer: any color type / bit depth / interlace -------------- */

typedef struct {
    int color_type, bit_depth, interlace;
    int with_trns;   /* palette images only */
} Fmt;

static const png_color palette[4] = {
    {255, 0, 0}, {0, 255, 0}, {0, 0, 255}, {10, 20, 30}
};

/* Test pattern, as the RGB triple png_load should produce for pixel (x, y) */
static void expected_rgb(const Fmt *f, uint32_t x, uint32_t y, uint8_t rgb[3]) {
    switch (f->color_type) {
    case PNG_COLOR_TYPE_GRAY:
    case PNG_COLOR_TYPE_GRAY_ALPHA:
        if (f->bit_depth == 1) {
            rgb[0] = rgb[1] = rgb[2] = ((x + y) & 1) ? 255 : 0;
        } else {
            rgb[0] = rgb[1] = rgb[2] = (uint8_t)(x * 16 + y);
        }
        return;
    case PNG_COLOR_TYPE_PALETTE: {
        const png_color *c = &palette[(x + y) % 4];
        rgb[0] = c->red; rgb[1] = c->green; rgb[2] = c->blue;
        return;
    }
    default:  /* RGB, RGBA */
        rgb[0] = (uint8_t)(x * 10);
        rgb[1] = (uint8_t)(y * 10);
        rgb[2] = (uint8_t)(x + y);
    }
}

static void write_fixture(const char *path, const Fmt *f, uint32_t w, uint32_t h) {
    FILE *fp = fopen(path, "wb");
    png_structp png = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    png_infop info = png_create_info_struct(png);
    png_init_io(png, fp);
    png_set_IHDR(png, info, w, h, f->bit_depth, f->color_type, f->interlace,
                 PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
    if (f->color_type == PNG_COLOR_TYPE_PALETTE) {
        png_set_PLTE(png, info, palette, 4);
        if (f->with_trns) {
            png_byte alpha[4] = {255, 128, 0, 64};
            png_set_tRNS(png, info, alpha, 4, NULL);
        }
    }
    png_write_info(png, info);

    size_t rowbytes = png_get_rowbytes(png, info);
    png_bytep *rows = malloc(h * sizeof(png_bytep));
    for (uint32_t y = 0; y < h; y++) {
        rows[y] = calloc(rowbytes, 1);
        for (uint32_t x = 0; x < w; x++) {
            uint8_t rgb[3];
            expected_rgb(f, x, y, rgb);
            png_bytep r = rows[y];
            switch (f->color_type) {
            case PNG_COLOR_TYPE_GRAY:
                if (f->bit_depth == 1) r[x / 8] |= (uint8_t)((rgb[0] ? 1 : 0) << (7 - x % 8));
                else r[x] = rgb[0];
                break;
            case PNG_COLOR_TYPE_GRAY_ALPHA:
                r[x * 2] = rgb[0]; r[x * 2 + 1] = 0x80;
                break;
            case PNG_COLOR_TYPE_PALETTE: {
                uint8_t idx = (x + y) % 4;
                if (f->bit_depth == 2) r[x / 4] |= (uint8_t)(idx << (6 - 2 * (x % 4)));
                else r[x] = idx;
                break;
            }
            case PNG_COLOR_TYPE_RGB:
                if (f->bit_depth == 16) {
                    for (int c = 0; c < 3; c++) {
                        r[x * 6 + c * 2]     = rgb[c];  /* high byte kept */
                        r[x * 6 + c * 2 + 1] = 0x77;    /* low byte stripped */
                    }
                } else {
                    memcpy(&r[x * 3], rgb, 3);
                }
                break;
            case PNG_COLOR_TYPE_RGBA:
                memcpy(&r[x * 4], rgb, 3);
                r[x * 4 + 3] = (uint8_t)(x * 7);
                break;
            }
        }
    }
    png_write_image(png, rows);
    png_write_end(png, NULL);
    png_destroy_write_struct(&png, &info);
    fclose(fp);
    for (uint32_t y = 0; y < h; y++) free(rows[y]);
    free(rows);
}

/* Gray images load as one channel, everything else as RGB */
static int image_matches(const Image *img, const Fmt *f, uint32_t w, uint32_t h) {
    uint32_t ch = (f->color_type & PNG_COLOR_MASK_COLOR) ? 3 : 1;
    if (img->width != w || img->height != h || img->channels != ch) return 0;
    for (uint32_t y = 0; y < h; y++)
        for (uint32_t x = 0; x < w; x++) {
            uint8_t rgb[3];
            expected_rgb(f, x, y, rgb);
            if (memcmp(&img->rows[y][x * ch], rgb, ch) != 0) return 0;
        }
    return 1;
}

static void check_variant(const char *name, Fmt f) {
    /* Odd sizes so packed formats have partial bytes and Adam7 has short passes */
    const uint32_t w = 13, h = 9;
    const char *p = path_in_dir(name);
    write_fixture(p, &f, w, h);
    Image *img = png_load(p);
    CHECK(img != NULL);
    if (img) CHECK(image_matches(img, &f, w, h));
    if (!img || !image_matches(img, &f, w, h))
        fprintf(stderr, "    (variant: %s)\n", name);
    image_free(img);
    remove(p);
}

/* ---- png_load: supported variants --------------------------------------- */

static void test_load_rgb8(void)        { check_variant("rgb8.png",    (Fmt){PNG_COLOR_TYPE_RGB, 8, PNG_INTERLACE_NONE, 0}); }
static void test_load_rgb16(void)       { check_variant("rgb16.png",   (Fmt){PNG_COLOR_TYPE_RGB, 16, PNG_INTERLACE_NONE, 0}); }
static void test_load_rgba8(void)       { check_variant("rgba8.png",   (Fmt){PNG_COLOR_TYPE_RGBA, 8, PNG_INTERLACE_NONE, 0}); }
static void test_load_gray8(void)       { check_variant("gray8.png",   (Fmt){PNG_COLOR_TYPE_GRAY, 8, PNG_INTERLACE_NONE, 0}); }
static void test_load_gray1(void)       { check_variant("gray1.png",   (Fmt){PNG_COLOR_TYPE_GRAY, 1, PNG_INTERLACE_NONE, 0}); }
static void test_load_gray_alpha8(void) { check_variant("ga8.png",     (Fmt){PNG_COLOR_TYPE_GRAY_ALPHA, 8, PNG_INTERLACE_NONE, 0}); }
static void test_load_palette8(void)    { check_variant("pal8.png",    (Fmt){PNG_COLOR_TYPE_PALETTE, 8, PNG_INTERLACE_NONE, 0}); }
static void test_load_palette2(void)    { check_variant("pal2.png",    (Fmt){PNG_COLOR_TYPE_PALETTE, 2, PNG_INTERLACE_NONE, 0}); }
static void test_load_palette_trns(void){ check_variant("paltrns.png", (Fmt){PNG_COLOR_TYPE_PALETTE, 8, PNG_INTERLACE_NONE, 1}); }
static void test_load_interlaced(void)  { check_variant("adam7.png",   (Fmt){PNG_COLOR_TYPE_RGB, 8, PNG_INTERLACE_ADAM7, 0}); }
static void test_load_interlaced_palette(void) {
    check_variant("adam7pal.png", (Fmt){PNG_COLOR_TYPE_PALETTE, 8, PNG_INTERLACE_ADAM7, 0});
}

static void test_load_reports_unsuitable(void) {
    struct { const char *name; Fmt f; const char *unsuitable; } cases[] = {
        {"d_rgb8.png",    {PNG_COLOR_TYPE_RGB, 8, PNG_INTERLACE_NONE, 0},        NULL},
        {"d_adam7.png",   {PNG_COLOR_TYPE_RGB, 8, PNG_INTERLACE_ADAM7, 0},       NULL},
        {"d_gray8.png",   {PNG_COLOR_TYPE_GRAY, 8, PNG_INTERLACE_NONE, 0},       NULL},
        {"d_gray1.png",   {PNG_COLOR_TYPE_GRAY, 1, PNG_INTERLACE_NONE, 0},       "fewer than 8 bits per sample"},
        {"d_pal8.png",    {PNG_COLOR_TYPE_PALETTE, 8, PNG_INTERLACE_NONE, 0},    "a color palette"},
        {"d_pal2.png",    {PNG_COLOR_TYPE_PALETTE, 2, PNG_INTERLACE_NONE, 0},    "a color palette"},
        {"d_rgb16.png",   {PNG_COLOR_TYPE_RGB, 16, PNG_INTERLACE_NONE, 0},       "16-bit color"},
        {"d_rgba8.png",   {PNG_COLOR_TYPE_RGBA, 8, PNG_INTERLACE_NONE, 0},       "transparency"},
        {"d_ga8.png",     {PNG_COLOR_TYPE_GRAY_ALPHA, 8, PNG_INTERLACE_NONE, 0}, "transparency"},
        {"d_paltrns.png", {PNG_COLOR_TYPE_PALETTE, 8, PNG_INTERLACE_NONE, 1},    "transparency"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const char *p = path_in_dir(cases[i].name);
        write_fixture(p, &cases[i].f, 5, 5);
        Image *img = png_load(p);
        CHECK(img != NULL);
        if (img) {
            const char *want = cases[i].unsuitable, *got = img->unsuitable;
            int ok = want ? got && strcmp(got, want) == 0 : got == NULL;
            CHECK(ok);
            if (!ok) fprintf(stderr, "    (%s: unsuitable = %s)\n", cases[i].name,
                             got ? got : "NULL");
        }
        image_free(img);
        remove(p);
    }
}

/* ---- png_load: bad input ------------------------------------------------ */

static void png_chunk(FILE *fp, const char *type, const uint8_t *data, uint32_t len) {
    uint8_t be[4] = {len >> 24, len >> 16, len >> 8, len};
    fwrite(be, 1, 4, fp);
    fwrite(type, 1, 4, fp);
    if (len) fwrite(data, 1, len, fp);
    uLong crc = crc32(0, (const Bytef *)type, 4);
    if (len) crc = crc32(crc, data, len);
    uint8_t c[4] = {crc >> 24, crc >> 16, crc >> 8, crc};
    fwrite(c, 1, 4, fp);
}

/* An RGB8 PNG whose header claims w x h but carries almost no pixel data */
static void write_lying_header(const char *path, uint32_t w, uint32_t h) {
    FILE *fp = fopen(path, "wb");
    fwrite("\x89PNG\r\n\x1a\n", 1, 8, fp);
    uint8_t ihdr[13] = {w >> 24, w >> 16, w >> 8, w, h >> 24, h >> 16, h >> 8, h,
                        8, PNG_COLOR_TYPE_RGB, 0, 0, 0};
    png_chunk(fp, "IHDR", ihdr, 13);
    uint8_t raw[8] = {0}, z[64];
    uLongf zlen = sizeof(z);
    compress(z, &zlen, raw, sizeof(raw));
    png_chunk(fp, "IDAT", z, (uint32_t)zlen);
    png_chunk(fp, "IEND", NULL, 0);
    fclose(fp);
}

static void test_load_missing_file(void) {
    CHECK(png_load(path_in_dir("does-not-exist.png")) == NULL);
}

static void test_load_empty_file(void) {
    const char *p = path_in_dir("empty.png");
    write_bytes(p, "", 0);
    CHECK(png_load(p) == NULL);
    remove(p);
}

static void test_load_not_png(void) {
    const char *p = path_in_dir("text.png");
    write_bytes(p, "this is not a png file at all\n", 30);
    CHECK(png_load(p) == NULL);
    remove(p);
}

static void test_load_truncated(void) {
    const Fmt f = {PNG_COLOR_TYPE_RGB, 8, PNG_INTERLACE_NONE, 0};
    const char *p = path_in_dir("trunc.png");
    write_fixture(p, &f, 64, 64);
    struct stat st;
    stat(p, &st);
    CHECK(truncate(p, st.st_size / 2) == 0);
    CHECK(png_load(p) == NULL);
    remove(p);
}

static void test_load_huge_dimensions(void) {
    /* ~3 TB if allocated: must be rejected before any allocation */
    const char *p = path_in_dir("huge.png");
    write_lying_header(p, 1000000, 1000000);
    alarm(10);  /* without the size cap this grinds through ~3 TB of mallocs */
    CHECK(png_load(p) == NULL);
    alarm(0);
    remove(p);
}

static void test_load_tall_narrow(void) {
    /* Small row size, but 1 x 400M is 1.2 GB of pixels plus 3.2 GB of row
       pointers: the total must be capped, not just the row width */
    const char *p = path_in_dir("tall.png");
    write_lying_header(p, 1, 400000000);
    CHECK(png_load(p) == NULL);
    remove(p);
}

/* ---- png_save ------------------------------------------------------------ */

static Image *make_image(uint32_t w, uint32_t h) {
    Image *img = calloc(1, sizeof(Image));
    img->width = w;
    img->height = h;
    img->channels = 3;
    img->rows = malloc((h ? h : 1) * sizeof(uint8_t *));
    for (uint32_t y = 0; y < h; y++) {
        img->rows[y] = malloc((size_t)w * 3 + 1);
        for (uint32_t i = 0; i < w * 3; i++)
            img->rows[y][i] = (uint8_t)(i * 31 + y * 17);
    }
    return img;
}

static int images_equal(const Image *a, const Image *b) {
    if (a->width != b->width || a->height != b->height || a->channels != b->channels) return 0;
    for (uint32_t y = 0; y < a->height; y++)
        if (memcmp(a->rows[y], b->rows[y], (size_t)a->width * a->channels) != 0) return 0;
    return 1;
}

static void test_save_roundtrip(void) {
    Image *img = make_image(37, 23);
    const char *p = path_in_dir("rt.png");
    CHECK(png_save(img, p) == 0);
    Image *back = png_load(p);
    CHECK(back && images_equal(img, back));
    CHECK(count_dir_entries() == 1);  /* no leftover temp file */
    image_free(back);
    image_free(img);
    remove(p);
}

static void test_save_gray_roundtrip(void) {
    /* Gray stays gray: one sample per pixel, written as an 8-bit gray PNG */
    Image *img = make_image(17, 11);
    img->channels = 1;
    const char *p = path_in_dir("gray.png");
    CHECK(png_save(img, p) == 0);
    Image *back = png_load(p);
    CHECK(back && back->channels == 1 && back->unsuitable == NULL);
    CHECK(back && images_equal(img, back));
    image_free(back);
    image_free(img);
    remove(p);
}

static void test_save_overwrites(void) {
    const char *p = path_in_dir("over.png");
    write_bytes(p, "old contents", 12);
    Image *img = make_image(5, 5);
    CHECK(png_save(img, p) == 0);
    Image *back = png_load(p);
    CHECK(back && images_equal(img, back));
    image_free(back);
    image_free(img);
    remove(p);
}

static void test_save_mode_follows_umask(void) {
    mode_t old = umask(027);
    Image *img = make_image(2, 2);
    const char *p = path_in_dir("mode.png");
    CHECK(png_save(img, p) == 0);
    struct stat st;
    CHECK(stat(p, &st) == 0 && (st.st_mode & 0777) == 0640);
    umask(old);
    image_free(img);
    remove(p);
}

static mode_t mode_of(const char *p) {
    struct stat st;
    return stat(p, &st) == 0 ? st.st_mode & 0777 : (mode_t)-1;
}

static void test_save_keeps_existing_mode(void) {
    /* A private image must stay private, a shared one shared, whatever
       the umask; only new files take their mode from the umask */
    mode_t old = umask(022);
    Image *img = make_image(2, 2);
    const char *p = path_in_dir("private.png");
    write_bytes(p, "x", 1);
    chmod(p, 0600);
    CHECK(png_save(img, p) == 0);
    CHECK(mode_of(p) == 0600);

    umask(077);
    chmod(p, 0664);
    CHECK(png_save(img, p) == 0);
    CHECK(mode_of(p) == 0664);

    umask(old);
    image_free(img);
    remove(p);
}

static void test_save_through_symlink(void) {
    /* -o pointing at a symlink updates the file it points to (here in
       another directory) and leaves the link in place */
    char sub[512], target[600], link[600];
    snprintf(sub, sizeof(sub), "%s/elsewhere", dir);
    mkdir(sub, 0700);
    snprintf(target, sizeof(target), "%s/real.png", sub);
    snprintf(link, sizeof(link), "%s/link.png", dir);
    write_bytes(target, "old", 3);
    chmod(target, 0640);
    CHECK(symlink(target, link) == 0);

    Image *img = make_image(3, 3);
    CHECK(png_save(img, link) == 0);
    struct stat st;
    CHECK(lstat(link, &st) == 0 && S_ISLNK(st.st_mode));
    Image *back = png_load(target);
    CHECK(back && images_equal(img, back));
    CHECK(mode_of(target) == 0640);
    CHECK(count_dir_entries() == 2);  /* elsewhere/ and link.png: no temp file */

    image_free(back);
    image_free(img);
    remove(link);
    remove(target);
    rmdir(sub);
}

static void test_save_dangling_symlink(void) {
    /* A link to nothing has no file to write through to: it is replaced */
    const char *link = path_in_dir("dangling.png");
    CHECK(symlink("/nonexistent/scattersteg-target.png", link) == 0);
    Image *img = make_image(2, 2);
    CHECK(png_save(img, link) == 0);
    struct stat st;
    CHECK(lstat(link, &st) == 0 && S_ISREG(st.st_mode));
    image_free(img);
    remove(link);
}

static void test_save_missing_dir(void) {
    Image *img = make_image(2, 2);
    CHECK(png_save(img, path_in_dir("no/such/dir/x.png")) == -1);
    CHECK(errno == ENOENT);
    CHECK(count_dir_entries() == 0);
    image_free(img);
}

static void test_save_unwritable_dir(void) {
    if (geteuid() == 0) { printf("     (skipped as root)\n"); return; }
    char sub[512];
    snprintf(sub, sizeof(sub), "%s/ro", dir);
    mkdir(sub, 0700);
    char out[600];
    snprintf(out, sizeof(out), "%s/x.png", sub);
    write_bytes(out, "precious", 8);
    chmod(sub, 0500);

    Image *img = make_image(2, 2);
    CHECK(png_save(img, out) == -1);
    CHECK(errno == EACCES);

    chmod(sub, 0700);
    FILE *fp = fopen(out, "rb");
    char buf[16] = {0};
    CHECK(fp && fread(buf, 1, sizeof(buf), fp) == 8 && memcmp(buf, "precious", 8) == 0);
    if (fp) fclose(fp);

    image_free(img);
    remove(out);
    rmdir(sub);
}

static void test_save_libpng_failure_keeps_existing(void) {
    /* A zero-width image makes libpng fail mid-save, after the temp file
       exists: the old output must survive and the temp file must go. */
    const char *p = path_in_dir("keep.png");
    write_bytes(p, "precious", 8);
    Image *img = make_image(0, 4);
    CHECK(png_save(img, p) == -1);
    CHECK(errno == 0);  /* documented: 0 when libpng failed internally */
    CHECK(count_dir_entries() == 1);

    FILE *fp = fopen(p, "rb");
    char buf[16] = {0};
    CHECK(fp && fread(buf, 1, sizeof(buf), fp) == 8 && memcmp(buf, "precious", 8) == 0);
    if (fp) fclose(fp);
    image_free(img);
    remove(p);
}

static void test_fuzz_regressions(void) {
    /* Inputs the fuzzer once broke png_load or png_save with. Each must
       either fail to load, or save and reload with the same pixels. */
    DIR *d = opendir("tests/fuzz/regressions/png_load");
    CHECK(d != NULL);
    if (!d) return;
    struct dirent *e;
    int n = 0;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char in[600];
        snprintf(in, sizeof(in), "tests/fuzz/regressions/png_load/%s", e->d_name);
        Image *img = png_load(in);
        if (img) {
            const char *out = path_in_dir("regression.png");
            int saved = png_save(img, out) == 0;
            CHECK(saved);
            Image *back = saved ? png_load(out) : NULL;
            CHECK(back && images_equal(img, back));
            if (!back || !images_equal(img, back)) fprintf(stderr, "    (%s)\n", e->d_name);
            image_free(back);
            image_free(img);
            remove(out);
        }
        n++;
    }
    closedir(d);
    CHECK(n >= 2);
}

static void test_image_free_null(void) {
    image_free(NULL);
    CHECK(1);
}

int main(void) {
    const char *base = getenv("TMPDIR");
    snprintf(dir, sizeof(dir), "%s/scattersteg-test-XXXXXX", base ? base : "/tmp");
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }

    RUN(test_load_rgb8);
    RUN(test_load_rgb16);
    RUN(test_load_rgba8);
    RUN(test_load_gray8);
    RUN(test_load_gray1);
    RUN(test_load_gray_alpha8);
    RUN(test_load_palette8);
    RUN(test_load_palette2);
    RUN(test_load_palette_trns);
    RUN(test_load_interlaced);
    RUN(test_load_interlaced_palette);
    RUN(test_load_reports_unsuitable);
    RUN(test_load_missing_file);
    RUN(test_load_empty_file);
    RUN(test_load_not_png);
    RUN(test_load_truncated);
    RUN(test_load_huge_dimensions);
    RUN(test_load_tall_narrow);
    RUN(test_save_roundtrip);
    RUN(test_save_gray_roundtrip);
    RUN(test_save_overwrites);
    RUN(test_save_mode_follows_umask);
    RUN(test_save_keeps_existing_mode);
    RUN(test_save_through_symlink);
    RUN(test_save_dangling_symlink);
    RUN(test_save_missing_dir);
    RUN(test_save_unwritable_dir);
    RUN(test_save_libpng_failure_keeps_existing);
    RUN(test_fuzz_regressions);
    RUN(test_image_free_null);

    rmdir(dir);
    return TEST_SUMMARY();
}
