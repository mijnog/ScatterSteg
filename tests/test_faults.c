/* SPDX-License-Identifier: MIT OR Apache-2.0
   Copyright (C) 2026 Maxime de Montbron */
/* Sweeps png_load and png_save over every faultable libc call: for each N,
   fail the Nth call and check the function fails cleanly. Built with
   png_io.c force-including fault.h; ASan reports any leak at exit. */
#define _POSIX_C_SOURCE 200809L
#include "test.h"
#include "fault.h"
#include "png_io.h"
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>

static char dir[256];
static char out_path[512];

static int count_dir_entries(void) {
    DIR *d = opendir(dir);
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)))
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) n++;
    closedir(d);
    return n;
}

static int count_open_fds(void) {
    DIR *d = opendir("/proc/self/fd");
    int n = 0;
    while (readdir(d)) n++;
    closedir(d);
    return n;
}

static Image *make_image(uint32_t w, uint32_t h) {
    Image *img = calloc(1, sizeof(Image));
    img->width = w;
    img->height = h;
    img->channels = 3;
    img->rows = malloc(h * sizeof(uint8_t *));
    for (uint32_t y = 0; y < h; y++) {
        img->rows[y] = malloc((size_t)w * 3);
        for (uint32_t i = 0; i < w * 3; i++) img->rows[y][i] = (uint8_t)(i ^ y);
    }
    return img;
}

static int images_equal(const Image *a, const Image *b) {
    if (a->width != b->width || a->height != b->height) return 0;
    for (uint32_t y = 0; y < a->height; y++)
        if (memcmp(a->rows[y], b->rows[y], (size_t)a->width * 3) != 0) return 0;
    return 1;
}

static void write_text(const char *path, const char *s) {
    FILE *fp = fopen(path, "wb");
    fputs(s, fp);
    fclose(fp);
}

static int file_is(const char *path, const char *s) {
    char buf[64] = {0};
    FILE *fp = fopen(path, "rb");
    if (!fp) return 0;
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    return n == strlen(s) && memcmp(buf, s, n) == 0;
}

static void test_load_sweep(void) {
    char src[512];
    snprintf(src, sizeof(src), "%s/src.png", dir);
    Image *ref = make_image(16, 8);
    CHECK(png_save(ref, src) == 0);

    int fds = count_open_fds();
    unsigned n, fired = 0;
    for (n = 1; n < 1000; n++) {
        fault_arm(n);
        Image *img = png_load(src);
        int hit = fault_fired();
        fault_arm(0);
        if (!hit) {  /* ran past the last faultable call: must succeed */
            CHECK(img && images_equal(img, ref));
            image_free(img);
            break;
        }
        fired++;
        /* A failure must give NULL; one whose result is ignored (fclose
           after reading) may still give the full image, never a partial one */
        CHECK(img == NULL || images_equal(img, ref));
        CHECK(count_open_fds() == fds);
        CHECK(fault_bad_closes() == 0);
        image_free(img);
    }
    printf("     (%u faults injected into png_load)\n", fired);
    CHECK(fired >= 3);
    image_free(ref);
    remove(src);
}

static void test_save_sweep(void) {
    Image *img = make_image(16, 8);
    int fds = count_open_fds();
    unsigned n, fired = 0, rename_at = 0;
    for (n = 1; n < 1000; n++) {
        write_text(out_path, "precious");
        fault_arm(n);
        errno = 0;
        int r = png_save(img, out_path);
        int err = errno;
        int hit = fault_fired();
        const char *name = fault_fired_name();
        unsigned bad = fault_bad_closes();
        fault_arm(0);

        if (!hit) {
            CHECK(r == 0);
            Image *back = png_load(out_path);
            CHECK(back && images_equal(back, img));
            image_free(back);
            break;
        }
        fired++;
        if (strcmp(name, "rename") == 0) rename_at = n;
        /* Not fatal: fchown (the save goes ahead without the old file's
           group; test_save_fchown_failure_drops_group_access checks the
           mode), and the directory sync after the rename, by which point
           the file is in place */
        if (strcmp(name, "fchown") == 0 || (rename_at && n > rename_at)) {
            CHECK(r == 0);
            Image *back = png_load(out_path);
            CHECK(back && images_equal(back, img));
            image_free(back);
            CHECK(count_dir_entries() == 1);
            CHECK(count_open_fds() == fds);
            continue;
        }
        CHECK(r == -1);
        CHECK(err != 0);   /* every injected fault sets errno; it must survive */
        CHECK(file_is(out_path, "precious"));
        CHECK(count_dir_entries() == 1);  /* temp file cleaned up */
        CHECK(count_open_fds() == fds);
        CHECK(bad == 0);
        if (r != -1 || !err || bad || count_dir_entries() != 1)
            fprintf(stderr, "    (fault %u: %s, errno %d, bad closes %u)\n", n, name, err, bad);
    }
    printf("     (%u faults injected into png_save)\n", fired);
    CHECK(fired >= 6);  /* malloc mkstemp fdopen fflush fsync fclose rename */
    image_free(img);
    remove(out_path);
}

static void test_save_fclose_failure_no_double_close(void) {
    /* The bug fixed earlier: fclose fails but has released the fd, and the
       error path closed it again. Find the fclose call and fail exactly it. */
    Image *img = make_image(4, 4);
    for (unsigned n = 1; n < 1000; n++) {
        fault_arm(n);
        png_save(img, out_path);
        int hit = fault_fired();
        const char *name = fault_fired_name();
        unsigned bad = fault_bad_closes();
        fault_arm(0);
        if (!hit) { CHECK(!"fclose never reached"); break; }
        if (strcmp(name, "fclose") == 0) {
            CHECK(bad == 0);
            break;
        }
    }
    image_free(img);
    remove(out_path);
}

static void test_save_mkstemp_failure_spares_existing_file(void) {
    /* When mkstemp gives up, the template holds a name it tried, which may
       be someone else's file. The fault wrapper leaves "<path>.FAULTY". */
    char victim[600];
    snprintf(victim, sizeof(victim), "%s.FAULTY", out_path);
    write_text(victim, "not yours");
    Image *img = make_image(4, 4);
    for (unsigned n = 1; n < 1000; n++) {
        fault_arm(n);
        int r = png_save(img, out_path);
        int hit = fault_fired();
        const char *name = fault_fired_name();
        fault_arm(0);
        if (!hit) { CHECK(!"mkstemp never reached"); break; }
        if (strcmp(name, "mkstemp") == 0) {
            CHECK(r == -1);
            CHECK(file_is(victim, "not yours"));
            break;
        }
    }
    image_free(img);
    remove(victim);
    remove(out_path);
}

static void test_save_fchown_failure_drops_group_access(void) {
    /* Replacing a group-shared file whose group we can't keep (not a
       member): the new file must not pass the group bits to our group */
    Image *img = make_image(4, 4);
    for (unsigned n = 1; n < 1000; n++) {
        write_text(out_path, "shared");
        chmod(out_path, 0664);
        fault_arm(n);
        int r = png_save(img, out_path);
        int hit = fault_fired();
        const char *name = fault_fired_name();
        fault_arm(0);
        if (!hit) { CHECK(!"fchown never reached"); break; }
        if (strcmp(name, "fchown") == 0) {
            struct stat st;
            CHECK(r == 0);  /* not fatal: the save goes ahead */
            CHECK(stat(out_path, &st) == 0 && (st.st_mode & 0777) == 0604);
            break;
        }
    }
    image_free(img);
    remove(out_path);
}

int main(void) {
    const char *base = getenv("TMPDIR");
    snprintf(dir, sizeof(dir), "%s/scattersteg-fault-XXXXXX", base ? base : "/tmp");
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }
    snprintf(out_path, sizeof(out_path), "%s/out.png", dir);

    RUN(test_load_sweep);
    RUN(test_save_sweep);
    RUN(test_save_fclose_failure_no_double_close);
    RUN(test_save_mkstemp_failure_spares_existing_file);
    RUN(test_save_fchown_failure_drops_group_access);

    rmdir(dir);
    return TEST_SUMMARY();
}
