/* libFuzzer target: png_load on arbitrary bytes. Chunk CRCs are recomputed
   first, so mutations reach the decoder instead of failing the CRC check. */
#include "png_io.h"
#include <png.h>
#include <zlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char path[64];

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    snprintf(path, sizeof(path), "/dev/shm/fuzz-png-load-%d.png", (int)getpid());
    return 0;
}

static void fix_crcs(uint8_t *d, size_t n) {
    size_t pos = 8;
    while (pos + 12 <= n) {
        uint32_t len = (uint32_t)d[pos] << 24 | d[pos + 1] << 16 | d[pos + 2] << 8 | d[pos + 3];
        if (len > n - pos - 12) break;
        uLong crc = crc32(0, d + pos + 4, len + 4);
        uint8_t *c = d + pos + 8 + len;
        c[0] = crc >> 24; c[1] = crc >> 16; c[2] = crc >> 8; c[3] = crc;
        pos += 12 + len;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint8_t *buf = malloc(size ? size : 1);
    memcpy(buf, data, size);
    fix_crcs(buf, size);

    FILE *fp = fopen(path, "wb");
    fwrite(buf, 1, size, fp);
    fclose(fp);
    free(buf);

    Image *img = png_load(path);
    if (img) {
        /* Whatever loads must be a consistent, fully readable RGB image */
        if (img->width == 0 || img->height == 0) abort();
        if ((size_t)img->width * img->height * 3 > ((size_t)1 << 30)) abort();
        volatile uint8_t sink = 0;
        for (uint32_t y = 0; y < img->height; y++)
            sink ^= img->rows[y][0] ^ img->rows[y][(size_t)img->width * 3 - 1];
        (void)sink;
        image_free(img);
    }
    return 0;
}
