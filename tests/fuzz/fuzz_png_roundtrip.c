/* libFuzzer target: png_save then png_load must give back the same pixels,
   for any dimensions and contents. */
#include "png_io.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char path[64];

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    snprintf(path, sizeof(path), "/dev/shm/fuzz-png-rt-%d.png", (int)getpid());
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    uint32_t w = data[0] % 200 + 1, h = data[1] % 200 + 1;
    data += 2;
    size -= 2;

    Image img = {w, h, malloc(h * sizeof(uint8_t *))};
    for (uint32_t y = 0; y < h; y++) {
        img.rows[y] = malloc((size_t)w * 3);
        for (uint32_t i = 0; i < w * 3; i++)
            img.rows[y][i] = size ? data[(y * w * 3 + i) % size] : (uint8_t)i;
    }

    if (png_save(&img, path) != 0) abort();
    Image *back = png_load(path);
    if (!back || back->width != w || back->height != h) abort();
    for (uint32_t y = 0; y < h; y++)
        if (memcmp(back->rows[y], img.rows[y], (size_t)w * 3) != 0) abort();

    image_free(back);
    for (uint32_t y = 0; y < h; y++) free(img.rows[y]);
    free(img.rows);
    return 0;
}
