/* SPDX-License-Identifier: MIT OR Apache-2.0
   Copyright (C) 2026 Maxime de Montbron */
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
    if (size < 3) return 0;
    uint32_t w = data[0] % 200 + 1, h = data[1] % 200 + 1, ch = (data[2] & 1) ? 1 : 3;
    data += 3;
    size -= 3;

    Image img = {.width = w, .height = h, .channels = ch, .rows = malloc(h * sizeof(uint8_t *))};
    for (uint32_t y = 0; y < h; y++) {
        img.rows[y] = malloc((size_t)w * ch);
        for (uint32_t i = 0; i < w * ch; i++)
            img.rows[y][i] = size ? data[(y * w * ch + i) % size] : (uint8_t)i;
    }

    if (png_save(&img, path) != 0) abort();
    Image *back = png_load(path);
    if (!back || back->width != w || back->height != h || back->channels != ch) abort();
    for (uint32_t y = 0; y < h; y++)
        if (memcmp(back->rows[y], img.rows[y], (size_t)w * ch) != 0) abort();

    image_free(back);
    for (uint32_t y = 0; y < h; y++) free(img.rows[y]);
    free(img.rows);
    return 0;
}
