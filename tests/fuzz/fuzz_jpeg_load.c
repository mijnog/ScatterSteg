/* SPDX-License-Identifier: MIT OR Apache-2.0
   Copyright (C) 2026 Maxime de Montbron */
/* libFuzzer target: jpeg_load on arbitrary bytes. Every JPEG that loads
   must have valid carriers, and if jpeg_check_writable accepts it (as
   encode requires), save and reload with the same carriers. */
#include "jpeg_io.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char path[64], out_path[64];

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    snprintf(path, sizeof(path), "/dev/shm/fuzz-jpeg-load-%d.jpg", (int)getpid());
    snprintf(out_path, sizeof(out_path), "/dev/shm/fuzz-jpeg-save-%d.jpg", (int)getpid());
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FILE *fp = fopen(path, "wb");
    fwrite(data, 1, size, fp);
    fclose(fp);

    JpegImage *j = jpeg_load(path);
    if (!j) return 0;
    Carrier c = jpeg_carrier(j);
    if (c.n_coefs % 63 != 0) abort();  /* every AC coefficient */

    if (jpeg_check_writable(j) != 0) {
        jpeg_free(j);
        return 0;
    }
    if (jpeg_save(j, out_path) != 0) abort();
    JpegImage *back = jpeg_load(out_path);
    if (!back) abort();
    Carrier b = jpeg_carrier(back);
    if (b.n_coefs != c.n_coefs) abort();
    for (uint32_t i = 0; i < c.n_coefs; i++)
        if (*carrier_coef(&b, i) != *carrier_coef(&c, i)) abort();
    jpeg_free(back);
    jpeg_free(j);
    return 0;
}
