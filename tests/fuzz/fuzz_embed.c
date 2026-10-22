/* libFuzzer target: scatter + embed. Checks that encode followed by decode
   gives the data back for any image size, key and message, and that
   decoding a garbage image (as decode does with a wrong passphrase) stays
   in bounds. */
#include "embed.h"
#include "prng.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    return sodium_init() < 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Layout: w (1) | h (1) | key (32) | pixels... then message = the rest */
    if (size < 34) return 0;
    uint32_t w = data[0] % 64 + 1, h = data[1] % 64 + 1;
    const uint8_t *key = data + 2;
    data += 34;
    size -= 34;

    uint32_t count = w * h;
    Image img = {w, h, malloc(h * sizeof(uint8_t *))};
    for (uint32_t y = 0; y < h; y++) {
        img.rows[y] = malloc((size_t)w * 3);
        for (uint32_t i = 0; i < w * 3; i++)
            img.rows[y][i] = size ? data[(y * w * 3 + i) % size] : 0;
    }

    uint32_t *idx = prng_scatter(key, count);
    if (!idx) abort();

    /* Garbage decode: header bits are whatever the pixels hold */
    uint32_t claimed = embed_peek_len(&img, idx, count);
    uint32_t cap = count * 3 >= 32 ? (count * 3 - 32) / 8 : 0;
    uint32_t want = claimed < cap ? claimed : cap;
    uint8_t *junk = malloc(want ? want : 1);
    embed_decode(&img, idx, count, junk, want);
    free(junk);

    /* Round trip */
    uint32_t len = (uint32_t)size;
    int r = embed_encode(&img, idx, count, data, len);
    if ((uint64_t)32 + (uint64_t)len * 8 <= (uint64_t)count * 3) {
        if (r != 0) abort();
        if (embed_peek_len(&img, idx, count) != len) abort();
        uint8_t *out = malloc(len ? len : 1);
        embed_decode(&img, idx, count, out, len);
        if (memcmp(out, data, len) != 0) abort();
        free(out);
    } else if (r != -1) {
        abort();
    }

    free(idx);
    for (uint32_t y = 0; y < h; y++) free(img.rows[y]);
    free(img.rows);
    return 0;
}
