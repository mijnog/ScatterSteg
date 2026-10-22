/* libFuzzer target: for any carrier count, message length, cover bits and
   costs (including extreme ones), the STC syndrome of what stc_embed
   returns is the message. */
#include "stc.h"
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    size_t n = ((size_t)data[0] | (size_t)data[1] << 8) % 6000 + 1;
    size_t mlen = (size_t)data[2] % 300 + 1;
    data += 3;
    size -= 3;
    size_t used = stc_carriers(n, mlen);
    if (!used) return 0;

    uint8_t *x = malloc(used), *y = malloc(used), *m = malloc(mlen), *back = malloc(mlen);
    float *costs = malloc(used * sizeof(float));
    for (size_t i = 0; i < used; i++) {
        uint8_t b = data[i % size];
        x[i] = b & 1;
        /* costs from tiny to huge, never zero or negative */
        costs[i] = (float)((b >> 1) + 1) * ((b & 0x80) ? 1e6f : 1e-3f);
    }
    for (size_t i = 0; i < mlen; i++) m[i] = (data[(i * 7) % size] >> 3) & 1;

    if (stc_embed(x, costs, m, mlen, used, y) != 0) abort();
    stc_extract(y, mlen, used, back);
    if (memcmp(m, back, mlen) != 0) abort();
    free(x); free(y); free(m); free(back); free(costs);
    return 0;
}
