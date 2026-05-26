#include "prng.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

uint32_t *prng_scatter(const uint8_t *key, uint32_t count) {
    if (count == 0) return NULL;
    if (count > UINT32_MAX / sizeof(uint32_t)) return NULL;

    /* Generate a stream of random bytes using ChaCha20 */
    uint8_t nonce[crypto_stream_chacha20_NONCEBYTES] = {0};
    uint32_t stream_len = count * sizeof(uint32_t);
    uint8_t *stream = malloc(stream_len);
    if (!stream) return NULL;
    crypto_stream_chacha20(stream, stream_len, nonce, key);

    /* Fill indices array: [0, 1, 2, ..., count-1] */
    uint32_t *indices = malloc(count * sizeof(uint32_t));
    if (!indices) {
        free(stream);
        return NULL;
    }
    for (uint32_t i = 0; i < count; i++)
        indices[i] = i;

    /* Fisher-Yates shuffle using stream bytes as randomness */
    for (uint32_t i = count - 1; i > 0; i--) {
        uint32_t r;
        memcpy(&r, stream + i * sizeof(uint32_t), sizeof(uint32_t));
        uint32_t j = r % (i + 1);

        uint32_t tmp = indices[i];
        indices[i]   = indices[j];
        indices[j]   = tmp;
    }

    free(stream);
    return indices;
}
