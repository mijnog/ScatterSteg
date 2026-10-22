#include "test.h"
#include "prng.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>

static int is_permutation(const uint32_t *idx, uint32_t count) {
    uint8_t *seen = calloc(count, 1);
    int ok = 1;
    for (uint32_t i = 0; i < count; i++) {
        if (idx[i] >= count || seen[idx[i]]) { ok = 0; break; }
        seen[idx[i]] = 1;
    }
    free(seen);
    return ok;
}

static void test_is_permutation(void) {
    uint8_t key[crypto_stream_chacha20_KEYBYTES] = {1, 2, 3};
    uint32_t sizes[] = {1, 2, 3, 100, 4096, 100003};
    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        uint32_t *idx = prng_scatter(key, sizes[s]);
        CHECK(idx != NULL);
        if (idx) CHECK(is_permutation(idx, sizes[s]));
        free(idx);
    }
}

static void test_deterministic(void) {
    uint8_t key[crypto_stream_chacha20_KEYBYTES] = {42};
    uint32_t *a = prng_scatter(key, 5000);
    uint32_t *b = prng_scatter(key, 5000);
    CHECK(a && b && memcmp(a, b, 5000 * sizeof(uint32_t)) == 0);
    free(a);
    free(b);
}

static void test_key_changes_order(void) {
    uint8_t k1[crypto_stream_chacha20_KEYBYTES] = {0};
    uint8_t k2[crypto_stream_chacha20_KEYBYTES] = {0};
    k2[31] = 1;  /* differ only in the last key byte */
    uint32_t *a = prng_scatter(k1, 5000);
    uint32_t *b = prng_scatter(k2, 5000);
    CHECK(a && b && memcmp(a, b, 5000 * sizeof(uint32_t)) != 0);
    free(a);
    free(b);
}

static void test_not_sequential(void) {
    /* The point of scattering: the first slots should not be pixels 0, 1, 2... */
    uint8_t key[crypto_stream_chacha20_KEYBYTES] = {7};
    uint32_t count = 10000;
    uint32_t *idx = prng_scatter(key, count);
    uint32_t fixed = 0;
    for (uint32_t i = 0; i < count; i++)
        if (idx[i] == i) fixed++;
    /* A random permutation has ~1 fixed point on average */
    CHECK(fixed < 20);
    /* The first 100 slots should be spread across the image, not clustered */
    uint32_t in_first_tenth = 0;
    for (uint32_t i = 0; i < 100; i++)
        if (idx[i] < count / 10) in_first_tenth++;
    CHECK(in_first_tenth < 30);
    free(idx);
}

static void test_zero_count(void) {
    uint8_t key[crypto_stream_chacha20_KEYBYTES] = {0};
    CHECK(prng_scatter(key, 0) == NULL);
}

static void test_count_too_large(void) {
    uint8_t key[crypto_stream_chacha20_KEYBYTES] = {0};
    CHECK(prng_scatter(key, UINT32_MAX / sizeof(uint32_t) + 1) == NULL);
}

int main(void) {
    if (sodium_init() < 0) return 1;
    RUN(test_is_permutation);
    RUN(test_deterministic);
    RUN(test_key_changes_order);
    RUN(test_not_sequential);
    RUN(test_zero_count);
    RUN(test_count_too_large);
    return TEST_SUMMARY();
}
