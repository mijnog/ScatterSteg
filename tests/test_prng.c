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

/* ---- format v2 ---------------------------------------------------------- */

static void test_v2_is_permutation(void) {
    uint8_t key[32] = {5};
    uint32_t sizes[] = {1, 2, 3, 43, 100, 4096, 100003};
    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        uint32_t *idx = prng_permutation(key, sizes[s]);
        CHECK(idx && is_permutation(idx, sizes[s]));
        free(idx);
    }
    CHECK(prng_permutation(key, 0) == NULL);
}

static void test_v2_known_answer(void) {
    /* Pins the v2 format: any change here makes existing images unreadable.
       Also matches the independent Python implementation in test_cli.py. */
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    const uint32_t want[16] = {9, 6, 0, 5, 1, 4, 14, 2, 11, 12, 8, 10, 13, 15, 3, 7};
    uint32_t *p = prng_permutation(key, 16);
    CHECK(p && memcmp(p, want, sizeof(want)) == 0);
    free(p);
    p = prng_permutation(key, 1000003);  /* crosses many keystream chunks */
    CHECK(p && p[0] == 28573 && p[500000] == 738660 && p[1000002] == 51748);
    free(p);
}

static void test_v2_deterministic_and_keyed(void) {
    uint8_t k1[32] = {1}, k2[32] = {1};
    k2[31] = 1;
    uint32_t *a = prng_permutation(k1, 5000), *b = prng_permutation(k1, 5000);
    uint32_t *c = prng_permutation(k2, 5000);
    CHECK(a && b && c);
    CHECK(memcmp(a, b, 5000 * sizeof(uint32_t)) == 0);
    CHECK(memcmp(a, c, 5000 * sizeof(uint32_t)) != 0);
    free(a); free(b); free(c);
}

static void test_v2_sample_is_prefix(void) {
    uint8_t key[32] = {77};
    struct { uint32_t count, k; } cases[] = {{1, 1}, {2, 2}, {43, 43}, {100, 43}, {4096, 43}, {100003, 200}};
    for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        uint32_t *full = prng_permutation(key, cases[c].count);
        uint32_t *part = malloc(cases[c].k * sizeof(uint32_t));
        CHECK(prng_sample(key, cases[c].count, cases[c].k, part) == 0);
        CHECK(full && memcmp(full, part, cases[c].k * sizeof(uint32_t)) == 0);
        free(full);
        free(part);
    }
    uint32_t out[4];
    CHECK(prng_sample(key, 3, 4, out) == -1);
}

static void test_v2_unbiased(void) {
    /* All 6 orderings of 3 items, over 12000 keys: each expected 2000, and a
       fair shuffle stays within +-10% (over 4 standard deviations) */
    uint32_t seen[6] = {0};
    uint8_t key[32] = {0};
    for (uint32_t t = 0; t < 12000; t++) {
        memcpy(key, &t, sizeof(t));
        uint32_t *p = prng_permutation(key, 3);
        seen[p[0] * 2 + (p[1] > p[2])]++;
        free(p);
    }
    for (int i = 0; i < 6; i++) CHECK(seen[i] > 1800 && seen[i] < 2200);
}

int main(void) {
    if (sodium_init() < 0) return 1;
    RUN(test_v2_is_permutation);
    RUN(test_v2_known_answer);
    RUN(test_v2_deterministic_and_keyed);
    RUN(test_v2_sample_is_prefix);
    RUN(test_v2_unbiased);
    RUN(test_is_permutation);
    RUN(test_deterministic);
    RUN(test_key_changes_order);
    RUN(test_not_sequential);
    RUN(test_zero_count);
    RUN(test_count_too_large);
    return TEST_SUMMARY();
}
