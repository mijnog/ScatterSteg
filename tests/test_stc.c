/* SPDX-License-Identifier: AGPL-3.0-or-later
   Copyright (C) 2026 Maxime de Montbron */
#include "test.h"
#include "stc.h"
#include <stdlib.h>
#include <string.h>

static uint32_t rng = 12345;
static uint32_t next_rand(void) {
    rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;
    return rng;
}

static void random_bits(uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) b[i] = next_rand() & 1;
}

static size_t changes(const uint8_t *x, const uint8_t *y, size_t n) {
    size_t c = 0;
    for (size_t i = 0; i < n; i++) c += x[i] != y[i];
    return c;
}

/* Embed m into random cover bits, check the syndrome comes back as m;
   returns how many bits changed */
static size_t roundtrip(size_t n_avail, size_t mlen, const float *costs_or_null, int *ok) {
    size_t n = stc_carriers(n_avail, mlen);
    uint8_t *x = malloc(n), *y = malloc(n), *m = malloc(mlen), *back = malloc(mlen);
    float *costs = malloc(n * sizeof(float));
    random_bits(x, n);
    random_bits(m, mlen);
    for (size_t i = 0; i < n; i++) costs[i] = costs_or_null ? costs_or_null[i] : 1;
    *ok = stc_embed(x, costs, m, mlen, n, y) == 0;
    stc_extract(y, mlen, n, back);
    *ok = *ok && memcmp(m, back, mlen) == 0;
    size_t c = changes(x, y, n);
    free(x); free(y); free(m); free(back); free(costs);
    return c;
}

static void test_roundtrips(void) {
    /* Every width regime: 1 (full), between 1 and 2, exact multiples,
       fractional, and the 64 cap; tiny messages too */
    struct { size_t n, mlen; } cases[] = {
        {1, 1}, {7, 7}, {100, 1}, {100, 3}, {1000, 999}, {1000, 600},
        {1000, 500}, {1000, 499}, {1000, 333}, {10000, 37}, {100000, 1000},
        {100000, 99999}, {5000, 50},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int ok;
        roundtrip(cases[i].n, cases[i].mlen, NULL, &ok);
        CHECK(ok);
        if (!ok) fprintf(stderr, "    (n %zu, mlen %zu)\n", cases[i].n, cases[i].mlen);
    }
}

static void test_chunk_boundaries(void) {
    /* Over 2^20 carriers: the trellis runs in several independent chunks,
       which the extractor must split the same way */
    int ok;
    roundtrip(3000000, 100000, NULL, &ok);  /* width 30: 3 runs */
    CHECK(ok);
    roundtrip(2200000, 2100000, NULL, &ok); /* width 1-2: 2+ runs */
    CHECK(ok);
}

static void test_fewer_changes(void) {
    /* Writing bits directly changes half of them; STC far fewer. Close to
       (within ~50% of) the theoretical bound at each rate. */
    int ok;
    size_t c = roundtrip(1000000, 100000, NULL, &ok);   /* rate 0.1 */
    CHECK(ok && c < 100000 * 0.20);
    c = roundtrip(1000000, 500000, NULL, &ok);          /* rate 0.5 */
    CHECK(ok && c < 500000 * 0.30);
    c = roundtrip(1000000, 900000, NULL, &ok);          /* rate 0.9: still a gain */
    CHECK(ok && c < 900000 * 0.42);
}

static void test_costs_steer_changes(void) {
    /* Even carriers cost 1000x: changes should all but avoid them */
    size_t n = 200000, mlen = 20000;
    float *costs = malloc(n * sizeof(float));
    for (size_t i = 0; i < n; i++) costs[i] = i % 2 ? 1 : 1000;
    uint8_t *x = malloc(n), *y = malloc(n), *m = malloc(mlen), *back = malloc(mlen);
    random_bits(x, n);
    random_bits(m, mlen);
    CHECK(stc_embed(x, costs, m, mlen, n, y) == 0);
    stc_extract(y, mlen, n, back);
    CHECK(memcmp(m, back, mlen) == 0);
    size_t even = 0, odd = 0;
    for (size_t i = 0; i < n; i++)
        if (x[i] != y[i]) { if (i % 2) odd++; else even++; }
    CHECK(odd > 0 && even * 100 < odd);
    free(costs); free(x); free(y); free(m); free(back);
}

static void test_already_there(void) {
    /* Cover bits that already have the right syndrome need no changes */
    size_t n = 50000, mlen = 5000;
    uint8_t *x = malloc(n), *y = malloc(n), *z = malloc(n), *m = malloc(mlen);
    float *costs = malloc(n * sizeof(float));
    for (size_t i = 0; i < n; i++) costs[i] = 1;
    random_bits(x, n);
    random_bits(m, mlen);
    CHECK(stc_embed(x, costs, m, mlen, n, y) == 0);
    CHECK(stc_embed(y, costs, m, mlen, n, z) == 0);
    CHECK(changes(y, z, n) == 0);
    free(x); free(y); free(z); free(m); free(costs);
}

static void test_carriers(void) {
    CHECK(stc_carriers(100, 0) == 0);
    CHECK(stc_carriers(99, 100) == 0);
    CHECK(stc_carriers(100, 100) == 100);
    CHECK(stc_carriers(150, 100) == 150);
    CHECK(stc_carriers(1000000, 10) == 640);  /* capped at 64 per bit */
}

static void test_known_answer(void) {
    /* Pins the format's code (submatrix, block layout, chunking): any
       change here makes existing images unreadable. The Python
       implementation in test_cli.py computes the same. */
    size_t n = 1000, mlen = 77;
    uint8_t y[1000], m[77];
    uint32_t s = 7;
    for (size_t i = 0; i < n; i++) { s = s * 1103515245u + 12345u; y[i] = (s >> 16) & 1; }
    stc_extract(y, mlen, n, m);
    uint32_t packed = 0, ones = 0;
    for (size_t i = 0; i < mlen; i++) { ones += m[i]; if (i < 32) packed |= (uint32_t)m[i] << i; }
    CHECK(packed == 0x39fb2d1e);
    CHECK(ones == 41);
    if (packed != 0x39fb2d1e || ones != 41)
        fprintf(stderr, "    (got packed 0x%08x, ones %u)\n", packed, ones);
}

int main(void) {
    RUN(test_roundtrips);
    RUN(test_chunk_boundaries);
    RUN(test_fewer_changes);
    RUN(test_costs_steer_changes);
    RUN(test_already_there);
    RUN(test_carriers);
    RUN(test_known_answer);
    return TEST_SUMMARY();
}
