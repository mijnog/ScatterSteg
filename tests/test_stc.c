/* SPDX-License-Identifier: MIT OR Apache-2.0
   Copyright (C) 2026 Maxime de Montbron */
#include "test.h"
#include "stc.h"
#include "parallel.h"
#include <math.h>
#include <stdint.h>
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
       fractional, and the 1024 cap; tiny messages too */
    struct { size_t n, mlen; } cases[] = {
        {1, 1}, {7, 7}, {100, 1}, {100, 3}, {1000, 999}, {1000, 600},
        {1000, 500}, {1000, 499}, {1000, 333}, {10000, 37}, {100000, 1000},
        {100000, 99999}, {5000, 50}, {200000, 100},
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

static void test_many_chunks(void) {
    /* More runs than PARALLEL_MAX threads: width 2, so 2^20 / 2 = 524288
       bits per run and 9 runs; every worker is started and the 9th run waits
       for a free one */
    int ok;
    roundtrip(4500000, 4300000, NULL, &ok);
    CHECK(ok);
}

static void test_carriers(void) {
    CHECK(stc_carriers(100, 0) == 0);
    CHECK(stc_carriers(99, 100) == 0);
    CHECK(stc_carriers(100, 100) == 100);
    CHECK(stc_carriers(150, 100) == 150);
    CHECK(stc_carriers(1000000, 10) == 10240);  /* capped at 1024 per bit */
    CHECK(stc_carriers(10239, 10) == 10239);
    CHECK(stc_carriers(10245, 10) == 10240);    /* exactly 1024 per bit, and some over */
#if SIZE_MAX > UINT32_MAX
    CHECK(stc_carriers(UINT32_MAX, UINT32_MAX) == UINT32_MAX);  /* the largest mlen */
    CHECK(stc_carriers((size_t)UINT32_MAX + 1, (size_t)UINT32_MAX + 1) == 0);
#endif
}

static void test_edge_embeds(void) {
    /* One carrier, message 0, cover 0: nothing to change */
    uint8_t x0 = 0, m0 = 0, m1 = 1, y = 9;
    float one = 1, inf = INFINITY;
    CHECK(stc_embed(&x0, &one, &m0, 1, 1, &y) == 0 && y == 0);
    /* One carrier, message 1: it must change */
    y = 9;
    CHECK(stc_embed(&x0, &one, &m1, 1, 1, &y) == 0 && y == 1);
    /* All-zero cover and message: syndrome already right, no change */
    size_t n = 5000, mlen = 500;
    uint8_t *x = calloc(n, 1), *m = calloc(mlen, 1), *yy = malloc(n);
    float *costs = malloc(n * sizeof(float));
    for (size_t i = 0; i < n; i++) costs[i] = 1;
    CHECK(stc_embed(x, costs, m, mlen, n, yy) == 0 && changes(x, yy, n) == 0);
    free(x); free(m); free(yy); free(costs);
    /* No finite way to the message: reported, not a made-up y */
    CHECK(stc_embed(&x0, &inf, &m1, 1, 1, &y) == -1);
}

/* FNV-1a, as rust/tests/vectors.rs */
static uint64_t fnv(const uint8_t *b, size_t n) {
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < n; i++) h = (h ^ b[i]) * 1099511628211ull;
    return h;
}

static void test_embed_known_answer(void) {
    /* Pins the embedder's output, tie-breaking included, and the split into
       runs (the last case has three): rust/tests/vectors.rs's stc_matches_c,
       same inputs and hashes, so both builds write the same bits */
    struct { size_t navail, mlen, n; uint64_t hash; } cases[] = {
        {1000, 100, 1000, 11783339882688702857ull},
        {50000, 300, 50000, 11670365125730500980ull},
        {20000, 20000, 20000, 12041373877459508547ull},
        {3000000, 5000, 3000000, 10689391206250108763ull},
    };
    for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        size_t n = stc_carriers(cases[c].navail, cases[c].mlen), mlen = cases[c].mlen;
        CHECK(n == cases[c].n);
        uint64_t r = 12345 + c;
#define STEP() (r = r * 6364136223846793005ull + 1442695040888963407ull)
        uint8_t *x = malloc(n), *y = malloc(n), *m = malloc(mlen), *back = malloc(mlen);
        float *co = malloc(n * sizeof(float));
        for (size_t i = 0; i < n; i++) {
            uint64_t v = STEP();
            x[i] = (v >> 33) & 1;
            co[i] = 1.0f + (float)((v >> 40) & 7) * 0.5f;
        }
        for (size_t i = 0; i < mlen; i++) m[i] = (STEP() >> 35) & 1;
#undef STEP
        CHECK(stc_embed(x, co, m, mlen, n, y) == 0);
        uint64_t h = fnv(y, n);
        CHECK(h == cases[c].hash);
        if (h != cases[c].hash) fprintf(stderr, "    (case %zu: got %llu)\n", c, (unsigned long long)h);
        stc_extract(y, mlen, n, back);
        CHECK(memcmp(m, back, mlen) == 0);
        free(x); free(y); free(m); free(back); free(co);
    }
}

static void test_known_answer_runs(void) {
    /* As test_known_answer, over three runs (2^20 / 31 = 33825 bits each),
       so the restart at each run is pinned too. Values from test_cli.py's
       stc_extract. */
    size_t n = 3000000, mlen = 100000;
    uint8_t *y = malloc(n), *m = malloc(mlen);
    uint32_t s = 7;
    for (size_t i = 0; i < n; i++) { s = s * 1103515245u + 12345u; y[i] = (s >> 16) & 1; }
    stc_extract(y, mlen, n, m);
    uint32_t packed = 0, run2 = 0, ones = 0;
    for (size_t i = 0; i < mlen; i++) ones += m[i];
    for (size_t i = 0; i < 32; i++) { packed |= (uint32_t)m[i] << i; run2 |= (uint32_t)m[33825 + i] << i; }
    CHECK(packed == 0xb27e28d5);
    CHECK(run2 == 0x80cd8639);
    CHECK(ones == 49962);
    CHECK(fnv(m, mlen) == 6591896953287329387ull);
    if (packed != 0xb27e28d5 || run2 != 0x80cd8639 || ones != 49962)
        fprintf(stderr, "    (got packed 0x%08x, run2 0x%08x, ones %u)\n", packed, run2, ones);
    free(y); free(m);
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

/* parallel_for runs every index once, in ranges that join up, whatever n
   and the range size (as rust/src/parallel.rs's test) */
static void mark(void *ctx, size_t from, size_t to) {
    unsigned char *seen = ctx;
    for (size_t i = from; i < to; i++) seen[i]++;
}

static void test_parallel_for(void) {
    static const size_t sizes[] = {0, 1, 7, 8, 9, 1000, 65537};
    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++)
        for (size_t least = 1; least <= 4096; least *= 64) {
            size_t n = sizes[s];
            unsigned char *seen = calloc(n + 1, 1);
            CHECK(seen != NULL);
            if (!seen) return;
            parallel_for(n, least, mark, seen);
            int once = 1;
            for (size_t i = 0; i < n; i++) once &= seen[i] == 1;
            CHECK(once && seen[n] == 0);
            free(seen);
        }
}

int main(void) {
    RUN(test_roundtrips);
    RUN(test_chunk_boundaries);
    RUN(test_fewer_changes);
    RUN(test_costs_steer_changes);
    RUN(test_already_there);
    RUN(test_many_chunks);
    RUN(test_carriers);
    RUN(test_edge_embeds);
    RUN(test_embed_known_answer);
    RUN(test_known_answer);
    RUN(test_known_answer_runs);
    RUN(test_parallel_for);
    return TEST_SUMMARY();
}
