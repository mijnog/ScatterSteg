/* SPDX-License-Identifier: MIT OR Apache-2.0
   Copyright (C) 2026 Maxime de Montbron */
#ifndef PARALLEL_H
#define PARALLEL_H

/* Loops whose iterations are independent, run on several threads. Each
   iteration computes what it would alone, so the result is the same,
   bit for bit, on any number of threads. rust/src/parallel.rs is the
   same. Header-only, so each source sees its own build's macros. */

#include <pthread.h>
#include <stddef.h>
#include <unistd.h>

/* Threads to use at most: the trellis holds up to 16 MiB of path per
   running chunk (stc.c), and past 8 the loops gain little */
#define PARALLEL_MAX 8

/* Threads for `jobs` independent jobs: one per online CPU, at most
   PARALLEL_MAX and one per job. One in fault-injection builds, which count
   calls and must see them in a fixed order, and in the codec fuzzer's
   (whose inputs are small: threads would only cost time). */
static inline size_t parallel_threads(size_t jobs) {
#if defined(FAULT_H) || defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    (void)jobs;
    return 1;
#else
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    size_t t = cpus > 0 ? (size_t)cpus : 1;
    if (t > PARALLEL_MAX) t = PARALLEL_MAX;
    if (t > jobs) t = jobs;
    return t ? t : 1;
#endif
}

typedef void (*ParallelFn)(void *ctx, size_t from, size_t to);

typedef struct {
    ParallelFn fn;
    void *ctx;
    size_t from, to;
} ParallelRange;

static inline void *parallel_run_range(void *arg) {
    ParallelRange *r = (ParallelRange *)arg;
    r->fn(r->ctx, r->from, r->to);
    return NULL;
}

/* fn(ctx, from, to) over 0 .. n-1, in ranges of at least `least` (so a
   small loop stays on one thread). A thread that can't start has its
   range run by the caller. fn mustn't fail. */
static inline void parallel_for(size_t n, size_t least, ParallelFn fn, void *ctx) {
    if (n == 0) return;
    size_t t = parallel_threads(least ? (n + least - 1) / least : n);
    ParallelRange ranges[PARALLEL_MAX];
    pthread_t workers[PARALLEL_MAX];
    int started[PARALLEL_MAX] = {0};
    for (size_t i = 0; i < t; i++)
        ranges[i] = (ParallelRange){fn, ctx, n / t * i + (i < n % t ? i : n % t),
                                    n / t * (i + 1) + (i + 1 < n % t ? i + 1 : n % t)};
    for (size_t i = 1; i < t; i++)
        started[i] = pthread_create(&workers[i], NULL, parallel_run_range, &ranges[i]) == 0;
    parallel_run_range(&ranges[0]);
    for (size_t i = 1; i < t; i++) {
        if (started[i]) pthread_join(workers[i], NULL);
        else parallel_run_range(&ranges[i]);
    }
}

#endif
