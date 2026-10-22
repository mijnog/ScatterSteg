#include "stc.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>

/* Constraint height: the trellis has 2^STC_H states. 7 is the usual
   trade-off: within a few percent of the best possible embedding
   efficiency, at 128 cheap steps per carrier. */
#define STC_H      7
#define STATES     (1u << STC_H)
/* Carriers per message bit, at most: past this the gain in efficiency is
   small and the trellis work (proportional to carriers used) isn't */
#define STC_MAX_W  64
/* Message bits per trellis run. The trellis is run in independent chunks so
   the path memory (2^STC_H bits per carrier) stays bounded: a chunk spans at
   most about 2^20 carriers, i.e. 16 MiB of path bits. */
#define STC_CHUNK_CARRIERS ((size_t)1 << 20)

size_t stc_carriers(size_t n_avail, size_t mlen) {
    if (mlen == 0 || n_avail < mlen) return 0;
    return n_avail / mlen >= STC_MAX_W ? mlen * STC_MAX_W : n_avail;
}

/* The public submatrix, as columns of STC_H bits (bit r = row r), enough
   for the widest block. Pseudo-random from that width (splitmix64), with
   the top and bottom rows set in every column, which a good submatrix
   needs: the bottom row lets every block reach either value of its message
   bit, the top row spreads each change over all the rows it covers. */
static void submatrix(size_t width, uint32_t *cols) {
    uint64_t s = 0x5354432d48415431ull ^ (uint64_t)width;  /* "STC-HAT1" */
    for (size_t j = 0; j < width; j++) {
        uint64_t z = (s += 0x9E3779B97F4A7C15ull);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        z ^= z >> 31;
        cols[j] = ((uint32_t)z & (STATES - 1)) | 1u | (1u << (STC_H - 1));
    }
}

/* First carrier of message bit i's block */
static size_t block_start(size_t i, size_t mlen, size_t n) {
    return (size_t)(((unsigned __int128)i * n) / mlen);
}

/* Message bits per trellis run, so a run spans at most about
   STC_CHUNK_CARRIERS carriers */
static size_t chunk_bits(size_t mlen, size_t n) {
    size_t widest = n / mlen + 1;
    size_t b = STC_CHUNK_CARRIERS / widest;
    return b ? b : 1;
}

/* Viterbi over message bits [a, b). The state is the partial syndrome of the
   next STC_H rows; choosing y = 1 for a carrier XORs its column in. After a
   block, its row is complete and must equal its message bit; the window
   then shifts down a row. x, costs and y start at block a's first carrier. */
static int embed_chunk(const uint8_t *x, const float *costs, const uint8_t *m,
                       size_t a, size_t b, size_t mlen, size_t n,
                       const uint32_t *cols, uint8_t *y) {
    size_t base = block_start(a, mlen, n), len = block_start(b, mlen, n) - base;
    double *cost = malloc(STATES * sizeof(double));
    double *next = malloc(STATES * sizeof(double));
    uint8_t *path = malloc((len ? len : 1) * (STATES / 8));  /* chosen y, per carrier and state */
    if (!cost || !next || !path) {
        free(cost); free(next); free(path);
        return -1;
    }
    for (unsigned s = 0; s < STATES; s++) cost[s] = INFINITY;
    cost[0] = 0;

    for (size_t i = a; i < b; i++) {
        size_t from = block_start(i, mlen, n) - base, to = block_start(i + 1, mlen, n) - base;
        for (size_t k = from; k < to; k++) {
            uint32_t col = cols[k - from];
            double flip = costs[k];
            double c0 = x[k] ? flip : 0, c1 = x[k] ? 0 : flip;  /* cost of y = 0 / 1 */
            uint8_t *p = path + k * (STATES / 8);
            memset(p, 0, STATES / 8);
            for (unsigned s = 0; s < STATES; s++) {
                double keep = cost[s] + c0, take = cost[s ^ col] + c1;
                if (take < keep) {
                    next[s] = take;
                    p[s >> 3] |= (uint8_t)(1u << (s & 7));
                } else {
                    next[s] = keep;
                }
            }
            double *t = cost; cost = next; next = t;
        }
        /* Row i is done: keep states whose low bit is m[i], and shift */
        for (unsigned s = 0; s < STATES / 2; s++) next[s] = cost[(s << 1) | m[i]];
        for (unsigned s = STATES / 2; s < STATES; s++) next[s] = INFINITY;
        double *t = cost; cost = next; next = t;
    }

    /* Rows past the run don't exist (H is truncated): any end state will
       do, so take the cheapest, and walk the path back */
    unsigned s = 0;
    for (unsigned t = 1; t < STATES; t++) if (cost[t] < cost[s]) s = t;
    for (size_t i = b; i-- > a;) {
        s = (s << 1) | m[i];
        size_t from = block_start(i, mlen, n) - base, to = block_start(i + 1, mlen, n) - base;
        for (size_t k = to; k-- > from;) {
            y[k] = (path[k * (STATES / 8) + (s >> 3)] >> (s & 7)) & 1;
            if (y[k]) s ^= cols[k - from];
        }
    }
    free(cost); free(next); free(path);
    return 0;
}

int stc_embed(const uint8_t *x, const float *costs, const uint8_t *m,
              size_t mlen, size_t n, uint8_t *y) {
    size_t widest = n / mlen + 1;
    uint32_t *cols = malloc(widest * sizeof(uint32_t));
    if (!cols) return -1;
    submatrix(widest, cols);
    size_t per = chunk_bits(mlen, n);
    for (size_t a = 0; a < mlen; a += per) {
        size_t b = mlen - a < per ? mlen : a + per;
        size_t at = block_start(a, mlen, n);
        if (embed_chunk(x + at, costs + at, m, a, b, mlen, n, cols, y + at) != 0) {
            free(cols);
            return -1;
        }
    }
    free(cols);
    return 0;
}

void stc_extract(const uint8_t *y, size_t mlen, size_t n, uint8_t *m) {
    uint32_t cols[STC_MAX_W + 1];
    size_t widest = n / mlen + 1;
    if (widest > STC_MAX_W + 1) {  /* stc_carriers never gives this */
        memset(m, 0, mlen);
        return;
    }
    submatrix(widest, cols);
    size_t per = chunk_bits(mlen, n);
    uint32_t state = 0;
    for (size_t i = 0; i < mlen; i++) {
        if (i % per == 0) state = 0;  /* each run starts afresh */
        size_t from = block_start(i, mlen, n), to = block_start(i + 1, mlen, n);
        for (size_t k = from; k < to; k++)
            if (y[k]) state ^= cols[k - from];
        m[i] = state & 1;
        state >>= 1;
    }
}
