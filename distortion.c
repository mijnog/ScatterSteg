/* SPDX-License-Identifier: MIT OR Apache-2.0
   Copyright (C) 2026 Maxime de Montbron */
#include "distortion.h"
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* The Daubechies 8 decomposition filters, low and high pass, to the digits
   the references give them (wavelets.h) */
#define TAPS 16
static const double LO[TAPS] = {
    -0.00011747678400228192, 0.00067544940599855677, -0.00039174037299597711,
    -0.0048703529930106603, 0.0087460940470156547, 0.013981027917015516,
    -0.044088253931064719, -0.017369301002022108, 0.12874742662018601,
    0.00047248457399797254, -0.28401554296242809, -0.015829105256023893,
    0.58535468365486909, 0.67563073629801285, 0.31287159091446592,
    0.054415842243081609};
static const double HI[TAPS] = {
    -0.054415842243081609, 0.31287159091446592, -0.67563073629801285,
    0.58535468365486909, 0.015829105256023893, -0.28401554296242809,
    -0.00047248457399797254, 0.12874742662018601, 0.017369301002022108,
    -0.044088253931064719, -0.013981027917015516, 0.0087460940470156547,
    0.0048703529930106603, -0.00039174037299597711, -0.00067544940599855677,
    -0.00011747678400228192};

/* The three directional sub-bands: vertical filter, horizontal filter */
static const double *const BANDS[3][2] = {{LO, HI}, {HI, LO}, {HI, HI}};  /* LH, HL, HH */

/* Planes are mirrored out by this much on every side, as the references
   pad them, so the filters near an edge see the image, not zeros */
#define PAD 16

/* 2^-6, the J-UNIWARD paper's and MATLAB reference's (the C++ one has
   0.0156); S-UNIWARD uses 1 */
/* As the references write it */
#define PI 3.14159265358979323846

#define SIGMA_JPEG    0.015625
#define SIGMA_SPATIAL 1.0

/* Index j mirrored into 0..n-1 (MATLAB's 'symmetric': the edge sample is
   repeated). Repeatedly, for planes narrower than PAD, which the
   references don't handle. */
static long mirror(long j, long n) {
    while (j < 0 || j >= n) j = j < 0 ? -j - 1 : 2 * n - j - 1;
    return j;
}

/* out[i] = sum over t of in[i + t - 8] * k[t], zero outside 0..n-1, along a
   line of n samples `step` apart: the references' "same"-size correlation
   with a 16-tap filter */
static void corr_line(const float *in, float *out, size_t n, size_t step, const double *k) {
    for (size_t i = 0; i < n; i++) {
        double s = 0;
        for (int t = 0; t < TAPS; t++) {
            long j = (long)i + t - 8;
            if (j >= 0 && j < (long)n) s += in[(size_t)j * step] * k[t];
        }
        out[i * step] = (float)s;
    }
}

/* The same in double precision, for J-UNIWARD, whose reference works in
   double: its costs divide by |residual| + 2^-6, so a residual near 0 is
   sensitive to rounding */
static void corr_line_d(const double *in, double *out, size_t n, size_t step, const double *k) {
    for (size_t i = 0; i < n; i++) {
        double s = 0;
        for (int t = 0; t < TAPS; t++) {
            long j = (long)i + t - 8;
            if (j >= 0 && j < (long)n) s += in[(size_t)j * step] * k[t];
        }
        out[i * step] = s;
    }
}

/* Separable correlation of a w x h plane: down the columns with kv, then
   along the rows with kh. out may be in; tmp must be neither. */
static void corr2(const float *in, float *tmp, float *out, size_t w, size_t h,
                  const double *kv, const double *kh) {
    for (size_t x = 0; x < w; x++) corr_line(in + x, tmp + x, h, w, kv);
    for (size_t y = 0; y < h; y++) corr_line(tmp + y * w, out + y * w, w, 1, kh);
}

/* Room for a padded plane of -byte samples, or NULL if its size
   would overflow */
static void *padded_plane(uint32_t w, uint32_t h, size_t size, size_t *pw, size_t *ph) {
    *pw = (size_t)w + 2 * PAD;
    *ph = (size_t)h + 2 * PAD;
    if (*pw > SIZE_MAX / size / *ph) return NULL;
    return malloc(*pw * *ph * size);
}

/* WOW and S-UNIWARD share everything but what they do with each sub-band's
   residual R. The references convolve the image with each filter (R),
   then correlate a function of R with the filter's absolute value: the sum
   of how much a change at a pixel moves each residual it reaches. WOW
   correlates |R| itself and adds up the reciprocals (Hoelder norm with
   p = -1); S-UNIWARD correlates 1 / (|R| + sigma) and adds those up. Either
   way a change is cheap where every direction is busy. */
static float *wavelet_costs(const Image *img, int uniward) {
    uint32_t w = img->width, h = img->height, ch = img->channels;
    size_t pw, ph;
    size_t plane = (size_t)w * h;
    float *pad = padded_plane(w, h, sizeof(float), &pw, &ph);
    float *tmp = pad ? malloc(pw * ph * sizeof(float)) : NULL;
    float *r = tmp ? malloc(pw * ph * sizeof(float)) : NULL;
    float *costs = plane <= SIZE_MAX / sizeof(float) / ch ? malloc(plane * ch * sizeof(float)) : NULL;
    if (!pad || !tmp || !r || !costs) {
        free(pad); free(tmp); free(r); free(costs);
        return NULL;
    }
    for (uint32_t c = 0; c < ch; c++) {
        for (size_t y = 0; y < ph; y++) {
            const uint8_t *row = img->rows[mirror((long)y - PAD, h)];
            for (size_t x = 0; x < pw; x++)
                pad[y * pw + x] = row[(size_t)mirror((long)x - PAD, w) * ch + c];
        }
        for (size_t i = 0; i < plane; i++) costs[i * ch + c] = 0;
        for (int b = 0; b < 3; b++) {
            double rv[TAPS], rh[TAPS], av[TAPS], ah[TAPS];
            for (int t = 0; t < TAPS; t++) {
                rv[t] = BANDS[b][0][TAPS - 1 - t];  /* convolution: the filter reversed */
                rh[t] = BANDS[b][1][TAPS - 1 - t];
                av[t] = fabs(BANDS[b][0][t]);
                ah[t] = fabs(BANDS[b][1][t]);
            }
            corr2(pad, tmp, r, pw, ph, rv, rh);
            for (size_t i = 0; i < pw * ph; i++)
                r[i] = uniward ? (float)(1.0 / (fabs(r[i]) + SIGMA_SPATIAL)) : fabsf(r[i]);
            corr2(r, tmp, r, pw, ph, av, ah);
            /* The references' crop: an even-length filter's centre is half a
               sample off, which their crop (and MATLAB's circshift) moves
               back by one */
            for (size_t y = 0; y < h; y++)
                for (size_t x = 0; x < w; x++) {
                    float xi = r[(y + PAD + 1) * pw + x + PAD + 1];
                    costs[(y * w + x) * ch + c] += uniward ? xi : 1.0f / xi;
                }
        }
    }
    for (size_t i = 0; i < plane * ch; i++)
        if (!(costs[i] <= DISTORTION_WET_SPATIAL)) costs[i] = DISTORTION_WET_SPATIAL;  /* and NaN */
    free(pad);
    free(tmp);
    free(r);
    return costs;
}

float *distortion_wow(const Image *img) {
    return wavelet_costs(img, 0);
}

float *distortion_suniward(const Image *img) {
    return wavelet_costs(img, 1);
}

/* J-UNIWARD's sum runs over the 23 x 23 window of sub-band coefficients a
   block's change reaches: 8 pixels widened by the 16-tap filter */
#define REACH (8 + TAPS - 1)

struct JUniward {
    size_t pw;
    float *rinv[3];                      /* 1 / (|sub-band| + sigma), padded */
    double impact[3][64][REACH * REACH]; /* |sub-band change| per DCT mode */
};

/* The 8-point DCT basis, as the references write it: alpha(u) cos(pi/8 (x + 1/2) u) */
static void dct_basis(double basis[8][8]) {
    for (int x = 0; x < 8; x++)
        for (int u = 0; u < 8; u++)
            basis[x][u] = (u ? sqrt(2.0 / 8) : sqrt(1.0 / 8)) * cos(PI / 8 * (x + 0.5) * u);
}

void distortion_idct_block(const int16_t coef[64], const uint16_t quant[64], float out[64]) {
    double basis[8][8], tmp[8][8];
    dct_basis(basis);
    for (int x = 0; x < 8; x++)
        for (int v = 0; v < 8; v++) {
            double s = 0;
            for (int u = 0; u < 8; u++) s += basis[x][u] * coef[u * 8 + v] * quant[u * 8 + v];
            tmp[x][v] = s;
        }
    for (int x = 0; x < 8; x++)
        for (int y = 0; y < 8; y++) {
            double s = 128;
            for (int v = 0; v < 8; v++) s += tmp[x][v] * basis[y][v];
            s = floor(s + 0.5);
            out[x * 8 + y] = (float)(s < 0 ? 0 : s > 255 ? 255 : s);
        }
}

/* "Full"-size correlation of n samples `step` apart with a 16-tap filter:
   out[i] = sum over t of in[i + t - 15] * k[t], for i in 0..n+14 */
static void full_line(const double *in, double *out, int n, int step, const double *k) {
    for (int i = 0; i < n + TAPS - 1; i++) {
        double s = 0;
        for (int t = 0; t < TAPS; t++) {
            int j = i + t - (TAPS - 1);
            if (j >= 0 && j < n) s += in[j * step] * k[t];
        }
        out[i * step] = s;
    }
}

JUniward *juniward_new(const float *pixels, uint32_t w, uint32_t h, const uint16_t quant[64]) {
    JUniward *j = calloc(1, sizeof(JUniward));
    size_t pw, ph;
    double *pad = j ? padded_plane(w, h, sizeof(double), &pw, &ph) : NULL;
    double *tmp = pad ? malloc(pw * ph * sizeof(double)) : NULL;
    double *r = tmp ? malloc(pw * sizeof(double)) : NULL;  /* one row */
    if (!r) {
        free(tmp);
        tmp = NULL;
    }
    for (int b = 0; tmp && b < 3; b++)
        if (!(j->rinv[b] = malloc(pw * ph * sizeof(float)))) {
            free(tmp);
            tmp = NULL;
        }
    if (!tmp) {
        free(pad);
        free(r);
        juniward_free(j);
        return NULL;
    }
    j->pw = pw;
    for (size_t y = 0; y < ph; y++)
        for (size_t x = 0; x < pw; x++)
            pad[y * pw + x] = pixels[(size_t)mirror((long)y - PAD, h) * w + (size_t)mirror((long)x - PAD, w)];
    /* Unlike S-UNIWARD's, the J-UNIWARD reference correlates the image with
       the filters rather than convolving */
    for (int b = 0; b < 3; b++) {
        for (size_t x = 0; x < pw; x++) corr_line_d(pad + x, tmp + x, ph, pw, BANDS[b][0]);
        for (size_t y = 0; y < ph; y++) {
            corr_line_d(tmp + y * pw, r, pw, 1, BANDS[b][1]);
            for (size_t x = 0; x < pw; x++)
                j->rinv[b][y * pw + x] = (float)(1.0 / (fabs(r[x]) + SIGMA_JPEG));
        }
    }
    free(pad);
    free(tmp);
    free(r);

    /* What a change of 1 in each DCT mode does to each sub-band: the mode's
       basis pattern times its quantization step, filtered (full size) */
    double basis[8][8];
    dct_basis(basis);
    for (int k = 0; k < 64; k++) {
        int u = k / 8, v = k % 8;
        double pattern[8 * 8], cols[REACH * 8], out[REACH * REACH];
        for (int x = 0; x < 8; x++)
            for (int y = 0; y < 8; y++) pattern[x * 8 + y] = basis[x][u] * basis[y][v];
        for (int b = 0; b < 3; b++) {
            for (int y = 0; y < 8; y++) full_line(pattern + y, cols + y, 8, 8, BANDS[b][0]);
            for (int x = 0; x < REACH; x++) full_line(cols + x * 8, out + x * REACH, 8, 1, BANDS[b][1]);
            for (int i = 0; i < REACH * REACH; i++) j->impact[b][k][i] = fabs(out[i] * quant[k]);
        }
    }
    return j;
}

/* The sum, over the sub-bands and the window the block's change reaches,
   of how much the change moves each sub-band coefficient relative to the
   cover's own: J-UNIWARD's relative change in the wavelet domain */
float juniward_cost(const JUniward *j, uint32_t bx, uint32_t by, int k) {
    size_t r0 = (size_t)by * 8 + PAD - 6, c0 = (size_t)bx * 8 + PAD - 6;
    double rho = 0;
    for (int b = 0; b < 3; b++) {
        const double *imp = j->impact[b][k];
        for (int rs = 0; rs < REACH; rs++) {
            const float *rinv = j->rinv[b] + (r0 + rs) * j->pw + c0;
            for (int cs = 0; cs < REACH; cs++) rho += imp[rs * REACH + cs] * rinv[cs];
        }
    }
    return rho <= DISTORTION_WET_JPEG ? (float)rho : DISTORTION_WET_JPEG;
}

void juniward_free(JUniward *j) {
    if (!j) return;
    for (int b = 0; b < 3; b++) free(j->rinv[b]);
    free(j);
}
