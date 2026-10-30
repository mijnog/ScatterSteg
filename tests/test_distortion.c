/* SPDX-License-Identifier: MIT OR Apache-2.0
   Copyright (C) 2026 Maxime de Montbron */
#include "distortion.h"
#include "test.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>

/* A w x h image with ch channels, from the same formula rust/src/distortion.rs uses */
static Image *pattern(uint32_t w, uint32_t h, uint32_t ch) {
    Image *img = calloc(1, sizeof(Image));
    img->width = w;
    img->height = h;
    img->channels = ch;
    img->rows = malloc(h * sizeof(uint8_t *));
    for (uint32_t y = 0; y < h; y++) {
        img->rows[y] = malloc((size_t)w * ch);
        for (uint32_t x = 0; x < w; x++)
            for (uint32_t c = 0; c < ch; c++)
                img->rows[y][x * ch + c] = (uint8_t)(((y * 37 + x * 11 + (x * y) % 7) * 13) + c * 71);
    }
    return img;
}

/* Half flat, half noise */
static Image *half_flat(uint32_t w, uint32_t h) {
    Image *img = pattern(w, h, 1);
    for (uint32_t y = 0; y < h; y++)
        for (uint32_t x = 0; x < w; x++)
            img->rows[y][x] = x < w / 2 ? 128 : (uint8_t)((y * w + x) * 2654435761u >> 13);
    return img;
}

static int close_to(float got, float want) {
    return fabsf(got - want) <= 1e-5f * fabsf(want);
}

/* Known answers, from this implementation on a 24 x 20 gray image: it
   matched the authors' reference code to within 5.3e-4 (WOW) and 2.3e-5
   (S-UNIWARD) relative, on photographs and on odd sizes (see
   benchmark/README.md, "Distortion models"). Every 37th sample. */
static void test_wow_known_answer(void) {
    static const float want[] = {0.0141366525f, 0.0145788305f, 0.0143218692f, 0.0129158907f,
        0.0106896516f, 0.014331637f, 0.0144222546f, 0.0116113629f, 0.0166720171f,
        0.0135587277f, 0.0129521862f, 0.0161323864f, 0.0165558197f};
    Image *img = pattern(24, 20, 1);
    float *costs = distortion_wow(img);
    CHECK(costs != NULL);
    for (int i = 0; i < 13; i++) CHECK(close_to(costs[i * 37], want[i]));
    free(costs);
    image_free(img);
}

static void test_suniward_known_answer(void) {
    static const float want[] = {0.766949177f, 0.539925933f, 0.641394734f, 0.507885456f,
        0.700752497f, 0.777545214f, 1.01516366f, 0.426031649f, 0.770571947f, 0.693113446f,
        0.76456368f, 0.588670015f, 0.764136136f};
    Image *img = pattern(24, 20, 1);
    float *costs = distortion_suniward(img);
    CHECK(costs != NULL);
    for (int i = 0; i < 13; i++) CHECK(close_to(costs[i * 37], want[i]));
    free(costs);
    image_free(img);
}

static const uint16_t Q75[64] = {8, 6, 5, 8, 12, 20, 26, 31, 6, 6, 7, 10, 13, 29, 30, 28, 7, 7, 8,
    12, 20, 29, 35, 28, 7, 9, 11, 15, 26, 44, 40, 31, 9, 11, 19, 28, 34, 55, 52, 39, 12, 18, 28,
    32, 41, 52, 57, 46, 25, 32, 39, 44, 52, 61, 60, 51, 36, 46, 48, 49, 56, 50, 52, 50};

/* J-UNIWARD on a 16 x 16 plane with quality 75's luminance table; the
   implementation matched the reference to 1.2e-7 relative */
static void test_juniward_known_answer(void) {
    static const struct { uint32_t bx, by; int k; float want; } cases[] = {
        {0, 0, 1, 5.34709358f}, {0, 0, 9, 7.0657196f}, {1, 0, 63, 90.6809921f},
        {0, 1, 8, 6.65914679f}, {1, 1, 27, 29.6261711f}, {1, 1, 2, 3.98322415f}};
    Image *img = pattern(16, 16, 1);
    float pixels[256];
    for (int i = 0; i < 256; i++) pixels[i] = img->rows[i / 16][i % 16];
    JUniward *j = juniward_new(pixels, 16, 16, Q75);
    CHECK(j != NULL);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        CHECK(close_to(juniward_cost(j, cases[i].bx, cases[i].by, cases[i].k), cases[i].want));
    juniward_free(j);
    image_free(img);
}

/* All three put changes where the image is busy */
static void test_flat_areas_dear(void) {
    Image *img = half_flat(64, 64);
    float *wow = distortion_wow(img), *uni = distortion_suniward(img);
    CHECK(wow && uni);
    size_t flat = 32 * 64 + 4, busy = 32 * 64 + 60;
    CHECK(wow[flat] > 1000 * wow[busy]);
    CHECK(uni[flat] > 10 * uni[busy]);
    free(wow);
    free(uni);
    float pixels[64 * 64];
    for (int i = 0; i < 64 * 64; i++) pixels[i] = img->rows[i / 64][i % 64];
    JUniward *j = juniward_new(pixels, 64, 64, Q75);
    CHECK(j != NULL);
    for (int k = 1; k < 64; k++) CHECK(juniward_cost(j, 0, 4, k) > 5 * juniward_cost(j, 7, 4, k));
    juniward_free(j);
    image_free(img);
}

/* Flat everywhere: WOW's residuals are all 0, so every cost is wet (the
   reference's NaN and infinity cases); S-UNIWARD's stay finite */
static void test_flat_image_costs(void) {
    Image *img = pattern(20, 20, 1);
    for (int y = 0; y < 20; y++) memset(img->rows[y], 77, 20);
    float *wow = distortion_wow(img), *uni = distortion_suniward(img);
    CHECK(wow && uni);
    for (int i = 0; i < 400; i++) {
        CHECK(wow[i] == DISTORTION_WET_SPATIAL);
        CHECK(uni[i] > 0 && uni[i] < DISTORTION_WET_SPATIAL);
    }
    free(wow);
    free(uni);
    image_free(img);
}

/* Each channel is costed alone: an RGB image's channel c gets the costs
   that channel would get as a gray image */
static void test_channels_independent(void) {
    Image *rgb = pattern(19, 23, 3), *gray = pattern(19, 23, 1);
    for (uint32_t c = 0; c < 3; c++) {
        for (uint32_t y = 0; y < 23; y++)
            for (uint32_t x = 0; x < 19; x++) gray->rows[y][x] = rgb->rows[y][x * 3 + c];
        float *a = distortion_suniward(rgb), *b = distortion_suniward(gray);
        float *wa = distortion_wow(rgb), *wb = distortion_wow(gray);
        CHECK(a && b && wa && wb);
        int same = 1;
        for (size_t i = 0; i < 19 * 23; i++)
            same &= a[i * 3 + c] == b[i] && wa[i * 3 + c] == wb[i];
        CHECK(same);
        free(a); free(b); free(wa); free(wb);
    }
    image_free(rgb);
    image_free(gray);
}

/* Smaller than the filters (which the references don't handle): every
   cost still positive and finite */
static void test_tiny_images(void) {
    static const uint32_t sizes[][2] = {{1, 1}, {2, 1}, {1, 7}, {3, 5}, {15, 16}, {17, 2}};
    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        Image *img = pattern(sizes[s][0], sizes[s][1], 3);
        float *wow = distortion_wow(img), *uni = distortion_suniward(img);
        CHECK(wow && uni);
        for (size_t i = 0; i < (size_t)sizes[s][0] * sizes[s][1] * 3; i++) {
            CHECK(wow[i] > 0 && wow[i] <= DISTORTION_WET_SPATIAL);
            CHECK(uni[i] > 0 && uni[i] <= DISTORTION_WET_SPATIAL);
        }
        free(wow);
        free(uni);
        image_free(img);
    }
    float px[64];
    for (int i = 0; i < 64; i++) px[i] = (float)(i * 7 % 256);
    JUniward *j = juniward_new(px, 8, 8, Q75);  /* one block */
    CHECK(j != NULL);
    for (int k = 1; k < 64; k++) {
        float c = juniward_cost(j, 0, 0, k);
        CHECK(c > 0 && c <= DISTORTION_WET_JPEG);
    }
    juniward_free(j);
}

/* The inverse DCT: an empty block is mid-gray, a DC of d moves every pixel
   by d * q / 8, and the result is rounded and clamped */
static void test_idct_block(void) {
    int16_t coef[64] = {0};
    uint16_t q[64];
    float out[64];
    for (int k = 0; k < 64; k++) q[k] = 1;
    distortion_idct_block(coef, q, out);
    for (int i = 0; i < 64; i++) CHECK(out[i] == 128);
    coef[0] = 80;
    q[0] = 2;
    distortion_idct_block(coef, q, out);
    for (int i = 0; i < 64; i++) CHECK(out[i] == 148);
    coef[0] = 1023;
    q[0] = 16;
    distortion_idct_block(coef, q, out);
    for (int i = 0; i < 64; i++) CHECK(out[i] == 255);
    coef[0] = -1023;
    distortion_idct_block(coef, q, out);
    for (int i = 0; i < 64; i++) CHECK(out[i] == 0);
    /* The first horizontal AC: a cosine across, the same down every column */
    memset(coef, 0, sizeof(coef));
    coef[1] = 40;
    distortion_idct_block(coef, q, out);
    for (int x = 0; x < 8; x++) {
        CHECK(out[x * 8 + 0] > 128 && out[x * 8 + 7] < 128);
        CHECK(out[x * 8 + 2] == out[2]);
    }
}

/* Regression: the model names were once an enum, which #if reads as 0, so
   every "#if SCATTERSTEG_PNG_COSTS == COSTS_WOW" matched and default
   builds silently used WOW and J-UNIWARD. The preprocessor and the
   compiler must agree on which model was picked. */
static void test_model_choice_seen_by_preprocessor(void) {
#if SCATTERSTEG_PNG_COSTS == COSTS_WOW
    int png = COSTS_WOW;
#elif SCATTERSTEG_PNG_COSTS == COSTS_SUNIWARD
    int png = COSTS_SUNIWARD;
#else
    int png = COSTS_HILL;
#endif
#if SCATTERSTEG_JPEG_COSTS == COSTS_JUNIWARD
    int jpeg = COSTS_JUNIWARD;
#else
    int jpeg = COSTS_UERD;
#endif
    CHECK(png == SCATTERSTEG_PNG_COSTS);
    CHECK(jpeg == SCATTERSTEG_JPEG_COSTS);
    CHECK(COSTS_HILL != COSTS_WOW && COSTS_WOW != COSTS_SUNIWARD && COSTS_HILL != COSTS_SUNIWARD);
    CHECK(COSTS_UERD != COSTS_JUNIWARD);
}

int main(void) {
    RUN(test_model_choice_seen_by_preprocessor);
    RUN(test_wow_known_answer);
    RUN(test_suniward_known_answer);
    RUN(test_juniward_known_answer);
    RUN(test_flat_areas_dear);
    RUN(test_flat_image_costs);
    RUN(test_channels_independent);
    RUN(test_tiny_images);
    RUN(test_idct_block);
    return TEST_SUMMARY();
}
