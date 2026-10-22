#include "embed.h"
#include <sodium.h>
#include <string.h>

/* Random coin flips, drawn from libsodium 64 at a time */
typedef struct {
    uint64_t bits;
    int left;
} Coins;

static int flip(Coins *c) {
    if (c->left == 0) {
        randombytes_buf(&c->bits, sizeof(c->bits));
        c->left = 64;
    }
    int heads = c->bits & 1;
    c->bits >>= 1;
    c->left--;
    return heads;
}

/* LSB matching: when the LSB is wrong, add or subtract 1 at random rather
   than overwriting it. Overwriting only ever maps 2k <-> 2k+1, which leaves
   the pair statistics that chi-square, RS and sample pair analysis detect;
   a random +-1 doesn't. Decoding only reads the LSB, so it's unchanged. */
static void write_bit(Image *img, uint32_t pixel_idx, int channel, uint8_t bit, Coins *coins) {
    uint32_t x = pixel_idx % img->width;
    uint32_t y = pixel_idx / img->width;
    uint8_t *ch = &img->rows[y][x * 3 + channel];
    if ((*ch & 0x01) == (bit & 0x01)) return;
    if (*ch == 0)        *ch = 1;
    else if (*ch == 255) *ch = 254;
    else                 *ch = flip(coins) ? *ch + 1 : *ch - 1;
}

static uint8_t read_bit(const Image *img, uint32_t pixel_idx, int channel) {
    uint32_t x = pixel_idx % img->width;
    uint32_t y = pixel_idx / img->width;
    return img->rows[y][x * 3 + channel] & 0x01;
}

int embed_encode(Image *img, const uint32_t *indices, uint32_t count,
                 const uint8_t *data, uint32_t data_len) {
    uint64_t bits_needed = 32 + (uint64_t)data_len * 8;
    if (bits_needed > (uint64_t)count * 3)
        return -1;

    uint32_t bit_pos = 0;
    Coins coins = {0, 0};

    for (int b = 0; b < 32; b++) {
        uint8_t bit = (data_len >> b) & 0x01;
        write_bit(img, indices[bit_pos / 3], bit_pos % 3, bit, &coins);
        bit_pos++;
    }

    for (uint32_t i = 0; i < data_len; i++) {
        for (int b = 0; b < 8; b++) {
            uint8_t bit = (data[i] >> b) & 0x01;
            write_bit(img, indices[bit_pos / 3], bit_pos % 3, bit, &coins);
            bit_pos++;
        }
    }
    sodium_memzero(&coins, sizeof(coins));
    return 0;
}

void embed_decode(const Image *img, const uint32_t *indices,
                  uint32_t count, uint8_t *out, uint32_t out_size) {
    uint32_t bit_pos = 0;

    uint32_t data_len = 0;
    for (int b = 0; b < 32; b++) {
        if (bit_pos / 3 >= count) return;
        uint8_t bit = read_bit(img, indices[bit_pos / 3], bit_pos % 3);
        data_len |= ((uint32_t)bit << b);
        bit_pos++;
    }

    if (data_len > out_size) data_len = out_size;

    for (uint32_t i = 0; i < data_len; i++) {
        uint8_t byte = 0;
        for (int b = 0; b < 8; b++) {
            if (bit_pos / 3 >= count) break;
            uint8_t bit = read_bit(img, indices[bit_pos / 3], bit_pos % 3);
            byte |= (bit << b);
            bit_pos++;
        }
        out[i] = byte;
    }
}

uint32_t embed_peek_len(const Image *img, const uint32_t *indices, uint32_t count) {
    uint32_t data_len = 0;
    for (int b = 0; b < 32; b++) {
        if ((uint32_t)b / 3 >= count) return 0;
        uint8_t bit = read_bit(img, indices[b / 3], b % 3);
        data_len |= ((uint32_t)bit << b);
    }
    return data_len;
}

int embed_write_raw(Image *img, const uint32_t *indices, uint32_t count,
                    const uint8_t *data, uint32_t len) {
    if ((uint64_t)len * 8 > (uint64_t)count * 3) return -1;
    Coins coins = {0, 0};
    for (uint32_t pos = 0; pos < len * 8; pos++)
        write_bit(img, indices[pos / 3], pos % 3, (data[pos / 8] >> (pos % 8)) & 0x01, &coins);
    sodium_memzero(&coins, sizeof(coins));
    return 0;
}

int embed_read_raw(const Image *img, const uint32_t *indices, uint32_t count,
                   uint8_t *out, uint32_t len) {
    if ((uint64_t)len * 8 > (uint64_t)count * 3) return -1;
    memset(out, 0, len);
    for (uint32_t pos = 0; pos < len * 8; pos++)
        out[pos / 8] |= (uint8_t)(read_bit(img, indices[pos / 3], pos % 3) << (pos % 8));
    return 0;
}
