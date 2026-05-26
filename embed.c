#include "embed.h"
#include <string.h>

static void write_bit(Image *img, uint32_t pixel_idx, int channel, uint8_t bit) {
    uint32_t x = pixel_idx % img->width;
    uint32_t y = pixel_idx / img->width;
    uint8_t *ch = &img->rows[y][x * 3 + channel];
    *ch = (*ch & 0xFE) | (bit & 0x01);
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

    for (int b = 0; b < 32; b++) {
        uint8_t bit = (data_len >> b) & 0x01;
        write_bit(img, indices[bit_pos / 3], bit_pos % 3, bit);
        bit_pos++;
    }

    for (uint32_t i = 0; i < data_len; i++) {
        for (int b = 0; b < 8; b++) {
            uint8_t bit = (data[i] >> b) & 0x01;
            write_bit(img, indices[bit_pos / 3], bit_pos % 3, bit);
            bit_pos++;
        }
    }
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
