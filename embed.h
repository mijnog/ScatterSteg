#ifndef EMBED_H
#define EMBED_H

#include <stdint.h>
#include "png_io.h"

int  embed_encode(Image *img, const uint32_t *indices, uint32_t count,
                  const uint8_t *data, uint32_t data_len);

void embed_decode(const Image *img, const uint32_t *indices,
                  uint32_t count, uint8_t *out, uint32_t out_size);

uint32_t embed_peek_len(const Image *img, const uint32_t *indices, uint32_t count);

#endif /* EMBED_H */
