#ifndef EMBED_H
#define EMBED_H

#include <stdint.h>
#include "png_io.h"

/* Bits go LSB first into the listed pixels, img->channels per pixel (one
   per sample), by LSB matching. */

int  embed_encode(Image *img, const uint32_t *indices, uint32_t count,
                  const uint8_t *data, uint32_t data_len);

void embed_decode(const Image *img, const uint32_t *indices,
                  uint32_t count, uint8_t *out, uint32_t out_size);

uint32_t embed_peek_len(const Image *img, const uint32_t *indices, uint32_t count);

/* Raw bytes with no length header, LSB first, img->channels bits per pixel
   (format v2 uses these for the salt). Return 0, or -1 if len bytes don't
   fit in count pixels. */
int embed_write_raw(Image *img, const uint32_t *indices, uint32_t count,
                    const uint8_t *data, uint32_t len);
int embed_read_raw(const Image *img, const uint32_t *indices, uint32_t count,
                   uint8_t *out, uint32_t len);

#endif /* EMBED_H */
