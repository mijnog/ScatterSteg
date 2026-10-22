#ifndef EMBED_H
#define EMBED_H

#include <stddef.h>
#include <stdint.h>
#include "png_io.h"

/* Bits go LSB first into the listed pixels, img->channels per pixel (one
   per sample). */

/* Writing is two-phase: embed_encode and embed_write_raw record which
   samples must change in a plan, and embed_apply changes them all at once,
   pairing them up so the histogram is preserved (see embed.c). */
typedef struct EmbedPlan EmbedPlan;

typedef struct {
    size_t changes;    /* samples whose LSB had to flip */
    size_t exchanged;  /* of those, how many swapped values in pairs */
} EmbedStats;

EmbedPlan *embed_plan_new(void);  /* NULL if out of memory */
void embed_plan_free(EmbedPlan *plan);
/* Make the recorded changes. Returns 0, or -1 if out of memory (now or
   while recording), in which case the image is unchanged. stats may be NULL. */
int  embed_apply(EmbedPlan *plan, EmbedStats *stats);

/* Returns 0, or -1 if the data doesn't fit in count pixels */
int  embed_encode(Image *img, const uint32_t *indices, uint32_t count,
                  const uint8_t *data, uint32_t data_len, EmbedPlan *plan);

void embed_decode(const Image *img, const uint32_t *indices,
                  uint32_t count, uint8_t *out, uint32_t out_size);

uint32_t embed_peek_len(const Image *img, const uint32_t *indices, uint32_t count);

/* Raw bytes with no length header, LSB first, img->channels bits per pixel
   (format v2 uses these for the salt). Return 0, or -1 if len bytes don't
   fit in count pixels. */
int embed_write_raw(Image *img, const uint32_t *indices, uint32_t count,
                    const uint8_t *data, uint32_t len, EmbedPlan *plan);
int embed_read_raw(const Image *img, const uint32_t *indices, uint32_t count,
                   uint8_t *out, uint32_t len);

#endif /* EMBED_H */
