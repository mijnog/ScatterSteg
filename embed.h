#ifndef EMBED_H
#define EMBED_H

#include <stddef.h>
#include <stdint.h>
#include "png_io.h"

/* Where the bits go: positions of one or more samples each, in an order
   the caller's permutation picks. Either a PNG image (a position is a
   pixel, with one sample per channel) or a list of JPEG DCT coefficients
   (a position is one coefficient). Bits go LSB first. */
typedef struct {
    Image *img;        /* PNG, or NULL */
    int16_t **coefs;   /* JPEG: n_coefs pointers to carrier coefficients */
    uint32_t n_coefs;
} Carrier;

static inline Carrier carrier_of_image(Image *img) {
    Carrier c = {img, NULL, 0};
    return c;
}

uint32_t carrier_positions(const Carrier *c);  /* pixels, or coefficients */
uint32_t carrier_channels(const Carrier *c);   /* samples per position */

/* Writing is two-phase: embed_encode and embed_write_raw record which
   samples must change in a plan, and embed_apply changes them all at once,
   pairing them up so the histogram is preserved (see embed.c). A plan
   holds samples of one carrier type. */
typedef struct EmbedPlan EmbedPlan;

typedef struct {
    size_t changes;    /* samples whose LSB had to flip */
    size_t exchanged;  /* of those, how many swapped values in pairs */
} EmbedStats;

EmbedPlan *embed_plan_new(void);  /* NULL if out of memory */
void embed_plan_free(EmbedPlan *plan);
/* Make the recorded changes. Returns 0, or -1 if out of memory (now or
   while recording), in which case nothing is changed. stats may be NULL. */
int  embed_apply(EmbedPlan *plan, EmbedStats *stats);

/* A 32-bit length, then the data. Returns 0, or -1 if it doesn't fit in
   count positions. */
int  embed_encode(const Carrier *c, const uint32_t *indices, uint32_t count,
                  const uint8_t *data, uint32_t data_len, EmbedPlan *plan);

void embed_decode(const Carrier *c, const uint32_t *indices,
                  uint32_t count, uint8_t *out, uint32_t out_size);

uint32_t embed_peek_len(const Carrier *c, const uint32_t *indices, uint32_t count);

/* Raw bytes with no length header (format v2 uses these for the salt).
   Return 0, or -1 if len bytes don't fit in count positions. */
int embed_write_raw(const Carrier *c, const uint32_t *indices, uint32_t count,
                    const uint8_t *data, uint32_t len, EmbedPlan *plan);
int embed_read_raw(const Carrier *c, const uint32_t *indices, uint32_t count,
                   uint8_t *out, uint32_t len);

#endif /* EMBED_H */
