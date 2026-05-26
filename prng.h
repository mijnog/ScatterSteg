#ifndef PRNG_H
#define PRNG_H

#include <stdint.h>

uint32_t *prng_scatter(const uint8_t *key, uint32_t count);

#endif /* PRNG_H */
