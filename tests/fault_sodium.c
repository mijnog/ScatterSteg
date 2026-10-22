#define FAULT_IMPL
#include "fault.h"
#include <errno.h>
#include <sodium.h>

/* Argon2id allocates its memory (64 MiB here) inside libsodium, out of
   reach of the malloc wrapper; failing it as a whole covers that case. */
int fault_crypto_pwhash(unsigned char *out, unsigned long long outlen,
                        const char *passwd, unsigned long long passwdlen,
                        const unsigned char *salt, unsigned long long opslimit,
                        size_t memlimit, int alg) {
    if (fault_should_fail("crypto_pwhash")) { errno = ENOMEM; return -1; }
    return crypto_pwhash(out, outlen, passwd, passwdlen, salt, opslimit, memlimit, alg);
}

void *fault_sodium_malloc(size_t size) {
    if (fault_should_fail("sodium_malloc")) { errno = ENOMEM; return NULL; }
    return sodium_malloc(size);
}
