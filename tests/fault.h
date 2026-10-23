/* SPDX-License-Identifier: AGPL-3.0-or-later
   Copyright (C) 2026 Maxime de Montbron */
#ifndef FAULT_H
#define FAULT_H

/* Fault injection. Force-included (-include tests/fault.h) into the sources
   under test, it routes every libc call that can fail through a wrapper in
   fault.c. Arming fault N makes the Nth such call fail as the real one can,
   so a sweep over N walks every error path one at a time. */

#define _POSIX_C_SOURCE 200809L  /* same values the sources define */
#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void *fault_malloc(size_t size);
void *fault_realloc(void *p, size_t size);
FILE *fault_fopen(const char *path, const char *mode);
FILE *fault_fdopen(int fd, const char *mode);
int   fault_mkstemp(char *tmpl);
int   fault_fflush(FILE *fp);
int   fault_fsync(int fd);
int   fault_fclose(FILE *fp);
int   fault_close(int fd);
int   fault_rename(const char *from, const char *to);
int   fault_fchown(int fd, uid_t owner, gid_t group);
/* In fault_sodium.c, linked only into builds that use libsodium */
int   fault_crypto_pwhash(unsigned char *out, unsigned long long outlen,
                          const char *passwd, unsigned long long passwdlen,
                          const unsigned char *salt, unsigned long long opslimit,
                          size_t memlimit, int alg);
void *fault_sodium_malloc(size_t size);

/* For wrappers: count a call, true if it is the one to fail */
int fault_should_fail(const char *name);

/* Arm: fail the nth faultable call from now on (1-based), 0 disarms.
   Also read from $FAULT_AT at startup, for whole-program runs. */
void fault_arm(unsigned n);
/* Did the armed fault fire? Which call was it? */
int         fault_fired(void);
const char *fault_fired_name(void);
/* Number of close() calls that hit EBADF, i.e. closed an fd twice */
unsigned    fault_bad_closes(void);

#ifndef FAULT_IMPL
#define malloc  fault_malloc
#define realloc fault_realloc
#define fopen   fault_fopen
#define fdopen  fault_fdopen
#define mkstemp fault_mkstemp
#define fflush  fault_fflush
#define fsync   fault_fsync
#define fclose  fault_fclose
#define close   fault_close
#define rename  fault_rename
#define fchown  fault_fchown
#define crypto_pwhash fault_crypto_pwhash
#define sodium_malloc fault_sodium_malloc
#endif

#endif /* FAULT_H */
