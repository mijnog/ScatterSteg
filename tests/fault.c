/* SPDX-License-Identifier: AGPL-3.0-or-later
   Copyright (C) 2026 Maxime de Montbron */
#define FAULT_IMPL
#include "fault.h"
#include <errno.h>
#include <string.h>

static unsigned    armed_at;    /* fail this call number; 0 = never */
static unsigned    calls;       /* faultable calls since arming */
static const char *fired_name;  /* which call failed, NULL if none */
static unsigned    bad_closes;

void fault_arm(unsigned n) {
    armed_at   = n;
    calls      = 0;
    fired_name = NULL;
    bad_closes = 0;
}

int         fault_fired(void)      { return fired_name != NULL; }
const char *fault_fired_name(void) { return fired_name ? fired_name : "none"; }
unsigned    fault_bad_closes(void) { return bad_closes; }

int fault_should_fail(const char *name) {
    if (!armed_at || fired_name) return 0;
    if (++calls != armed_at) return 0;
    fired_name = name;
    return 1;
}

/* Whole-program builds: arm from the environment, and say on exit whether
   the fault was reached so a sweep knows when it has run out of calls. */
static void report(void) {
    if (armed_at)
        fprintf(stderr, fired_name ? "FAULT_FIRED %s\n" : "FAULT_NOT_REACHED\n",
                fired_name);
}

__attribute__((constructor)) static void fault_init(void) {
    const char *env = getenv("FAULT_AT");
    if (env && *env) {
        fault_arm((unsigned)strtoul(env, NULL, 10));
        atexit(report);
    }
}

void *fault_malloc(size_t size) {
    if (fault_should_fail("malloc")) { errno = ENOMEM; return NULL; }
    return malloc(size);
}

void *fault_calloc(size_t n, size_t size) {
    if (fault_should_fail("calloc")) { errno = ENOMEM; return NULL; }
    return calloc(n, size);
}

void *fault_realloc(void *p, size_t size) {
    if (fault_should_fail("realloc")) { errno = ENOMEM; return NULL; }
    return realloc(p, size);
}

FILE *fault_fopen(const char *path, const char *mode) {
    if (fault_should_fail("fopen")) { errno = EMFILE; return NULL; }
    return fopen(path, mode);
}

FILE *fault_fdopen(int fd, const char *mode) {
    if (fault_should_fail("fdopen")) { errno = ENOMEM; return NULL; }
    return fdopen(fd, mode);
}

/* glibc leaves its last attempted name in the template when mkstemp gives
   up; mimic that with a fixed name so tests can plant a file there. */
int fault_mkstemp(char *tmpl) {
    if (fault_should_fail("mkstemp")) {
        size_t len = strlen(tmpl);
        if (len >= 6) memcpy(tmpl + len - 6, "FAULTY", 6);
        errno = EEXIST;
        return -1;
    }
    return mkstemp(tmpl);
}

int fault_fflush(FILE *fp) {
    if (fault_should_fail("fflush")) { errno = ENOSPC; return EOF; }
    return fflush(fp);
}

int fault_fsync(int fd) {
    if (fault_should_fail("fsync")) { errno = EIO; return -1; }
    return fsync(fd);
}

/* A failing fclose still releases the stream and its fd (C17 7.21.5.1),
   so close for real and then report the error. */
int fault_fclose(FILE *fp) {
    if (fault_should_fail("fclose")) {
        fclose(fp);
        errno = EIO;
        return EOF;
    }
    return fclose(fp);
}

int fault_close(int fd) {
    int r = close(fd);
    if (r != 0 && errno == EBADF) bad_closes++;
    return r;
}

int fault_fchown(int fd, uid_t owner, gid_t group) {
    if (fault_should_fail("fchown")) { errno = EPERM; return -1; }
    return fchown(fd, owner, group);
}

int fault_rename(const char *from, const char *to) {
    if (fault_should_fail("rename")) { errno = EXDEV; return -1; }
    return rename(from, to);
}
