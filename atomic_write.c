/* SPDX-License-Identifier: MIT OR Apache-2.0
   Copyright (C) 2026 Maxime de Montbron */
#define _XOPEN_SOURCE 700  /* mkstemp, fchmod, fchown, fsync, realpath */
#include "atomic_write.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Make the rename itself durable: until the directory is synced, a crash
   can lose it even though the file's data was synced. Best effort: the file
   is already in place, and some filesystems can't sync a directory. */
static void sync_dir_of(const char *dest) {
    const char *slash = strrchr(dest, '/');
    char *dir = slash ? strndup(dest, slash == dest ? 1 : (size_t)(slash - dest)) : strdup(".");
    if (!dir) return;
    int fd = open(dir, O_RDONLY | O_DIRECTORY);
    free(dir);
    if (fd < 0) return;
    if (fsync(fd) != 0) { /* nothing to do */ }
    close(fd);
}

static int write_and_rename(const char *path, int (*write)(FILE *fp, const void *ctx), const void *ctx) {
    /* Write through a symlink to the file it points to rather than replacing
       the link itself. A new path, or a dangling link, is used as is. */
    char *target = realpath(path, NULL);
    const char *dest = target ? target : path;
    struct stat existing;
    int replacing = stat(dest, &existing) == 0;
    /* rename would replace a FIFO, socket or device (even /dev/null, as
       root) with a regular file, rather than write to it: refuse */
    if (replacing && !S_ISREG(existing.st_mode)) {
        free(target);
        errno = EINVAL;
        return -1;
    }

    errno = 0;
    size_t len = strlen(dest);
    char *tmp = malloc(len + sizeof(".XXXXXX"));
    if (!tmp) {
        int err = errno;
        free(target);
        errno = err;
        return -1;
    }
    memcpy(tmp, dest, len);
    memcpy(tmp + len, ".XXXXXX", sizeof(".XXXXXX"));

    FILE *fp = NULL;

    /* On failure tmp may name someone else's file, so don't goto fail's remove */
    int fd = mkstemp(tmp);
    if (fd < 0) {
        int err = errno;
        free(tmp);
        free(target);
        errno = err;
        return -1;
    }

    /* Replacing a file: keep its permissions and group, so a private image
       stays private and a shared one stays shared. If its group can't be
       kept (we're not a member), don't grant its group bits to another.
       A new file gets the usual umask-based mode (mkstemp makes it 0600). */
    mode_t mode;
    if (replacing) {
        mode = existing.st_mode & 0777;
        if (fchown(fd, (uid_t)-1, existing.st_gid) != 0) {
            mode &= ~(mode_t)0070;
            errno = 0;
        }
    } else {
        mode_t mask = umask(0);
        umask(mask);
        mode = 0666 & ~mask;
    }
    if (fchmod(fd, mode) != 0) goto fail;

    fp = fdopen(fd, "wb");
    if (!fp) goto fail;

    errno = 0;
    if (write(fp, ctx) != 0) goto fail;

    /* Buffered write errors (disk full, quota) only surface here */
    if (fflush(fp) != 0 || ferror(fp) || fsync(fileno(fp)) != 0) goto fail;
    /* fclose releases fd even when it fails, so fail must not close it again */
    int closed = fclose(fp);
    fp = NULL;
    fd = -1;
    if (closed != 0) goto fail;
    if (rename(tmp, dest) != 0) goto fail;
    sync_dir_of(dest);
    free(tmp);
    free(target);
    return 0;

fail:
    {
        /* cleanup calls may clobber errno; keep the one from the failure */
        int err = errno;
        if (fp) fclose(fp);
        else if (fd >= 0) close(fd);
        remove(tmp);
        free(tmp);
        free(target);
        errno = err;
        return -1;
    }
}

/* Ctrl+C (or kill, or a closed terminal) while the temp file exists would
   leave it behind, beside the output. So those signals wait until it has
   been renamed into place or removed; one that arrived meanwhile is
   delivered then. The CLI writes from memory, so this holds them for the
   write and fsync alone. */
int atomic_write(const char *path, int (*write)(FILE *fp, const void *ctx), const void *ctx) {
    sigset_t hold, old;
    sigemptyset(&hold);
    sigaddset(&hold, SIGINT);
    sigaddset(&hold, SIGQUIT);
    sigaddset(&hold, SIGTERM);
    sigaddset(&hold, SIGHUP);
    sigprocmask(SIG_BLOCK, &hold, &old);
    int r = write_and_rename(path, write, ctx);
    int err = errno;
    sigprocmask(SIG_SETMASK, &old, NULL);
    errno = err;
    return r;
}
