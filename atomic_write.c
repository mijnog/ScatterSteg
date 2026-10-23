#define _XOPEN_SOURCE 700  /* mkstemp, fchmod, fchown, fsync, realpath */
#include "atomic_write.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int atomic_write(const char *path, int (*write)(FILE *fp, const void *ctx), const void *ctx) {
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
