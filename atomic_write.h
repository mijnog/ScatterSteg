/* SPDX-License-Identifier: MIT OR Apache-2.0
   Copyright (C) 2026 Maxime de Montbron */
#ifndef ATOMIC_WRITE_H
#define ATOMIC_WRITE_H

#include <stdio.h>

/* Writes a file by calling write(fp, ctx) on a temp file beside `path`, then
   renaming it into place, so a failed write never truncates or deletes an
   existing file (e.g. -i a.png -o a.png). A symlink at `path` is written
   through, and an existing file keeps its permissions and group. Anything
   at `path` other than a regular file (a FIFO, device, directory...) is
   left alone: errno EINVAL. SIGINT, SIGQUIT, SIGTERM and SIGHUP are held
   until the temp file is renamed or removed, so none leaves it behind.

   write returns 0, or -1 leaving errno set (or 0 if the cause has no errno,
   e.g. an encoder's internal error). Returns 0, or -1 with errno likewise. */
int atomic_write(const char *path, int (*write)(FILE *fp, const void *ctx), const void *ctx);

#endif /* ATOMIC_WRITE_H */
