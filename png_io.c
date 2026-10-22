#define _XOPEN_SOURCE 700  /* mkstemp, fchmod, fchown, fsync, realpath */
#include "png_io.h"
#include <png.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*




  10.
*/

/* Largest decoded pixel buffer png_load will allocate (1 GiB) */
#define PNG_MAX_PIXEL_BYTES ((size_t)1 << 30)

Image *png_load(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;

    png_structp png = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png) { fclose(fp); return NULL; }
    png_infop info = png_create_info_struct(png);
    if (!info) { png_destroy_read_struct(&png, NULL, NULL); fclose(fp); return NULL; }

    /* volatile: assigned after setjmp, so must survive the longjmp intact */
    Image *volatile img = NULL;

    /* libpng uses longjmp for errors — if anything goes wrong it jumps here */
    if (setjmp(png_jmpbuf(png))) {
        image_free(img);  /* NULL for the size checks below; fully allocated
                             by the time png_read_image can fail */
        png_destroy_read_struct(&png, &info, NULL);
        fclose(fp);
        return NULL;
    }

    // Tell libpng to read from FILE* fp
    png_init_io(png, fp);
    // Read the image header (png_read_info) — this fills width, height, bit depth, color type
    png_read_info(png, info);

    // Get width and height
    uint32_t width  = png_get_image_width(png, info);
    uint32_t height = png_get_image_height(png, info);

    /* Force any PNG variant into 8-bit RGB */
    png_set_strip_alpha(png);     /* drop alpha channel if present */
    png_set_gray_to_rgb(png);     /* expand grayscale to RGB       */
    png_set_strip_16(png);        /* 16-bit channels → 8-bit       */
    png_set_palette_to_rgb(png);  /* indexed color → RGB           */
    png_set_interlace_handling(png);    /* de-interlace Adam7 images     */
    png_read_update_info(png, info);    /* apply the transforms          */

    /* Rows are allocated as row_size below; refuse anything the transforms
       didn't turn into exactly that, rather than let libpng overrun them.
       row_size is computed once in size_t so the check and malloc agree.
       png_error reports the cause and jumps to the cleanup handler above. */
    size_t row_size = (size_t)width * 3;  /* 3 bytes per pixel: R G B */
    if (row_size / 3 != width || png_get_rowbytes(png, info) != row_size)
        png_error(png, "unexpected decoded row size");

    /* The header's dimensions are untrusted: cap the total allocation before
       making it, so a tiny file can't request terabytes. This also bounds
       height, so the row-pointer array below can't overflow. libpng rejects
       a zero height in png_read_info, so the division is safe. */
    if (row_size > PNG_MAX_PIXEL_BYTES / height)
        png_error(png, "image dimensions too large");

    // Allocate the Image struct and its row pointers
    img = malloc(sizeof(Image));
    if (!img) {
        png_destroy_read_struct(&png, &info, NULL);
        fclose(fp);
        return NULL;
    }
    img->width  = width;
    img->height = height;
    img->rows   = malloc(height * sizeof(uint8_t *));
    if (!img->rows) {
        free(img);
        png_destroy_read_struct(&png, &info, NULL);
        fclose(fp);
        return NULL;
    }
    for (uint32_t y = 0; y < height; y++) {
        img->rows[y] = malloc(row_size);
        if (!img->rows[y]) {
            for (uint32_t i = 0; i < y; i++)
                free(img->rows[i]);
            free(img->rows);
            free(img);
            png_destroy_read_struct(&png, &info, NULL);
            fclose(fp);
            return NULL;
        }
    }

    // Read the pixel data (png_read_image)
    png_read_image(png, img->rows);

    // Clean up
    png_destroy_read_struct(&png, &info, NULL);
    fclose(fp);
    return img;
}

/* Write to a temp file beside `path`, then rename() it into place. The
   destination is only replaced once the new PNG is complete, so a failed
   write never truncates or deletes an existing file (e.g. -i a.png -o a.png).
   On failure, errno describes the cause (0 if libpng failed internally). */
int png_save(const Image *img, const char *path) {
    /* Write through a symlink to the file it points to rather than replacing
       the link itself. A new path, or a dangling link, is used as is. */
    char *target = realpath(path, NULL);
    const char *dest = target ? target : path;
    struct stat existing;
    int replacing = stat(dest, &existing) == 0;

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
    png_structp png = NULL;
    png_infop info = NULL;

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

    png = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png) goto fail;
    info = png_create_info_struct(png);
    if (!info) goto fail;

    // error handling
    if (setjmp(png_jmpbuf(png))) goto fail;

    // file to write to
    png_init_io(png, fp);

    // declare pixel data format
    png_set_IHDR(png, info,
        img->width, img->height,
        8,
        PNG_COLOR_TYPE_RGB,
        PNG_INTERLACE_NONE,
        PNG_COMPRESSION_TYPE_DEFAULT,
        PNG_FILTER_TYPE_DEFAULT);

    //  write the PNG header
    png_write_info(png, info);
    // write the pixel rows
    png_write_image(png, img->rows);
    // finalize the file
    png_write_end(png, NULL);

    // cleanup — buffered write errors (disk full, quota) only surface here
    png_destroy_write_struct(&png, &info);
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
        if (png) png_destroy_write_struct(&png, info ? &info : NULL);
        if (fp) fclose(fp);
        else if (fd >= 0) close(fd);
        remove(tmp);
        free(tmp);
        free(target);
        errno = err;
        return -1;
    }
}


void image_free(Image *img) {
    if (!img) return;
    for (uint32_t y = 0; y < img->height; y++)
        free(img->rows[y]);
    free(img->rows);
    free(img);
}