/* SPDX-License-Identifier: AGPL-3.0-or-later
   Copyright (C) 2026 Maxime de Montbron */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include <termios.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <sodium.h>
#include <strings.h>
#include "png_io.h"
#include "jpeg_io.h"
#include "embed.h"
#include "codec.h"
#include "atomic_write.h"

#define PASSPHRASE_CHUNK 256  /* passphrase buffer grows by this much */
/* The terminal's line editor holds 4095 bytes per line and silently drops
   the rest, so a line that long may have been cut short: refuse it. */
#define PASSPHRASE_MAX_LEN 4094
/* Shorter passphrases are refused on encode (decode accepts any, for old
   images). Length is a crude measure, so `passphrase` generates good ones. */
#define PASSPHRASE_MIN_LEN 12

/* Secrets (passphrase, message, keys, plaintext) live in sodium_malloc
   memory: locked so it can't be swapped to disk (within the locked memory
   limit: see warn_if_swappable), fenced by guard pages, and
   wiped by sodium_free. They are read and written with read() and write(),
   never through a stdio buffer, which would keep a copy outside it. */

/* Wipe and free a passphrase from read_passphrase. NULL is fine. */
static void free_passphrase(char *passphrase) {
    sodium_free(passphrase);
}

/* Terminal settings to put back if a signal kills us while echo is off */
static int tty_restore_fd = -1;
static struct termios tty_restore;

static const int restore_signals[] = {SIGINT, SIGQUIT, SIGTERM, SIGHUP};
#define N_RESTORE_SIGNALS (sizeof(restore_signals) / sizeof(restore_signals[0]))

/* Restore echo, then die from the same signal. SA_RESETHAND has already
   reinstated the default action, which runs once this handler returns. */
static void restore_tty_and_die(int sig) {
    tcsetattr(tty_restore_fd, TCSANOW, &tty_restore);
    if (write(tty_restore_fd, "\n", 1) < 0) { /* nothing to do */ }
    raise(sig);
}

/* Read a passphrase from the terminal with echo off. Returns it in a heap
   buffer for free_passphrase; on EOF or error, prints why and returns NULL.
   As a C string it ends at the first NUL (typed as Ctrl+@, or pasted), which
   would silently cut it short: refused unless allow_nul, which decode
   passes so images made with such a passphrase still open. */
static char *read_passphrase(const char *prompt, int allow_nul) {
    FILE *tty = fopen("/dev/tty", "r+");
    if (!tty) {
        fprintf(stderr, "Error: could not read passphrase\n");
        return NULL;
    }
    /* Unbuffered, so no copy of the passphrase is left in stdio's buffer */
    setvbuf(tty, NULL, _IONBF, 0);

    int fd = fileno(tty);
    struct termios old, silent;
    if (tcgetattr(fd, &old) != 0) {
        fclose(tty);
        fprintf(stderr, "Error: could not read passphrase\n");
        return NULL;
    }

    /* Ctrl+C and friends would otherwise leave the terminal without echo.
       A signal we were started ignoring (nohup, a script) stays ignored:
       it can't kill us, so there's nothing to restore. */
    tty_restore_fd = fd;
    tty_restore = old;
    struct sigaction on_signal = {.sa_handler = restore_tty_and_die, .sa_flags = SA_RESETHAND};
    struct sigaction saved[N_RESTORE_SIGNALS];
    sigemptyset(&on_signal.sa_mask);
    for (size_t i = 0; i < N_RESTORE_SIGNALS; i++) {
        sigaction(restore_signals[i], NULL, &saved[i]);
        if (saved[i].sa_handler != SIG_IGN)
            sigaction(restore_signals[i], &on_signal, NULL);
    }

    silent = old;
    silent.c_lflag &= ~ECHO;
    tcsetattr(fd, TCSAFLUSH, &silent);

    fputs(prompt, tty);
    fflush(tty);

    size_t cap = PASSPHRASE_CHUNK;
    size_t len = 0;
    char *buf = sodium_malloc(cap);
    int c = EOF;
    while (buf && (c = fgetc(tty)) != EOF && c != '\n') {
        if (len + 1 >= cap) {
            /* Grow by copying; sodium_free wipes the old buffer */
            char *bigger = sodium_malloc(cap + PASSPHRASE_CHUNK);
            if (bigger) memcpy(bigger, buf, len);
            sodium_free(buf);
            buf = bigger;
            cap += PASSPHRASE_CHUNK;
            if (!buf) break;
        }
        buf[len++] = (char)c;
    }

    tcsetattr(fd, TCSAFLUSH, &old);
    for (size_t i = 0; i < N_RESTORE_SIGNALS; i++)
        sigaction(restore_signals[i], &saved[i], NULL);
    fputs("\n", tty);
    fclose(tty);

    if (!buf || (c == EOF && len == 0)) {  /* out of memory, or Ctrl+D */
        sodium_free(buf);
        fprintf(stderr, "Error: could not read passphrase\n");
        return NULL;
    }
    if (len > PASSPHRASE_MAX_LEN) {
        sodium_free(buf);
        fprintf(stderr, "Error: passphrase too long (max %d bytes)\n", PASSPHRASE_MAX_LEN);
        return NULL;
    }
    if (!allow_nul && memchr(buf, '\0', len)) {
        sodium_free(buf);
        fprintf(stderr, "Error: the passphrase contains a NUL byte (Ctrl+@), "
                        "which would cut it short\n");
        return NULL;
    }
    buf[len] = '\0';
    return buf;
}


/* A loaded cover in either format, and the carrier its bits go into */
typedef struct {
    Image *png;
    JpegImage *jpeg;
    Carrier carrier;
} Cover;

/* Loads a PNG or JPEG (by its first bytes). Prints why and returns -1 if
   it can't. png_load caps images at 1 GiB, so positions fit in 32 bits. */
static int cover_load(const char *path, Cover *c) {
    memset(c, 0, sizeof(*c));
    if (is_jpeg_file(path)) {
        c->jpeg = jpeg_load(path);
        if (c->jpeg) c->carrier = jpeg_carrier(c->jpeg);
    } else {
        c->png = png_load(path);
        if (c->png) c->carrier = carrier_of_image(c->png);
    }
    if (!c->png && !c->jpeg) {
        fprintf(stderr, "Error: could not load '%s'\n", path);
        return -1;
    }
    return 0;
}

static void cover_free(Cover *c) {
    image_free(c->png);
    jpeg_free(c->jpeg);
}

/* A digest of all a decoder reads: the carrier's size and every sample, in
   order */
static void carrier_digest(const Carrier *c, uint8_t out[crypto_generichash_BYTES]) {
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, crypto_generichash_BYTES);
    uint32_t shape[2] = {carrier_positions(c), carrier_channels(c)};
    crypto_generichash_update(&st, (const uint8_t *)shape, sizeof(shape));
    if (c->img) {
        for (uint32_t y = 0; y < c->img->height; y++)
            crypto_generichash_update(&st, c->img->rows[y], (size_t)c->img->width * c->img->channels);
    } else {
        int16_t buf[4096];
        for (uint32_t i = 0; i < c->n_coefs;) {
            size_t n = 0;
            while (n < 4096 && i < c->n_coefs) buf[n++] = *c->coefs[i++];
            crypto_generichash_update(&st, (const uint8_t *)buf, n * sizeof(int16_t));
        }
    }
    crypto_generichash_final(&st, out, crypto_generichash_BYTES);
}

typedef struct {
    const char *buf;
    size_t len;
} Bytes;

static int write_bytes(FILE *fp, const void *ctx) {
    const Bytes *b = ctx;
    return fwrite(b->buf, 1, b->len, fp) == b->len ? 0 : -1;
}

/* Outcome of cover_save, besides 0 */
enum { SAVE_FAILED = -1, SAVE_UNREADABLE = -2, SAVE_CHANGED = -3 };

/* Encodes the cover in memory and reads that back: only if a decoder sees
   the same carrier does it go to path (atomically), so an encoder that
   changes a sample on the way out can't lose the message unnoticed. Frees
   the cover first, so only one image is in memory at a time. SAVE_FAILED
   leaves errno set (0 if the encoder failed); SAVE_UNREADABLE is also what
   running out of memory reading back gives. */
static int cover_save(Cover *c, const char *path) {
    uint8_t want[crypto_generichash_BYTES], got[crypto_generichash_BYTES];
    carrier_digest(&c->carrier, want);
    int is_jpeg = c->jpeg != NULL;

    char *buf = NULL;
    size_t len = 0;
    errno = 0;
    FILE *out = open_memstream(&buf, &len);
    int r = !out ? -1 : is_jpeg ? jpeg_write(c->jpeg, out) : png_write(c->png, out);
    if (out && fclose(out) != 0) r = -1;  /* also sets buf and len */
    cover_free(c);
    if (r != 0) {
        int err = errno;
        free(buf);
        errno = err;
        return SAVE_FAILED;
    }

    FILE *in = fmemopen(buf, len, "rb");
    Cover back = {0};
    if (in && is_jpeg) back.jpeg = jpeg_read(in);
    else if (in) back.png = png_read(in);
    if (!back.png && !back.jpeg) {
        free(buf);
        return SAVE_UNREADABLE;
    }
    back.carrier = is_jpeg ? jpeg_carrier(back.jpeg) : carrier_of_image(back.png);
    carrier_digest(&back.carrier, got);
    cover_free(&back);
    if (sodium_memcmp(want, got, sizeof(want)) != 0) {
        free(buf);
        return SAVE_CHANGED;
    }

    Bytes bytes = {buf, len};
    r = atomic_write(path, write_bytes, &bytes);
    int err = errno;
    free(buf);
    errno = err;
    return r == 0 ? 0 : SAVE_FAILED;
}

/* The output has the cover's format; refuse a name that says otherwise */
static int output_name_matches(const char *input, const char *output) {
    const char *ext = strrchr(output, '.');
    if (!ext) return 1;
    int says_jpeg = !strcasecmp(ext, ".jpg") || !strcasecmp(ext, ".jpeg");
    int says_png = !strcasecmp(ext, ".png");
    if (is_jpeg_file(input) ? says_png : says_jpeg) {
        fprintf(stderr, "Error: the output is a %s, like the cover; give it a %s name\n",
                is_jpeg_file(input) ? "JPEG" : "PNG", is_jpeg_file(input) ? ".jpg" : ".png");
        return 0;
    }
    return 1;
}

/* Read the entire contents of stdin into a sodium_malloc buffer.
   Prints a prompt first if stdin is a terminal. Caller must sodium_free.
   The message may hold any bytes, NUL included: its length (less a final
   newline, unless raw) goes in *out_len. Stops reading once that is longer than
   max_len, so a huge stdin can't exhaust memory or overflow the payload
   length: then sets *too_long and returns NULL. Also NULL on a read error
   or out of memory, with errno set. */
static char *read_message(size_t max_len, size_t *out_len, int *too_long, int raw) {
    *too_long = 0;
    if (isatty(STDIN_FILENO))
        fprintf(stderr, "Message (Ctrl+D when done):\n");

    size_t cap = 1024;
    size_t len = 0;
    char *buf = sodium_malloc(cap);
    if (!buf) return NULL;

    /* read(), not stdio: a FILE buffer would keep a copy of the message
       in ordinary heap memory, unlocked and never wiped */
    for (;;) {
        if (len + 1 >= cap) {
            /* Grow by copying; sodium_free wipes the old buffer */
            char *bigger = sodium_malloc(cap * 2);
            if (!bigger) { sodium_free(buf); return NULL; }
            memcpy(bigger, buf, len);
            sodium_free(buf);
            buf = bigger;
            cap *= 2;
        }
        /* max_len + 2 bytes in all tell a message that is too long */
        size_t want = cap - 1 - len;
        if (want > max_len + 2 - len) want = max_len + 2 - len;
        ssize_t n = read(STDIN_FILENO, buf + len, want);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) {  /* not the end: don't hide a partial message */
            int err = errno;
            sodium_free(buf);
            errno = err;
            return NULL;
        }
        if (n == 0) break;
        len += (size_t)n;
        if (len > max_len + 1) {  /* max_len + 1 is fine if the last is '\n' */
            sodium_free(buf);
            *too_long = 1;
            return NULL;
        }
    }

    if (!raw && len > 0 && buf[len - 1] == '\n')
        len--;
    if (len > max_len) {
        sodium_free(buf);
        *too_long = 1;
        return NULL;
    }
    buf[len] = '\0';
    *out_len = len;
    return buf;
}

/* Write all n bytes to fd, unbuffered: stdout's FILE buffer would keep a
   copy of secrets in ordinary heap memory. Returns 0, or -1 (errno set). */
static int write_all(int fd, const void *data, size_t n) {
    const char *p = data;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0 && errno == EINTR) continue;
        if (w < 0) return -1;
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

/* Print a random passphrase: 5 groups of 5 characters from a 31-character
   alphabet without look-alikes (0/o, 1/l/i), about 124 bits in all.
   Returns 0, or -1 (and says why) if it couldn't be written. */
static int generate_passphrase(void) {
    static const char alphabet[] = "abcdefghjkmnpqrstuvwxyz23456789";
    char out[30];
    size_t n = 0;
    for (int group = 0; group < 5; group++) {
        if (group) out[n++] = '-';
        for (int i = 0; i < 5; i++)
            out[n++] = alphabet[randombytes_uniform(sizeof(alphabet) - 1)];
    }
    out[n++] = '\n';
    int r = write_all(STDOUT_FILENO, out, n);
    sodium_memzero(out, sizeof(out));
    if (r != 0) fprintf(stderr, "Error: could not write the passphrase: %s\n", strerror(errno));
    return r;
}

/* sodium_malloc locks memory against swapping only within the locked
   memory limit (RLIMIT_MEMLOCK, often 8 MiB), and says nothing when it
   can't. Locking len bytes at p again tells: say so if they aren't. */
static void warn_if_swappable(void *p, size_t len) {
    if (len == 0 || sodium_mlock(p, len) == 0) return;
    struct rlimit lock;
    if (getrlimit(RLIMIT_MEMLOCK, &lock) == 0 && lock.rlim_cur != RLIM_INFINITY)
        fprintf(stderr, "Warning: the message is larger than the memory this process may lock "
                        "(%llu KiB, see `ulimit -l`), so it may be written to swap\n",
                (unsigned long long)lock.rlim_cur / 1024);
    else
        fprintf(stderr, "Warning: the message could not be locked in memory, "
                        "so it may be written to swap\n");
}

/* Keep secrets out of core dumps, and (Linux) stop other processes of the
   same user from attaching a debugger to read them */
static void protect_process(void) {
    struct rlimit none = {0, 0};
    setrlimit(RLIMIT_CORE, &none);
    /* Let sodium_malloc lock as much as we may: the soft limit can be
       below the hard one */
    struct rlimit lock;
    if (getrlimit(RLIMIT_MEMLOCK, &lock) == 0 && lock.rlim_cur < lock.rlim_max) {
        lock.rlim_cur = lock.rlim_max;
        setrlimit(RLIMIT_MEMLOCK, &lock);
    }
#ifdef __linux__
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s encode [-r] -i <cover.png|jpg> -o <output.png|jpg>\n", prog);
    fprintf(stderr, "       %s decode [-r] -i <image.png|jpg>\n", prog);
    fprintf(stderr, "       %s passphrase\n", prog);
    fprintf(stderr, "Message is read from stdin. `passphrase` prints a strong random passphrase.\n");
    fprintf(stderr, "Without -r, encode drops one trailing newline and decode adds one; -r keeps the bytes exactly.\n");
}

int main(int argc, char *argv[]) {
    protect_process();
    if (sodium_init() < 0) {
        fprintf(stderr, "Error: failed to initialise libsodium\n");
        return 1;
    }

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const char *input  = NULL;
    const char *output = NULL;
    int raw = 0;  /* -r: no newline stripped from the message or added to it */

    int opt;
    while ((opt = getopt(argc - 1, argv + 1, "i:o:r")) != -1) {
        switch (opt) {
            case 'i': input  = optarg; break;
            case 'o': output = optarg; break;
            case 'r': raw = 1; break;
            default:
                usage(argv[0]);
                return 1;
        }
    }

    if (strcmp(argv[1], "passphrase") == 0) {
        if (generate_passphrase() != 0) return 1;

    } else if (strcmp(argv[1], "encode") == 0) {
        if (!input || !output) {
            fprintf(stderr, "Error: encode requires -i and -o\n");
            usage(argv[0]);
            return 1;
        }
        /* Before the name check, which reads the input's first bytes: a
           missing file would otherwise be called a PNG */
        FILE *in = fopen(input, "rb");
        if (!in) {
            fprintf(stderr, "Error: could not load '%s': %s\n", input, strerror(errno));
            return 1;
        }
        fclose(in);
        if (!output_name_matches(input, output)) return 1;
        /* Checked again when writing; here, before the passphrase prompt */
        struct stat out_st;
        if (stat(output, &out_st) == 0 && !S_ISREG(out_st.st_mode)) {
            fprintf(stderr, "Error: '%s' exists and is not a regular file\n", output);
            return 1;
        }

        char *passphrase = read_passphrase("Passphrase: ", 0);
        if (!passphrase) return 1;
        if (strlen(passphrase) < PASSPHRASE_MIN_LEN) {
            free_passphrase(passphrase);
            fprintf(stderr, "Error: passphrase too short (min %d bytes); "
                            "`scattersteg passphrase` generates a strong one\n", PASSPHRASE_MIN_LEN);
            return 1;
        }
        char *confirm = read_passphrase("Confirm passphrase: ", 0);
        if (!confirm) {
            free_passphrase(passphrase);
            return 1;
        }
        if (strcmp(passphrase, confirm) != 0) {
            free_passphrase(passphrase);
            free_passphrase(confirm);
            fprintf(stderr, "Error: passphrases do not match\n");
            return 1;
        }
        free_passphrase(confirm);

        Cover cover;
        if (cover_load(input, &cover) != 0) {
            free_passphrase(passphrase);
            return 1;
        }

        /* A PNG output is 8-bit RGB or gray: any other cover would come out
           in a visibly different format, which gives it away */
        if (cover.png && cover.png->unsuitable) {
            free_passphrase(passphrase);
            fprintf(stderr, "Error: '%s' has %s, which the output can't keep; "
                            "use an 8-bit RGB or grayscale PNG without transparency "
                            "as the cover\n", input, cover.png->unsuitable);
            cover_free(&cover);
            return 1;
        }

        if (cover.jpeg && jpeg_unsuitable(cover.jpeg)) {
            free_passphrase(passphrase);
            fprintf(stderr, "Error: '%s' has %s, which the output can't keep; "
                            "use another cover\n", input, jpeg_unsuitable(cover.jpeg));
            cover_free(&cover);
            return 1;
        }

        /* Before jpeg_check_writable, which decodes the cover again: a few
           bytes can declare a huge frame with next to no carriers */
        if (codec_too_small(&cover.carrier)) {
            free_passphrase(passphrase);
            cover_free(&cover);
            fprintf(stderr, "Error: image too small to hide a message\n");
            return 1;
        }

        if (cover.jpeg && jpeg_check_writable(cover.jpeg) != 0) {
            free_passphrase(passphrase);
            fprintf(stderr, "Error: '%s' is a JPEG that can't be rewritten losslessly; "
                            "use another cover\n", input);
            cover_free(&cover);
            return 1;
        }

        Carrier carrier = cover.carrier;
        CodecPrepared *prep = codec_prepare(&carrier, passphrase);
        free_passphrase(passphrase);
        if (!prep) {
            cover_free(&cover);
            return 1;
        }

        int too_long;
        size_t message_len;
        char *message = read_message(codec_max_message(prep), &message_len, &too_long, raw);
        int read_err = errno;  /* before the cleanup below changes it */
        if (!message) {
            codec_prepared_free(prep);
            cover_free(&cover);
            if (too_long) fprintf(stderr, "Error: message too long for this image\n");
            else fprintf(stderr, "Error: could not read message: %s\n", strerror(read_err));
            return 1;
        }
        uint32_t msg_len = (uint32_t)message_len;  /* at most codec_max_message */
        warn_if_swappable(message, msg_len);
        /* Empty message: nothing to hide, so write nothing */
        if (msg_len == 0) {
            codec_prepared_free(prep);
            sodium_free(message);
            cover_free(&cover);
            fprintf(stderr, "Message is empty; nothing written\n");
            return 0;
        }

        int embedded = codec_embed(prep, &carrier, (const uint8_t *)message, msg_len);
        sodium_free(message);
        if (embedded != 0) {
            cover_free(&cover);
            fprintf(stderr, embedded == -1 ? "Error: message too long for this image\n"
                                           : "Error: allocation failed\n");
            return 1;
        }
        int is_png = cover.png != NULL;
        int saved = cover_save(&cover, output);  /* frees the cover */
        if (saved == SAVE_FAILED) {
            fprintf(stderr, "Error: could not write '%s': %s\n", output,
                    errno ? strerror(errno) : is_png ? "PNG encoding failed" : "JPEG encoding failed");
            return 1;
        }
        if (saved != 0) {
            fprintf(stderr, saved == SAVE_UNREADABLE
                        ? "Error: could not read the output back to check it (out of memory?); "
                          "nothing written\n"
                        : "Error: the output didn't read back as written, so the message would be "
                          "lost; nothing written. Please report this, with the cover if you can\n");
            return 1;
        }

    } else if (strcmp(argv[1], "decode") == 0) {
        if (!input) {
            fprintf(stderr, "Error: decode requires -i\n");
            usage(argv[0]);
            return 1;
        }

        char *passphrase = read_passphrase("Passphrase: ", 1);
        if (!passphrase) return 1;

        Cover cover;
        if (cover_load(input, &cover) != 0) {
            free_passphrase(passphrase);
            return 1;
        }
        Carrier carrier = cover.carrier;
        if (carrier_positions(&carrier) < codec_header_pixels(carrier_channels(&carrier))) {
            free_passphrase(passphrase);
            cover_free(&cover);
            fprintf(stderr, "Error: image too small to contain a message\n");
            return 1;
        }

        uint8_t *plaintext = NULL;
        uint32_t pt_len = 0;
        int v1;
        int r = codec_decode(&carrier, passphrase, &plaintext, &pt_len, &v1);
        if (v1)
            fprintf(stderr, "Warning: this image uses the old v1 format, which protects "
                            "the passphrase less well; re-encode it\n");
        free_passphrase(passphrase);
        cover_free(&cover);
        if (r == NO_MATCH)
            fprintf(stderr, "Error: decryption failed — wrong passphrase, "
                            "or no message in this image\n");
        if (r != DECODED) return 1;

        warn_if_swappable(plaintext, pt_len);
        if (pt_len > 0) {  /* empty message: print nothing */
            /* All of it, NULs too. The newline goes in the same write, so
               the plaintext buffer has room: open_box allocates pt_len + 1. */
            if (!raw) plaintext[pt_len] = '\n';
            if (write_all(STDOUT_FILENO, plaintext, pt_len + !raw) != 0) {
                /* e.g. a full disk: the message was not saved */
                fprintf(stderr, "Error: could not write the message: %s\n", strerror(errno));
                sodium_free(plaintext);
                return 1;
            }
        }
        sodium_free(plaintext);

    } else {
        fprintf(stderr, "Error: unknown command '%s'\n", argv[1]);
        usage(argv[0]);
        return 1;
    }

    return 0;
}
