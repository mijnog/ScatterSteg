/* SPDX-License-Identifier: MIT OR Apache-2.0
   Copyright (C) 2026 Maxime de Montbron */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
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
/* Shorter passphrases are refused on encode (on decode, one can only fail).
   Length is a crude measure, so `passphrase` generates good ones. */
#define PASSPHRASE_MIN_LEN 12
/* As in rust/Cargo.toml, which tests/test_cli.py checks */
#define SCATTERSTEG_VERSION "0.1.0"

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
   As a C string it would end at the first NUL (typed as Ctrl+@, or pasted),
   which would silently cut it short: refused. */
static char *read_passphrase(const char *prompt) {
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

    /* One byte at a time with read(): even unbuffered, stdio passes each
       byte through a buffer of its own, which nothing wipes */
    size_t cap = PASSPHRASE_CHUNK;
    size_t len = 0;
    char *buf = sodium_malloc(cap);
    unsigned char c = 0;
    int hit_eof = 0;
    while (buf) {
        ssize_t n = read(fd, &c, 1);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            hit_eof = 1;
            break;
        }
        if (c == '\n') break;
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
    sodium_memzero(&c, sizeof c);  /* the last byte read */

    tcsetattr(fd, TCSAFLUSH, &old);
    for (size_t i = 0; i < N_RESTORE_SIGNALS; i++)
        sigaction(restore_signals[i], &saved[i], NULL);
    fputs("\n", tty);
    fclose(tty);

    if (!buf || (hit_eof && len == 0)) {  /* out of memory, or Ctrl+D */
        sodium_free(buf);
        fprintf(stderr, "Error: could not read passphrase\n");
        return NULL;
    }
    if (len > PASSPHRASE_MAX_LEN) {
        sodium_free(buf);
        fprintf(stderr, "Error: passphrase too long (max %d bytes)\n", PASSPHRASE_MAX_LEN);
        return NULL;
    }
    if (memchr(buf, '\0', len)) {
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

/* Whether the cover can carry a message: the output would keep its format
   and not give the changes away, and it holds at least one byte. If not,
   prints why and returns -1. Checks a JPEG can be rewritten by encoding it
   in memory, so it costs about as much as loading it. */
static int cover_check(Cover *c, const char *path) {
    /* A PNG output is 8-bit RGB or gray: any other cover would come out
       in a visibly different format, which gives it away */
    if (c->png && c->png->unsuitable) {
        fprintf(stderr, "Error: '%s' has %s, which the output can't keep; "
                        "use an 8-bit RGB or grayscale PNG without transparency "
                        "as the cover\n", path, c->png->unsuitable);
        return -1;
    }
    if (c->jpeg && jpeg_unsuitable(c->jpeg)) {
        fprintf(stderr, "Error: '%s' has %s, which the output can't keep; "
                        "use another cover\n", path, jpeg_unsuitable(c->jpeg));
        return -1;
    }
    /* Before jpeg_check_writable, which decodes the cover again: a few
       bytes can declare a huge frame with next to no carriers */
    if (codec_capacity(&c->carrier) == 0) {
        fprintf(stderr, "Error: image too small to hide a message\n");
        return -1;
    }
    if (c->jpeg && jpeg_check_writable(c->jpeg) != 0) {
        fprintf(stderr, "Error: '%s' is a JPEG that can't be rewritten losslessly; "
                        "use another cover\n", path);
        return -1;
    }
    return 0;
}

/* The suggested most to store in the cover (see
   CODEC_SUGGESTED_UNITS_PER_BYTE), never more than it holds */
static size_t suggested(const Cover *c) {
    uint64_t units = c->png ? (uint64_t)c->png->width * c->png->height : jpeg_nonzero_ac(c->jpeg);
    size_t most = (size_t)(units / CODEC_SUGGESTED_UNITS_PER_BYTE), holds = codec_capacity(&c->carrier);
    return most < holds ? most : holds;
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

/* Read all of fd into a sodium_malloc buffer, byte for byte (NUL
   included); its length goes in *out_len. Caller must sodium_free.
   Prints a prompt first if prompt is set and fd is a terminal. Stops
   reading once that is longer than max_len, so a huge input can't exhaust
   memory or overflow the payload length: then sets *too_long and returns
   NULL. Also NULL on a read error or out of memory, with errno set. */
static char *read_message(int fd, size_t max_len, size_t *out_len, int *too_long, int prompt) {
    *too_long = 0;
    if (prompt && isatty(fd))
        fprintf(stderr, "Message (Ctrl+D when done):\n");

    size_t cap = 1024;
    size_t len = 0;
    char *buf = sodium_malloc(cap);
    if (!buf) return NULL;

    /* read(), not stdio: a FILE buffer would keep a copy of the message
       in ordinary heap memory, unlocked and never wiped */
    for (;;) {
        if (len == cap) {
            /* Grow by copying; sodium_free wipes the old buffer */
            char *bigger = sodium_malloc(cap * 2);
            if (!bigger) { sodium_free(buf); return NULL; }
            memcpy(bigger, buf, len);
            sodium_free(buf);
            buf = bigger;
            cap *= 2;
        }
        /* max_len + 1 bytes in all tell a message that is too long */
        size_t want = cap - len;
        if (want > max_len + 1 - len) want = max_len + 1 - len;
        ssize_t n = read(fd, buf + len, want);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) {  /* not the end: don't hide a partial message */
            int err = errno;
            sodium_free(buf);
            errno = err;
            return NULL;
        }
        if (n == 0) break;
        len += (size_t)n;
        if (len > max_len) {
            sodium_free(buf);
            *too_long = 1;
            return NULL;
        }
    }
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

/* The command line has steghide's syntax (its commands and option names,
   for the features ScatterSteg has), so its users find what they know; the
   wording is ScatterSteg's own. See CLAUDE.md. */

/* The synopsis, to stderr after a mistake; with the options too, to
   stdout, when asked for (help) */
static void usage(FILE *out, const char *prog) {
    fprintf(out, "Usage: %s embed -cf <cover.png|jpg> [-ef <file>] [-sf <output.png|jpg>] [options]\n", prog);
    fprintf(out, "       %s extract -sf <image.png|jpg> [-xf <file>] [options]\n", prog);
    fprintf(out, "       %s info <image.png|jpg>\n", prog);
    fprintf(out, "       %s passphrase | encinfo | license | version | help\n", prog);
    if (out != stdout) return;
    fprintf(out, "\n"
                 "embed hides a file (-ef, or standard input) in a cover image, writing\n"
                 "the result to -sf, or over the cover if there's no -sf. extract gets it\n"
                 "back: into -xf, else into the file name stored with it, else onto\n"
                 "standard output (-xf - for that always). The passphrase is always typed\n"
                 "at the prompt. info says whether an image can be a cover, and how much\n"
                 "it holds; passphrase prints a strong random passphrase.\n"
                 "\n"
                 "  -z, --compress [1-9]   compression level, 9 (the default) smallest\n"
                 "  -Z, --dontcompress     store the file as is\n"
                 "  -N, --dontembedname    don't store the file's name\n"
                 "  -f, --force            replace files that already exist\n"
                 "  -q, --quiet            print only prompts, warnings and errors\n"
                 "  -v, --verbose          say what was stored, and how\n"
                 "Long forms of the others: --embedfile, --coverfile, --stegofile, --extractfile.\n");
}

enum { CMD_EMBED = 1, CMD_EXTRACT = 2, CMD_INFO = 4 };

typedef struct {
    const char *short_name, *long_name;
    int commands;          /* the CMD_* it belongs to */
    int takes;             /* 0: nothing, 1: a value, 2: a level, if one follows */
    const char *refused;   /* why ScatterSteg doesn't take it, or NULL */
} OptionSpec;

static const OptionSpec option_specs[] = {
    {"-ef", "--embedfile",     CMD_EMBED,               1, NULL},
    {"-cf", "--coverfile",     CMD_EMBED,               1, NULL},
    {"-sf", "--stegofile",     CMD_EMBED | CMD_EXTRACT, 1, NULL},
    {"-xf", "--extractfile",   CMD_EXTRACT,             1, NULL},
    {"-z",  "--compress",      CMD_EMBED,               2, NULL},
    {"-Z",  "--dontcompress",  CMD_EMBED,               0, NULL},
    {"-N",  "--dontembedname", CMD_EMBED,               0, NULL},
    {"-f",  "--force",         CMD_EMBED | CMD_EXTRACT, 0, NULL},
    {"-q",  "--quiet",         CMD_EMBED | CMD_EXTRACT, 0, NULL},
    {"-v",  "--verbose",       CMD_EMBED | CMD_EXTRACT, 0, NULL},
    {"-p",  "--passphrase",    0, 1, "the passphrase is never taken on the command line, where "
                                     "other users (ps) and the shell history could read it; "
                                     "type it at the prompt"},
    {"-e",  "--encryption",    0, 1, "the encryption is fixed (XSalsa20-Poly1305) and always on "
                                     "(see encinfo)"},
    {"-K",  "--nochecksum",    0, 0, "the message is always authenticated (Poly1305), which "
                                     "checks its integrity; there is no separate checksum"},
};

typedef struct {
    const char *embed_file, *cover_file, *stego_file, *extract_file;
    const char *operand;  /* info's image */
    int level;            /* compression level 1-9, or 0 for -Z */
    int no_name, force, quiet, verbose;
} Options;

/* The options after the command. Prints why and returns -1 if they don't
   make sense for it. */
static int parse_options(int cmd, const char *cmd_name, int argc, char *argv[], Options *o) {
    memset(o, 0, sizeof(*o));
    o->level = 9;
    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];
        const OptionSpec *spec = NULL;
        for (size_t k = 0; k < sizeof(option_specs) / sizeof(option_specs[0]); k++)
            if (!strcmp(a, option_specs[k].short_name) || !strcmp(a, option_specs[k].long_name))
                spec = &option_specs[k];
        if (!spec) {
            if (a[0] == '-' && a[1]) {
                fprintf(stderr, "Error: unknown option '%s'\n", a);
                return -1;
            }
            if (cmd == CMD_INFO && !o->operand) {
                o->operand = a;
                continue;
            }
            fprintf(stderr, "Error: unexpected argument '%s'\n", a);
            return -1;
        }
        if (spec->refused) {
            fprintf(stderr, "Error: %s isn't supported: %s\n", a, spec->refused);
            return -1;
        }
        if (!(spec->commands & cmd)) {
            fprintf(stderr, "Error: %s is not an option of %s\n", a, cmd_name);
            return -1;
        }
        const char *value = NULL;
        if (spec->takes == 1) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: %s needs a value\n", a);
                return -1;
            }
            value = argv[++i];
        }
        switch (spec->short_name[1]) {
            case 'e': o->embed_file = value; break;
            case 'c': o->cover_file = value; break;
            case 's': o->stego_file = value; break;
            case 'x': o->extract_file = value; break;
            case 'z':
                o->level = 9;
                if (i + 1 < argc && argv[i + 1][0] >= '1' && argv[i + 1][0] <= '9' && !argv[i + 1][1])
                    o->level = argv[++i][0] - '0';
                break;
            case 'Z': o->level = 0; break;
            case 'N': o->no_name = 1; break;
            case 'f': o->force = 1; break;
            case 'q': o->quiet = 1; break;
            case 'v': o->verbose = 1; break;
        }
    }
    return 0;
}

/* Whether a and b name the same existing file */
static int same_file(const char *a, const char *b) {
    struct stat sa, sb;
    return stat(a, &sa) == 0 && stat(b, &sb) == 0 && sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
}

/* Says so and returns 1 if path exists (a dangling link too) and force
   isn't set: only -f replaces a file */
static int refuse_existing(const char *path, int force, const char *hint) {
    struct stat st;
    if (force || lstat(path, &st) != 0) return 0;
    fprintf(stderr, "Error: '%s' already exists; use -f to replace it%s\n", path, hint);
    return 1;
}

/* atomic_write's writer for a secret: unbuffered, so stdio keeps no copy of
   it in ordinary heap memory */
static int write_secret(FILE *fp, const void *ctx) {
    const Bytes *b = ctx;
    if (setvbuf(fp, NULL, _IONBF, 0) != 0) return -1;
    return fwrite(b->buf, 1, b->len, fp) == b->len ? 0 : -1;
}

static int do_embed(const Options *o) {
    if (!o->cover_file) {
        fprintf(stderr, "Error: embed needs a cover image: -cf <cover.png|jpg>\n");
        return 1;
    }
    const char *output = o->stego_file ? o->stego_file : o->cover_file;
    if (!strcmp(o->cover_file, "-") || !strcmp(output, "-")) {
        fprintf(stderr, "Error: the cover and the output must be files, not standard "
                        "input or output\n");
        return 1;
    }
    /* Before the name check, which reads the cover's first bytes: a
       missing file would otherwise be called a PNG */
    FILE *in = fopen(o->cover_file, "rb");
    if (!in) {
        fprintf(stderr, "Error: could not load '%s': %s\n", o->cover_file, strerror(errno));
        return 1;
    }
    fclose(in);
    if (!output_name_matches(o->cover_file, output)) return 1;
    /* Checked again when writing; here, before the passphrase prompt */
    struct stat out_st;
    if (stat(output, &out_st) == 0 && !S_ISREG(out_st.st_mode)) {
        fprintf(stderr, "Error: '%s' exists and is not a regular file\n", output);
        return 1;
    }
    /* Writing over the cover is what embed without -sf is for */
    if (!same_file(o->cover_file, output) && refuse_existing(output, o->force, "")) return 1;

    /* The message: -ef's file, with its name unless -N, or standard input */
    int from_stdin = !o->embed_file || !strcmp(o->embed_file, "-");
    const char *name = NULL;
    int fd = STDIN_FILENO;
    if (!from_stdin) {
        fd = open(o->embed_file, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            fprintf(stderr, "Error: could not read '%s': %s\n", o->embed_file, strerror(errno));
            return 1;
        }
        const char *slash = strrchr(o->embed_file, '/');
        name = o->no_name ? NULL : slash ? slash + 1 : o->embed_file;
        if (name && !codec_name_ok(name)) {
            fprintf(stderr, "Error: the file's name can't be stored with it (at most %d bytes, "
                            "no control characters); rename it, or use -N\n", CODEC_NAME_MAX);
            close(fd);
            return 1;
        }
    }

    int status = 1;
    char *passphrase = NULL, *message = NULL;
    Cover cover = {0};
    CodecPrepared *prep = NULL;
    size_t holds = 0, suggest = 0, message_len = 0;
    int too_long = 0, read_err = 0;
    CodecEmbedded stored;

    passphrase = read_passphrase("Passphrase: ");
    if (!passphrase) goto done;
    if (strlen(passphrase) < PASSPHRASE_MIN_LEN) {
        fprintf(stderr, "Error: passphrase too short (min %d bytes); "
                        "`scattersteg passphrase` generates a strong one\n", PASSPHRASE_MIN_LEN);
        goto done;
    }
    char *confirm = read_passphrase("Confirm passphrase: ");
    if (!confirm) goto done;
    int match = strcmp(passphrase, confirm) == 0;
    free_passphrase(confirm);
    if (!match) {
        fprintf(stderr, "Error: passphrases do not match\n");
        goto done;
    }

    if (cover_load(o->cover_file, &cover) != 0 || cover_check(&cover, o->cover_file) != 0)
        goto done;
    suggest = suggested(&cover);
    if (!o->quiet) fprintf(stderr, "Deriving keys...\n");
    prep = codec_prepare(&cover.carrier, passphrase);
    free_passphrase(passphrase);
    passphrase = NULL;
    if (!prep) goto done;
    holds = codec_max_message(prep);

    message = read_message(fd, CODEC_MESSAGE_MAX, &message_len, &too_long, from_stdin && !o->quiet);
    read_err = errno;  /* before the cleanup below changes it */
    if (!message) {
        if (too_long) fprintf(stderr, "Error: message too long (max %u MiB)\n", CODEC_MESSAGE_MAX >> 20);
        else fprintf(stderr, "Error: could not read the message: %s\n", strerror(read_err));
        goto done;
    }
    warn_if_swappable(message, message_len);
    /* Empty message: almost always a mistake (nothing piped in, an empty
       file, Ctrl+D too soon), and a script must not take it for a written
       output: fail, and write nothing */
    if (message_len == 0) {
        fprintf(stderr, "Error: the message is empty; nothing written\n");
        goto done;
    }

    int embedded = codec_embed(prep, &cover.carrier, name, (const uint8_t *)message,
                               (uint32_t)message_len, o->level, &stored);
    prep = NULL;  /* codec_embed freed it */
    sodium_free(message);
    message = NULL;
    if (embedded == -1) {
        fprintf(stderr, "Error: message too long for this image, which holds %zu bytes "
                        "(more if the message compresses well%s)\n",
                holds, name ? ", less the file name's length" : "");
        goto done;
    } else if (embedded != 0) {
        fprintf(stderr, "Error: allocation failed\n");
        goto done;
    }
    int is_png = cover.png != NULL;
    int saved = cover_save(&cover, output);  /* frees the cover */
    cover = (Cover){0};
    if (saved == SAVE_FAILED) {
        fprintf(stderr, "Error: could not write '%s': %s\n", output,
                errno ? strerror(errno) : is_png ? "PNG encoding failed" : "JPEG encoding failed");
        goto done;
    }
    if (saved != 0) {
        fprintf(stderr, saved == SAVE_UNREADABLE
                    ? "Error: could not read the output back to check it (out of memory?); "
                      "nothing written\n"
                    : "Error: the output didn't read back as written, so the message would be "
                      "lost; nothing written. Please report this, with the cover if you can\n");
        goto done;
    }
    /* Advice, not a limit: lighter payloads are harder to detect */
    if (!o->quiet && stored.hidden - 1 > suggest)
        fprintf(stderr, "Warning: %u bytes stored, more than the %zu suggested for this image;\n"
                        "the more is hidden, the easier it is to detect (see `scattersteg info`)\n",
                stored.hidden - 1, suggest);
    if (o->verbose)
        fprintf(stderr, "Stored %zu bytes%s%s%s as %u (%s), in an image that holds %zu as is\n",
                message_len, name ? " from '" : "", name ? name : "", name ? "'" : "",
                stored.hidden, stored.compressed ? "compressed" : "not compressed", holds);
    if (!o->quiet) fprintf(stderr, "Wrote '%s'\n", output);
    status = 0;

done:
    if (fd != STDIN_FILENO) close(fd);
    free_passphrase(passphrase);
    sodium_free(message);
    codec_prepared_free(prep);
    cover_free(&cover);
    return status;
}

static int do_extract(const Options *o) {
    if (!o->stego_file) {
        fprintf(stderr, "Error: extract needs an image: -sf <image.png|jpg>\n");
        return 1;
    }
    if (!strcmp(o->stego_file, "-")) {
        fprintf(stderr, "Error: the image must be a file, not standard input\n");
        return 1;
    }
    int to_stdout = o->extract_file && !strcmp(o->extract_file, "-");
    if (o->extract_file && !to_stdout && refuse_existing(o->extract_file, o->force, ""))
        return 1;

    char *passphrase = read_passphrase("Passphrase: ");
    if (!passphrase) return 1;
    Cover cover;
    if (cover_load(o->stego_file, &cover) != 0) {
        free_passphrase(passphrase);
        return 1;
    }
    if (carrier_positions(&cover.carrier) < codec_header_pixels(carrier_channels(&cover.carrier))) {
        free_passphrase(passphrase);
        cover_free(&cover);
        fprintf(stderr, "Error: image too small to contain a message\n");
        return 1;
    }

    uint8_t *plaintext = NULL;
    uint32_t pt_len = 0;
    char name[CODEC_NAME_MAX + 1] = "";
    if (!o->quiet) fprintf(stderr, "Deriving keys...\n");
    int r = codec_decode(&cover.carrier, passphrase, &plaintext, &pt_len, name);
    free_passphrase(passphrase);
    cover_free(&cover);
    if (r == NO_MATCH)
        fprintf(stderr, "Error: decryption failed — wrong passphrase, "
                        "or no message in this image\n");
    if (r != DECODED) return 1;

    /* Where it goes: -xf, else the name stored with it, else stdout */
    const char *dest = to_stdout ? NULL : o->extract_file ? o->extract_file : name[0] ? name : NULL;
    int status = 1;
    warn_if_swappable(plaintext, pt_len);
    if (o->verbose)
        fprintf(stderr, "Found %u bytes%s%s%s\n", pt_len, name[0] ? ", stored as '" : "",
                name, name[0] ? "'" : "");
    if (!dest) {
        /* All of it, NULs too, unbuffered (write_all) */
        if (write_all(STDOUT_FILENO, plaintext, pt_len) != 0)
            fprintf(stderr, "Error: could not write the message: %s\n", strerror(errno));
        else
            status = 0;
    } else if (dest == name && refuse_existing(name, o->force, ", or -xf to choose another name")) {
        /* nothing written */
    } else {
        Bytes bytes = {(const char *)plaintext, pt_len};
        if (atomic_write(dest, write_secret, &bytes) != 0) {
            fprintf(stderr, "Error: could not write '%s': %s\n", dest,
                    errno ? strerror(errno) : "write failed");
        } else {
            if (!o->quiet) fprintf(stderr, "Wrote '%s'\n", dest);
            status = 0;
        }
    }
    sodium_free(plaintext);
    return status;
}

/* info: the cover's format and size, and the longest message it holds,
   or why it can't be a cover. Needs no passphrase: the capacity depends on
   the image alone. Returns the exit status. */
static int show_info(const char *input) {
    Cover cover;
    if (cover_load(input, &cover) != 0) return 1;
    if (cover_check(&cover, input) != 0) {
        cover_free(&cover);
        return 1;
    }
    uint32_t w, h;
    char format[64];
    if (cover.png) {
        w = cover.png->width;
        h = cover.png->height;
        snprintf(format, sizeof(format), "PNG, %ux%u, %s", w, h,
                 cover.png->channels == 1 ? "gray" : "RGB");
    } else {
        jpeg_size(cover.jpeg, &w, &h);
        snprintf(format, sizeof(format), "JPEG, %ux%u", w, h);
    }
    size_t capacity = codec_capacity(&cover.carrier), suggest = suggested(&cover);
    cover_free(&cover);

    char out[256];
    int n = snprintf(out, sizeof(out), "Format:    %s\n"
                                       "Capacity:  %zu bytes (more if the message compresses)\n"
                                       "Suggested: at most %zu bytes; less is harder to detect\n",
                     format, capacity, suggest);
    if (write_all(STDOUT_FILENO, out, (size_t)n) != 0) {
        fprintf(stderr, "Error: could not write the information: %s\n", strerror(errno));
        return 1;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    protect_process();
    if (sodium_init() < 0) {
        fprintf(stderr, "Error: failed to initialise libsodium\n");
        return 1;
    }

    if (argc < 2) {
        usage(stderr, argv[0]);
        return 1;
    }

    /* Each command also as --command, and help as -h */
    const char *cmd = argv[1];
    if (!strncmp(cmd, "--", 2) && strcmp(cmd, "--passphrase") != 0) cmd += 2;
    else if (!strcmp(cmd, "-h")) cmd = "help";

    int which = !strcmp(cmd, "embed") ? CMD_EMBED : !strcmp(cmd, "extract") ? CMD_EXTRACT
              : !strcmp(cmd, "info") ? CMD_INFO : 0;
    if (which) {
        Options o;
        if (parse_options(which, cmd, argc, argv, &o) != 0) {
            usage(stderr, argv[0]);
            return 1;
        }
        if (which == CMD_EMBED) return do_embed(&o);
        if (which == CMD_EXTRACT) return do_extract(&o);
        if (!o.operand) {
            fprintf(stderr, "Error: info needs an image: info <image.png|jpg>\n");
            usage(stderr, argv[0]);
            return 1;
        }
        return show_info(o.operand);
    }

    int bare = !strcmp(cmd, "passphrase") || !strcmp(cmd, "encinfo") || !strcmp(cmd, "license") ||
               !strcmp(cmd, "version") || !strcmp(cmd, "help");
    if (!bare) {
        fprintf(stderr, "Error: unknown command '%s'\n", argv[1]);
        usage(stderr, argv[0]);
        return 1;
    }
    if (argc > 2) {
        fprintf(stderr, "Error: %s takes no options or arguments\n", cmd);
        usage(stderr, argv[0]);
        return 1;
    }

    if (!strcmp(cmd, "passphrase")) return generate_passphrase() == 0 ? 0 : 1;
    if (!strcmp(cmd, "help")) {
        usage(stdout, argv[0]);
        return fflush(stdout) == 0 ? 0 : 1;
    }
    const char *text = !strcmp(cmd, "version")
        ? "scattersteg " SCATTERSTEG_VERSION "\n"
        : !strcmp(cmd, "encinfo")
        ? "ScatterSteg always encrypts and authenticates the message with XSalsa20-Poly1305\n"
          "(libsodium's secretbox), keyed by Argon2id from the passphrase: there is no\n"
          "algorithm or mode to choose.\n"
        : "ScatterSteg " SCATTERSTEG_VERSION "\n"
          "Copyright (C) 2026 Maxime de Montbron\n"
          "Free software under the MIT license or the Apache License 2.0, at your option: you may\n"
          "use, change and share it on its terms. It comes with NO WARRANTY. See the\n"
          "LICENSE-MIT and LICENSE-APACHE files, or <https://opensource.org/license/mit> and\n"
          "<https://www.apache.org/licenses/LICENSE-2.0>.\n";
    if (write_all(STDOUT_FILENO, text, strlen(text)) != 0) {
        fprintf(stderr, "Error: could not write: %s\n", strerror(errno));
        return 1;
    }
    return 0;
}
