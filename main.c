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
#include "prng.h"
#include "embed.h"
#include "stc.h"

#define PASSPHRASE_CHUNK 256  /* passphrase buffer grows by this much */
/* The terminal's line editor holds 4095 bytes per line and silently drops
   the rest, so a line that long may have been cut short: refuse it. */
#define PASSPHRASE_MAX_LEN 4094
/* Shorter passphrases are refused on encode (decode accepts any, for old
   images). Length is a crude measure, so `passphrase` generates good ones. */
#define PASSPHRASE_MIN_LEN 12

/* Secrets (passphrase, message, keys, plaintext) live in sodium_malloc
   memory: locked so it can't be swapped to disk, fenced by guard pages, and
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
   buffer for free_passphrase; on EOF or error, prints why and returns NULL. */
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
    buf[len] = '\0';
    return buf;
}

/* ---- File format ----------------------------------------------------------

   v3 (written by encode):
     salt     16 random bytes, in the first 43 pixels (RGB; 128 for gray)
              of a public permutation (prng_permutation keyed with BLAKE2b
              of V2_SALT_LABEL), so it is spread over the image
     keys     master = Argon2id(passphrase, salt, "moderate": 3 passes,
              256 MiB); scatter and encryption keys = crypto_kdf subkeys 1
              and 2 of master, context V2_KDF_CONTEXT
     order    prng_permutation(scatter key) with the salt pixels removed
     payload  [nonce 24 | secretbox]: its 32-bit little-endian length in
              the first 32 samples in that order, then its bits as the STC
              syndrome of the samples after them (see v3_carriers, stc.h)

   v2 (decode only): salt, keys and order as v3; the length, then the
     payload's bits written straight into the samples in order.

   v1 (decode only): scatter key = keyed BLAKE2b of the passphrase alone,
     which let a wrong passphrase be rejected without Argon2id; payload =
     length, then [salt 16 | nonce 24 | secretbox] in prng_scatter order;
     encryption key = Argon2id(passphrase, salt, "interactive").

   Every pixel carries one bit per sample (R, G, B, or gray LSBs), written
   by LSB matching (a JPEG: one per carrier coefficient). There is no
   version marker, which would itself give the image away: decode tries
   v3, then v2, then v1 (RGB PNG only). */

#define SALT_BYTES      crypto_pwhash_SALTBYTES             /* 16 */
#define MAX_SALT_PIXELS (SALT_BYTES * 8)                    /* gray: 1 bit each */
#define V2_SALT_LABEL   "ScatterSteg v2 salt positions"
#define V2_KDF_CONTEXT  "ScatStg2"                          /* exactly 8 chars */
#define V2_OVERHEAD     (crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)
#define V1_OVERHEAD     (SALT_BYTES + V2_OVERHEAD)

/* Pixels holding the v2 salt, and the 32-bit length header */
static uint32_t salt_pixel_count(uint32_t channels) {
    return (SALT_BYTES * 8 + channels - 1) / channels;
}

static uint32_t header_pixels(uint32_t channels) {
    return (32 + channels - 1) / channels;
}

typedef struct {
    uint8_t scatter[crypto_stream_chacha20_ietf_KEYBYTES];
    uint8_t enc[crypto_secretbox_KEYBYTES];
} Keys;

/* v2: both keys from one Argon2id run, so every passphrase guess costs one.
   Returns them for sodium_free, or prints why and returns NULL. */
static Keys *derive_keys_v2(const char *passphrase, const uint8_t salt[SALT_BYTES]) {
    Keys *keys = sodium_malloc(sizeof(Keys));
    uint8_t *master = sodium_malloc(crypto_kdf_KEYBYTES);
    fprintf(stderr, "Deriving keys...\n");
    if (!keys || !master ||
        crypto_pwhash(master, crypto_kdf_KEYBYTES, passphrase, strlen(passphrase), salt,
                      crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        sodium_free(keys);
        sodium_free(master);
        fprintf(stderr, "Error: key derivation failed (out of memory)\n");
        return NULL;
    }
    crypto_kdf_derive_from_key(keys->scatter, sizeof(keys->scatter), 1, V2_KDF_CONTEXT, master);
    crypto_kdf_derive_from_key(keys->enc, sizeof(keys->enc), 2, V2_KDF_CONTEXT, master);
    sodium_free(master);
    return keys;
}

/* Where v2 keeps the salt: public, so the decoder can find it before it has
   any key. Returns 0, or -1 on allocation failure. */
static int salt_pixels(uint32_t count, uint32_t k, uint32_t *out) {
    uint8_t key[crypto_stream_chacha20_ietf_KEYBYTES];
    crypto_generichash(key, sizeof(key), (const uint8_t *)V2_SALT_LABEL,
                       strlen(V2_SALT_LABEL), NULL, 0);
    return prng_sample(key, count, k, out);
}

static int cmp_u32(const void *a, const void *b) {
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return (x > y) - (x < y);
}

/* The v2 message order: the secret permutation with the k salt pixels
   taken out, count - k entries. NULL on allocation failure. */
static uint32_t *payload_order(const uint8_t *scatter_key, uint32_t count,
                               const uint32_t *salt_px, uint32_t k) {
    uint32_t sorted[MAX_SALT_PIXELS];
    memcpy(sorted, salt_px, k * sizeof(uint32_t));
    qsort(sorted, k, sizeof(uint32_t), cmp_u32);

    uint32_t *order = prng_permutation(scatter_key, count);
    if (!order) return NULL;
    uint32_t n = 0;
    for (uint32_t i = 0; i < count; i++)
        if (!bsearch(&order[i], sorted, k, sizeof(uint32_t), cmp_u32))
            order[n++] = order[i];
    return order;
}

/* v1 (decode only). The scatter key comes from the passphrase alone, so
   guesses can be checked against the length header without Argon2id. */
static void derive_scatter_key_v1(const char *passphrase,
                                  uint8_t scatter_key[crypto_stream_chacha20_KEYBYTES]) {
    crypto_generichash(scatter_key, crypto_stream_chacha20_KEYBYTES,
                       (const uint8_t *)passphrase, strlen(passphrase),
                       (const uint8_t *)"scatter", 7);
}

static int derive_enc_key_v1(const char *passphrase, const uint8_t salt[SALT_BYTES],
                             uint8_t enc_key[crypto_secretbox_KEYBYTES]) {
    return crypto_pwhash(enc_key, crypto_secretbox_KEYBYTES,
                         passphrase, strlen(passphrase), salt,
                         crypto_pwhash_OPSLIMIT_INTERACTIVE,
                         crypto_pwhash_MEMLIMIT_INTERACTIVE,
                         crypto_pwhash_ALG_ARGON2ID13);
}

/* Outcome of trying to decode with one format */
enum { DECODED, NO_MATCH, FAILED };

/* Read the length-prefixed payload in `order` (n pixels). NO_MATCH if the
   length is out of range, as it is for a wrong passphrase or format;
   FAILED (with a message) if out of memory. */
static int read_payload(const Carrier *c, const uint32_t *order, uint32_t n,
                        uint32_t min_len, uint8_t **payload, uint32_t *len) {
    if (n < header_pixels(carrier_channels(c))) return NO_MATCH;
    uint32_t max_len = (uint32_t)(((uint64_t)n * carrier_channels(c) - 32) / 8);
    *len = embed_peek_len(c, order, n);
    if (*len < min_len || *len > max_len) return NO_MATCH;
    *payload = malloc(*len);
    if (!*payload) {
        fprintf(stderr, "Error: allocation failed\n");
        return FAILED;
    }
    embed_decode(c, order, n, *payload, *len);
    return DECODED;
}

/* The v3 layout over n positions of ch samples, shared by encode and
   decode so it can't drift between them: the 32-bit length goes straight
   into the first 32 samples, and the payload's bits are the STC syndrome
   of samples from 32 on. */

/* Samples after the length header; 0 if the header doesn't fit */
static size_t v3_samples(uint32_t n, uint32_t ch) {
    return n < header_pixels(ch) ? 0 : (size_t)n * ch - 32;
}

/* How many samples from 32 on carry a len-byte payload's syndrome (*mlen
   = 8 * len message bits); 0 if it doesn't fit */
static size_t v3_carriers(uint32_t n, uint32_t ch, uint32_t len, size_t *mlen) {
    *mlen = (size_t)len * 8;
    return stc_carriers(v3_samples(n, ch), *mlen);
}

/* v3 (see v3_samples). NO_MATCH if the length doesn't fit. */
static int read_payload_v3(const Carrier *c, const uint32_t *order, uint32_t n,
                           uint8_t **payload, uint32_t *len) {
    if (n < header_pixels(carrier_channels(c))) return NO_MATCH;
    *len = embed_peek_len(c, order, n);
    size_t mlen;
    size_t used = *len < V2_OVERHEAD ? 0 : v3_carriers(n, carrier_channels(c), *len, &mlen);
    if (!used) return NO_MATCH;

    uint8_t *y = malloc(used), *m = malloc(mlen);
    *payload = calloc(*len, 1);
    if (!y || !m || !*payload) {
        free(y); free(m); free(*payload);
        *payload = NULL;
        fprintf(stderr, "Error: allocation failed\n");
        return FAILED;
    }
    embed_get_bits(c, order, 32, used, y);
    stc_extract(y, mlen, used, m);
    for (size_t i = 0; i < mlen; i++) (*payload)[i / 8] |= (uint8_t)(m[i] << (i % 8));
    free(y);
    free(m);
    return DECODED;
}

/* Records the v3 changes for payload (see v3_samples) in plan: the
   STC picks, among all sample bits with the right syndrome, the set
   cheapest to reach under embed_costs. Returns 0, -1 if it doesn't fit,
   or -2 if out of memory. */
static int embed_payload_v3(const Carrier *c, const uint32_t *order, uint32_t n,
                            const uint8_t *payload, uint32_t len, EmbedPlan *plan) {
    size_t mlen;
    size_t used = v3_carriers(n, carrier_channels(c), len, &mlen);
    if (!used) return -1;

    uint8_t header[4] = {(uint8_t)len, (uint8_t)(len >> 8), (uint8_t)(len >> 16), (uint8_t)(len >> 24)};
    embed_write_raw(c, order, n, header, sizeof(header), plan);

    uint8_t *x = malloc(used), *y = malloc(used), *m = malloc(mlen);
    float *costs = malloc(used * sizeof(float));
    int r = -2;
    if (x && y && m && costs) {
        for (size_t i = 0; i < mlen; i++) m[i] = (payload[i / 8] >> (i % 8)) & 1;
        embed_get_bits(c, order, 32, used, x);
        embed_costs(c, order, 32, used, costs);
        if (stc_embed(x, costs, m, mlen, used, y) == 0) {
            embed_set_bits(c, order, 32, used, y, plan);
            r = 0;
        }
    }
    free(x); free(y); free(m); free(costs);
    return r;
}

/* Open [nonce | secretbox] with key. NO_MATCH if it doesn't authenticate. */
static int open_box(const uint8_t *box, uint32_t box_len, const uint8_t *key,
                    uint8_t **plaintext, uint32_t *pt_len) {
    *pt_len = box_len - V2_OVERHEAD;
    *plaintext = sodium_malloc(*pt_len + 1);
    if (!*plaintext) {
        fprintf(stderr, "Error: allocation failed\n");
        return FAILED;
    }
    const uint8_t *nonce = box, *ct = box + crypto_secretbox_NONCEBYTES;
    if (crypto_secretbox_open_easy(*plaintext, ct, box_len - crypto_secretbox_NONCEBYTES,
                                   nonce, key) != 0) {
        sodium_free(*plaintext);
        *plaintext = NULL;
        return NO_MATCH;
    }
    (*plaintext)[*pt_len] = '\0';
    return DECODED;
}

static int decode_v2(const Carrier *c, const char *passphrase,
                     uint8_t **plaintext, uint32_t *pt_len) {
    uint32_t count = carrier_positions(c);
    uint32_t k = salt_pixel_count(carrier_channels(c));
    if (count < k + header_pixels(carrier_channels(c))) return NO_MATCH;
    uint32_t salt_px[MAX_SALT_PIXELS];
    uint8_t salt[SALT_BYTES];
    if (salt_pixels(count, k, salt_px) != 0) {
        fprintf(stderr, "Error: allocation failed\n");
        return FAILED;
    }
    embed_read_raw(c, salt_px, k, salt, SALT_BYTES);

    Keys *keys = derive_keys_v2(passphrase, salt);
    if (!keys) return FAILED;
    uint32_t *order = payload_order(keys->scatter, count, salt_px, k);
    if (!order) {
        sodium_free(keys);
        fprintf(stderr, "Error: allocation failed\n");
        return FAILED;
    }

    /* v3 and v2 share salt, keys and order; they differ in how the payload
       sits in it. Try v3 (what encode writes), then v2. */
    int r = NO_MATCH;
    for (int v3 = 1; v3 >= 0 && r == NO_MATCH; v3--) {
        uint8_t *payload = NULL;
        uint32_t len = 0;
        r = v3 ? read_payload_v3(c, order, count - k, &payload, &len)
               : read_payload(c, order, count - k, V2_OVERHEAD, &payload, &len);
        if (r == DECODED)
            r = open_box(payload, len, keys->enc, plaintext, pt_len);
        if (payload) sodium_memzero(payload, len);
        free(payload);
    }
    free(order);
    sodium_free(keys);
    return r;
}

static int decode_v1(const Carrier *c, const char *passphrase,
                     uint8_t **plaintext, uint32_t *pt_len) {
    if (!c->img || c->img->channels != 3) return NO_MATCH;  /* v1 only ever wrote RGB PNG */
    uint32_t count = carrier_positions(c);
    uint8_t scatter_key[crypto_stream_chacha20_KEYBYTES];
    derive_scatter_key_v1(passphrase, scatter_key);
    uint32_t *order = prng_scatter(scatter_key, count);
    sodium_memzero(scatter_key, sizeof(scatter_key));
    if (!order) {
        fprintf(stderr, "Error: allocation failed\n");
        return FAILED;
    }

    uint8_t *payload = NULL;
    uint32_t len = 0;
    int r = read_payload(c, order, count, V1_OVERHEAD, &payload, &len);
    free(order);
    if (r != DECODED) return r;

    /* v1 payload = [salt | nonce | secretbox] */
    uint8_t *enc_key = sodium_malloc(crypto_secretbox_KEYBYTES);
    if (!enc_key || derive_enc_key_v1(passphrase, payload, enc_key) != 0) {
        fprintf(stderr, "Error: key derivation failed (out of memory)\n");
        r = FAILED;
    } else {
        r = open_box(payload + SALT_BYTES, len - SALT_BYTES, enc_key, plaintext, pt_len);
    }
    sodium_free(enc_key);
    sodium_memzero(payload, len);
    free(payload);
    return r;
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

static int cover_save(const Cover *c, const char *path) {
    return c->png ? png_save(c->png, path) : jpeg_save(c->jpeg, path);
}

static void cover_free(Cover *c) {
    image_free(c->png);
    jpeg_free(c->jpeg);
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
   newline) goes in *out_len. Stops reading once that is longer than
   max_len, so a huge stdin can't exhaust memory or overflow the payload
   length: then sets *too_long and returns NULL. Also NULL on a read error
   or out of memory, with errno set. */
static char *read_message(size_t max_len, size_t *out_len, int *too_long) {
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

    if (len > 0 && buf[len - 1] == '\n')
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

/* Keep secrets out of core dumps, and (Linux) stop other processes of the
   same user from attaching a debugger to read them */
static void protect_process(void) {
    struct rlimit none = {0, 0};
    setrlimit(RLIMIT_CORE, &none);
#ifdef __linux__
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s encode -i <cover.png|jpg> -o <output.png|jpg>\n", prog);
    fprintf(stderr, "       %s decode -i <image.png|jpg>\n", prog);
    fprintf(stderr, "       %s passphrase\n", prog);
    fprintf(stderr, "Message is read from stdin. `passphrase` prints a strong random passphrase.\n");
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

    int opt;
    while ((opt = getopt(argc - 1, argv + 1, "i:o:")) != -1) {
        switch (opt) {
            case 'i': input  = optarg; break;
            case 'o': output = optarg; break;
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
        if (!output_name_matches(input, output)) return 1;
        /* Checked again when writing; here, before the passphrase prompt */
        struct stat out_st;
        if (stat(output, &out_st) == 0 && !S_ISREG(out_st.st_mode)) {
            fprintf(stderr, "Error: '%s' exists and is not a regular file\n", output);
            return 1;
        }

        char *passphrase = read_passphrase("Passphrase: ");
        if (!passphrase) return 1;
        if (strlen(passphrase) < PASSPHRASE_MIN_LEN) {
            free_passphrase(passphrase);
            fprintf(stderr, "Error: passphrase too short (min %d bytes); "
                            "`scattersteg passphrase` generates a strong one\n", PASSPHRASE_MIN_LEN);
            return 1;
        }
        char *confirm = read_passphrase("Confirm passphrase: ");
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

        if (cover.jpeg && jpeg_check_writable(cover.jpeg) != 0) {
            free_passphrase(passphrase);
            fprintf(stderr, "Error: '%s' is a JPEG that can't be rewritten losslessly; "
                            "use another cover\n", input);
            cover_free(&cover);
            return 1;
        }

        Carrier carrier = cover.carrier;
        uint32_t count = carrier_positions(&carrier);
        uint32_t k = salt_pixel_count(carrier_channels(&carrier));
        if (count < k + header_pixels(carrier_channels(&carrier))) {
            free_passphrase(passphrase);
            cover_free(&cover);
            fprintf(stderr, "Error: image too small to hide a message\n");
            return 1;
        }

        uint8_t salt[SALT_BYTES];
        randombytes_buf(salt, sizeof(salt));
        Keys *keys = derive_keys_v2(passphrase, salt);
        free_passphrase(passphrase);
        if (!keys) {
            cover_free(&cover);
            return 1;
        }

        uint32_t salt_px[MAX_SALT_PIXELS];
        uint32_t *order = NULL;
        if (salt_pixels(count, k, salt_px) == 0)
            order = payload_order(keys->scatter, count, salt_px, k);
        if (!order) {
            sodium_free(keys);
            cover_free(&cover);
            fprintf(stderr, "Error: allocation failed\n");
            return 1;
        }

        /* The most the v3 layout holds: one payload bit per sample after
           the 32-bit header. Under 2^32, as positions are 32-bit and 3
           samples each at most. */
        size_t samples = v3_samples(count - k, carrier_channels(&carrier));
        size_t max_msg = samples / 8 > V2_OVERHEAD ? samples / 8 - V2_OVERHEAD : 0;
        int too_long;
        size_t message_len;
        char *message = read_message(max_msg, &message_len, &too_long);
        int read_err = errno;  /* before the cleanup below changes it */
        if (!message) {
            sodium_free(keys);
            free(order);
            cover_free(&cover);
            if (too_long) fprintf(stderr, "Error: message too long for this image\n");
            else fprintf(stderr, "Error: could not read message: %s\n", strerror(read_err));
            return 1;
        }
        uint32_t msg_len = (uint32_t)message_len;  /* at most max_msg */
        /* Empty message: nothing to hide, so write nothing */
        if (msg_len == 0) {
            sodium_free(keys);
            sodium_free(message);
            free(order);
            cover_free(&cover);
            fprintf(stderr, "Message is empty; nothing written\n");
            return 0;
        }

        /* payload = [nonce | secretbox(message)] */
        uint32_t payload_len = V2_OVERHEAD + msg_len;
        uint8_t *payload = malloc(payload_len);
        if (!payload) {
            sodium_free(keys);
            sodium_free(message);
            free(order);
            cover_free(&cover);
            fprintf(stderr, "Error: allocation failed\n");
            return 1;
        }
        randombytes_buf(payload, crypto_secretbox_NONCEBYTES);
        crypto_secretbox_easy(payload + crypto_secretbox_NONCEBYTES, (const uint8_t *)message,
                              msg_len, payload, keys->enc);
        sodium_free(keys);
        sodium_free(message);

        /* Record every change (payload and salt), then make them together so
           they can be paired up to keep the histogram (see embed_apply) */
        EmbedPlan *plan = embed_plan_new();
        int embedded = plan ? embed_payload_v3(&carrier, order, count - k, payload, payload_len, plan) : -2;
        sodium_memzero(payload, payload_len);
        free(payload);
        free(order);
        if (embedded == -1) {
            embed_plan_free(plan);
            cover_free(&cover);
            fprintf(stderr, "Error: message too long for this image\n");
            return 1;
        }
        if (embedded != 0 || embed_write_raw(&carrier, salt_px, k, salt, SALT_BYTES, plan) != 0 ||
            embed_apply(plan, NULL) != 0) {
            embed_plan_free(plan);
            cover_free(&cover);
            fprintf(stderr, "Error: allocation failed\n");
            return 1;
        }
        embed_plan_free(plan);

        if (cover_save(&cover, output) != 0) {
            fprintf(stderr, "Error: could not write '%s': %s\n", output,
                    errno ? strerror(errno) : cover.png ? "PNG encoding failed" : "JPEG encoding failed");
            cover_free(&cover);
            return 1;
        }
        cover_free(&cover);

    } else if (strcmp(argv[1], "decode") == 0) {
        if (!input) {
            fprintf(stderr, "Error: decode requires -i\n");
            usage(argv[0]);
            return 1;
        }

        char *passphrase = read_passphrase("Passphrase: ");
        if (!passphrase) return 1;

        Cover cover;
        if (cover_load(input, &cover) != 0) {
            free_passphrase(passphrase);
            return 1;
        }
        Carrier carrier = cover.carrier;
        if (carrier_positions(&carrier) < header_pixels(carrier_channels(&carrier))) {
            free_passphrase(passphrase);
            cover_free(&cover);
            fprintf(stderr, "Error: image too small to contain a message\n");
            return 1;
        }

        uint8_t *plaintext = NULL;
        uint32_t pt_len = 0;
        int r = decode_v2(&carrier, passphrase, &plaintext, &pt_len);
        if (r == NO_MATCH) {
            r = decode_v1(&carrier, passphrase, &plaintext, &pt_len);
            if (r == DECODED)
                fprintf(stderr, "Warning: this image uses the old v1 format, which protects "
                                "the passphrase less well; re-encode it\n");
        }
        free_passphrase(passphrase);
        cover_free(&cover);
        if (r == NO_MATCH)
            fprintf(stderr, "Error: decryption failed — wrong passphrase, "
                            "or no message in this image\n");
        if (r != DECODED) return 1;

        if (pt_len > 0) {  /* empty message: print nothing */
            /* All of it, NULs too. The newline goes in the same write, so
               the plaintext buffer has room: open_box allocates pt_len + 1. */
            plaintext[pt_len] = '\n';
            if (write_all(STDOUT_FILENO, plaintext, pt_len + 1) != 0) {
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
