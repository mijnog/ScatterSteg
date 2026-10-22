#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sodium.h>
#include "png_io.h"
#include "prng.h"
#include "embed.h"

#define PASSPHRASE_CHUNK 256  /* passphrase buffer grows by this much */
/* The terminal's line editor holds 4095 bytes per line and silently drops
   the rest, so a line that long may have been cut short: refuse it. */
#define PASSPHRASE_MAX_LEN 4094

/* Wipe and free a passphrase from read_passphrase. NULL is fine. */
static void free_passphrase(char *passphrase) {
    if (!passphrase) return;
    sodium_memzero(passphrase, strlen(passphrase));
    free(passphrase);
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

    /* Ctrl+C and friends would otherwise leave the terminal without echo */
    tty_restore_fd = fd;
    tty_restore = old;
    struct sigaction on_signal = {.sa_handler = restore_tty_and_die, .sa_flags = SA_RESETHAND};
    struct sigaction saved[N_RESTORE_SIGNALS];
    sigemptyset(&on_signal.sa_mask);
    for (size_t i = 0; i < N_RESTORE_SIGNALS; i++)
        sigaction(restore_signals[i], &on_signal, &saved[i]);

    silent = old;
    silent.c_lflag &= ~ECHO;
    tcsetattr(fd, TCSAFLUSH, &silent);

    fputs(prompt, tty);
    fflush(tty);

    size_t cap = PASSPHRASE_CHUNK;
    size_t len = 0;
    char *buf = malloc(cap);
    int c = EOF;
    while (buf && (c = fgetc(tty)) != EOF && c != '\n') {
        if (len + 1 >= cap) {
            /* Not realloc: it could leave the old copy behind in freed memory */
            char *bigger = malloc(cap + PASSPHRASE_CHUNK);
            if (bigger) memcpy(bigger, buf, len);
            sodium_memzero(buf, cap);
            free(buf);
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
        free(buf);
        fprintf(stderr, "Error: could not read passphrase\n");
        return NULL;
    }
    if (len > PASSPHRASE_MAX_LEN) {
        sodium_memzero(buf, len);
        free(buf);
        fprintf(stderr, "Error: passphrase too long (max %d bytes)\n", PASSPHRASE_MAX_LEN);
        return NULL;
    }
    buf[len] = '\0';
    return buf;
}

/* ---- File format ----------------------------------------------------------

   v2 (written by encode):
     salt     16 random bytes, in the LSBs of the first 43 pixels of a public
              permutation (prng_permutation keyed with BLAKE2b of
              V2_SALT_LABEL), so it is spread over the image
     keys     master = Argon2id(passphrase, salt, "moderate": 3 passes,
              256 MiB); scatter and encryption keys = crypto_kdf subkeys 1
              and 2 of master, context V2_KDF_CONTEXT
     payload  32-bit little-endian length, then [nonce 24 | secretbox], in
              the order of prng_permutation(scatter key) with the salt
              pixels removed

   v1 (decode only): scatter key = keyed BLAKE2b of the passphrase alone,
     which let a wrong passphrase be rejected without Argon2id; payload =
     length, then [salt 16 | nonce 24 | secretbox] in prng_scatter order;
     encryption key = Argon2id(passphrase, salt, "interactive").

   Every pixel carries 3 bits (R, G, B LSBs), written by LSB matching. There
   is no version marker, which would itself give the image away: decode
   tries v2, then v1. */

#define SALT_BYTES      crypto_pwhash_SALTBYTES             /* 16 */
#define V2_SALT_PIXELS  ((SALT_BYTES * 8 + 2) / 3)          /* 43 */
#define HEADER_PIXELS   11                                  /* 32-bit length */
#define V2_SALT_LABEL   "ScatterSteg v2 salt positions"
#define V2_KDF_CONTEXT  "ScatStg2"                          /* exactly 8 chars */
#define V2_OVERHEAD     (crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)
#define V1_OVERHEAD     (SALT_BYTES + V2_OVERHEAD)

typedef struct {
    uint8_t scatter[crypto_stream_chacha20_ietf_KEYBYTES];
    uint8_t enc[crypto_secretbox_KEYBYTES];
} Keys;

/* v2: both keys from one Argon2id run, so every passphrase guess costs one.
   Returns 0, or -1 if Argon2id ran out of memory. */
static int derive_keys_v2(const char *passphrase, const uint8_t salt[SALT_BYTES], Keys *keys) {
    uint8_t master[crypto_kdf_KEYBYTES];
    if (crypto_pwhash(master, sizeof(master), passphrase, strlen(passphrase), salt,
                      crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0)
        return -1;
    crypto_kdf_derive_from_key(keys->scatter, sizeof(keys->scatter), 1, V2_KDF_CONTEXT, master);
    crypto_kdf_derive_from_key(keys->enc, sizeof(keys->enc), 2, V2_KDF_CONTEXT, master);
    sodium_memzero(master, sizeof(master));
    return 0;
}

/* Where v2 keeps the salt: public, so the decoder can find it before it has
   any key. Returns 0, or -1 on allocation failure. */
static int salt_pixels(uint32_t count, uint32_t out[V2_SALT_PIXELS]) {
    uint8_t key[crypto_stream_chacha20_ietf_KEYBYTES];
    crypto_generichash(key, sizeof(key), (const uint8_t *)V2_SALT_LABEL,
                       strlen(V2_SALT_LABEL), NULL, 0);
    return prng_sample(key, count, V2_SALT_PIXELS, out);
}

static int cmp_u32(const void *a, const void *b) {
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return (x > y) - (x < y);
}

/* The v2 message order: the secret permutation with the salt pixels taken
   out, count - V2_SALT_PIXELS entries. NULL on allocation failure. */
static uint32_t *payload_order(const uint8_t *scatter_key, uint32_t count,
                               const uint32_t salt_px[V2_SALT_PIXELS]) {
    uint32_t sorted[V2_SALT_PIXELS];
    memcpy(sorted, salt_px, sizeof(sorted));
    qsort(sorted, V2_SALT_PIXELS, sizeof(uint32_t), cmp_u32);

    uint32_t *order = prng_permutation(scatter_key, count);
    if (!order) return NULL;
    uint32_t n = 0;
    for (uint32_t i = 0; i < count; i++)
        if (!bsearch(&order[i], sorted, V2_SALT_PIXELS, sizeof(uint32_t), cmp_u32))
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
static int read_payload(const Image *img, const uint32_t *order, uint32_t n,
                        uint32_t min_len, uint8_t **payload, uint32_t *len) {
    if (n < HEADER_PIXELS) return NO_MATCH;
    uint32_t max_len = (uint32_t)(((uint64_t)n * 3 - 32) / 8);
    *len = embed_peek_len(img, order, n);
    if (*len < min_len || *len > max_len) return NO_MATCH;
    *payload = malloc(*len);
    if (!*payload) {
        fprintf(stderr, "Error: allocation failed\n");
        return FAILED;
    }
    embed_decode(img, order, n, *payload, *len);
    return DECODED;
}

/* Open [nonce | secretbox] with key. NO_MATCH if it doesn't authenticate. */
static int open_box(const uint8_t *box, uint32_t box_len, const uint8_t *key,
                    uint8_t **plaintext, uint32_t *pt_len) {
    *pt_len = box_len - V2_OVERHEAD;
    *plaintext = malloc(*pt_len + 1);
    if (!*plaintext) {
        fprintf(stderr, "Error: allocation failed\n");
        return FAILED;
    }
    const uint8_t *nonce = box, *ct = box + crypto_secretbox_NONCEBYTES;
    if (crypto_secretbox_open_easy(*plaintext, ct, box_len - crypto_secretbox_NONCEBYTES,
                                   nonce, key) != 0) {
        free(*plaintext);
        *plaintext = NULL;
        return NO_MATCH;
    }
    (*plaintext)[*pt_len] = '\0';
    return DECODED;
}

static int decode_v2(const Image *img, uint32_t count, const char *passphrase,
                     uint8_t **plaintext, uint32_t *pt_len) {
    if (count < V2_SALT_PIXELS + HEADER_PIXELS) return NO_MATCH;
    uint32_t salt_px[V2_SALT_PIXELS];
    uint8_t salt[SALT_BYTES];
    if (salt_pixels(count, salt_px) != 0) {
        fprintf(stderr, "Error: allocation failed\n");
        return FAILED;
    }
    embed_read_raw(img, salt_px, V2_SALT_PIXELS, salt, SALT_BYTES);

    Keys keys;
    fprintf(stderr, "Deriving keys...\n");
    if (derive_keys_v2(passphrase, salt, &keys) != 0) {
        fprintf(stderr, "Error: key derivation failed (out of memory)\n");
        return FAILED;
    }
    uint32_t *order = payload_order(keys.scatter, count, salt_px);
    if (!order) {
        sodium_memzero(&keys, sizeof(keys));
        fprintf(stderr, "Error: allocation failed\n");
        return FAILED;
    }

    uint8_t *payload = NULL;
    uint32_t len = 0;
    int r = read_payload(img, order, count - V2_SALT_PIXELS, V2_OVERHEAD, &payload, &len);
    free(order);
    if (r == DECODED)
        r = open_box(payload, len, keys.enc, plaintext, pt_len);
    sodium_memzero(&keys, sizeof(keys));
    if (payload) sodium_memzero(payload, len);
    free(payload);
    return r;
}

static int decode_v1(const Image *img, uint32_t count, const char *passphrase,
                     uint8_t **plaintext, uint32_t *pt_len) {
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
    int r = read_payload(img, order, count, V1_OVERHEAD, &payload, &len);
    free(order);
    if (r != DECODED) return r;

    /* v1 payload = [salt | nonce | secretbox] */
    uint8_t enc_key[crypto_secretbox_KEYBYTES];
    if (derive_enc_key_v1(passphrase, payload, enc_key) != 0) {
        fprintf(stderr, "Error: key derivation failed (out of memory)\n");
        r = FAILED;
    } else {
        r = open_box(payload + SALT_BYTES, len - SALT_BYTES, enc_key, plaintext, pt_len);
    }
    sodium_memzero(enc_key, sizeof(enc_key));
    sodium_memzero(payload, len);
    free(payload);
    return r;
}

/* Read the entire contents of stdin into a heap-allocated buffer.
   Prints a prompt first if stdin is a terminal. Caller must free. */
static char *read_message(void) {
    if (isatty(STDIN_FILENO))
        fprintf(stderr, "Message (Ctrl+D when done):\n");

    size_t cap = 1024;
    size_t len = 0;
    char *buf = malloc(cap);
    if (!buf) return NULL;

    int c;
    while ((c = getchar()) != EOF) {
        if (len + 1 >= cap) {
            cap *= 2;
            char *tmp = realloc(buf, cap);
            if (!tmp) { free(buf); return NULL; }
            buf = tmp;
        }
        buf[len++] = (char)c;
    }

    if (len > 0 && buf[len - 1] == '\n')
        len--;
    buf[len] = '\0';
    return buf;
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s encode -i <input.png> -o <output.png>\n", prog);
    fprintf(stderr, "       %s decode -i <input.png>\n", prog);
    fprintf(stderr, "Message is read from stdin.\n");
}

int main(int argc, char *argv[]) {
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

    if (strcmp(argv[1], "encode") == 0) {
        if (!input || !output) {
            fprintf(stderr, "Error: encode requires -i and -o\n");
            usage(argv[0]);
            return 1;
        }

        char *passphrase = read_passphrase("Passphrase: ");
        if (!passphrase) return 1;
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

        Image *img = png_load(input);
        if (!img) {
            free_passphrase(passphrase);
            fprintf(stderr, "Error: could not load '%s'\n", input);
            return 1;
        }

        /* The output is 8-bit RGB: a cover that would lose something in that
           conversion comes out visibly different, which gives it away */
        if (img->dropped) {
            free_passphrase(passphrase);
            fprintf(stderr, "Error: '%s' has %s, which the output can't keep; "
                            "use an 8-bit RGB PNG as the cover\n", input, img->dropped);
            image_free(img);
            return 1;
        }

        if (img->width == 0 || img->height > UINT32_MAX / img->width) {
            free_passphrase(passphrase);
            image_free(img);
            fprintf(stderr, "Error: image dimensions overflow\n");
            return 1;
        }
        uint32_t count = img->width * img->height;
        if (count < V2_SALT_PIXELS + HEADER_PIXELS) {
            free_passphrase(passphrase);
            image_free(img);
            fprintf(stderr, "Error: image too small to hide a message\n");
            return 1;
        }

        uint8_t salt[SALT_BYTES];
        randombytes_buf(salt, sizeof(salt));
        Keys keys;
        fprintf(stderr, "Deriving keys...\n");
        int derived = derive_keys_v2(passphrase, salt, &keys);
        free_passphrase(passphrase);
        if (derived != 0) {
            image_free(img);
            fprintf(stderr, "Error: key derivation failed (out of memory)\n");
            return 1;
        }

        uint32_t salt_px[V2_SALT_PIXELS];
        uint32_t *order = NULL;
        if (salt_pixels(count, salt_px) == 0)
            order = payload_order(keys.scatter, count, salt_px);
        if (!order) {
            sodium_memzero(&keys, sizeof(keys));
            image_free(img);
            fprintf(stderr, "Error: allocation failed\n");
            return 1;
        }

        char *message = read_message();
        if (!message) {
            sodium_memzero(&keys, sizeof(keys));
            free(order);
            image_free(img);
            fprintf(stderr, "Error: could not read message\n");
            return 1;
        }
        uint32_t msg_len = (uint32_t)strlen(message);
        /* Empty message: nothing to hide, so write nothing */
        if (msg_len == 0) {
            sodium_memzero(&keys, sizeof(keys));
            free(message);
            free(order);
            image_free(img);
            fprintf(stderr, "Message is empty; nothing written\n");
            return 0;
        }

        /* payload = [nonce | secretbox(message)] */
        uint32_t payload_len = V2_OVERHEAD + msg_len;
        uint8_t *payload = malloc(payload_len);
        if (!payload) {
            sodium_memzero(&keys, sizeof(keys));
            sodium_memzero(message, msg_len);
            free(message);
            free(order);
            image_free(img);
            fprintf(stderr, "Error: allocation failed\n");
            return 1;
        }
        randombytes_buf(payload, crypto_secretbox_NONCEBYTES);
        crypto_secretbox_easy(payload + crypto_secretbox_NONCEBYTES, (const uint8_t *)message,
                              msg_len, payload, keys.enc);
        sodium_memzero(&keys, sizeof(keys));
        sodium_memzero(message, msg_len);
        free(message);

        int embedded = embed_encode(img, order, count - V2_SALT_PIXELS, payload, payload_len);
        sodium_memzero(payload, payload_len);
        free(payload);
        free(order);
        if (embedded != 0) {
            image_free(img);
            fprintf(stderr, "Error: message too long for this image\n");
            return 1;
        }
        embed_write_raw(img, salt_px, V2_SALT_PIXELS, salt, SALT_BYTES);

        if (png_save(img, output) != 0) {
            fprintf(stderr, "Error: could not write '%s': %s\n", output,
                    errno ? strerror(errno) : "PNG encoding failed");
            image_free(img);
            return 1;
        }
        image_free(img);

    } else if (strcmp(argv[1], "decode") == 0) {
        if (!input) {
            fprintf(stderr, "Error: decode requires -i\n");
            usage(argv[0]);
            return 1;
        }

        char *passphrase = read_passphrase("Passphrase: ");
        if (!passphrase) return 1;

        Image *img = png_load(input);
        if (!img) {
            free_passphrase(passphrase);
            fprintf(stderr, "Error: could not load '%s'\n", input);
            return 1;
        }

        if (img->width == 0 || img->height > UINT32_MAX / img->width) {
            free_passphrase(passphrase);
            image_free(img);
            fprintf(stderr, "Error: image dimensions overflow\n");
            return 1;
        }
        uint32_t count = img->width * img->height;
        if (count < HEADER_PIXELS) {
            free_passphrase(passphrase);
            image_free(img);
            fprintf(stderr, "Error: image too small to contain a message\n");
            return 1;
        }

        uint8_t *plaintext = NULL;
        uint32_t pt_len = 0;
        int r = decode_v2(img, count, passphrase, &plaintext, &pt_len);
        if (r == NO_MATCH) {
            r = decode_v1(img, count, passphrase, &plaintext, &pt_len);
            if (r == DECODED)
                fprintf(stderr, "Warning: this image uses the old v1 format, which protects "
                                "the passphrase less well; re-encode it\n");
        }
        free_passphrase(passphrase);
        image_free(img);
        if (r == NO_MATCH)
            fprintf(stderr, "Error: decryption failed — wrong passphrase, "
                            "or no message in this image\n");
        if (r != DECODED) return 1;

        if (pt_len > 0)  /* empty message: print nothing */
            printf("%s\n", (char *)plaintext);
        sodium_memzero(plaintext, pt_len);
        free(plaintext);

    } else {
        fprintf(stderr, "Error: unknown command '%s'\n", argv[1]);
        usage(argv[0]);
        return 1;
    }

    return 0;
}
