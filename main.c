#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sodium.h>
#include "png_io.h"
#include "prng.h"
#include "embed.h"

#define PASSPHRASE_MAX 256

static int read_passphrase(const char *prompt, char *buf, size_t max_len) {
    FILE *tty = fopen("/dev/tty", "r+");
    if (!tty) return -1;

    int fd = fileno(tty);
    struct termios old, silent;
    if (tcgetattr(fd, &old) != 0) {
        fclose(tty);
        return -1;
    }

    silent = old;
    silent.c_lflag &= ~ECHO;
    tcsetattr(fd, TCSAFLUSH, &silent);

    fputs(prompt, tty);
    fflush(tty);
    char *result = fgets(buf, (int)max_len, tty);

    tcsetattr(fd, TCSAFLUSH, &old);
    fputs("\n", tty);
    fclose(tty);

    if (!result) return -1;

    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n')
        buf[len - 1] = '\0';

    return 0;
}

/* Derive the scatter key from the passphrase alone using BLAKE2b.
   A fast hash is fine here: scatter key only determines pixel order,
   not message secrecy. Brute-force is still bottlenecked by the
   Argon2id step needed to derive the encryption key. */
static void derive_scatter_key(const char *passphrase,
                                uint8_t scatter_key[crypto_stream_chacha20_KEYBYTES]) {
    crypto_generichash(scatter_key, crypto_stream_chacha20_KEYBYTES,
                       (const uint8_t *)passphrase, strlen(passphrase),
                       (const uint8_t *)"scatter", 7);
}

/* Derive the encryption key from passphrase + salt using Argon2id.
   Argon2id is intentionally slow and memory-hard, making brute-force
   attacks on the passphrase expensive. Returns 0 on success, -1 if
   out of memory. */
static int derive_enc_key(const char *passphrase,
                          const uint8_t salt[crypto_pwhash_SALTBYTES],
                          uint8_t enc_key[crypto_secretbox_KEYBYTES]) {
    return crypto_pwhash(enc_key, crypto_secretbox_KEYBYTES,
                         passphrase, strlen(passphrase),
                         salt,
                         crypto_pwhash_OPSLIMIT_INTERACTIVE,
                         crypto_pwhash_MEMLIMIT_INTERACTIVE,
                         crypto_pwhash_ALG_ARGON2ID13);
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

        char passphrase[PASSPHRASE_MAX];
        char confirm[PASSPHRASE_MAX];

        if (read_passphrase("Passphrase: ", passphrase, sizeof(passphrase)) != 0) {
            fprintf(stderr, "Error: could not read passphrase\n");
            return 1;
        }
        if (read_passphrase("Confirm passphrase: ", confirm, sizeof(confirm)) != 0) {
            sodium_memzero(passphrase, sizeof(passphrase));
            fprintf(stderr, "Error: could not read passphrase\n");
            return 1;
        }
        if (strcmp(passphrase, confirm) != 0) {
            sodium_memzero(passphrase, sizeof(passphrase));
            sodium_memzero(confirm, sizeof(confirm));
            fprintf(stderr, "Error: passphrases do not match\n");
            return 1;
        }
        sodium_memzero(confirm, sizeof(confirm));

        uint8_t salt[crypto_pwhash_SALTBYTES];
        randombytes_buf(salt, sizeof(salt));

        uint8_t scatter_key[crypto_stream_chacha20_KEYBYTES];
        uint8_t enc_key[crypto_secretbox_KEYBYTES];
        derive_scatter_key(passphrase, scatter_key);
        fprintf(stderr, "Deriving keys...\n");
        if (derive_enc_key(passphrase, salt, enc_key) != 0) {
            sodium_memzero(passphrase, sizeof(passphrase));
            fprintf(stderr, "Error: key derivation failed (out of memory)\n");
            return 1;
        }
        sodium_memzero(passphrase, sizeof(passphrase));

        Image *img = png_load(input);
        if (!img) {
            sodium_memzero(enc_key, sizeof(enc_key));
            fprintf(stderr, "Error: could not load '%s'\n", input);
            return 1;
        }

        if (img->width == 0 || img->height > UINT32_MAX / img->width) {
            sodium_memzero(enc_key, sizeof(enc_key));
            image_free(img);
            fprintf(stderr, "Error: image dimensions overflow\n");
            return 1;
        }
        uint32_t count = img->width * img->height;
        uint32_t *indices = prng_scatter(scatter_key, count);
        sodium_memzero(scatter_key, sizeof(scatter_key));
        if (!indices) {
            sodium_memzero(enc_key, sizeof(enc_key));
            image_free(img);
            fprintf(stderr, "Error: image too small or allocation failed\n");
            return 1;
        }

        /* Encrypt: payload = [salt | nonce | MAC+ciphertext] */
        char *message = read_message();
        if (!message) {
            sodium_memzero(enc_key, sizeof(enc_key));
            free(indices);
            image_free(img);
            fprintf(stderr, "Error: could not read message\n");
            return 1;
        }
        uint32_t msg_len = (uint32_t)strlen(message);
        uint8_t nonce[crypto_secretbox_NONCEBYTES];
        randombytes_buf(nonce, sizeof(nonce));

        uint32_t ct_len      = crypto_secretbox_MACBYTES + msg_len;
        uint32_t payload_len = crypto_pwhash_SALTBYTES + crypto_secretbox_NONCEBYTES + ct_len;
        uint8_t *payload = malloc(payload_len);
        if (!payload) {
            sodium_memzero(enc_key, sizeof(enc_key));
            free(message);
            free(indices);
            image_free(img);
            fprintf(stderr, "Error: allocation failed\n");
            return 1;
        }

        uint8_t *p = payload;
        memcpy(p, salt, crypto_pwhash_SALTBYTES);           p += crypto_pwhash_SALTBYTES;
        memcpy(p, nonce, crypto_secretbox_NONCEBYTES);      p += crypto_secretbox_NONCEBYTES;
        crypto_secretbox_easy(p, (const uint8_t *)message, msg_len, nonce, enc_key);
        sodium_memzero(enc_key, sizeof(enc_key));
        free(message);

        if (embed_encode(img, indices, count, payload, payload_len) != 0) {
            fprintf(stderr, "Error: message too long for this image\n");
            sodium_memzero(payload, payload_len);
            free(payload);
            free(indices);
            image_free(img);
            return 1;
        }
        sodium_memzero(payload, payload_len);
        free(payload);

        png_save(img, output);
        free(indices);
        image_free(img);

    } else if (strcmp(argv[1], "decode") == 0) {
        if (!input) {
            fprintf(stderr, "Error: decode requires -i\n");
            usage(argv[0]);
            return 1;
        }

        char passphrase[PASSPHRASE_MAX];
        if (read_passphrase("Passphrase: ", passphrase, sizeof(passphrase)) != 0) {
            fprintf(stderr, "Error: could not read passphrase\n");
            return 1;
        }

        Image *img = png_load(input);
        if (!img) {
            sodium_memzero(passphrase, sizeof(passphrase));
            fprintf(stderr, "Error: could not load '%s'\n", input);
            return 1;
        }

        if (img->width == 0 || img->height > UINT32_MAX / img->width) {
            sodium_memzero(passphrase, sizeof(passphrase));
            image_free(img);
            fprintf(stderr, "Error: image dimensions overflow\n");
            return 1;
        }
        uint32_t count = img->width * img->height;

        /* Scatter key depends only on the passphrase, so we can derive it
           immediately and use it to read the payload (which contains the salt). */
        uint8_t scatter_key[crypto_stream_chacha20_KEYBYTES];
        derive_scatter_key(passphrase, scatter_key);

        uint32_t *indices = prng_scatter(scatter_key, count);
        sodium_memzero(scatter_key, sizeof(scatter_key));
        if (!indices) {
            sodium_memzero(passphrase, sizeof(passphrase));
            image_free(img);
            fprintf(stderr, "Error: image too small or allocation failed\n");
            return 1;
        }

        uint64_t bits = (uint64_t)count * 3;
        if (bits < 32) {
            sodium_memzero(passphrase, sizeof(passphrase));
            free(indices);
            image_free(img);
            fprintf(stderr, "Error: image too small to contain a message\n");
            return 1;
        }
        uint32_t max_payload_len = (uint32_t)((bits - 32) / 8);
        uint32_t min_payload_len = crypto_pwhash_SALTBYTES +
                                   crypto_secretbox_NONCEBYTES +
                                   crypto_secretbox_MACBYTES + 1;

        uint32_t payload_len = embed_peek_len(img, indices, count);
        if (payload_len > max_payload_len || payload_len < min_payload_len) {
            sodium_memzero(passphrase, sizeof(passphrase));
            free(indices);
            image_free(img);
            fprintf(stderr, "Error: invalid message length in image\n");
            return 1;
        }

        uint8_t *payload = malloc(payload_len);
        if (!payload) {
            sodium_memzero(passphrase, sizeof(passphrase));
            free(indices);
            image_free(img);
            fprintf(stderr, "Error: allocation failed\n");
            return 1;
        }

        embed_decode(img, indices, count, payload, payload_len);
        free(indices);
        image_free(img);

        /* Salt is the first bytes of the payload — use it to derive enc key. */
        uint8_t salt[crypto_pwhash_SALTBYTES];
        memcpy(salt, payload, crypto_pwhash_SALTBYTES);

        uint8_t enc_key[crypto_secretbox_KEYBYTES];
        fprintf(stderr, "Deriving keys...\n");
        if (derive_enc_key(passphrase, salt, enc_key) != 0) {
            sodium_memzero(passphrase, sizeof(passphrase));
            sodium_memzero(payload, payload_len);
            free(payload);
            fprintf(stderr, "Error: key derivation failed (out of memory)\n");
            return 1;
        }
        sodium_memzero(passphrase, sizeof(passphrase));

        /* Decrypt: payload = [salt | nonce | MAC+ciphertext] */
        const uint8_t *nonce = payload + crypto_pwhash_SALTBYTES;
        const uint8_t *ct    = nonce + crypto_secretbox_NONCEBYTES;
        uint32_t ct_len      = payload_len - crypto_pwhash_SALTBYTES - crypto_secretbox_NONCEBYTES;
        uint32_t pt_len      = ct_len - crypto_secretbox_MACBYTES;

        uint8_t *plaintext = malloc(pt_len + 1);
        if (!plaintext) {
            sodium_memzero(enc_key, sizeof(enc_key));
            sodium_memzero(payload, payload_len);
            free(payload);
            fprintf(stderr, "Error: allocation failed\n");
            return 1;
        }

        if (crypto_secretbox_open_easy(plaintext, ct, ct_len, nonce, enc_key) != 0) {
            sodium_memzero(enc_key, sizeof(enc_key));
            sodium_memzero(payload, payload_len);
            free(payload);
            free(plaintext);
            fprintf(stderr, "Error: decryption failed — wrong passphrase or corrupted image\n");
            return 1;
        }
        sodium_memzero(enc_key, sizeof(enc_key));
        sodium_memzero(payload, payload_len);
        free(payload);

        plaintext[pt_len] = '\0';
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
