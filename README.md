# ScatterSteg

A command-line steganography tool that hides encrypted messages inside PNG images.

## Rationale

Most LSB steganography tools embed data sequentially — bit 0 goes into pixel 0, bit 1 into pixel 1, and so on. This makes detection straightforward: statistical analysis of the least-significant bits reveals a clear pattern in the first N pixels.

ScatterSteg takes a different approach. The embedding positions are derived from a passphrase using ChaCha20, producing a pseudo-random permutation of pixel indices. Without the passphrase, an attacker cannot determine which pixels carry data, let alone recover it.

The message itself is also encrypted with XSalsa20-Poly1305 (`crypto_secretbox`) before embedding, so even if the scatter pattern were somehow recovered, the payload remains ciphertext. A random nonce is generated for each encode operation, meaning the same message encoded twice produces different output.

## Features

- **Scatter-based LSB embedding** — pixel selection is a ChaCha20-derived Fisher-Yates shuffle, not sequential
- **Authenticated encryption** — XSalsa20-Poly1305 encrypts and authenticates the message before embedding; wrong passphrase on decode fails with an explicit error
- **Argon2id key derivation** — passphrase is run through Argon2id (winner of the Password Hashing Competition) before any key material is derived; this makes brute-force attacks expensive in both time and memory
- **Domain-separated keys** — a single Argon2id call produces 64 bytes split into independent scatter and encryption keys, so the two keys share no material
- **Random nonce per encode** — identical messages encoded with the same passphrase produce different steg images
- **Input validation** — image capacity is checked before embedding; decoded length headers are validated against actual image capacity before any allocation

## Dependencies

- [libsodium](https://doc.libsodium.org/) — ChaCha20, BLAKE2b, XSalsa20-Poly1305
- [libpng](http://www.libpng.org/pub/png/libpng.html) — PNG read/write

On Ubuntu/Debian:

```bash
sudo apt install libsodium-dev libpng-dev
```

## Building

```bash
make
```

## Usage

**Encode** a message into a PNG:

```bash
# pipe from a file
echo "your message" | ./scattersteg encode -i cover.png -o steg.png

# or type interactively (Ctrl+D when done)
./scattersteg encode -i cover.png -o steg.png
```

You will be prompted to enter and confirm a passphrase.

**Decode** a message from a PNG:

```bash
./scattersteg decode -i steg.png
```

You will be prompted for the passphrase used during encoding.

## Limitations

- Supports RGB PNG images only (alpha, grayscale, and palette images are converted automatically on load)
- This is a learning project, not a production security tool
