# ScatterSteg

A command-line steganography tool that hides encrypted messages inside PNG images.

## Rationale

Most LSB steganography tools embed data sequentially — bit 0 goes into pixel 0, bit 1 into pixel 1, and so on. This makes detection straightforward: statistical analysis of the least-significant bits reveals a clear pattern in the first N pixels.

ScatterSteg takes a different approach. The embedding positions are derived from a passphrase using ChaCha20, producing a pseudo-random permutation of pixel indices. Without the passphrase, an attacker cannot determine which pixels carry data, let alone recover it.

Scattering hides *where* the data is, but not by itself *that* it is there. Simply overwriting the least-significant bit only ever swaps a value with its partner (2k ↔ 2k+1), which leaves a statistical fingerprint across the whole image that detectors such as sample pair analysis pick up wherever the bits are. So ScatterSteg uses LSB matching instead: when a value's LSB needs to change, it randomly adds or subtracts 1. The hidden bit is the same and decoding is unchanged, but the fingerprint is gone.

The message itself is also encrypted with XSalsa20-Poly1305 (`crypto_secretbox`) before embedding, so even if the scatter pattern were somehow recovered, the payload remains ciphertext. A random nonce is generated for each encode operation, meaning the same message encoded twice produces different output.

## Features

- **Scatter-based LSB embedding** — pixel selection is a ChaCha20-derived Fisher-Yates shuffle, not sequential
- **LSB matching** — bits are embedded by a random ±1 change rather than by overwriting the LSB, so no sample changes by more than 1 and the pair statistics that classic steganalysis relies on are left intact
- **Authenticated encryption** — XSalsa20-Poly1305 encrypts and authenticates the message before embedding; wrong passphrase on decode fails with an explicit error
- **Argon2id key derivation** — the encryption key is derived with Argon2id (winner of the Password Hashing Competition), which is slow and memory-hard by design (see Limitations for how far that protects the passphrase)
- **Separate keys** — the scatter key is derived from the passphrase with keyed BLAKE2b, and the encryption key with Argon2id and a random salt stored in the image. The scatter key only decides pixel order; the message's secrecy rests on the Argon2id key
- **Random nonce per encode** — identical messages encoded with the same passphrase produce different steg images
- **Passphrase read from terminal** — passphrase is never passed as a command-line argument (not visible in `ps`), echo is disabled during input, and passphrase memory is zeroed immediately after key derivation
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

## Testing

```bash
make test       # unit, CLI and fault-injection tests, under ASan/UBSan (~10 s)
make fuzz       # libFuzzer on the PNG loader and embedder (needs clang; FUZZ_TIME=60 per target)
make coverage   # line coverage over the whole suite; annotated sources in tests/build/cov
```

`make test` needs Python 3 (standard library only). The CLI tests drive the binary through a pseudo-terminal, since the passphrase is read from `/dev/tty`. The fault-injection tests make each `malloc`, `fopen`, `fclose`, `rename` and similar call fail in turn, and check that every error path fails cleanly.

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

- The output is always an 8-bit RGB PNG. Grayscale and palette covers are converted to RGB, which keeps their pixels exactly. Covers with transparency or 16-bit color are refused, because converting them would visibly change the image.
- Against the classic detectors, the chi-square attack and sample pair analysis, embedding was not detectable in testing: chi-square stayed negative even at full capacity, and sample pair analysis stayed at the cover's own value up to about 25% of capacity. Modern machine-learning steganalysis can detect LSB matching at lower payloads and hasn't been tested. Keep messages small relative to the cover; a few KB in a photo-sized image uses well under 1% of its capacity.
- Argon2id does not fully protect weak passphrases. The message length is read using only the fast BLAKE2b scatter key, and for a wrong passphrase it is almost always out of range, so most wrong guesses can be rejected without running Argon2id. Testing a guess costs about one pixel-order shuffle: roughly 100× cheaper than Argon2id for a 256×256 image, about 2× for 1920×1080, and no cheaper for 12 MP photos. Use a long, random passphrase.
- Smooth, flat areas (digital art, gradients) hide data worse than noisy photographs, since any ±1 change stands out where neighbouring pixels are identical.
- Anyone who has the original cover can find the changes by comparing pixels, and the output's PNG metadata and compression differ from the cover's.
- This is a learning project, not a production security tool
