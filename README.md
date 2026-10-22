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
- **Histogram-preserving exchange** — when two samples that both need their LSB flipped hold values one apart, they swap values instead (the idea behind steghide; Hetzl & Mutzel, 2005). On photos over 99% of changes pair up, so the histogram is unchanged apart from a parity shift that no LSB method can avoid
- **Authenticated encryption** — XSalsa20-Poly1305 encrypts and authenticates the message before embedding; wrong passphrase on decode fails with an explicit error
- **Argon2id key derivation** — one Argon2id run (winner of the Password Hashing Competition; 256 MiB, 3 passes) with a random per-image salt derives a master key, split into independent scatter and encryption keys. Nothing about the message, not even where it is, can be checked without paying for Argon2id, so every passphrase guess costs about 0.2 s and 256 MiB
- **Unbiased, portable pixel order** — the shuffle draws its random numbers without modulo bias and reads them in a fixed byte order, so an image decodes the same on any machine
- **Random nonce per encode** — identical messages encoded with the same passphrase produce different steg images
- **Passphrase read from terminal** — passphrase is never passed as a command-line argument (not visible in `ps`), echo is disabled during input and restored even if the program is interrupted, and new images need at least 12 bytes; `scattersteg passphrase` generates a strong one
- **Secrets kept in protected memory** — the passphrase, message, keys and decrypted text live in libsodium's guarded memory (locked against swapping, fenced by guard pages, wiped on release); core dumps are disabled and, on Linux, other processes can't attach a debugger
- **Hardened build** — the release binary is built with `_FORTIFY_SOURCE=3`, stack protection, PIE and full RELRO
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
make test       # unit, CLI and fault-injection tests, under ASan/UBSan (~1 min)
make fuzz       # libFuzzer on the PNG loader and embedder (needs clang; FUZZ_TIME=60 per target)
make coverage   # line coverage over the whole suite; annotated sources in tests/build/cov
```

GitHub Actions runs the build, `make test` and a minute of fuzzing per target on every push. `make test` needs Python 3 (standard library only). The CLI tests drive the binary through a pseudo-terminal, since the passphrase is read from `/dev/tty`. The fault-injection tests make each `malloc`, `fopen`, `fclose`, `rename` and similar call fail in turn, and check that every error path fails cleanly.

## Usage

**Encode** a message into a PNG:

```bash
# pipe from a file
echo "your message" | ./scattersteg encode -i cover.png -o steg.png

# or type interactively (Ctrl+D when done)
./scattersteg encode -i cover.png -o steg.png
```

You will be prompted to enter and confirm a passphrase of at least 12 bytes. To generate a strong one (about 124 bits):

```bash
./scattersteg passphrase
```

**Decode** a message from a PNG:

```bash
./scattersteg decode -i steg.png
```

You will be prompted for the passphrase used during encoding.

## File format (v2)

There is no header or version marker in the image, since one would give the image away. Every pixel carries one bit per sample, in the LSBs of R, G and B (or of the gray value), written by exchanging values between pairs of samples where possible and LSB matching otherwise.

1. **Salt** — 16 random bytes in the first 43 pixels (128 for grayscale) of a public pixel order: `prng_permutation` keyed with `BLAKE2b-256("ScatterSteg v2 salt positions")`. Public, so the decoder can find it before it has a key, and spread out rather than in a corner.
2. **Keys** — `master = Argon2id(passphrase, salt, opslimit 3, memlimit 256 MiB)`; the scatter key and encryption key are `crypto_kdf` subkeys 1 and 2 of `master`, context `ScatStg2`.
3. **Payload** — a 32-bit little-endian length, then `nonce (24) || crypto_secretbox(message)`, in the order of `prng_permutation(scatter key)` with the salt pixels removed.

`prng_permutation(key, n)` is a forward Fisher–Yates shuffle (for `i` from 0 to n−2, swap slot `i` with `i + uniform(n − i)`), with `uniform` drawing little-endian 32-bit words from the ChaCha20-IETF keystream of `key` (zero nonce, counter from 0) and rejecting values below `2³² mod bound`. Decode tries v2 first and falls back to the v1 format of earlier versions.

## Limitations

- Covers must be 8-bit RGB or 8-bit grayscale PNGs without transparency, and the output keeps that format. Covers with transparency, 16-bit color, a color palette or fewer than 8 bits per sample are refused, since the output would come out in a visibly different format. A grayscale cover holds a third as much as an RGB one.
- Against the classic detectors, the chi-square attack and sample pair analysis, embedding was not detectable in testing on photographs: chi-square stayed negative even at full capacity, and sample pair analysis stayed within about 0.1 of the cover's own estimate at every payload (with LSB overwriting it tracks the payload, e.g. about 0.5 at half capacity). Modern machine-learning steganalysis can detect LSB matching at lower payloads and hasn't been tested. Keep messages small relative to the cover; a few KB in a photo-sized image uses well under 1% of its capacity.
- Images written before format v2 still decode, with a warning. In that old format most wrong passphrases could be rejected without running Argon2id (about 100× cheaper per guess on small images), so re-encode them.
- The exchange keeps the histogram except for one shift: carrier samples end up half even and half odd, because the encrypted message bits are random. Histogram-based detectors such as HCF-COM still see that shift, so exchange improved them only modestly in testing.
- Covers with gaps in their histogram (posterized images, or ones with few distinct values) hide data badly: changes there create values the image never had, and there's no neighbouring value to exchange with.
- Smooth, flat areas (digital art, gradients) hide data worse than noisy photographs, since any ±1 change stands out where neighbouring pixels are identical.
- The output keeps the cover's metadata chunks that come before the image data (gamma, color profile, physical size, text, modification time, EXIF, and unknown chunks marked safe to copy), but not chunks placed after it, and the image data is recompressed. Anyone who has the original cover can find the changes by comparing pixels.
- This is a learning project, not a production security tool
