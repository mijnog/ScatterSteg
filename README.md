# ScatterSteg

A command-line steganography tool that hides encrypted messages inside PNG and JPEG images.

## Rationale

Most LSB steganography tools embed data sequentially — bit 0 goes into pixel 0, bit 1 into pixel 1, and so on. This makes detection straightforward: statistical analysis of the least-significant bits reveals a clear pattern in the first N pixels.

ScatterSteg takes a different approach. The embedding positions are derived from a passphrase using ChaCha20, producing a pseudo-random permutation of pixel indices. Without the passphrase, an attacker cannot determine which pixels carry data, let alone recover it.

Scattering hides *where* the data is, but not by itself *that* it is there. Simply overwriting the least-significant bit only ever swaps a value with its partner (2k ↔ 2k+1), which leaves a statistical fingerprint across the whole image that detectors such as sample pair analysis pick up wherever the bits are. So ScatterSteg uses LSB matching instead: when a value's LSB needs to change, it randomly adds or subtracts 1. The hidden bit is the same and decoding is unchanged, but the fingerprint is gone.

The message itself is also encrypted with XSalsa20-Poly1305 (`crypto_secretbox`) before embedding, so even if the scatter pattern were somehow recovered, the payload remains ciphertext. A random nonce is generated for each encode operation, meaning the same message encoded twice produces different output.

## Features

- **Scatter-based LSB embedding** — pixel selection is a ChaCha20-derived Fisher-Yates shuffle, not sequential
- **LSB matching** — bits are embedded by a random ±1 change rather than by overwriting the LSB, so no sample changes by more than 1 and the pair statistics that classic steganalysis relies on are left intact
- **PNG and JPEG covers** — in a JPEG the message goes into the quantized DCT coefficients, which are read and written losslessly: no pixels are decoded and recompressed, a JPEG that isn't modified comes back byte for byte, and the output keeps the cover's quantization, subsampling, progressive or baseline coding, restart interval and markers (EXIF, ICC profile, comments)
- **Syndrome coding (STC)** — the message isn't written into carrier bits one for one: it is the *syndrome* of many more carrier bits (syndrome-trellis codes, Filler, Judas & Fridrich, 2011), and the encoder finds, with the Viterbi algorithm, the cheapest set of changes that produces it. At 5–10% of capacity that took 2.4–3.3× fewer changes on the photos tested, and it leaves the cover's own bits, and their statistics, nearly as they were
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
- [libjpeg-turbo](https://libjpeg-turbo.org/) (or libjpeg) — JPEG coefficient read/write

On Ubuntu/Debian:

```bash
sudo apt install libsodium-dev libpng-dev libjpeg-dev
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

**Encode** a message into a PNG or JPEG (the output is in the cover's format):

```bash
# pipe from a file
echo "your message" | ./scattersteg encode -i cover.png -o steg.png

# or type interactively (Ctrl+D when done)
./scattersteg encode -i cover.png -o steg.png

# JPEG covers work the same way
echo "your message" | ./scattersteg encode -i photo.jpg -o steg.jpg
```

You will be prompted to enter and confirm a passphrase of at least 12 bytes. To generate a strong one (about 124 bits):

```bash
./scattersteg passphrase
```

**Decode** a message:

```bash
./scattersteg decode -i steg.png
```

You will be prompted for the passphrase used during encoding.

## File format (v3)

There is no header or version marker in the image, since one would give the image away. Every pixel holds one bit per sample, in the LSBs of R, G and B (or of the gray value), set by exchanging values between pairs of samples where possible and LSB matching otherwise. Below, "sample k" means bit position k counted along the payload order: pixel `order[k / channels]`, channel `k % channels`.

1. **Salt** — 16 random bytes in the first 43 pixels (128 for grayscale) of a public pixel order: `prng_permutation` keyed with `BLAKE2b-256("ScatterSteg v2 salt positions")`. Public, so the decoder can find it before it has a key, and spread out rather than in a corner.
2. **Keys** — `master = Argon2id(passphrase, salt, opslimit 3, memlimit 256 MiB)`; the scatter key and encryption key are `crypto_kdf` subkeys 1 and 2 of `master`, context `ScatStg2`.
3. **Order** — `prng_permutation(scatter key)` over the pixels, with the salt pixels removed.
4. **Length** — the box length L (32 bits, little-endian), in the LSBs of samples 0–31.
5. **Box** — `nonce (24) || crypto_secretbox(message)`, as bits (LSB first), is the STC syndrome of the LSBs of the samples from 32 on. With N samples left and m = 8L message bits, n = min(N, 64·m) of them are used; message bit i is row i of H·y, where block i covers samples ⌊i·n/m⌋ to ⌊(i+1)·n/m⌋ − 1 and its j-th sample contributes column j of the 7-row submatrix to rows i…i+6. Columns: splitmix64 seeded with `0x5354432d48415431 ^ (⌊n/m⌋ + 1)`, low 7 bits, with bits 0 and 6 set. The rows run in independent chunks of ⌊2²⁰ / (⌊n/m⌋ + 1)⌋ message bits.

**JPEG** uses the same layout over a different kind of position: each *carrier* is one AC coefficient with |value| ≥ 2, taken in component, block-row, block and coefficient order, and carries one bit. So the salt takes the first 128 carriers of the public order. DC coefficients, zeros and ±1 are never used, and embedding keeps every carrier at |value| ≥ 2 and within ±1023, so the decoder finds the same carriers and the encoder can write them.

**Costs** steer which samples change, and are the encoder's choice (the decoder doesn't need them): uniform for PNG; for JPEG, the coefficient's quantization step, ×1.5 when |value| = 2.

**v2** is the same with the box's bits written straight into samples 32 on; **v1** used a BLAKE2b-only scatter key. Decode tries v3, v2 (same keys, one Argon2id run), then v1.

`prng_permutation(key, n)` is a forward Fisher–Yates shuffle (for `i` from 0 to n−2, swap slot `i` with `i + uniform(n − i)`), with `uniform` drawing little-endian 32-bit words from the ChaCha20-IETF keystream of `key` (zero nonce, counter from 0) and rejecting values below `2³² mod bound`.

## Limitations

- Covers must be 8-bit RGB or 8-bit grayscale PNGs without transparency, and the output keeps that format. Covers with transparency, 16-bit color, a color palette or fewer than 8 bits per sample are refused, since the output would come out in a visibly different format. A grayscale cover holds a third as much as an RGB one.
- Against the classic detectors, embedding was not detectable in testing on photographs: the chi-square attack stayed negative at full capacity, and sample pair analysis stayed near the cover's own estimate at every payload (with LSB overwriting it tracks the payload, e.g. about 0.5 at half capacity). Against the HCF-COM detectors for LSB matching, syndrome coding is what made the difference: on a photo, Ker's adjacency HCF-COM moved by 0.5–0.7 at 5–25% of capacity, against 2.4–10.7 when writing bits directly. Modern machine-learning steganalysis hasn't been tested, and content-adaptive costs, which are aimed at it, did worse than uniform costs on the detectors above, so PNG uses uniform costs for now. Keep messages small relative to the cover; a few KB in a photo-sized image uses well under 1% of its capacity.
- JPEG covers carry far less than PNGs (one bit per AC coefficient with |value| ≥ 2: about 0.12–0.15 bits per pixel on the photos tested, e.g. ~68 KB in a 4.5-megapixel photo), and are more detectable per bit. JPEG coefficients are much more often 2 than 3, 4 than 5 and so on; writing message bits directly evens that out (the ratio of 2s to 3s fell from 2.09 to 1.67 at 25% of capacity on a photo), which calibration-based JPEG steganalysis estimates and would notice. Syndrome coding with the costs above holds it within about 0.5% of the cover's up to 25% (2.087 → 2.079 on the same photo), with 2–2.6× fewer changes. Past about half of capacity there's little room left to choose, and the shift returns. (The classic chi-square attack on coefficients did not fire at any payload.)
- A JPEG is re-encoded from the same coefficients, so the image data is unchanged except where bits were embedded, but the file isn't byte for byte the cover: optimized Huffman tables are optimized afresh, and a progressive file gets libjpeg's standard scan sequence. JPEGs libjpeg can decode but not re-encode (found by fuzzing: some redefine quantization tables between scans), 12-bit, lossless and over-large JPEGs are refused as covers.
- v1 images (written before format v2) still decode, with a warning: in v1 most wrong passphrases could be rejected without running Argon2id (about 100× cheaper per guess on small images), so re-encode them. v2 images decode silently; they're as well protected, just more detectable.
- The exchange keeps the histogram except where pairs can't be found, and syndrome coding keeps changes few, but both lose their edge near full capacity: the closer the message is to the number of carrier bits, the less freedom there is in choosing which to change.
- Covers with gaps in their histogram (posterized images, or ones with few distinct values) hide data badly: changes there create values the image never had, and there's no neighbouring value to exchange with.
- Smooth, flat areas (digital art, gradients) hide data worse than noisy photographs, since any ±1 change stands out where neighbouring pixels are identical.
- The output keeps the cover's metadata chunks that come before the image data (gamma, color profile, physical size, text, modification time, EXIF, and unknown chunks marked safe to copy), but not chunks placed after it, and the image data is recompressed. Anyone who has the original cover can find the changes by comparing pixels.
- This is a learning project, not a production security tool
