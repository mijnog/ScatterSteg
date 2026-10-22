# ScatterSteg

**Hide encrypted messages inside PNG and JPEG images — scattered, syndrome-coded and statistically quiet.**

```bash
echo "meet at the old bridge" | ./scattersteg encode -i photo.jpg -o holiday.jpg
./scattersteg decode -i holiday.jpg
```

ScatterSteg combines modern authenticated encryption with steganography techniques from the research literature, so the image that comes out looks, to the eye and to classic steganalysis, like the one that went in.

## Highlights

**Steganography**
- 🎲 **Scattered embedding** — bits go to a secret, passphrase-derived permutation of the image, never to the first N pixels
- 🧮 **Syndrome-trellis codes (STC)** — the message is the *syndrome* of many carrier bits, and a Viterbi search finds the cheapest changes that produce it: **2.4–3.3× fewer changes** at typical payloads
- ⚖️ **Histogram-preserving exchange** — changes are paired up as value swaps (the idea behind steghide), so over 99% of them leave the image histogram untouched
- ±1 **LSB matching** — no value ever changes by more than 1, and there's none of the pairs-of-values fingerprint that LSB overwriting leaves
- 🖼️ **PNG and JPEG** — JPEG messages live in the DCT coefficients, read and written **losslessly**: nothing is decompressed and recompressed
- 🪞 **The cover's format survives** — grayscale stays grayscale, progressive stays progressive, EXIF, ICC profiles, text and other metadata are carried over; covers that would come out visibly different are refused

**Cryptography**
- 🔐 **XSalsa20-Poly1305** authenticated encryption, with a fresh nonce every time
- 🧂 **Argon2id** (256 MiB, 3 passes) with a per-image salt gates *everything*: without paying for it, an attacker can't even tell where the message would be — each passphrase guess costs ~0.2 s and 256 MiB
- 🧷 **No version marker or header** in the image to give it away

**Engineering**
- 🛡️ Secrets in **libsodium guarded memory** (locked, guard pages, wiped), core dumps off, debugger attach blocked, hardened build (FORTIFY 3, PIE, full RELRO)
- 🧪 Hundreds of unit checks, end-to-end CLI tests, **fault injection on every failing call**, **five libFuzzer targets**, AddressSanitizer/UBSan everywhere, and CI on every push

## Quick start

```bash
sudo apt install libsodium-dev libpng-dev libjpeg-dev   # Ubuntu/Debian
make

./scattersteg passphrase                                 # a strong random passphrase (~124 bits)
echo "your message" | ./scattersteg encode -i cover.png -o steg.png
./scattersteg decode -i steg.png
```

The passphrase is always read from the terminal, never from the command line (so it never shows up in `ps`), with echo off. New images need at least 12 bytes of passphrase. The message comes from stdin, or is typed at the terminal (Ctrl+D to finish). The output has the cover's format, so a JPEG cover gives a JPEG.

## How it works

```
 passphrase ──┐
              ▼
 salt ──► Argon2id ──► master key ──┬──► scatter key ──► secret pixel order
 (16 random bytes,                   └──► encryption key
  at public positions)                          │
                                                ▼
 message ─────────────────────────► XSalsa20-Poly1305 ──► box
                                                │
                                                ▼
             STC: find the cheapest bit changes that make
             the box the syndrome of the carriers' bits
                                                │
                                                ▼
             pair the changes into value swaps where possible,
             ±1 nudges otherwise ──► write the image back
```

1. **Keys.** A random salt is hidden at public pseudo-random positions. Argon2id turns the passphrase and salt into a master key, split into a *scatter key* and an *encryption key*.
2. **Encryption.** The message is sealed with XSalsa20-Poly1305. A wrong passphrase or a tampered image fails authentication with a clear error.
3. **Where.** The scatter key drives an unbiased ChaCha20 Fisher–Yates shuffle that orders the carriers: pixel samples in a PNG, AC coefficients with |value| ≥ 2 in a JPEG.
4. **What changes.** Instead of writing each bit into one carrier (and changing about half of them), the box becomes the syndrome H·y of many more carrier bits. A Viterbi pass over a 128-state trellis finds the cheapest y with that syndrome, so few carriers change and the cover's own statistics are left nearly intact.
5. **How it changes.** Every change is ±1. Pairs of carriers that need flipping and hold values one apart swap values instead, which leaves the histogram exactly as it was.

## Measured, not assumed

Every claim about detectability was measured on real images (two photographs; the overwriting baseline for sample pair analysis on a painting), against the classic detectors for LSB steganography:

| Detector | Writing bits directly | ScatterSteg (STC) |
|---|---|---|
| Changes needed, PNG at 5–10% of capacity | 340–682 K | **102–221 K** |
| Ker's adjacency HCF-COM shift (cover 93.81), 5–25% | 2.4–10.7 | **0.5–0.7** |
| JPEG 2:3 coefficient ratio at 25% (cover 2.087) | 1.671 (−20%) | **2.079 (−0.4%)** |
| Chi-square attack, any payload | fires with sequential LSB | **doesn't fire** |
| Sample pair analysis | tracks payload with LSB overwriting (≈0.5 at half capacity) | **stays within 0.1 of the cover's value** |

Some ideas that *didn't* survive measurement were dropped. For example, content-adaptive PNG costs did worse than uniform costs on these detectors, so they aren't used. See [Limitations](#limitations) for where the method stops working.

## Robustness

Fuzzing found real bugs, and each one is fixed and kept as a regression test in `tests/fuzz/regressions`:

- a 290-byte PNG that made Ubuntu's libpng allocate **1.3 GB** (libpng now runs on a capped allocator)
- a text chunk libpng will read but refuses to write back
- JPEGs that decode but can't be re-encoded (out-of-range coefficients, quantization tables redefined mid-file, oversampled progressive scans); encode now does a trial write and refuses them up front

Other defences:
- Images are capped at 1 GiB of pixels or coefficients before anything is allocated.
- Progressive JPEGs are capped at 500 scans.
- Output is written to a temp file, fsync'd and renamed into place, so a failed write never destroys an existing file. It keeps the existing file's permissions and group, and writes through symlinks.
- Ctrl+C at the passphrase prompt restores the terminal.

## Testing

```bash
make test       # unit, CLI and fault-injection tests, under ASan/UBSan (~2 min)
make fuzz       # libFuzzer: PNG loader, JPEG loader, embedder, STC, PNG round trip (needs clang)
make coverage   # line coverage over the whole suite (~98%); annotated sources in tests/build/cov
```

- **Unit tests:** cover every module, including known-answer tests that pin the file format.
- **CLI tests:** drive the real binary through a pseudo-terminal, and cross-check it against an independent Python implementation of the format, in both directions.
- **Fault injection:** makes each `malloc`, `fopen`, `fclose`, `rename`, `crypto_pwhash` and similar call fail in turn, and checks every error path fails cleanly: no leaks, no double closes, no damaged output.
- **CI:** GitHub Actions builds, tests and fuzzes on every push. `make test` needs only Python 3's standard library.

## Supported covers

| | PNG | JPEG |
|---|---|---|
| Kinds | 8-bit RGB or grayscale, no transparency | 8-bit baseline or progressive, Huffman or arithmetic coding |
| Carriers | every sample (3 bits per RGB pixel) | AC coefficients with \|value\| ≥ 2 |
| Typical capacity | ~760 KB in a 1080p image | ~0.12–0.15 bits/pixel (~68 KB in 4.5 MP) |
| Kept from the cover | gAMA, cHRM, sRGB, iCCP, pHYs, text, tIME, eXIf, safe-to-copy chunks | quantization, sampling, coding mode, restart interval, APPn/COM markers |
| Refused | palette, transparency, 16-bit, <8-bit gray | 12-bit, lossless, not re-encodable |

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

- **Not independently reviewed.** The engineering is thoroughly tested, but neither the cryptography nor the steganography has had an outside audit. Don't stake anyone's safety on it.
- **Machine-learning steganalysis hasn't been tested.** Modern detectors are much stronger than the classic ones measured above. Keep messages small relative to the cover; a few KB in a photo-sized image uses well under 1% of its capacity.
- **Near full capacity the advantages fade.** The closer the message is to the number of carrier bits, the less freedom STC and the exchange have, and the JPEG 2:3 shift returns past about half of capacity.
- **Choose noisy photographs as covers.** Flat areas, gradients and posterized images (few distinct values, gaps in the histogram) hide data badly: any ±1 change stands out where neighbouring pixels are identical, and there's no neighbouring value to exchange with.
- **JPEG carries less, and is more detectable per bit, than PNG.** A JPEG is re-encoded from the same coefficients, so only embedded positions change, but the file isn't byte for byte the cover: optimized Huffman tables are optimized afresh, and a progressive file gets libjpeg's standard scan sequence.
- **Some metadata is lost.** PNG chunks placed after the image data aren't kept, and the PNG image data is recompressed. Anyone who has the original cover can find the changes by comparing pixels.
- **Old images.** v1 images (from before format v2) still decode, with a warning to re-encode them, because in v1 most wrong passphrases could be rejected without running Argon2id. v2 images decode silently; they're as well protected, just more detectable.
- **Ctrl+Z at the passphrase prompt** can leave terminal echo off (Ctrl+C, SIGTERM and SIGHUP are handled).

## References

- T. Filler, J. Judas, J. Fridrich — *Minimizing Additive Distortion in Steganography Using Syndrome-Trellis Codes* (2011)
- S. Hetzl, P. Mutzel — *A Graph-Theoretic Approach to Steganography* (2005), the method behind steghide; reimplemented here from the paper
- A. Ker — *Steganalysis of LSB Matching in Grayscale Images* (2005); S. Dumitrescu, X. Wu, Z. Wang — *Detection of LSB Steganography via Sample Pair Analysis* (2003); A. Westfeld, A. Pfitzmann — *Attacks on Steganographic Systems* (1999): the detectors measured against
- [libsodium](https://doc.libsodium.org/), [libpng](http://www.libpng.org/pub/png/libpng.html), [libjpeg-turbo](https://libjpeg-turbo.org/)
