# ScatterSteg

ScatterSteg is a command-line tool for hiding encrypted messages in PNG and JPEG images. It combines authenticated encryption and memory-hard key derivation with steganographic techniques from the research literature (syndrome-trellis coding, LSB matching and histogram-preserving value exchange), so that the output image is statistically close to the cover it was made from.

```bash
echo "meet at the old bridge" | ./scattersteg encode -i photo.jpg -o holiday.jpg
./scattersteg decode -i holiday.jpg
```

## Features

### Steganography

- **Keyed embedding order.** Bits are placed along a secret permutation of the image derived from the passphrase, not sequentially from the first pixel.
- **Syndrome-trellis codes (STC).** The message is encoded as the syndrome of a larger set of carrier bits, and a Viterbi search selects the least costly set of changes that produces it. At typical payloads this requires 2.4–3.3 times fewer changes than writing the bits directly.
- **Histogram-preserving exchange.** Required changes are paired into value swaps where possible (the approach used by steghide), which leaves the image histogram unchanged for over 99% of changes on photographs.
- **LSB matching.** No sample changes by more than 1, and the pairs-of-values artifact produced by LSB replacement is avoided.
- **PNG and JPEG covers.** In JPEG images the message is carried by the quantized DCT coefficients, which are read and written losslessly; the image is never decompressed and recompressed.
- **Format preservation.** The output keeps the cover's format and metadata: grayscale remains grayscale, progressive JPEGs remain progressive, and EXIF, ICC profiles and text chunks are retained. Covers that could not be reproduced in their original format are refused.

### Cryptography

- **Authenticated encryption** with XSalsa20-Poly1305 and a fresh random nonce for every message.
- **Argon2id key derivation** (256 MiB, 3 passes) with a per-image salt. Both the embedding order and the encryption key depend on it, so no property of the message, including its location, can be tested without completing a full Argon2id computation; each passphrase guess costs about 0.2 s and 256 MiB.
- **No header or version marker** is stored in the image.

### Engineering

- Secrets are held in libsodium guarded memory (locked, guard pages, wiped on release); core dumps are disabled and, on Linux, debugger attachment is blocked. The release build uses `_FORTIFY_SOURCE=3`, stack protection, PIE and full RELRO.
- The test suite comprises unit tests, end-to-end CLI tests, fault injection on every fallible library call, five libFuzzer targets and AddressSanitizer/UndefinedBehaviorSanitizer instrumentation, and runs in CI on every push.

## Quick start

```bash
sudo apt install libsodium-dev libpng-dev libjpeg-dev   # Ubuntu/Debian
make

./scattersteg passphrase                                 # a strong random passphrase (~124 bits)
echo "your message" | ./scattersteg encode -i cover.png -o steg.png
./scattersteg decode -i steg.png
```

The passphrase is read from the terminal with echo disabled and is never accepted as a command-line argument, so it does not appear in the process list. New images require a passphrase of at least 12 bytes. The message is read from standard input, or typed at the terminal and terminated with Ctrl+D. The output is written in the cover's format.

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

1. **Key derivation.** A random salt is stored at public pseudo-random positions. Argon2id derives a master key from the passphrase and salt, from which a *scatter key* and an *encryption key* are derived.
2. **Encryption.** The message is sealed with XSalsa20-Poly1305. A wrong passphrase or a modified image fails authentication and is reported as an error.
3. **Embedding order.** The scatter key drives an unbiased Fisher–Yates shuffle (ChaCha20) over the carriers: pixel samples in a PNG, AC coefficients with |value| ≥ 2 in a JPEG.
4. **Syndrome coding.** Rather than writing each bit into one carrier, which changes about half of them, the encrypted payload is encoded as the syndrome H·y of a larger set of carrier bits. A Viterbi search over a 128-state trellis selects the least costly y with that syndrome, so few carriers change and the cover's statistics are largely preserved.
5. **Sample modification.** Every change is ±1. Where two carriers that both require a change hold values one apart, they exchange values instead, leaving the histogram unchanged.

## Steganalysis results

All detectability figures below were measured on real images (two photographs; the overwriting baseline for sample pair analysis on a painting), against the classic detectors for LSB steganography:

| Detector | Writing bits directly | ScatterSteg (STC) |
|---|---|---|
| Changes needed, PNG at 5–10% of capacity | 340–682 K | **102–221 K** |
| Ker's adjacency HCF-COM shift (cover 93.81), 5–25% | 2.4–10.7 | **0.5–0.7** |
| JPEG 2:3 coefficient ratio at 25% (cover 2.087) | 1.671 (−20%) | **2.079 (−0.4%)** |
| Chi-square attack, any payload | triggered by sequential LSB | **not triggered** |
| Sample pair analysis | tracks payload with LSB overwriting (≈0.5 at half capacity) | **stays within 0.1 of the cover's value** |

### Against a trained classifier, and against steghide

The classic detectors above test one statistic each. A harder test is a machine-learning detector trained on cover/stego pairs. [`benchmark/`](benchmark/) embeds the same random messages with ScatterSteg, steghide 0.5.1 and plain LSB embedding into 476 photographs (512×512, from Wikimedia Commons) and trains an RBF SVM on half the pairs. The table gives its detection error on the other half: 0.5 means it cannot beat guessing, and lower means easier to detect. Payload is bits per pixel for PNG and BMP, and per non-zero AC coefficient for JPEG. Standard error is about ±0.02.

| Pixel payload | LSB matching | steghide (BMP) | **ScatterSteg (PNG)** |
|---|---|---|---|
| 0.05 | 0.34 | 0.14 | **0.46** |
| 0.10 | 0.25 | 0.12 | **0.41** |
| 0.20 | 0.16 | 0.10 | **0.31** |
| 0.40 | 0.10 | 0.07 | **0.20** |

| JPEG payload | steghide | **ScatterSteg** |
|---|---|---|
| 0.05 | 0.34 | **0.42** |
| 0.10 | 0.24 | **0.40** |
| 0.20 | 0.13 | **0.23** |

A stronger, SRM-style rich-model detector (about 7,000 features per channel and an ensemble classifier) on the same files gives:

| Pixel payload | LSB matching | steghide (BMP) | **ScatterSteg (PNG)** |
|---|---|---|---|
| 0.05 | 0.17 | 0.04 | **0.35** |
| 0.10 | 0.09 | 0.03 | **0.25** |
| 0.20 | 0.05 | 0.02 | **0.14** |
| 0.40 | 0.02 | 0.02 | **0.07** |

At the same payload, ScatterSteg is harder for these detectors to catch than steghide and than naive LSB embedding, with both detectors. The rich-model detector is the better estimate: it catches steghide 96–98% of the time at every payload tested, and ScatterSteg about 65% of the time at 0.05 bits per pixel and about 93% at 0.4. So small messages are hard to detect, and large ones are not. This is a relative result, not a claim of undetectability: the covers come from one source, the detector is trained at a known payload, the SRM-style detector is a reimplementation and not the published model, and deep-learning detectors have not been run (they would score every column lower). For JPEG (payload in bits per non-zero AC coefficient), a DCTR-style rich-model detector (5,120 features, ensemble classifier) gives ScatterSteg 0.47, 0.40 and 0.26 at 0.05, 0.1 and 0.2, against steghide 0.21, 0.10 and 0.03: the same ranking, with steghide caught 97% of the time at 0.2 and ScatterSteg 74%. The [benchmark README](benchmark/README.md) has the method and the full list of limitations.

Techniques that did not improve these results were not adopted; for example, content-adaptive PNG costs performed worse than uniform costs against these detectors. See [Limitations](#limitations) for where the method stops working.

## Robustness

Fuzzing has found the following defects, each of which is fixed and retained as a regression test in `tests/fuzz/regressions`:

- A 290-byte PNG that caused Ubuntu's libpng to allocate 1.3 GB. libpng now uses a capped allocator.
- A text chunk that libpng reads but refuses to write. Ancillary chunks are now copied as raw bytes, so such chunks are kept as they were.
- JPEG files that decode but cannot be re-encoded (out-of-range coefficients, quantization tables redefined between scans, sampling factors too large for progressive scans). The encoder now performs a trial write and rejects such covers before deriving keys.
- A truncated progressive JPEG (a first AC scan at Al=1 and no refinement scan) that libjpeg writes back with different coefficients, which would silently corrupt a hidden message. The trial write now also reads its output back and rejects a cover that does not match exactly.

Additional safeguards:
- Decoded images are limited to 1 GiB of pixels or coefficients, checked before allocation, a PNG to 2²⁸ pixels (so the 4-byte-per-pixel permutation stays under 1 GiB too), and a JPEG to as many carriers as 1 GiB of per-carrier working memory allows (about 49 million).
- libpng may hold at most 128 MiB in all, so compressed text chunks cannot inflate without bound.
- Progressive JPEGs are limited to 500 scans.
- Output is written to a temporary file, synced and renamed into place, so a failed write never destroys an existing file. Existing permissions and group ownership are preserved, and symbolic links are written through.
- The terminal is restored if the program is interrupted at the passphrase prompt.

## Testing

```bash
make test       # unit, CLI and fault-injection tests, under ASan/UBSan (~2 min)
make fuzz       # libFuzzer: PNG loader, JPEG loader, embedder, STC, PNG round trip (needs clang)
make coverage   # line coverage over the whole suite (~98%); annotated sources in tests/build/cov
```

- **Unit tests** cover every module, including known-answer tests that fix the file format.
- **CLI tests** drive the binary through a pseudo-terminal and cross-check it in both directions against an independent Python implementation of the format.
- **Fault injection** causes each `malloc`, `fopen`, `fclose`, `rename`, `crypto_pwhash` and similar call to fail in turn, and verifies that every error path fails cleanly, without leaks, double closes or damaged output.
- **The Rust port** (`rust/`) runs the same CLI tests, and `tests/differential.py` gives both binaries the same ~165 odd covers (malformed chunks, truncated and mutated files, fuzzer regressions) and checks they agree on which load. See [rust/README.md](rust/README.md).
- **Continuous integration** builds, tests and fuzzes both implementations on every push. `make test` requires only the Python 3 standard library.

## Supported covers

| | PNG | JPEG |
|---|---|---|
| Kinds | 8-bit RGB or grayscale, no transparency | 8-bit baseline or progressive, Huffman or arithmetic coding |
| Carriers | every sample (3 bits per RGB pixel) | AC coefficients with \|value\| ≥ 2 |
| Typical capacity | ~760 KB in a 1080p image | ~0.12–0.15 bits/pixel (~68 KB in 4.5 MP) |
| Kept from the cover | interlacing, every ancillary chunk the PNG spec defines (color space, pHYs, text, tIME, eXIf...) and safe-to-copy chunks, byte for byte and in place, before or after the image data | quantization, sampling, coding mode, restart interval, APPn/COM markers |
| Refused | palette, transparency, 16-bit, <8-bit gray | 12-bit, lossless, not re-encodable, data after the image (MPO, Ultra HDR) |

## File format (v4)

The image contains no header or version marker, as either would reveal the presence of a message. Every pixel holds one bit per sample, in the LSBs of R, G and B (or of the gray value), set by exchanging values between pairs of samples where possible and LSB matching otherwise. Below, "sample k" means bit position k counted along the payload order: pixel `order[k / channels]`, channel `k % channels`.

1. **Salt** — 16 random bytes, carried as the STC syndrome (as in step 5, with the same costs) of the samples of a public *salt region*: the first k pixels of a public pixel order, `prng_permutation` keyed with `BLAKE2b-256("ScatterSteg v2 salt positions")`, where k = max(⌈128 / channels⌉, min(⌈8192 / channels⌉, ⌊pixels / 16⌋)) and the first min(k · channels, 64 · 128) of its samples are used. Public, so the decoder can find it before it has a key; syndrome-coded, so the roughly 18 changes it needs are as sparse as the payload's.
2. **Keys** — `master = Argon2id(passphrase, salt, opslimit 3, memlimit 256 MiB)`; the scatter key and encryption key are `crypto_kdf` subkeys 1 and 2 of `master`, context `ScatStg2`.
3. **Order** — `prng_permutation(scatter key)` over the pixels, with the salt pixels removed.
4. **Length** — the box length L (32 bits, little-endian), in the LSBs of samples 0–31.
5. **Box** — `nonce (24) || crypto_secretbox(message)`, as bits (LSB first), is the STC syndrome of the LSBs of the samples from 32 on. With N samples left and m = 8L message bits, n = min(N, 64·m) of them are used; message bit i is row i of H·y, where block i covers samples ⌊i·n/m⌋ to ⌊(i+1)·n/m⌋ − 1 and its j-th sample contributes column j of the 7-row submatrix to rows i…i+6. Columns: splitmix64 seeded with `0x5354432d48415431 ^ (⌊n/m⌋ + 1)`, low 7 bits, with bits 0 and 6 set. The rows run in independent chunks of ⌊2²⁰ / (⌊n/m⌋ + 1)⌋ message bits.

**JPEG** uses the same layout over a different kind of position: each *carrier* is one AC coefficient with |value| ≥ 2, taken in component, block-row, block and coefficient order, and carries one bit. Its salt region is counted in carriers (one sample each). DC coefficients, zeros and ±1 are never used, and embedding keeps every carrier at |value| ≥ 2 and within ±1023, so the decoder finds the same carriers and the encoder can write them.

**Costs** determine which samples change and are chosen by the encoder alone (the decoder does not use them): uniform for PNG; for JPEG, the coefficient's quantization step, ×1.5 when |value| = 2.

**v3** wrote the salt's bits straight into the first 43 public pixels (128 samples), about 64 changes at positions anyone can compute; a targeted test of prediction error at those positions detected it slightly above chance (AUC 0.56 on 500 ALASKA2 images, against 0.50 for v4). **v2** is v3 with the box's bits also written straight in, into samples 32 on; **v1** used a BLAKE2b-only scatter key. Decode tries v4, then v3 and v2 (which share a salt layout and keys, so one further Argon2id run), then v1.

`prng_permutation(key, n)` is a forward Fisher–Yates shuffle (for `i` from 0 to n−2, swap slot `i` with `i + uniform(n − i)`), with `uniform` drawing little-endian 32-bit words from the ChaCha20-IETF keystream of `key` (zero nonce, counter from 0) and rejecting values below `2³² mod bound`.

## Limitations

- **No independent review.** The implementation is extensively tested, but neither the cryptography nor the steganography has been externally audited. It should not be relied on where personal safety is at stake. See [THREAT_MODEL.md](THREAT_MODEL.md) for the security claims and their scope.
- **Machine-learning steganalysis.** Modern learned detectors are considerably stronger than the classic detectors measured above. Messages should be small relative to the cover; a few kilobytes in a photograph-sized image uses well under 1% of its capacity.
- **High payloads.** As the message approaches the number of carrier bits, STC and value exchange have less freedom, and the JPEG coefficient-ratio shift reappears beyond about half of capacity.
- **Cover selection.** Noisy photographs are the most suitable covers. Flat regions, gradients and posterized images (few distinct values or gaps in the histogram) conceal changes poorly, since a ±1 change is conspicuous among identical neighbours and no adjacent value is available for exchange.
- **JPEG capacity.** JPEG covers carry less data than PNG covers and are more detectable per bit. Only embedded coefficients change, but the file is not byte-identical to the cover: optimized Huffman tables are regenerated, and progressive files are written with libjpeg's standard scan sequence.
- **Metadata.** PNG image data is recompressed, and unknown chunks not marked safe to copy are dropped, as the PNG specification requires. Anyone holding the original cover can locate the changes by comparison.
- **Earlier formats.** Format v1 images remain readable but produce a warning recommending re-encoding, because v1 allowed most wrong passphrases to be rejected without an Argon2id computation. Format v2 and v3 images are read without a warning; they are equally well protected but more detectable.
- **Job control.** Suspending the program (Ctrl+Z) at the passphrase prompt can leave terminal echo disabled. Ctrl+C, SIGTERM and SIGHUP are handled.

## License

Copyright (C) 2026 Maxime de Montbron.

ScatterSteg is free software, licensed under the [GNU Affero General Public License v3.0 or later](LICENSE) (AGPL-3.0-or-later). You may use, modify and distribute it, but any distributed version, and any modified version made available to users over a network, must be released under the same license with its source code.

## References

- T. Filler, J. Judas, J. Fridrich — *Minimizing Additive Distortion in Steganography Using Syndrome-Trellis Codes* (2011)
- S. Hetzl, P. Mutzel — *A Graph-Theoretic Approach to Steganography* (2005), the method behind steghide; reimplemented here from the paper
- A. Ker — *Steganalysis of LSB Matching in Grayscale Images* (2005); S. Dumitrescu, X. Wu, Z. Wang — *Detection of LSB Steganography via Sample Pair Analysis* (2003); A. Westfeld, A. Pfitzmann — *Attacks on Steganographic Systems* (1999): the detectors measured against
- [libsodium](https://doc.libsodium.org/), [libpng](http://www.libpng.org/pub/png/libpng.html), [libjpeg-turbo](https://libjpeg-turbo.org/)
