# ScatterSteg

[![CI](https://github.com/mijnog/ScatterSteg/actions/workflows/ci.yml/badge.svg)](https://github.com/mijnog/ScatterSteg/actions/workflows/ci.yml)

ScatterSteg hides an encrypted message inside a PNG or JPEG photo. Only someone with the passphrase can read the message, and the photo is changed as little as possible, in the places where changes are hardest to notice, so that it is hard to tell from an ordinary photo.

```bash
echo "meet at the old bridge" | ./scattersteg encode -i photo.jpg -o holiday.jpg
./scattersteg decode -i holiday.jpg
```

## How safe is it?

- **The message itself is well protected.** It is encrypted and authenticated with standard, well-reviewed cryptography (libsodium), and every passphrase guess costs an attacker about 0.2 s and 256 MiB of memory. A changed image fails to decode; it never yields a wrong message.
- **Hiding that a message exists is harder, and only partly achieved.** The trained detectors measured so far catch ScatterSteg about 50–65% of the time at the payloads tested, against 96–98% for steghide. That is much better than steghide, but it is not invisibility, and stronger detectors would do better. See [Steganalysis results](#steganalysis-results).
- **Nobody independent has reviewed it.** The code is heavily tested and has had a security audit of its own ([`AUDIT-2026-10-24.md`](AUDIT-2026-10-24.md)), but no outside review. Don't rely on it where your safety is at stake.

[`THREAT_MODEL.md`](THREAT_MODEL.md) says exactly what it protects, against whom, and what it doesn't.

## Install

```bash
sudo apt install libsodium-dev libpng-dev libjpeg-dev   # Ubuntu/Debian
make
```

This builds `./scattersteg`. There is also a Rust version in [`rust/`](rust/README.md) with the same commands and file format (an image written by one decodes with the other): `cd rust && cargo build --release`, which also needs pkg-config and libclang.

## Use

```bash
./scattersteg passphrase                                  # print a strong random passphrase
echo "your message" | ./scattersteg encode -i cover.png -o secret.png
./scattersteg decode -i secret.png
```

- **The passphrase** is always typed at the terminal, with echo off, so it never appears in the process list or your shell history. A new image needs one of at least 12 bytes; `scattersteg passphrase` prints a random one of about 124 bits.
- **The message** is read from standard input: pipe it in, or type it and press Ctrl+D. An empty message is an error.
- **Files, byte for byte:** use `-r` on both commands, as in `encode -r -i cover.jpg -o out.jpg < secret.txt` and `decode -r -i out.jpg > secret.txt`. Without `-r`, encode drops one trailing newline and decode adds one, which suits typed text.
- **The output** has the cover's format and metadata: a progressive JPEG stays progressive, a grayscale PNG stays grayscale, and EXIF, ICC profiles and text are kept.
- **Nothing is written unless it will decode.** The output is built in memory and read back first; if a decoder wouldn't see exactly what was embedded, encode fails and writes nothing. An existing file is replaced in one step, so a failed or interrupted encode never destroys it.

### Choosing a cover

How hard the message is to detect depends mostly on the cover and on how much you hide.

- **Use a photo nobody else has.** Anyone who has the original can compare the two and see that something changed. Don't use a photo you've posted or sent, or one from the internet; never encode twice from the same photo; delete the original afterwards.
- **Use a noisy photo.** Busy, detailed photographs hide changes well. Flat areas, gradients, screenshots and drawings hide them badly.
- **Keep the message small.** A few kilobytes in a photo-sized image is far below its capacity, and lighter than any payload measured. Detection rises with the message size.
- **Prefer a file that a program has already rewritten** over one straight from a camera or phone. ScatterSteg writes the file anew, and a careful observer could notice that (see A1 in [`THREAT_MODEL.md`](THREAT_MODEL.md)).

| | PNG | JPEG |
|---|---|---|
| Accepted | 8-bit RGB or grayscale, no transparency | 8-bit baseline or progressive, Huffman or arithmetic coding |
| Capacity | about 760 KB in a 1080p image | about 0.12–0.15 bits per pixel (about 68 KB in 4.5 MP) |
| Kept from the cover | interlacing, and every ancillary chunk the PNG spec defines (color space, pHYs, text, tIME, eXIf...) or marks safe to copy, byte for byte and in place | quantization, sampling, coding mode, restart interval, APPn and COM markers |
| Refused | palette, transparency, 16-bit, gray below 8 bits, an `sBIT` chunk under 8, RGB whose pixels are all gray | 12-bit, lossless, files that can't be rewritten exactly, data after the image (MPO, Ultra HDR) |

ScatterSteg refuses a cover rather than produce an output that would give it away.

### Coming from steghide

| steghide | ScatterSteg |
|---|---|
| `steghide embed -cf cover.jpg -ef secret.txt -sf out.jpg` | `./scattersteg encode -r -i cover.jpg -o out.jpg < secret.txt` |
| `steghide extract -sf out.jpg -xf secret.txt` | `./scattersteg decode -r -i out.jpg > secret.txt` |
| `-p passphrase` | not accepted: typed at the terminal instead |
| `steghide info` | none: the image has no header, so there is nothing to report without the passphrase |
| `-e`, `-z`, `-N`, `-K` | none: the encryption is fixed, and no filename is stored |

ScatterSteg reads PNG and JPEG, not BMP, WAV or AU, and neither tool can read the other's images. Every encode and decode takes about 0.2 s, on purpose: that is the cost that slows down passphrase guessing.

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

1. **Keys.** A random salt is hidden at public positions. Argon2id turns the passphrase and salt into a master key, which gives a *scatter key* and an *encryption key*.
2. **Encryption.** The message is encrypted and authenticated with XSalsa20-Poly1305.
3. **Order.** The scatter key shuffles the image's carriers into a secret order: the pixel samples of a PNG, or the AC coefficients of magnitude 2 or more in a JPEG.
4. **Syndrome coding.** Instead of writing one bit into each carrier, which changes about half of them, syndrome-trellis codes (STC) find the cheapest set of changes that encodes the message. "Cheapest" comes from content-adaptive costs: HILL for PNG and UERD for JPEG make a change cheap where the image is busy and expensive where it is flat. This makes 2 to 3 times fewer changes than writing the bits directly, in the places hardest to notice.
5. **Changes.** Every change is ±1. Where two carriers that both need changing hold values one apart, they swap values instead, which leaves the image's histogram exactly as it was (93–98.5% of changes, on photographs).

JPEG coefficients are edited directly: the image is never decompressed and recompressed. The image stores no header or version marker. [`FORMAT.md`](FORMAT.md) specifies the format exactly.

## Steganalysis results

Detection error against the strongest detectors measured (0.5 means the detector is guessing; lower means easier to detect), on 480 photographs from Wikimedia Commons:

| Payload | 0.05 | 0.1 | 0.2 | 0.4 |
|---|---|---|---|---|
| **ScatterSteg, PNG** | **0.44** | **0.42** | **0.39** | **0.36** |
| **ScatterSteg, JPEG** | **0.50** | **0.48** | **0.39** | — |
| steghide (as BMP) | 0.04 | 0.03 | 0.02 | 0.02 |
| plain LSB matching | 0.17 | 0.09 | 0.05 | 0.02 |

Payload is message bits per pixel for PNG, and per non-zero AC coefficient for JPEG. steghide's JPEG figures are similar to its BMP ones (0.21, 0.10 and 0.03). The classic detectors (chi-square, sample pair analysis, HCF-COM) barely move.

These are relative results, not a claim of undetectability: the detectors are reimplementations trained on a few hundred images at a known payload, and the published models and deep-learning detectors, not yet run, would do better. [`benchmark/README.md`](benchmark/README.md) has every measurement, a second cover set, the method, and the full list of limitations.

## Limitations

- **The original photo gives it away.** Anyone with it can compare and see that something changed (not what).
- **Trained detectors catch it often**, more so as the message grows; see above.
- **Lossy processing destroys the message.** Most platforms recompress or resize uploads. Send the file itself.
- **Big messages are much easier to detect.** Near capacity, the coding has little freedom left.
- **Not deniable.** There is no decoy message: if you're forced to give up the passphrase, the message is revealed.
- **Very large images need a lot of memory**, up to several GB for the largest accepted (see A5 in the threat model).
- **Old images** (format v1) still open, with a warning to re-encode them: that format let wrong passphrases be rejected cheaply.
- **Suspending the program** (Ctrl+Z) at the passphrase prompt can leave the terminal's echo off. Ctrl+C, SIGTERM and SIGHUP are handled.

## Development

```bash
make test       # unit, CLI and fault-injection tests, under ASan/UBSan (~3 min)
make fuzz       # the six libFuzzer targets (needs clang)
make coverage   # line coverage over the whole suite (~98%); annotated sources in tests/build/cov
```

The tests include known-answer tests that fix the file format, end-to-end tests through a pseudo-terminal, a cross-check in both directions against an independent Python implementation, fault injection that makes each fallible library call fail in turn, and sanitizers throughout. The Rust port runs the same CLI tests, and C and Rust are fuzzed against each other. CI builds, tests and fuzzes both on every push.

Secrets are held in libsodium's guarded memory (locked against swap, fenced by guard pages, wiped on release); core dumps and debugger attachment are disabled, and the release build is hardened (`_FORTIFY_SOURCE=3`, stack protection, PIE, full RELRO). Untrusted images are parsed under fixed limits on memory and work; see A5 in [`THREAT_MODEL.md`](THREAT_MODEL.md).

[`CONTRIBUTING.md`](CONTRIBUTING.md) covers what a change needs; report security problems as described in [`SECURITY.md`](SECURITY.md).

## License

Copyright (C) 2026 Maxime de Montbron.

ScatterSteg is free software, licensed under the [GNU Affero General Public License v3.0 or later](LICENSE) (AGPL-3.0-or-later). You may use, modify and distribute it, but any distributed version, and any modified version made available to users over a network, must be released under the same license with its source code.

## References

- T. Filler, J. Judas, J. Fridrich — *Minimizing Additive Distortion in Steganography Using Syndrome-Trellis Codes* (2011)
- Li, Wang, Huang and Li (2014): HILL, the PNG costs
- Guo, Ni, Su, Chen and Shi (2015): UERD, the JPEG costs
- S. Hetzl, P. Mutzel — *A Graph-Theoretic Approach to Steganography* (2005), the method behind steghide; reimplemented here from the paper
- A. Ker — *Steganalysis of LSB Matching in Grayscale Images* (2005); S. Dumitrescu, X. Wu, Z. Wang — *Detection of LSB Steganography via Sample Pair Analysis* (2003); A. Westfeld, A. Pfitzmann — *Attacks on Steganographic Systems* (1999): the classic detectors measured against
- [libsodium](https://doc.libsodium.org/), [libpng](http://www.libpng.org/pub/png/libpng.html), [libjpeg-turbo](https://libjpeg-turbo.org/)
