# ScatterSteg

[![CI](https://github.com/mijnog/ScatterSteg/actions/workflows/ci.yml/badge.svg)](https://github.com/mijnog/ScatterSteg/actions/workflows/ci.yml)

ScatterSteg hides an encrypted message inside a PNG or JPEG photo. Only someone with the passphrase can read the message, and the photo is changed as little as possible, in the places where changes are hardest to notice, so that it is hard to tell from an ordinary photo.

```bash
./scattersteg embed -cf photo.jpg -ef plans.txt -sf holiday.jpg
./scattersteg extract -sf holiday.jpg        # writes plans.txt
```

The commands and options are steghide's, for everything ScatterSteg does, so steghide users already know them (see [Coming from steghide](#coming-from-steghide)).

## How safe is it?

- **The message itself is well protected.** It is encrypted and authenticated with standard, well-reviewed cryptography (libsodium), and every passphrase guess costs an attacker about 0.2 s and 256 MiB of memory. A changed image fails to decode; it never yields a wrong message.
- **Hiding that a message exists is harder, and only partly achieved.** Classic and feature-based detectors catch ScatterSteg 50–65% of the time at the payloads tested, against 96–98% for steghide. But a deep-learning detector (SRNet) trained on images like the cover catches it 87–93% of the time at moderate payloads. Small messages and private covers matter more than anything else. See [Steganalysis results](#steganalysis-results).
- **Nobody independent has reviewed it.** The code is heavily tested and has had a security audit of its own ([`AUDIT-2026-10-24.md`](AUDIT-2026-10-24.md)), but no outside review. Don't rely on it where your safety is at stake.

[`THREAT_MODEL.md`](THREAT_MODEL.md) says exactly what it protects, against whom, and what it doesn't.

## Install

Install the libraries for your distribution, then build:

```bash
# Ubuntu / Debian
sudo apt install gcc make libsodium-dev libpng-dev libjpeg-dev zlib1g-dev

# Arch (and Omarchy)
sudo pacman -S --needed base-devel libsodium libpng libjpeg-turbo zlib

# Fedora
sudo dnf install gcc make libsodium-devel libpng-devel libjpeg-turbo-devel zlib-devel

make
```

This builds `./scattersteg`. There is also a Rust version in [`rust/`](rust/README.md) with the same commands and file format (an image written by one extracts with the other). It needs a Rust toolchain from [rustup.rs](https://rustup.rs) (edition 2024, so Rust 1.85 or newer), plus pkg-config and libclang:

```bash
# Ubuntu / Debian
sudo apt install libclang-dev pkg-config

# Arch (and Omarchy)
sudo pacman -S --needed clang pkgconf

# Fedora
sudo dnf install clang-devel pkgconf-pkg-config

cd rust && cargo build --release
```

## Use

```bash
./scattersteg passphrase                                 # print a strong random passphrase
./scattersteg info cover.png                             # can it be a cover, and how much does it hold?
./scattersteg embed -cf cover.png -ef secret.txt -sf out.png
./scattersteg extract -sf out.png                        # restores secret.txt
echo "a short note" | ./scattersteg embed -cf cover.png -sf note.png
./scattersteg extract -sf note.png                       # prints it
```

- **The passphrase** is always typed at the terminal, with echo off, so it never appears in the process list or your shell history; `-p` is refused for that reason. A new image needs one of at least 12 bytes; `scattersteg passphrase` prints a random one of about 124 bits.
- **The message** is the file given with `-ef`, or standard input without it (pipe it in, or type it and press Ctrl+D). It is kept byte for byte. An empty message is an error.
- **The file's name** is stored with it, encrypted, and `extract` restores the file under that name in the current directory; `-N` leaves the name out. `extract -xf <file>` chooses where it goes, and `-xf -` prints it. A message from standard input, or one stored with `-N`, is printed.
- **Existing files** are never replaced unless you add `-f`. `embed` without `-sf` writes over the cover itself, which is what it's asked to do.
- **Compression:** `-z 1`…`-z 9` sets the level (9, the default, is smallest); `-Z` stores the message as it is.
- **Quiet and verbose:** `-q` drops the progress messages ("Deriving keys...", "Wrote ...", and the prompt to type a message); the passphrase prompts, warnings and errors remain. `-v` also says how much was stored, and whether it was compressed.
- **The output** has the cover's format and metadata: a progressive JPEG stays progressive, a grayscale PNG stays grayscale, and EXIF, ICC profiles and text are kept.
- **Nothing is written unless it will decode.** The output is built in memory and read back first; if a decoder wouldn't see exactly what was embedded, `embed` fails and writes nothing. An existing file is replaced in one step, so a failed or interrupted `embed` never destroys it.

### Choosing a cover

How hard the message is to detect depends mostly on the cover and on how much you hide.

- **Use a photo nobody else has.** Anyone who has the original can compare the two and see that something changed. Don't use a photo you've posted or sent, or one from the internet; never encode twice from the same photo; delete the original afterwards.
- **Use a noisy photo.** Busy, detailed photographs hide changes well. Flat areas, gradients, screenshots and drawings hide them badly.
- **Keep the message small.** A few kilobytes in a photo-sized image is far below its capacity (`scattersteg info` shows it), and lighter than any payload measured. Detection rises with the message size. Text is compressed automatically, so it takes about half its size; files that are already compressed (photos, zip archives) don't shrink. `info` prints a suggested most: a byte per 160 pixels (PNG) or non-zero AC coefficients (JPEG), which is 0.05 bits each, the lightest payload measured in [Steganalysis results](#steganalysis-results). It is advice, not a limit and not a guarantee: `embed` warns when the stored message is over it (`-q` silences that) and goes ahead.
- **Prefer a file that a program has already rewritten** over one straight from a camera or phone. ScatterSteg writes the file anew, and a careful observer could notice that (see A1 in [`THREAT_MODEL.md`](THREAT_MODEL.md)).

| | PNG | JPEG |
|---|---|---|
| Accepted | 8-bit RGB or grayscale, no transparency | 8-bit baseline or progressive, Huffman or arithmetic coding |
| Capacity (before compression) | about 760 KB in a 1080p image | about 0.12–0.15 bits per pixel (about 68 KB in 4.5 MP) |
| Kept from the cover | interlacing, and every ancillary chunk the PNG spec defines (color space, pHYs, text, tIME, eXIf...) or marks safe to copy, byte for byte and in place | quantization, sampling, coding mode, restart interval, APPn and COM markers |
| Refused | palette, transparency, 16-bit, gray below 8 bits, an `sBIT` chunk under 8, RGB whose pixels are all gray, animation (APNG) | 12-bit, lossless, files that can't be rewritten exactly, data after the image (MPO, Ultra HDR), a content credential (C2PA) |

ScatterSteg refuses a cover rather than produce an output that would give it away.

### Coming from steghide

The commands are the same: `embed`, `extract`, `info`, `encinfo`, `version`, `license` and `help` (each also as `--embed` and so on), with the same option names: `-ef`, `-cf`, `-sf`, `-xf`, `-z`, `-Z`, `-N`, `-f`, `-q`, `-v` and their long forms. A steghide command line works by changing `steghide` to `scattersteg`, except where ScatterSteg deliberately differs:

| | ScatterSteg |
|---|---|
| `-p <passphrase>` | refused: the passphrase is always typed at the prompt, never visible to other users or saved in shell history |
| `-e` (choose or turn off encryption), `-K` (no checksum) | refused: the encryption is fixed (XSalsa20-Poly1305, see `encinfo`), and every message is authenticated |
| `-cf -` or `-sf -` (cover from standard input, output to standard output) | not supported: the cover and the output are files |
| an existing output file | refused unless `-f`; there is no yes/no question |
| `info` | says whether the image can be a cover, its capacity, and a suggested most to store. It doesn't offer to look for a message: without the passphrase, nothing can tell. |
| `passphrase` | an extra command: prints a strong random passphrase |

ScatterSteg reads PNG and JPEG, not BMP, WAV or AU, and neither tool can read the other's images. Every `embed` and `extract` takes about 0.2 s, on purpose: that is the cost that slows down passphrase guessing.

## How it works

```
 passphrase ──┐
              ▼
 salt ──► Argon2id ──► master key ──┬──► scatter key ──► secret pixel order
 (16 random bytes,                   └──► encryption key
  at public positions)                          │
                                                ▼
 message ──► DEFLATE ──────────────► XSalsa20-Poly1305 ──► box
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
2. **Compression and encryption.** The message is compressed (DEFLATE) if that makes it shorter, since fewer bits to hide means fewer changes; text typically shrinks to half. It is then encrypted and authenticated with XSalsa20-Poly1305.
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

These detectors are reimplementations of rich models trained on a few hundred images, so read the table as a ranking. A deep-learning detector does far better:

| SRNet, 10,000 BOSSbase images at 256×256 | Payload | Detection error | Caught |
|---|---|---|---|
| ScatterSteg, PNG | 0.4 bits per pixel | 0.13 | 87% |
| ScatterSteg, JPEG | 0.2 bits per non-zero AC coefficient | 0.07 | 93% |

SRNet was trained on 7,000 cover/stego pairs from the same source as the test images, at a known payload: a capable warden's best case, but a realistic one. The lighter payloads are still being measured; until they are, assume that only small messages in private, noisy covers stay hidden. [`benchmark/README.md`](benchmark/README.md) has every measurement, the method, and the full list of limitations.

## Limitations

- **The original photo gives it away.** Anyone with it can compare and see that something changed (not what).
- **Trained detectors catch it often**, more so as the message grows; see above.
- **Lossy processing destroys the message.** Most platforms recompress or resize uploads. Send the file itself.
- **Big messages are much easier to detect.** Near capacity, the coding has little freedom left.
- **Not deniable.** There is no decoy message: if you're forced to give up the passphrase, the message is revealed.
- **Very large images need a lot of memory**, up to several GB for the largest accepted (see A5 in the threat model).
- **Suspending the program** (Ctrl+Z) at the passphrase prompt can leave the terminal's echo off. Ctrl+C, SIGTERM and SIGHUP are handled.

## Status and plans

ScatterSteg aims to be as hard to detect as current research allows, and built to the standard of security software: tested, fuzzed, audited and documented as it goes. It is pre-release, and until the first release the image format may change.

Next, each measured before it's kept:

- **JPEG: embed in every AC coefficient,** not only those of magnitude 2 or more, as the published schemes (UERD, J-UNIWARD) do. Concentrating the changes on fewer coefficients makes them easier to see.
- **Write files the way the cover was written.** The output is re-encoded with ScatterSteg's own settings (see A1 in [`THREAT_MODEL.md`](THREAT_MODEL.md)), which a careful observer can notice without any steganalysis. The fix is to reuse the cover's compression choices.
- **Ternary embedding,** where the message also chooses the direction of each change, for fewer changes per message.
- **A payload suggestion that follows the square root law:** the safe message size grows with the square root of the image size, not in proportion to it.
- **Comparison with the other modern tools** (HStego, phasm) and with Aletheia's detectors, to know where ScatterSteg stands.

Then a first release with a frozen format, and an independent review.

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

ScatterSteg is free software, dual-licensed under the [MIT License](LICENSE-MIT) or the [Apache License, Version 2.0](LICENSE-APACHE), at your option (`MIT OR Apache-2.0`). You may use, modify, distribute and integrate it, including in closed-source products, on the terms of either license.

The license was changed from AGPL-3.0-or-later to MIT OR Apache-2.0 to remove corporate adoption friction and let ScatterSteg be freely integrated into security frameworks, forensics tools, and open or closed pipelines.

## References

- T. Filler, J. Judas, J. Fridrich — *Minimizing Additive Distortion in Steganography Using Syndrome-Trellis Codes* (2011)
- B. Li, M. Wang, J. Huang, X. Li — *A New Cost Function for Spatial Image Steganography*, IEEE ICIP (2014), [doi:10.1109/ICIP.2014.7025854](https://doi.org/10.1109/ICIP.2014.7025854): HILL, the PNG costs
- L. Guo, J. Ni, W. Su, C. Tang, Y.-Q. Shi — *Using Statistical Image Model for JPEG Steganography: Uniform Embedding Revisited*, IEEE Transactions on Information Forensics and Security 10 (2015), [doi:10.1109/TIFS.2015.2473815](https://doi.org/10.1109/TIFS.2015.2473815): UERD, the JPEG costs
- S. Hetzl, P. Mutzel — *A Graph-Theoretic Approach to Steganography* (2005), the method behind steghide; reimplemented here from the paper
- A. Westfeld, A. Pfitzmann — *Attacks on Steganographic Systems*, Information Hiding 1999, LNCS 1768 (2000), [doi:10.1007/10719724_5](https://doi.org/10.1007/10719724_5): the chi-square attack, one of the three classic detectors ScatterSteg is tested against (see [Steganalysis results](#steganalysis-results))
- S. Dumitrescu, X. Wu, Z. Wang — *Detection of LSB Steganography via Sample Pair Analysis*, IEEE Transactions on Signal Processing 51 (2003), [doi:10.1109/TSP.2003.812753](https://doi.org/10.1109/TSP.2003.812753): sample pair analysis, the second classic detector
- A. Ker — *Steganalysis of LSB Matching in Grayscale Images*, IEEE Signal Processing Letters 12 (2005), [doi:10.1109/LSP.2005.847889](https://doi.org/10.1109/LSP.2005.847889): HCF-COM, the third
- [libsodium](https://doc.libsodium.org/), [libpng](http://www.libpng.org/pub/png/libpng.html), [libjpeg-turbo](https://libjpeg-turbo.org/)
