# Threat model

What ScatterSteg tries to protect, against whom, and what it explicitly doesn't. This is the document to start from when reviewing it: each claim below says how it's backed (design, tests, or measurement), so a reviewer can try to break it.

## What is protected

1. **The message's content.** Only someone with the passphrase can read it.
2. **The message's integrity.** Any change to it is detected; it's never silently altered.
3. **The message's existence.** An image carrying a message should be hard to tell from one that doesn't. This is the steganographic goal, and the hardest one: it's a statistical claim, not a cryptographic one.
4. **The passphrase**, while the program holds it.

## Adversaries

### A1 — The warden: bulk steganalysis, no passphrase

Someone who sees many images (a censor, a platform, a border check) and runs detectors over them, looking for any that carry hidden data.

- **Claim:** at low payloads, ScatterSteg output is not reliably distinguishable from clean images by the classic detectors for LSB steganography, and close to guessing at 0.05 bits per pixel by the trained classifiers measured in [Machine-learning detectors](#machine-learning-detectors). Deep-learning detectors have not been run; assume they do better.
- **How:** STC syndrome coding (few changes), ±1 changes paired as value swaps (the histogram kept), JPEG coefficients edited losslessly with costs that hold the coefficient statistics, the output in the cover's own format and metadata, and no header or marker in the image.
- **Evidence:** measured against chi-square, sample pair analysis, HCF-COM and adjacency HCF-COM (see the README), and against trained classifiers (see [Machine-learning detectors](#machine-learning-detectors) below). The planned evaluation with Aletheia's EfficientNet-B0 detectors on ALASKA2 has not been done.
- **Known-position test:** the salt must sit at public positions, so a warden can look exactly there. In format v3 it was written straight in (about 64 changes in 128 known samples), and a targeted test of prediction error at those positions detected it slightly above chance: AUC 0.56 over 500 ALASKA2 images, 9% detected at 5% false alarms. Format v4 carries the salt as an STC syndrome over a public region of ~8192 samples (about 18 sparse changes); the same test, and the same test over the whole region, are at chance (AUC 0.49–0.50).
- **Limits:** detectability rises with payload, falls with cover noise, and every detector here is public. A warden with a detector trained specifically on ScatterSteg output would do better than these: that hasn't been tested.

### A2 — The guesser: has the image, tries passphrases offline

- **Claim:** every guess costs one Argon2id run (256 MiB of memory, 3 passes, about 0.2 s on a laptop core), and nothing about the image lets a guess be rejected more cheaply.
- **How:** the salt is in the image at public positions; both the pixel order and the encryption key come from one Argon2id output, so even the length header can't be read without it. Authentication (Poly1305) is the only test of a guess.
- **Evidence:** design (`main.c`, file format in the README); format v1 lacked this and is only read for compatibility, with a warning.
- **Limits:** Argon2id slows guessing, it can't make a weak passphrase strong. `scattersteg passphrase` generates ~124 bits, which is out of reach; a short human-chosen one may not be. A v1 image is about 100× cheaper to attack.

### A3 — The comparer: has the image and the original cover

- **Not protected against.** Comparing the two shows which pixels changed, so that a message is present (not what it says). Never publish a cover you have used.

### A4 — The meddler: changes images in transit

- **Claim:** a modified image never yields a wrong message: decoding fails with an error.
- **Not protected against:** destruction. Recompressing, resizing, cropping or re-encoding the image (as most platforms do on upload) loses the message. ScatterSteg isn't designed to be robust to that; send the file itself.

### A5 — Malicious input files

Images may come from anyone, so the decoder parses hostile input.

- **Claim:** no input file causes memory corruption, unbounded memory use or unbounded time.
- **How:** capped allocations (1 GiB of pixels or coefficients, 1 GiB of per-carrier working memory for a JPEG, libpng behind an allocator capped at 64 MiB per allocation and 128 MiB in all, 16 MiB per chunk), at most 500 JPEG scans, libjpeg errors caught rather than exiting, coefficients range-checked before re-encoding.
- **Evidence:** five libFuzzer targets run on every push, fault injection on every failing call, ASan and UBSan across the test suite; every crash fuzzing found is kept as a regression test.
- **Assumes:** libpng, libjpeg-turbo and libsodium are themselves sound.
- **The Rust port** (`rust/`) swaps libpng for the `png` crate, with the file size capped at 1 GiB + 64 MiB and the same pixel, chunk and scan caps; a failed allocation aborts rather than exiting cleanly. The `png` crate is shown only the chunks it needs, so it cannot refuse (or panic on) a file libpng accepts. Fuzzed with cargo-fuzz in CI. See `rust/README.md`.

### A6 — Someone on the same machine

- **Partly protected.** Secrets live in libsodium guarded memory (locked against swap, guard pages, wiped on release), core dumps are disabled, and on Linux other processes of the same user can't attach a debugger.
- **Not protected against:** root, a keylogger, a compromised terminal or a malicious build of ScatterSteg or its libraries. The message is also read from stdin and printed to stdout, so wherever those go (shell history, files, pipes) is outside its control.

## Explicit non-goals

- **Deniability under coercion.** There's no decoy message or hidden second passphrase: if you're forced to give up the passphrase, the message is revealed.
- **Robustness** to lossy processing (A4).
- **Hiding the tool.** Having ScatterSteg installed, or in shell history, may itself be telling.
- **Sanitizing metadata.** The output deliberately keeps the cover's metadata (EXIF and so on) so it looks like the same file; if that metadata identifies you or your camera, choose another cover.

## Assumptions

- The operating system's random number generator is sound (libsodium's `randombytes`).
- libsodium's primitives are sound: XSalsa20-Poly1305, Argon2id, BLAKE2b, ChaCha20, and `crypto_kdf`.
- The terminal the passphrase is typed into is trusted.

## Cryptographic design, in brief

| Purpose | Construction |
|---|---|
| Key stretching | Argon2id, opslimit 3, memlimit 256 MiB, 16-byte random salt per image |
| Key separation | `crypto_kdf` subkeys 1 (scatter) and 2 (encryption), context `ScatStg2` |
| Encryption | XSalsa20-Poly1305 (`crypto_secretbox`), 24-byte random nonce |
| Pixel order | unbiased Fisher–Yates driven by ChaCha20-IETF keyed with the scatter key |
| Salt positions | the same shuffle keyed with BLAKE2b of a public label |

The secrecy of the pixel order isn't needed for confidentiality (the payload is encrypted and authenticated); it's there for steganographic security, so a warden can't look only where the data is.

## Machine-learning detectors

What has been measured is in [`benchmark/`](benchmark/README.md): 476 Wikimedia photographs, an RBF SVM on SPAM pixel features (PNG) or DCT co-occurrence features (JPEG), trained at the payload it is tested on. Detection error P_E (0.5 is guessing; lower means easier to detect), ±0.02:

| Payload (bits per pixel) | LSB matching | steghide | ScatterSteg PNG |
|---|---|---|---|
| 0.05 | 0.34 | 0.14 | 0.46 |
| 0.10 | 0.25 | 0.12 | 0.41 |
| 0.20 | 0.16 | 0.10 | 0.31 |
| 0.40 | 0.10 | 0.07 | 0.20 |

JPEG at 0.05, 0.1 and 0.2 bits per non-zero AC coefficient: ScatterSteg 0.42, 0.40, 0.23; steghide 0.34, 0.24, 0.13.

What this means for A1: a warden with a trained classifier of this strength catches a PNG filled to 0.4 bits per pixel about 80% of the time and does little better than chance at 0.05. ScatterSteg is harder to detect than steghide and naive LSB embedding at every payload tested. These detectors are modest, so absolute numbers are optimistic for the user. A rich-model (SRM-style) detector, a second cover set and deep-learning detectors are the next tests; results go here when they exist.

## Reporting a problem

See [SECURITY.md](SECURITY.md).
