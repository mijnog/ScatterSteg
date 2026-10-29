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

- **Claim:** at low payloads, ScatterSteg output is not reliably distinguishable from clean images by the classic detectors for LSB steganography, but the trained classifiers measured in [Machine-learning detectors](#machine-learning-detectors) catch it often: the stronger one catches PNG output about 56% of the time at 0.05 bits per pixel, the lightest payload measured, and 65% at 0.4 (HILL costs; 65% and 93% with the uniform costs used before). That is harder to detect than steghide or plain LSB embedding, not undetectable. Deep-learning detectors have not been run; assume they do better.
- **How:** STC syndrome coding (few changes) with HILL costs for PNG (changes where the image is busy), ±1 changes paired as value swaps (the histogram kept), JPEG coefficients edited losslessly with UERD costs (changes in busy blocks), the output in the cover's own format and metadata, and no header or marker in the image.
- **Evidence:** measured against chi-square, sample pair analysis, HCF-COM and adjacency HCF-COM (see [`benchmark/README.md`](benchmark/README.md#classic-detectors)), and against trained classifiers (see [Machine-learning detectors](#machine-learning-detectors) below). The planned evaluation with Aletheia's EfficientNet-B0 detectors on ALASKA2 has not been done.
- **Known-position test:** the salt must sit at public positions, so a warden can look exactly there. An earlier design wrote it straight in (about 64 changes in 128 known samples), and a targeted test of prediction error at those positions detected it slightly above chance: AUC 0.56 over 500 ALASKA2 images, 9% detected at 5% false alarms. The salt is now carried as an STC syndrome over a public region of ~8192 samples (about 18 sparse changes); the same test, and the same test over the whole region, are at chance (AUC 0.49–0.50).
- **File structure: not hidden.** The pixels or coefficients are all a detector needs to look at, but the file around them is written anew, not copied from the cover. A PNG is recompressed: the C build with libpng's default settings, the Rust build with its own compressor and 64 KiB data chunks, so the two builds' outputs differ from each other as well as from the cover. A JPEG is rewritten by libjpeg: a progressive one gets libjpeg's standard scan order rather than the camera's, and non-standard Huffman tables are rebuilt. None of this shows a message is present, but a warden who knows how the camera, phone or editor writes its files can tell this one was rewritten by something else, and may recognise ScatterSteg (or which build) from the details. Against a careful warden, prefer a cover that a program already rewrote the same way (a PNG saved with libpng's default settings, for the C build; a JPEG already re-encoded by libjpeg) over one straight from a camera or phone.
- **Limits:** detectability rises with payload, falls with cover noise, and every detector here is public. A warden with a detector trained specifically on ScatterSteg output would do better than these: that hasn't been tested.

### A2 — The guesser: has the image, tries passphrases offline

- **Claim:** every guess costs one Argon2id run (256 MiB of memory, 3 passes, about 0.2 s on a laptop core), and nothing about the image lets a guess be rejected more cheaply.
- **How:** the salt is in the image at public positions; both the pixel order and the encryption key come from one Argon2id output, so even the length header can't be read without it. Authentication (Poly1305) is the only test of a guess.
- **Evidence:** design (`codec.c`, [`FORMAT.md`](FORMAT.md)).
- **Limits:** Argon2id slows guessing, it can't make a weak passphrase strong. `scattersteg passphrase` generates ~124 bits, which is out of reach; a short human-chosen one may not be.

### A3 — The comparer: has the image and the original cover

- **Not protected against.** Comparing the two shows which samples changed, so that a message is present (not what it says), whatever the format. Never use a cover someone else has or could find (one you have posted or sent, a stock or downloaded image), never encode twice from the same cover (two outputs compared show the same), and delete the cover after use.

### A4 — The meddler: changes images in transit

- **Claim:** a modified image never yields a wrong message: decoding fails with an error.
- **Not protected against:** destruction. Recompressing, resizing, cropping or re-encoding the image (as most platforms do on upload) loses the message. ScatterSteg isn't designed to be robust to that; send the file itself.

### A5 — Malicious input files

Images may come from anyone, so the decoder parses hostile input.

- **Claim:** no input file causes memory corruption, unbounded memory use or unbounded time.
- **How:** capped allocations (1 GiB of pixels or coefficients, 1 GiB of per-carrier working memory for a JPEG, libpng behind an allocator capped at 64 MiB per allocation and 128 MiB in all, 16 MiB per chunk), at most 500 JPEG scans and 2²⁸ blocks visited by them in all (so a few-KB file of many scans over a huge frame is refused in about a second rather than read for 16), a Huffman-coded frame that declares more blocks than its file has bits refused before anything is allocated (a 330-byte file declaring 15144×32800 with no image data had cost 1.5 s and ~1 GB; arithmetic coding can spend far less than a bit on a block, so a hollow arithmetic-coded file still costs about 0.35 s and ~1 GB before it is refused), libjpeg errors caught rather than exiting, coefficients range-checked before re-encoding.
- **Peak memory is more than any one cap.** The caps bound each allocation, not their sum. Decoding the largest RGB PNG holds the pixels (768 MiB), the 1 GiB message order, and up to a byte per sample for the bits read back and again for the message bits: about 3.5 GB at once. The right passphrase reads the true length; a wrong one reads a random length, which for a few percent of guesses on a large image fits and costs the same. The Rust build's JPEG loader also keeps its own copy of the coefficients beside libjpeg's, up to 1 GiB more. Encode's HILL costs for a PNG add 4 bytes per sample (up to 3 GiB for the largest RGB cover), plus 8 bytes per pixel while they are computed (up to 2 GiB more), though only on a cover the user chose. So decoding or encoding a very large image can need several GiB, and fails where that isn't available.
- **Evidence:** six libFuzzer targets run on every push, fault injection on every failing call, ASan and UBSan across the test suite; every crash fuzzing found is kept as a regression test in `tests/fuzz/regressions`. Among what fuzzing found and is now fixed:
  - a 290-byte PNG that made Ubuntu's libpng allocate 1.3 GB (hence the capped allocator);
  - a text chunk that libpng reads but refuses to write (hence ancillary chunks are copied as raw bytes);
  - JPEGs that decode but can't be re-encoded (out-of-range coefficients, quantization tables redefined between scans, sampling factors too large for progressive scans), now refused by a trial write before keys are derived;
  - a truncated progressive JPEG that libjpeg writes back with different coefficients, which would have silently corrupted a hidden message; the trial write now reads its output back and must match exactly;
  - a 178-byte JPEG declaring a 15144×32800 frame, which cost seconds and ~1 GB to load (hence the hollow-frame check above).
- **Assumes:** libpng, libjpeg-turbo and libsodium are themselves sound.
- **The Rust port** (`rust/`) swaps libpng for the `png` crate, with the file size capped at 1 GiB + 64 MiB and the same pixel, chunk and scan caps; a failed allocation aborts rather than exiting cleanly. The `png` crate is shown only the chunks it needs, so it cannot refuse (or panic on) a file libpng accepts. Fuzzed with cargo-fuzz in CI. See `rust/README.md`.

### A6 — Someone on the same machine

- **Partly protected.** Secrets live in libsodium guarded memory (locked against swap, guard pages, wiped on release), core dumps are disabled, and on Linux other processes of the same user can't attach a debugger.
- **Limit:** memory is locked only up to the process's locked memory limit (`ulimit -l`, often 8 MiB; ScatterSteg raises its soft limit to the hard one). A message past it may be written to swap, and `encode` and `decode` warn when that happens. Raise the limit, or use encrypted swap, for large messages.
- **Side channels: not protected against, and not tested.** An attacker running code on the same CPU while ScatterSteg runs could in principle learn something from cache timing: Argon2id's second half reads memory at passphrase-dependent addresses (by design, as in all Argon2id), the shuffle that gives the secret order swaps at key-dependent positions, and the trellis search's work depends on the message. No constant-time or cache-timing analysis has been done. Run it on a machine you trust, not a shared host.
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

The measurements, their method and their limitations are in [`benchmark/README.md`](benchmark/README.md); this is the part that bears on A1. The detectors are reimplementations of the SRM-style (PNG) and DCTR-style (JPEG) rich models, trained on a few hundred cover/stego pairs at the payload they are tested on. Detection error P_E, where 0.5 is guessing and lower is easier to detect:

| Payload | 0.05 | 0.1 | 0.2 | 0.4 |
|---|---|---|---|---|
| ScatterSteg PNG, HILL (480 Wikimedia photographs) | 0.44 | 0.42 | 0.39 | 0.36 |
| ScatterSteg PNG, HILL (1000 grayscale BOSSbase images) | 0.46 | 0.43 | 0.35 | 0.22 |
| LSB matching (Wikimedia) | 0.17 | 0.09 | 0.05 | 0.02 |
| steghide (Wikimedia, as BMP) | 0.04 | 0.03 | 0.02 | 0.02 |
| ScatterSteg JPEG, UERD (payload per non-zero AC coefficient) | 0.50 | 0.48 | 0.39 | — |
| steghide JPEG | 0.21 | 0.10 | 0.03 | — |

What this means for A1: a warden with one of these detectors catches about 56% of ScatterSteg PNGs at 0.05 bits per pixel and 65% at 0.4, and 50–61% of its JPEGs at 0.05 to 0.2. That is better than chance at every payload, and a stronger detector would do better still: the published models and deep-learning detectors, not yet run, would score every row lower. ScatterSteg is harder to detect than steghide (caught 96–98% of the time) and than naive LSB embedding at every payload measured. Deep-learning detectors are the next test; results go here when they exist.

## Reporting a problem

See [SECURITY.md](SECURITY.md).
