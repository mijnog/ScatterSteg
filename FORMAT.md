# File format

What ScatterSteg writes into an image, exactly enough to write a compatible decoder. The current format is v4; earlier versions are described after it, and every version stays readable. The implementations are `codec.c` (C) and `rust/src/codec.rs` (Rust), and `tests/test_cli.py` checks both against an independent Python decoder.

## v4

The image contains no header or version marker, as either would reveal the presence of a message. Every pixel holds one bit per sample, in the LSBs of R, G and B (or of the gray value), set by exchanging values between pairs of samples where possible and LSB matching otherwise. Below, "sample k" means bit position k counted along the payload order: pixel `order[k / channels]`, channel `k % channels`.

1. **Salt** — 16 random bytes, carried as the STC syndrome (as in step 5, with the same costs) of the samples of a public *salt region*: the first k pixels of a public pixel order, `prng_permutation` keyed with `BLAKE2b-256("ScatterSteg v2 salt positions")`, where k = max(⌈128 / channels⌉, min(⌈8192 / channels⌉, ⌊pixels / 16⌋)) and the first min(k · channels, 64 · 128) of its samples are used. Public, so the decoder can find it before it has a key; syndrome-coded, so the roughly 18 changes it needs are as sparse as the payload's.
2. **Keys** — `master = Argon2id(passphrase, salt, opslimit 3, memlimit 256 MiB)`; the scatter key and encryption key are `crypto_kdf` subkeys 1 and 2 of `master`, context `ScatStg2`.
3. **Order** — `prng_permutation(scatter key)` over the pixels, with the salt pixels removed.
4. **Length** — the box length L (32 bits, little-endian), in the LSBs of samples 0–31.
5. **Box** — `nonce (24) || crypto_secretbox(message)`, as bits (LSB first), is the STC syndrome of the LSBs of the samples from 32 on. With N samples left and m = 8L message bits, n = min(N, 64·m) of them are used; message bit i is row i of H·y, where block i covers samples ⌊i·n/m⌋ to ⌊(i+1)·n/m⌋ − 1 and its j-th sample contributes column j of the 7-row submatrix to rows i…i+6. Columns: splitmix64 seeded with `0x5354432d48415431 ^ (⌊n/m⌋ + 1)`, low 7 bits, with bits 0 and 6 set. The rows run in independent chunks of ⌊2²⁰ / (⌊n/m⌋ + 1)⌋ message bits.

**JPEG** uses the same layout over a different kind of position: each *carrier* is one AC coefficient with |value| ≥ 2, taken in component, block-row, block and coefficient order, and carries one bit. Its salt region is counted in carriers (one sample each). DC coefficients, zeros and ±1 are never used, and embedding keeps every carrier at |value| ≥ 2 and within ±1023, so the decoder finds the same carriers and the encoder can write them.

**Costs** determine which samples change and are chosen by the encoder alone (the decoder does not use them). PNG uses HILL: per channel, the reciprocal of the 3×3 mean of the absolute KB high-pass residual, smoothed by a 15×15 mean, so a change is cheap where the image is busy. JPEG uses UERD: the coefficient's quantization step over the energy of its block (the sum of its dequantized AC magnitudes) plus a quarter of each of its eight neighbours', ×1.75 when |value| = 2.

**v3** wrote the salt's bits straight into the first 43 public pixels (128 samples), about 64 changes at positions anyone can compute; a targeted test of prediction error at those positions detected it slightly above chance (AUC 0.56 on 500 ALASKA2 images, against 0.50 for v4). **v2** is v3 with the box's bits also written straight in, into samples 32 on; **v1** used a BLAKE2b-only scatter key. Decode tries v4, then v3 and v2 (which share a salt layout and keys, so one further Argon2id run), then v1.

`prng_permutation(key, n)` is a forward Fisher–Yates shuffle (for `i` from 0 to n−2, swap slot `i` with `i + uniform(n − i)`), with `uniform` drawing little-endian 32-bit words from the ChaCha20-IETF keystream of `key` (zero nonce, counter from 0) and rejecting values below `2³² mod bound`.
