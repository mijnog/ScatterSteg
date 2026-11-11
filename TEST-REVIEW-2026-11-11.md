# Test review, 2026-11-11

The owner's request of 2026-11-01 (CLAUDE.md, "review the tests"): find what the tests miss, report by risk, propose tests, write none without approval. What was done on 2026-11-11, what it found, and what is still open. Code as of `main` at `f65bff7`.

## 1. Mutation testing (C coder)

[Mull](https://github.com/mull-project/mull) 0.37.0 on `stc.c` and `parallel.h`, driven by the `test_stc` unit test binary, built with clang 22, `-O0`, ASan and UBSan, every operator (`mutators: [cxx_all]`).

| Run | Survivors | Score |
|---|---|---|
| Before (tests as of `c3c5356`) | 41 (30 in `stc.c`, 11 in `parallel.h`) | 84% |
| After `b8b159f` and `7dece5c` | 23 | 91% |

The 23 left were triaged by reading the code: 14 equivalent (thread counts, values overwritten before use), 4 removed mutex locks (only a thread sanitizer could see them, and a lost update only runs a chunk twice with the same result), 3 frees on the out-of-memory exit (probably caught by the CLI fault sweep; not checked), an oversized path buffer (`stc.c:72`, memory only) and an empty extra chunk (`stc.c:171`, does nothing).

Not done: `codec.c` and `main.c` (they are in no C unit test, only reached through `tests/test_cli.py`, about 5 minutes a run), and `cargo-mutants` on the Rust build.

### Running Mull again

Linux packages go up to LLVM 22 (the system clang may be newer), so it runs in a container:

```dockerfile
FROM ubuntu:26.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang-22 llvm-22 lld-22 libclang-rt-22-dev make git python3 ca-certificates curl \
      libsodium-dev libpng-dev libjpeg-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
ARG REL=https://github.com/mull-project/mull/releases/download/0.37.0
RUN curl -fsSL -o /tmp/mull.deb ${REL}/Mull-0.37.0-ubuntu-amd64-26.04.deb \
    && curl -fsSL -o /tmp/mull-22.deb ${REL}/Mull-22-0.37.0-LLVM-22.1.2-ubuntu-amd64-26.04.deb \
    && apt-get update && apt-get install -y /tmp/mull.deb /tmp/mull-22.deb \
    && rm -rf /tmp/*.deb /var/lib/apt/lists/*
WORKDIR /work
```

In `/work` (a copy of the sources, with a `mull.yml` holding `mutators: [cxx_all]`; without it Mull uses a tiny default set):

```bash
F="-g -grecord-command-line -O0 -std=c17 -pthread -I. -Itests -fsanitize=address,undefined -fno-omit-frame-pointer"
clang-22 $F -fpass-plugin=/usr/lib/mull-ir-frontend-22 -c stc.c -o /tmp/stc.o   # one file per command, or Mull finds nothing
clang-22 $F -c tests/test_stc.c -o /tmp/test_stc.o
clang-22 -pthread -fsanitize=address,undefined /tmp/test_stc.o /tmp/stc.o -o /tmp/test_stc_mull -lm
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 mull-runner-22 --workers 6 --timeout 120000 /tmp/test_stc_mull
```

The timeout matters: the default (3 s) fails the warm-up run under ASan. About 10 minutes on 6 workers.

## 2. Hard-coded numbers in tests

Format quantities written as literals where they could be computed (found by reading, not acted on):

- `tests/test_cli.py`: the suggested size `492` (3 × isqrt(32000) − 42) and capacity `1332` (64 × 64), in assertions, comments and expected messages; the tiny-image suggestion cases, whose sizes only straddle the threshold while the fixed overhead is 42.
- `codec.h` (`CODEC_FIXED_BYTES 42`) and `rust/src/codec.rs` (`FIXED_BYTES: u64 = 42`): each written as a literal, not summed from the pieces it stands for.
- `FORMAT.md` doesn't define the payload suggestion (3 bytes per √pixels, 1 per √non-zero ACs), so a computed test of it has no spec to follow.

Checked 2026-11-11: `1332` is what the Python model and the C binary's `info` both give for a 64×64 RGB cover; 42 is salt 16 + length region 8 + MAC 16 + encoding 1 + name length 1, as both builds' comments and FORMAT.md's layout give. `tests/test_embed.c`'s "32-bit header" was checked and is right: it tests the test-only raw-LSB layer in `tests/embed_bytes.h`, not the format.

## 3. Comments and docs with checkable claims but no test

Not done.

## 4. Edge cases not covered

A read-only survey of all the tests found the cases below; a case is "untested" if a search of the tests for its values, functions and messages found nothing. Rows 7 and 16 were confirmed and fixed; rows 2–4 were addressed. The open rows were then checked one by one against the tests (searching `tests/` and `rust/` for each case's values, functions and messages); rows 6, 8, 9 and 12 are corrected below from what the survey said.

| # | Area | Case | Status |
|---|---|---|---|
| 1 | Limits | A record exactly at `RECORD_MAX`, and the 64 MiB read cap exactly (only one past is tested) | open |
| 2 | Parity | No JPEG message decoded by anything but the build that wrote it | **done** (`01b7a80`): `tests/differential.py` decodes each build's PNG and JPEG images with the other |
| 3 | Retries | The near-capacity retry paths run only by chance (fresh salt) | **checked**: coverage (`make coverage`) shows the existing suite reaches every branch of the retry loop in `codec.c`; not traced to which test decodes each |
| 4 | Threads | Output the same on 1 thread and many | **done** (`7dece5c`): the coder's known answers on one thread too, in both builds |
| 5 | Content credentials | JPEG extended XMP; PNG XMP in compressed iTXt or zTXt; PNG `caBX` | open; whether in scope is the owner's call |
| 6 | Proceed? question | Input typed before the question answers it (`ask_continue` doesn't flush the terminal first, unlike the passphrase prompt); with no terminal it goes ahead and warns after, as intended (`main.c` comment), but untested: the harness always runs on a terminal | open |
| 7 | Names | A stored or output name of 249–255 bytes failed (temp name too long) | **fixed** (`b65c28d`) |
| 8 | PNG | Adam7-interlaced covers: C's unit tests load and save them (`test_load_interlaced`, `test_save_keeps_interlacing`); untested end to end (the Python model reads non-interlaced PNG only), in Rust, and under 5 pixels wide or high | open |
| 9 | PNG (Rust) | Huge declared dimensions (C has `test_load_huge_dimensions` and `test_load_too_many_pixels`; Rust's `png_io.rs` has no tests) | open |
| 10 | JPEG | CMYK/YCCK, 12-bit, lossless, 4:2:2 and 4:4:0 | open |
| 11 | JPEG | A truncated JPEG as a cover | open; intended behaviour to decide |
| 12 | JPEG | AC coefficients at ±1023 in an embed round trip (only their cost is tested; the extreme DC, −1024, has `test_extreme_dc_accepted`) | open |
| 13 | Capacity | The smallest usable image (capacity 0 → 1) | open |
| 14 | Capacity | Gray covers big enough for the salt and length regions' caps | open |
| 15 | Names | The exact Unicode ranges refused and allowed; 4-byte UTF-8; a name `-` | open |
| 16 | Parity | A closed pipe killed C silently, Rust reported it | **fixed** (`f95f170`) |
| 17 | Suggestion | Capped at capacity; "1 byte"; JPEG smooth and too-small; values exactly at the thresholds | open |
| 18 | CLI | Several refusals and the full `-v` lines aren't checked word for word | open |
| 19 | Passphrase | An empty line; non-UTF-8; starting in the background; signals at Confirm and at Proceed? | open |
| 20 | Format | Splits other than 0 written by an independent encoder (`forge()` only writes 0) | open |
| 21 | Rust | `codec.rs`, `compress.rs`, `png_io.rs`, `prng.rs` have no unit tests | open |

Found on the way: `tests/fault_sodium.c` said Argon2 used 64 MiB; it uses 256 MiB (`crypto_pwhash_MEMLIMIT_MODERATE`, as FORMAT.md says): comment fixed. Measured: one Argon2id run with these settings takes 0.205 s (5 runs, i5-12400F, idle), as the README's "about 0.2 s" says.

Also found, not changed: C counts CPUs with `sysconf(_SC_NPROCESSORS_ONLN)`, which ignores affinity; Rust's `available_parallelism` honours affinity and cgroup quotas. Under `taskset` or in a container the builds may use different thread counts: same output, different speed and peak memory.

## 5. A self-check before writing (proposed, not decided)

Embedding never decodes its own result before saving: a coder bug would be caught only by the tests. Decoding the payload from the samples in memory before writing would turn such a bug into a refused embed. Upper bound on its cost: extract with the right passphrase minus extract with a wrong one (a wrong one stops after loading, Argon2 and the length), medians of 3, 12 MP photo (4241×2827) as JPEG and PNG, i5-12400F, load about 2.2 at start:

| Build | Cover, message | Embed | Bound |
|---|---|---|---|
| C | JPEG, suggested (3,909 B) | 4.10 s | 0.50 s |
| C | JPEG, capacity (2,962,080 B) | 7.19 s | 0.92 s |
| C | PNG, suggested (10,344 B) | 7.90 s | 0.90 s |
| C | PNG, capacity (4,494,692 B) | 11.86 s | 1.19 s |
| Rust | JPEG, suggested | 3.84 s | 0.41 s |
| Rust | JPEG, capacity | 5.25 s | 0.75 s |
| Rust | PNG, suggested | 7.65 s | 0.65 s |
| Rust | PNG, capacity | 11.90 s | 0.94 s |

The bound also counts decompressing and writing the message, which a self-check wouldn't do. Against the speed limits (3–5 s small, 15 s large): capacity stays under 15 s; JPEG at the suggested size moves to at most 4.25 s (Rust) and 4.6 s (C); PNG at the suggested size already misses (about 7.8 s). The owner decides.
