# ScatterSteg in Rust

A line-for-line port of the C implementation in the repository root. It keeps
the file format and the command line: an image written by one decodes with the
other, for PNG and JPEG.

    cargo build --release        # needs libsodium, libjpeg-turbo, pkg-config, libclang (see the README's install section)
    cd ../tests && SCATTERSTEG=../rust/target/release/scattersteg python3 test_cli.py

`--features fault-injection` builds the variant the fault sweeps in
`tests/test_cli.py` drive (`SCATTERSTEG_FAULT`, `FAULT_LONG_MIN=15`).

## Differences from the C version

On purpose:

- **Allocation failure aborts.** A failed heap allocation ends the process
  instead of printing "allocation failed" and exiting 1. Secrets still live in
  libsodium memory, and core dumps are disabled.
- **Files are read whole.** The input is buffered, after its first bytes match
  a PNG or JPEG signature and up to 1 GiB + 64 MiB, where C streams a JPEG
  (and keeps a PNG's bytes as it reads them, under the same cap). A
  JPEG's coefficients are held twice (libjpeg's and a copy), so its working
  memory is up to about double the 1 GiB cap. Checking the output, embed
  holds its bytes twice while it reads them back (C holds them once).
- **A bad zlib checksum (Adler-32) in the image data is not an error.** The
  `png` crate doesn't check it; libpng refuses the file. The output is valid.
- **Damaged compressed data after the last row fails the load.** libpng stops
  reading once the image is complete; the `png` crate reads the zlib stream to
  its end. (C-written images are never like this.)
- **No libpng width/height cap** (1,000,000). Only the 2^28-pixel cap applies.

Not on purpose, without effect on the output:

- **CPUs are counted differently.** C uses the online CPUs
  (`sysconf(_SC_NPROCESSORS_ONLN)`); Rust's `available_parallelism` also
  honours CPU affinity and cgroup quotas. Under `taskset` or in a container the
  two can use different thread counts (at most 8 either way): the same output,
  a different speed and peak memory.

Needed for compatibility:

- The PNG decoder sees only IHDR, PLTE, tRNS, IDAT and a closing IEND.
  libpng warns about a malformed gAMA, pHYs, fcTL and the like, a repeated
  PLTE or tRNS, or a missing IEND, and loads the file anyway; the `png`
  crate refuses (or, for a short palette, panics). A name that isn't four
  letters, or a bad CRC in a critical chunk, fails the load as in libpng. A
  lowercase third letter (newer libpng refuses it, older accepts it) loads
  but the chunk isn't written back, so we never write one libpng would refuse.
- After the image data, a chunk with a reserved name (lowercase third letter)
  ends reading in current libpng (1.6.59), as in Rust, but is accepted by older
  ones (Ubuntu's 1.6.43): C's output follows the libpng it is built with, so
  `diff_png` doesn't compare bytes for such files (pixels still must agree).
- An ancillary chunk with a bad CRC is kept and written back with a valid
  CRC, as libpng keeps it, so both versions write the same chunks.
- A JPEG's carrier cap uses C's per-carrier size (8-byte pointer included), so
  every JPEG Rust writes can be read by C.
- `check_writable` reads the encoded JPEG back and requires identical
  coefficients, as the C version now does.
- A passphrase with a NUL is refused, by embed and extract alike, as the C
  version would end it there.
- libjpeg's `error_exit` unwinds through its C frames instead of `longjmp`.
  That needs libjpeg built with unwind tables (the default on x86-64 and
  aarch64 Linux); without them the process aborts.

## Testing

    cargo test --release                      # unit tests, and every stored fuzz regression
    python3 ../tests/test_cli.py              # with SCATTERSTEG=target/release/scattersteg
    make -C .. rust-cli-test                  # the same, with the fault build, in parallel shards
    python3 ../tests/differential.py          # what each writes the other decodes; both load the same files (needs ../scattersteg)

Fuzzing (needs `cargo install cargo-fuzz` and a nightly toolchain):

    cargo +nightly fuzz run png_load  -- -max_len=20000 -rss_limit_mb=5000
    cargo +nightly fuzz run jpeg_load -- -max_len=20000 -rss_limit_mb=5000
    cargo +nightly fuzz run diff_png  -- -dict=dicts/png.dict  -max_len=20000 -rss_limit_mb=5000
    cargo +nightly fuzz run diff_jpeg -- -dict=dicts/jpeg.dict -max_len=20000 -rss_limit_mb=7000
    cargo +nightly fuzz run diff_codec -- -rss_limit_mb=4096

The targets mirror `tests/fuzz/fuzz_png_load.c` and `fuzz_jpeg_load.c`: whatever
loads must save and reload identically. Inputs that once broke them are kept in
`fuzz/regressions` and replayed by `cargo test`. CI runs both tests and a
minute of each fuzzer on every push.

`diff_png` and `diff_jpeg` link the C loaders in as well and check what C loads,
Rust loads with the same pixels or carriers, and that what one writes the other
reads back identically. Differences that are deliberate are listed above; the
PNG target skips them. `diff_codec` links C's file format (`codec.c`) and
checks, on carriers the fuzzer makes, that both decode alike and that what one
encodes the other decodes. Fuzzing builds (`--cfg fuzzing` here,
`FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` in C) swap Argon2id for BLAKE2b so
the fuzzer gets past key derivation: they must never be used for real secrets.
