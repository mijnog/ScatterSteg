# ScatterSteg in Rust

A line-for-line port of the C implementation in the repository root. It keeps
the file format and the command line: an image written by one decodes with the
other, for PNG and JPEG.

    cargo build --release        # needs libsodium, libjpeg-turbo, pkg-config, libclang
    cd ../tests && SCATTERSTEG=../rust/target/release/scattersteg python3 test_cli.py

`--features fault-injection` builds the variant the fault sweeps in
`tests/test_cli.py` drive (`SCATTERSTEG_FAULT`, `FAULT_LONG_MIN=15`).

## Differences from the C version

On purpose:

- **Allocation failure aborts.** A failed heap allocation ends the process
  instead of printing "allocation failed" and exiting 1. Secrets still live in
  libsodium memory, and core dumps are disabled.
- **PNG output bytes differ.** The Rust PNG writer (its own filter choice and
  zlib) gives a file about 12% larger than libpng's, with the same pixels,
  interlacing and ancillary chunks. JPEG output differs by a few bytes.
- **Files are read whole.** The input is buffered, after its first bytes match
  a PNG or JPEG signature and up to 1 GiB + 64 MiB, where C streamed it. A
  JPEG's coefficients are held twice (libjpeg's and a copy), so its working
  memory is up to about double the 1 GiB cap.
- **SIGPIPE is ignored** (the Rust runtime does it): a closed stdout is an
  error message and exit 1, not death by signal.
- **Chunks with a bad CRC are dropped.** libpng kept such an ancillary chunk
  and wrote it back with a valid CRC.
- **A bad zlib checksum (Adler-32) in the image data is not an error.** The
  `png` crate doesn't check it; libpng refuses the file. The output is valid.
- **No libpng width/height cap** (1,000,000). Only the 2^28-pixel cap applies.

Needed for compatibility:

- A passphrase ends at its first NUL, as the C string did.
- libjpeg's `error_exit` unwinds through its C frames instead of `longjmp`.
  That needs libjpeg built with unwind tables (the default on x86-64 and
  aarch64 Linux); without them the process aborts.
