# Contributing

Bug reports, test cases and fixes are welcome. For a vulnerability, or a detector that tells ScatterSteg output from clean images at payloads the README presents as low-risk, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Build and test

```bash
sudo apt install libsodium-dev libpng-dev libjpeg-dev    # Ubuntu/Debian
make
make test            # unit tests and the end-to-end CLI tests
make fuzz            # builds the libFuzzer targets (needs clang)
```

The Rust port builds with `cd rust && cargo build --release`. Its tests are `cargo test --release`, then `SCATTERSTEG=../rust/target/release/scattersteg python3 ../tests/test_cli.py` and `python3 ../tests/differential.py` (C and Rust must agree on which files load). See [`rust/README.md`](rust/README.md).

CI runs all of this on every push and pull request. A change should pass it.

## What a change needs

- **The two implementations stay compatible.** An image written by the C version must decode with the Rust one and the other way round. A change to the file format or to what counts as a loadable image goes into both, with a test in `tests/test_cli.py` and, for image loading, a file in `tests/fuzz/regressions` or `rust/fuzz/regressions`.
- **A bug found by fuzzing gets its input kept** as a regression file, so it is replayed by the tests.
- **Anything that changes which pixels or coefficients are altered** (costs, pairing, the STC) needs a detectability measurement, not just a round-trip test. [`benchmark/`](benchmark/README.md) shows how. Say what you measured and on what, and do not claim more than it supports.
- **Secrets stay in libsodium memory** (`Secret` in Rust). Do not copy a key, passphrase or plaintext into ordinary heap memory.
- Keep the code in the style of the file you are editing. Comments say why, not what.

## Reporting a bug

Include the command, the platform, the library versions (`pkg-config --modversion libpng libjpeg`), and, if an image is involved, whether you can share it. Never post a passphrase or a real message.
