# Contributing

Bug reports, test cases and fixes are welcome. For a vulnerability, or a detector that tells ScatterSteg output from clean images at payloads the README presents as low-risk, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Build and test

Install the libraries for your distribution as in the [README's install section](README.md#install), then:

```bash
make
make test            # unit tests and the end-to-end CLI tests
make rust-cli-test   # the same CLI tests against the Rust build (builds it first)
make fuzz            # builds the libFuzzer targets (needs clang)
```

The CLI tests run in parallel: `tests/run_sharded.py` splits them into `JOBS` shards (6 by default; `make test JOBS=4`), each a separate `tests/test_cli.py` process, so every test still runs once with its own temp directory and terminal. Tests go to shards longest first, by the times in `tests/durations.json`; after adding slow tests, refresh them with `python3 tests/run_sharded.py --record --profile c` (or `rust`, with `SCATTERSTEG` and the rest set as `make rust-cli-test` sets them). `JOBS=1` runs the suite as one process. On an i5-12400F (6 cores, 12 threads; 2026-11-02, idle), the CLI tests took 268.5 s for C (sanitizer builds) and 121.4 s for Rust as one process, and 61.9–62.2 s and 26.6–26.7 s in 6 shards (five runs each, all passing); the C suite can't go much lower, as its longest test, a fault sweep, takes about 50 s. 8 shards gave 67.9 s and 24.6 s, 4 gave 78.7 s and 36.4 s.

The Rust port builds with `cd rust && cargo build --release`. Its tests are `cargo test --release`, then `make rust-cli-test` (or `SCATTERSTEG=../rust/target/release/scattersteg python3 ../tests/test_cli.py`) and `python3 ../tests/differential.py` (an image either build writes must decode with the other, and both must agree on which files load). See [`rust/README.md`](rust/README.md).

CI runs all of this on every push and pull request. A change should pass it.

## What a change needs

- **The two implementations stay compatible.** An image written by the C version must decode with the Rust one and the other way round. A change to the file format or to what counts as a loadable image goes into both, with a test in `tests/test_cli.py` and, for image loading, a file in `tests/fuzz/regressions` or `rust/fuzz/regressions`.
- **The command line keeps steghide's syntax**: its command and option names, for every feature ScatterSteg has, so steghide users already know it. The wording of messages and help is ScatterSteg's own. [`CLAUDE.md`](CLAUDE.md) lists the deliberate differences.
- **A bug found by fuzzing gets its input kept** as a regression file, so it is replayed by the tests.
- **Anything that changes which pixels or coefficients are altered** (costs, pairing, the STC) needs a detectability measurement, not just a round-trip test. [`benchmark/`](benchmark/README.md) shows how. Say what you measured and on what, and do not claim more than it supports.
- **Secrets stay in libsodium memory** (`Secret` in Rust). Do not copy a key, passphrase or plaintext into ordinary heap memory.
- Keep the code in the style of the file you are editing. Comments say why, not what.

## Reporting a bug

Include the command, the platform, the library versions (`pkg-config --modversion libpng libjpeg`), and, if an image is involved, whether you can share it. Never post a passphrase or a real message.
