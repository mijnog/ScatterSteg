# Notes for Claude

## The command line has steghide's syntax

ScatterSteg competes with steghide, so its command line uses steghide's commands and option names for every feature ScatterSteg has: a steghide user should only have to type `scattersteg` instead of `steghide`. The commands are `embed`, `extract`, `info`, `encinfo`, `version`, `license` and `help` (each also as `--embed` and so on); the options are `-ef`, `-cf`, `-sf`, `-xf`, `-z`, `-Z`, `-N`, `-f`, `-q`, `-v`, with steghide's long forms (`--embedfile`, ...).

- **Syntax only, never steghide's text.** Messages, prompts and help text are ScatterSteg's own wording. Don't copy or paraphrase steghide's.
- **New features:** if steghide has an option or command for the same thing, use its name and meaning. If not, pick a name that doesn't clash with one of steghide's. ScatterSteg's own extras so far: the `passphrase` command, `info`'s capacity and suggested-payload lines, and `embed`'s warning when a message is over the suggestion.
- **Deliberate differences, not bugs** (the README's "Coming from steghide" lists them for users):
  - `-p <passphrase>` is refused, with an explanation: the passphrase is always typed at the prompt, never on the command line where `ps` and shell history would show it. The owner decided this; don't add `-p`.
  - `-e` and `-K` are refused: the encryption is fixed (XSalsa20-Poly1305) and every message is authenticated.
  - `-cf -` and `-sf -` (cover from stdin, output to stdout) aren't supported.
  - An existing output file is refused unless `-f`; there is no yes/no prompt. `-f` doesn't replace a file named by the image (the sender chose it): only `-xf <name> -f` does.
  - The stored file name must be UTF-8, not start with `.`, and hold no control or bidi characters (`-N` stores none). An extracted file is created 0600.
  - `info <image>` reports whether the image can be a cover, its capacity, and a suggested most to store (a byte per 160 pixels or non-zero AC coefficients, from the benchmarks' lightest payload). It doesn't look for a message: nothing can, without the passphrase.
  - Messages are always byte-exact (no newline added or removed).
- **Both front ends:** `main.c` (C) and `rust/src/main.rs` (Rust) must behave identically, wording included. `tests/test_cli.py` runs against each (`SCATTERSTEG=<binary>`).

## Handoff (2026-11-01): resume here

**State.** `main` is at `fef8071`: audit findings 1–8 fixed, three Rust PNG fixes diff_png found, the byte-embed cleanups, the review fixes. The fourth diff_png failure was libpng's version (CI's 1.6.43 against 1.6.59 here) deciding C's output for a reserved-name chunk after the image data; the target no longer compares bytes there (`rust/README.md`).

**Ternary (step 3), the decision.** SRNet on the costed-length format, JPEG UERD at 0.2, both from `uerdall_0.2`'s detector, 15 epochs (Kaggle, `~/bench/kaggle/out`): binary `uerdbin_0.2` P_E 0.083, ternary with 1024 samples per bit `uerdtern_0.2` 0.100 (±0.006): ternary slightly harder to detect, about 2 sd. DCTR (`~/bench/run-distortion/results-ternary.txt`): ternary-1024 0.440 against binary 0.420 at 0.2, 0.395 against 0.360 at 0.3. ALASKA2 (`~/bench/alaska-test/results-ternary.txt`): level to 0.2, J-UNIWARD model worse for ternary at 0.4 (0.33 against 0.37). Leans ternary at light payloads, not proven. The local `queue5.sh` run agrees (binary 0.088, ternary 0.099). Next: a second seed, then decide; if kept: Rust, `FORMAT.md`, the Python model in `tests/test_cli.py`, capacity arithmetic, `STC_MAX_W` 64 to 1024 (a format change), and what to do with PNG's exchange embedding. Prototype: branch `ternary-stc` (`e43c20e`, C only, `make STC=ternary`). The three result sets are in `benchmark/README.md` ("Ternary embedding (prototype)").

**Kaggle.** Public dataset `qpdbqp/scattersteg-srnet-ternary` and public notebook `qpdbqp/scattersteg-srnet-ternary-vs-binary` (`~/bench/kaggle/`; BOSSbase republished with its maintainer's permission). Setup: `~/bench/venv-kaggle`, token in `~/.kaggle/access_token` (0600). A run took ~45 minutes per detector on two T4s; future SRNet runs can go there (upload each stego set).

**Branches, and what each waits for**
- `ternary-stc` (local): the prototype above.
- `notes-alaska2` (notes moved to `benchmark/NOTES.md`; real camera fixtures `tests/fixtures/camera`, CC BY-SA 4.0, `test_real_camera_files`) and `jpeg-scan-script` (progressive/multi-scan covers keep their own scan script; `jpeg_fixture` options `mozscans`, `noninterleaved`; `test_keeps_cover_scans`): both had green CI; each needs a rebase onto `main` (they conflict in `CLAUDE.md` and `tests/test_cli.py`, one after the other), a new CI run and the owner's go-ahead. `notes-alaska2`'s notes should absorb what `benchmark/README.md` now has.

**Audit findings** (`AUDIT-2026-10-31.md`): all eight fixed and merged, nothing open. Name rule (UTF-8, no leading `.`, no C1/bidi controls) is a small format change, in `FORMAT.md`.
The old byte-writing embed functions are gone from the code (C keeps them as test helpers in `tests/embed_bytes.h`).

**Ternary STC (step 3), in progress.** `make STC=ternary` (C only): two binary STC layers (second LSB plane over the LSBs), the length region carries 64 bits (length and the first layer's size); unpaired ±1 changes, so no exchange embedding; format incompatible with the binary build. Round-trips on PNG and JPEG, 1 B to 20 KB; no change over ±1. Changes per image, binary ÷ ternary, 40 JPEGs: 1.00 / 1.13 / 1.14 at 0.05 / 0.2 / 0.4, far under the 1.75 the reference comparison suggested; at 0.4 ternary changes 830 zeros against 1,326. Raising `STC_MAX_W` (samples per message bit, now 64) to 1024 helps at 0.05 (ternary 1.15, binary 1.05) and is a format decision. **Pending (running, `~/bench/run-distortion/run-ternary.sh e43c20e`, log `run-ternary.log`):** ALASKA2 models (`~/bench/alaska-test/results-ternary.txt`) and DCTR (`~/bench/run-distortion/results-ternary.txt`) for binary and ternary at pool caps 64 and 1024. Decide from detection, not change counts. If kept: Rust, `FORMAT.md`, the Python model in `tests/test_cli.py`, the capacity and `max_message` arithmetic, SRNet on it, and a way to keep the exchange swaps for PNG if ternary loses on them.

**Background jobs.** None: all SRNet queues and the ternary benchmark are done (`~/bench/dl/runs/*/log.txt`).

**Tools.** mozjpeg 4.1.1 in `~/bench/ext/mozjpeg-src/build`, covers `~/bench/mozjpeg-covers`; `~/bench/venv-conseal` (conseal 2025.11 + jpeglib) for reference simulators (`benchmark/alaska2/sim_reference.py`); Aletheia at `~/bench/ext/aletheia`.

## Detectability plan (2026-10-31)

The file format isn't frozen: nobody uses ScatterSteg yet, so a format change needs no compatibility path. Each step is measured before it's kept; every change lands in C and Rust together, with `FORMAT.md` and the tests. The README's "Status and plans" is the public version of this list.

0. **Done:** JPEG covers carrying a content credential (C2PA) are refused, and since the 2026-10-31 audit also those whose XMP cites one. `THREAT_MODEL.md` covers pooled evidence, how files travel, unseen copies of the cover and device seizure (A7).

1. **Done: JPEG embeds in every AC coefficient** (zeros and ±1 included), as UED, UERD and J-UNIWARD were published. Results in `benchmark/README.md` (DCTR: better from 0.2 up; SRNet: no difference). It fits smooth covers that the old rule refused, which SRNet catches almost always: at 0.2 bits per non-zero AC, P_E runs from 0.002 (smoothest tenth) to 0.176 (busiest quarter) under either rule. That is step 4's job.
2. **Done: files are written the way the cover was** (PNG: row filters, IDAT size, zlib settings; camera JPEGs: header and Huffman tables; `diff_png`/`diff_jpeg` check C and Rust write the same bytes). Scan scripts of progressive/multi-scan covers are kept (merged with `jpeg-scan-script`). Left: progressive headers, fill bytes before EOI, padding-bit quirks, PNG level-0 stored blocks.
3. **Ternary embedding** (multi-layer STC; the message picks +1 or −1): fewer changes per bit, as the published HILL/UERD/J-UNIWARD results assume. It removes most of the exchange embedding's swaps, so measure it against the current binary + exchange, don't assume. **Prototype built (branch `ternary-stc`), detection run pending:** see the Handoff.
4. **Payload suggestion by the square root law, and by texture:** `info`'s suggested most should grow with √(pixels or non-zero ACs), not linearly, and be stricter for smooth covers: at 0.2 bits per nonzero AC, SRNet's P_E runs from 0.002 (smoothest tenth by nonzero-AC share) to 0.176 (busiest quarter), under either JPEG rule (`benchmark/README.md`). embed's over-the-suggestion warning follows it. Calibrate on the new rule's light-payload SRNet runs (below); do the same check for PNG (texture measure: mean HILL cost, say) with `hill_0.1`/`hill_0.2`.
5. **Know where we stand:** add HStego (J-UNIWARD/HILL with STC, the closest rival) and phasm-core (Rust, J-UNIWARD + STC), if it has a usable CLI, to the benchmark. Aletheia's ALASKA2 detectors on ScatterSteg: **done** (`benchmark/README.md`, `benchmark/alaska2/`).

**Kaggle (added 2026-10-31; the off-the-shelf ALASKA2 detectors are done):**
- **ALASKA2 as covers:** 75,000 photos from many cameras and developments, more varied than grayscale 256×256 BOSSbase; a better test of real photos.
- **Free GPUs:** Kaggle notebooks give ~30 GPU hours a week (2×T4 or P100), about double the local SRNet throughput. Upload the BOSSbase 256×256 covers and stego sets and `benchmark/dl/train.py` as a *private* dataset; run queued runs there in parallel with `~/bench/dl`.
- The owner signs in and runs uploads (their account and API key); Claude writes the notebooks and scripts. Keep uploads private: nothing personal, only covers, stego and code.
6. **Then stop chasing P_E:** user guidance in help and README (never a cover whose original exists anywhere else, fresh camera photos, small messages), a frozen format, a full audit of the frozen code (the 2026-10-24 and 2026-10-31 ones cover the code up to `75566c5`), a first release, an independent review. Later, maybe: synchronized changes (CMD/Synch). Not planned: a taller STC, adversarial embedding, side-informed JPEG.

**SRNet queue 4 is done** and in the tables (`benchmark/README.md`, `README.md`, `THREAT_MODEL.md`). Settled: HILL stays the PNG default (S-UNIWARD 0.095 against 0.129 at 0.4), UERD the JPEG one (J-UNIWARD 0.080 against 0.077 at 0.2). Light payloads (JPEG UERD, every AC): P_E 0.077 / 0.093 / 0.109 at 0.2 / 0.1 / 0.05, so 0.05 is still caught 89% of the time; PNG HILL 0.1: 0.339. Step 4's calibration can now start from these.

**Also open, smaller:**
- Progressive JPEG headers: the scans are now the cover's, but tables are written libjpeg's way (one DQT/DHT segment per table; mozjpeg packs them). Copying the cover's header, as `write_like_cover` does for one-scan files, would need the per-scan DHT segments matched too. mozjpeg 4.1.1 is built in `~/bench/ext/mozjpeg-src/build`; test covers in `~/bench/mozjpeg-covers`.
- JPEG encoder quirks not copied: 0xFF fill bytes before EOI (Reconyx), restart-interval padding bits other than libjpeg's 1s (`xmp_BlueSquare` in `ianare/exif-samples`).
- PNG: uncompressed (level-0) covers' stored blocks can't always be reproduced (they depend on the writer's buffer size).
- `tests/test_cli.py`'s camera-layout test repacks a fixture; real camera files (`ianare/exif-samples`, 106 MB) were only used by hand, from the scratchpad. A small vetted subset as fixtures would make that permanent.
- `CLAUDE.md` is turning into a lab notebook: move the result paragraphs above into `benchmark/README.md` and keep a short plan here.
