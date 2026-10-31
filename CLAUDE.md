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

## Handoff (2026-11-01, night): resume here

**Overnight, unattended:** (1) `~/bench/dl/train_queue4.sh` (light payloads; `hill_0.1` done, P_E 0.339; then `uerdall_0.1`, `suniward_0.2`, `juniwardall_0.1`, `uerdall_0.05`), then `~/bench/dl/queue5.sh` trains `uerdbin_0.2` (binary) and `uerdtern_0.2` (ternary, 1024 samples per bit), both on the costed-length format, 15 epochs from `uerdall_0.2` (log `queue5.log`, runs in `~/bench/dl/runs/`). That SRNet pair decides ternary: DCTR favoured ternary-1024 (P_E 0.440 vs 0.420 at 0.2, 0.395 vs 0.360 at 0.3; `~/bench/run-distortion/results-ternary.txt`), ALASKA2's J-UNIWARD model disfavoured it at 0.4 (0.33 vs 0.37; `~/bench/alaska-test/results-ternary.txt`); write all three into `benchmark/README.md`. (2) The owner's upload of the **public** Kaggle dataset `qpdbqp/scattersteg-srnet-ternary` (`~/bench/kaggle/bundle`, verified; BOSSbase republished with its maintainer's permission, by email to the owner). The notebook (`~/bench/kaggle/kernel/`, public, 2xT4) isn't pushed: `~/bench/venv-kaggle/bin/kaggle kernels push -p ~/bench/kaggle/kernel`, only if local results aren't in. Token in `~/.kaggle/access_token` (0600).

**Merge pending:** branch `cleanups` (`95fb324`, pushed; holds the audit fixes 1–8, three Rust PNG fixes diff_png found, the cleanups and the review fixes) fast-forwards `main` when its CI is green (owner approved). CI failed three times on diff_png, each a real C/Rust difference after the image data (second IHDR, reserved-letter name, bad-CRC critical chunk), each fixed with a regression file; 221,000 local runs since found nothing.

**Branches, and what each waits for**
- `audit-2026-10-31` (local, `.md` only): `AUDIT-2026-10-31.md` and the updated status table in `AUDIT-2026-10-24.md`. Push and merge on the owner's go-ahead, no CI needed.
- `ternary-stc` (local, `e43c20e`, prototype, C only): see below.
- `notes-alaska2` (notes moved to `benchmark/NOTES.md`; real camera fixtures `tests/fixtures/camera`, CC BY-SA 4.0, `test_real_camera_files`) and `jpeg-scan-script` (progressive/multi-scan covers keep their own scan script; `jpeg_fixture` options `mozscans`, `noninterleaved`; `test_keeps_cover_scans`): both pushed, CI green. They conflict in `CLAUDE.md` and `tests/test_cli.py`: rebase each onto `main` after the one before merges, with the owner's go-ahead for each. `notes-alaska2` should also get the ALASKA2 numbers, which are now in `benchmark/README.md`.

**Audit findings** (`AUDIT-2026-10-31.md`). **1–4 and 8 fixed on branch `audit-fixes`** (C and Rust, tests in `test_cli.py`; the name rule is a small format change, in `FORMAT.md`): C refuses a PNG past 1 GiB + 64 MiB as Rust does; stored names must be UTF-8, not start with `.`, no C1/bidi controls; `-f` replaces only a file named with `-xf`; extracted files 0600; libpng's messages silenced. **5–7 fixed on branch `audit-fixes-2`** (stacked on `audit-fixes`): the decoded name in locked memory; XMP citing a remote C2PA manifest refused (JPEG and PNG), maker-note signatures documented; the DHT rewrite checks its own input. Nothing left open from the audit.
The old byte-writing embed functions are gone from the code (C keeps them as test helpers in `tests/embed_bytes.h`).

**Ternary STC (step 3), in progress.** `make STC=ternary` (C only): two binary STC layers (second LSB plane over the LSBs), the length region carries 64 bits (length and the first layer's size); unpaired ±1 changes, so no exchange embedding; format incompatible with the binary build. Round-trips on PNG and JPEG, 1 B to 20 KB; no change over ±1. Changes per image, binary ÷ ternary, 40 JPEGs: 1.00 / 1.13 / 1.14 at 0.05 / 0.2 / 0.4, far under the 1.75 the reference comparison suggested; at 0.4 ternary changes 830 zeros against 1,326. Raising `STC_MAX_W` (samples per message bit, now 64) to 1024 helps at 0.05 (ternary 1.15, binary 1.05) and is a format decision. **Pending (running, `~/bench/run-distortion/run-ternary.sh e43c20e`, log `run-ternary.log`):** ALASKA2 models (`~/bench/alaska-test/results-ternary.txt`) and DCTR (`~/bench/run-distortion/results-ternary.txt`) for binary and ternary at pool caps 64 and 1024. Decide from detection, not change counts. If kept: Rust, `FORMAT.md`, the Python model in `tests/test_cli.py`, the capacity and `max_message` arithmetic, SRNet on it, and a way to keep the exchange swaps for PNG if ternary loses on them.

**Background jobs.** SRNet `train_queue4.sh` (`~/bench/dl/runs/*/log.txt`; `juniwardall_0.2` was finishing, then `hill_0.1`, `uerdall_0.1`, `suniward_0.2`, `juniwardall_0.1`, `uerdall_0.05`), and the ternary benchmark above.

**Tools.** mozjpeg 4.1.1 in `~/bench/ext/mozjpeg-src/build`, covers `~/bench/mozjpeg-covers`; `~/bench/venv-conseal` (conseal 2025.11 + jpeglib) for reference simulators (`benchmark/alaska2/sim_reference.py`); Aletheia at `~/bench/ext/aletheia`.

## Detectability plan (2026-10-31)

The file format isn't frozen: nobody uses ScatterSteg yet, so a format change needs no compatibility path. Each step is measured before it's kept; every change lands in C and Rust together, with `FORMAT.md` and the tests. The README's "Status and plans" is the public version of this list.

0. **Done:** JPEG covers carrying a content credential (C2PA) are refused, and since the 2026-10-31 audit also those whose XMP cites one. `THREAT_MODEL.md` covers pooled evidence, how files travel, unseen copies of the cover and device seizure (A7).

1. **Done: JPEG embeds in every AC coefficient** (zeros and ±1 included), as UED, UERD and J-UNIWARD were published. Results in `benchmark/README.md` (DCTR: better from 0.2 up; SRNet: no difference). It fits smooth covers that the old rule refused, which SRNet catches almost always: at 0.2 bits per non-zero AC, P_E runs from 0.002 (smoothest tenth) to 0.176 (busiest quarter) under either rule. That is step 4's job.
2. **Done: files are written the way the cover was** (PNG: row filters, IDAT size, zlib settings; camera JPEGs: header and Huffman tables; `diff_png`/`diff_jpeg` check C and Rust write the same bytes). Left: progressive scan scripts from other encoders (branch `jpeg-scan-script`), fill bytes before EOI, padding-bit quirks, PNG level-0 stored blocks.
3. **Ternary embedding** (multi-layer STC; the message picks +1 or −1): fewer changes per bit, as the published HILL/UERD/J-UNIWARD results assume. It removes most of the exchange embedding's swaps, so measure it against the current binary + exchange, don't assume. **Prototype built (branch `ternary-stc`), detection run pending:** see the Handoff.
4. **Payload suggestion by the square root law, and by texture:** `info`'s suggested most should grow with √(pixels or non-zero ACs), not linearly, and be stricter for smooth covers: at 0.2 bits per nonzero AC, SRNet's P_E runs from 0.002 (smoothest tenth by nonzero-AC share) to 0.176 (busiest quarter), under either JPEG rule (`benchmark/README.md`). embed's over-the-suggestion warning follows it. Calibrate on the new rule's light-payload SRNet runs (below); do the same check for PNG (texture measure: mean HILL cost, say) with `hill_0.1`/`hill_0.2`.
5. **Know where we stand:** add HStego (J-UNIWARD/HILL with STC, the closest rival) and phasm-core (Rust, J-UNIWARD + STC), if it has a usable CLI, to the benchmark. Aletheia's ALASKA2 detectors on ScatterSteg: **done** (`benchmark/README.md`, `benchmark/alaska2/`).

**Kaggle (added 2026-10-31; the off-the-shelf ALASKA2 detectors are done):**
- **ALASKA2 as covers:** 75,000 photos from many cameras and developments, more varied than grayscale 256×256 BOSSbase; a better test of real photos.
- **Free GPUs:** Kaggle notebooks give ~30 GPU hours a week (2×T4 or P100), about double the local SRNet throughput. Upload the BOSSbase 256×256 covers and stego sets and `benchmark/dl/train.py` as a *private* dataset; run queued runs there in parallel with `~/bench/dl`.
- The owner signs in and runs uploads (their account and API key); Claude writes the notebooks and scripts. Keep uploads private: nothing personal, only covers, stego and code.
6. **Then stop chasing P_E:** user guidance in help and README (never a cover whose original exists anywhere else, fresh camera photos, small messages), a frozen format, a full audit of the frozen code (the 2026-10-24 and 2026-10-31 ones cover the code up to `75566c5`), a first release, an independent review. Later, maybe: synchronized changes (CMD/Synch). Not planned: a taller STC, adversarial embedding, side-informed JPEG.

**SRNet queue 4 is running** (`train_queue4.sh be0265b`; `~/bench/dl/runs/*/log.txt`, `benchmark/dl/summarize.py ~/bench/dl`). Settled: HILL stays the PNG default (S-UNIWARD 0.095 against 0.129 at 0.4), UERD the JPEG one (J-UNIWARD 0.080 against 0.077 at 0.2, within the noise; UERD is far cheaper). Still training: `hill_0.1`, `uerdall_0.1`, `suniward_0.2`, `juniwardall_0.1`, `uerdall_0.05`. When they finish: the SRNet tables (`benchmark/README.md`, `README.md`, `THREAT_MODEL.md`) and step 4's calibration.

**Also open, smaller:** the encoder quirks in step 2; results belong in `benchmark/README.md`, the plan here.
