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
  - `info <image>` reports whether the image can be a cover, its capacity, and a suggested most to store (3 bytes per √pixels or 1 per √(non-zero AC coefficients), less the fixed overhead; none for a smooth cover). It doesn't look for a message: nothing can, without the passphrase.
  - Messages are always byte-exact (no newline added or removed).
- **Both front ends:** `main.c` (C) and `rust/src/main.rs` (Rust) must behave identically, wording included. `tests/test_cli.py` runs against each (`SCATTERSTEG=<binary>`).

## Handoff (2026-11-01): resume here

**State.** `main` is at `659aea2`: step 4 (the payload suggestion and the nonce, below), audit findings 1–8 fixed, the Rust PNG fixes diff_png found, the byte-embed cleanups, progressive/multi-scan JPEG covers keep their scan script (`test_keeps_cover_scans`), real camera fixtures (`tests/fixtures/camera`, `test_real_camera_files`), lab notes in `benchmark/NOTES.md`. The light-payload SRNet runs are in the tables. diff_png doesn't compare bytes for a reserved-name chunk after the image data, where libpng's version decides C's output (`rust/README.md`).

**Ternary (step 3): keep it, owner's go-ahead (2026-11-01); PNG check running.** SRNet, JPEG UERD at 0.2, 15 epochs from `uerdall_0.2`'s detector, binary `uerdbin_0.2` against ternary with 1024 samples per bit `uerdtern_0.2`: seed 0 Kaggle 0.083/0.100, seed 0 local 0.088/0.099, seed 1 Kaggle 0.083/0.097 (`~/bench/kaggle/out`, `out-seed1`); ternary harder to detect in every run, by 0.011–0.017 (±0.006 each). DCTR agrees (0.440 against 0.420 at 0.2), ALASKA2 level to 0.2, J-UNIWARD model against at 0.4. The literature expects a small JPEG gain and a bigger spatial one (Butora and Fridrich's side-informed modulation paper). The format isn't frozen, so the format change costs nothing. **Running on Kaggle:** PNG HILL at 0.2 bpp, binary+exchange `pngbin_0.2` against ternary `pngtern_0.2` (embedded by `~/bench/dl/queue6.sh`; dataset `qpdbqp/scattersteg-srnet-png`, notebook `qpdbqp/scattersteg-srnet-png-ternary-vs-binary` version 2, from `~/bench/kaggle/kernel-png`, 15 epochs from `hill_0.2`; results to `~/bench/kaggle/out-png`). Version 1 failed at load: train.py writes its cache next to the data, and Kaggle's input is read-only (the JPEG bundle had shipped its caches); v2 gives each run a writable folder of links. 4 nearly black covers the prototype couldn't embed in are left out of both sets. Its result decides PNG's exchange embedding. Then the port: Rust, `FORMAT.md`, the Python model in `tests/test_cli.py`, capacity and `max_message` arithmetic, `STC_MAX_W` 64 to 1024. Prototype: branch `ternary-stc` (`b5724d1`, C only, `make STC=ternary`; `b5724d1` fixed covers of mostly 0s/255s, where no ±1 change flips a second bit: layer A's share halves until it fits, down to plain ±1, the split being stored already): two binary STC layers (second LSB plane over the LSBs); the length region carries 64 bits (length and the first layer's size); changes per image, binary ÷ ternary, 1.00/1.13/1.14 at 0.05/0.2/0.4. Results in `benchmark/README.md` ("Ternary embedding (prototype)").

**Kaggle.** Public datasets `qpdbqp/scattersteg-srnet-ternary` (BOSSbase republished with its maintainer's permission) and `qpdbqp/scattersteg-srnet-png`; public notebooks `qpdbqp/scattersteg-srnet-ternary-vs-binary`, `-seed-1` and `qpdbqp/scattersteg-srnet-png-ternary-vs-binary` (`~/bench/kaggle/`). Setup: `~/bench/venv-kaggle`, token in `~/.kaggle/access_token` (0600). ~45 minutes per detector, two in parallel on two T4s; GPU time is limited (~30 h a week), so only runs that decide something. The owner pushes.

**Branches.** `ternary-stc` (local): the prototype above. `hstego-bench` (local, `475f20f`): `benchmark/hstego_embed.py` and an `hstego` option in `embed_jpg.py` and `alaska2/embed_set.py`; merge with step 5's results.

**Step 5 (HStego), running:** `~/bench/run-distortion/run-hstego.sh 475f20f` (log `run-hstego.log`): ScatterSteg as merged against HStego (`~/bench/ext/hstego`, `bf71f6e`; venv `~/bench/venv-hstego`, installed by the owner) through Aletheia's ALASKA2 models (0.05–0.4; `~/bench/alaska-test/results-hstego.txt`) and DCTR (0.05–0.3; `~/bench/run-distortion/results-hstego.txt`), same payloads. ~12 s per HStego embed. HStego caps messages at 0.05 bits per non-zero coefficient (linear); the cap is lifted to measure above it. Found: HStego's extract fails once a message spills past the first colour channel, because it splits by each channel's non-zero count and embedding changes the counts (Cb 12 → 44 bytes on one cover); it also takes the password on the command line. The owner wants the README to compare against steghide (the CTF default) and HStego (state of the art).

**Audit findings** (`AUDIT-2026-10-31.md`): all eight fixed and merged, nothing open.

**Step 4 (payload suggestion): merged (`b67d51b`).** The owner chose all three parts (2026-11-01): (1) a smooth cover gets no suggestion, and embed warns (JPEG under 14% of ACs non-zero, PNG mean residual |4x − neighbours|/4 under 1.7: the smoothest third, caught 93–98% at any payload); (2) the suggestion is 3 bytes per √pixels (PNG) or 1 per √(non-zero ACs) (JPEG) less 37 fixed bytes (`codec_suggested`), anchored on BOSSbase's lightest payloads with the overhead counted, the √n scaling from the literature (untested here: one image size); (3) the 24-byte secretbox nonce is gone (zero nonce; the key is unique per message as the salt is fresh; `test_fresh_salt`), overhead 62 to 38 bytes. Found on the way: the BOSSbase light payloads were dominated by that overhead ("0.05" was ~0.09 effective, 0.17 on smooth images), and texture matters more than payload; docs corrected. A size sweep (SRNet at several image sizes) would calibrate √n, if worth the GPU time.

**Tools.** mozjpeg 4.1.1 in `~/bench/ext/mozjpeg-src/build`, covers `~/bench/mozjpeg-covers`; `~/bench/venv-conseal` (conseal 2025.11 + jpeglib) for reference simulators (`benchmark/alaska2/sim_reference.py`); Aletheia at `~/bench/ext/aletheia`.

## Detectability plan (2026-10-31)

The file format isn't frozen: nobody uses ScatterSteg yet, so a format change needs no compatibility path. Each step is measured before it's kept; every change lands in C and Rust together, with `FORMAT.md` and the tests. The README's "Status and plans" is the public version of this list.

0. **Done:** JPEG covers carrying a content credential (C2PA) are refused, and since the 2026-10-31 audit also those whose XMP cites one. `THREAT_MODEL.md` covers pooled evidence, how files travel, unseen copies of the cover and device seizure (A7).

1. **Done: JPEG embeds in every AC coefficient** (zeros and ±1 included), as UED, UERD and J-UNIWARD were published. Results in `benchmark/README.md` (DCTR: better from 0.2 up; SRNet: no difference). It fits smooth covers that the old rule refused, which SRNet catches almost always: at 0.2 bits per non-zero AC, P_E runs from 0.002 (smoothest tenth) to 0.176 (busiest quarter) under either rule. That is step 4's job.
2. **Done: files are written the way the cover was** (PNG: row filters, IDAT size, zlib settings; camera JPEGs: header and Huffman tables; `diff_png`/`diff_jpeg` check C and Rust write the same bytes). Scan scripts of progressive/multi-scan covers are kept (merged with `jpeg-scan-script`). Left: progressive headers, fill bytes before EOI, padding-bit quirks, PNG level-0 stored blocks.
3. **Ternary embedding** (multi-layer STC; the message picks +1 or −1): fewer changes per bit, as the published HILL/UERD/J-UNIWARD results assume. It removes most of the exchange embedding's swaps, so measure it against the current binary + exchange, don't assume. **Kept (2026-11-01); PNG check and port pending:** see the Handoff.
4. **Done: payload suggestion by the square root law, and by texture** (see the Handoff): `info`'s suggested most should grow with √(pixels or non-zero ACs), not linearly, and be stricter for smooth covers: at 0.2 bits per nonzero AC, SRNet's P_E runs from 0.002 (smoothest tenth by nonzero-AC share) to 0.176 (busiest quarter), under either JPEG rule (`benchmark/README.md`). embed's over-the-suggestion warning follows it. Calibrate on the new rule's light-payload SRNet runs (below); do the same check for PNG (texture measure: mean HILL cost, say) with `hill_0.1`/`hill_0.2`.
5. **Know where we stand:** add HStego (J-UNIWARD/HILL with STC, the closest rival) and phasm-core (Rust, J-UNIWARD + STC), if it has a usable CLI, to the benchmark. Aletheia's ALASKA2 detectors on ScatterSteg: **done** (`benchmark/README.md`, `benchmark/alaska2/`).

**Kaggle (added 2026-10-31; the off-the-shelf ALASKA2 detectors are done):**
- **ALASKA2 as covers:** 75,000 photos from many cameras and developments, more varied than grayscale 256×256 BOSSbase; a better test of real photos.
- **Free GPUs:** Kaggle notebooks give ~30 GPU hours a week (2×T4 or P100), about double the local SRNet throughput. Datasets and notebooks are public (the owner's choice, for transparency).
- The owner signs in and runs uploads (their account and API key); Claude writes the notebooks and scripts. Nothing personal: only covers, stego and code.
6. **Then stop chasing P_E:** user guidance in help and README (never a cover whose original exists anywhere else, fresh camera photos, small messages), a frozen format, a full audit of the frozen code (the 2026-10-24 and 2026-10-31 ones cover the code up to `75566c5`), a first release, an independent review. Later, maybe: synchronized changes (CMD/Synch). Not planned: a taller STC, adversarial embedding, side-informed JPEG.

**SRNet queue 4 is done** and in the tables (`benchmark/README.md`, `README.md`, `THREAT_MODEL.md`). Settled: HILL stays the PNG default (S-UNIWARD 0.095 against 0.129 at 0.4), UERD the JPEG one (J-UNIWARD 0.080 against 0.077 at 0.2). Light payloads (JPEG UERD, every AC): P_E 0.077 / 0.093 / 0.109 at 0.2 / 0.1 / 0.05, so 0.05 is still caught 89% of the time; PNG HILL 0.1: 0.339. Step 4's calibration can now start from these.

**Also open, smaller:**
- Progressive JPEG headers: the scans are now the cover's, but tables are written libjpeg's way (one DQT/DHT segment per table; mozjpeg packs them). Copying the cover's header, as `write_like_cover` does for one-scan files, would need the per-scan DHT segments matched too. mozjpeg 4.1.1 is built in `~/bench/ext/mozjpeg-src/build`; test covers in `~/bench/mozjpeg-covers`.
- JPEG encoder quirks not copied: 0xFF fill bytes before EOI (Reconyx), restart-interval padding bits other than libjpeg's 1s (`xmp_BlueSquare` in `ianare/exif-samples`).
- PNG: uncompressed (level-0) covers' stored blocks can't always be reproduced (they depend on the writer's buffer size).
- Lab notes live in `benchmark/NOTES.md` and results in `benchmark/README.md`; keep this file a short plan. Real camera fixtures: `tests/fixtures/camera` (nine files, CC BY-SA 4.0, see its README).

## Formal verification (planned, start once the format settles)

Lean adds to the tests; it doesn't replace them. Start only after the ternary port is merged (step 4 is), since both change what the spec describes. Proofs cover our own maths, not libpng/libjpeg/zlib/libsodium, and never detectability (that's empirical: the benchmarks stay).

1. **Spec in Lean 4 + Mathlib** (`spec/`, or a separate repo): the format's pure core as plain functions, taken from `FORMAT.md`, not from the C:
   - the STC syndrome H·y, with the column rule;
   - `prng_permutation` (Fisher–Yates, with the keystream as an input; don't model ChaCha20);
   - the salt-region, length-region, capacity and `max_message` arithmetic;
   - `codec_suggested` (isqrt × bytes − `FIXED_BYTES`).
   It plays the role `tests/test_cli.py`'s Python model plays, but provable.
2. **First proofs (cheap):** the shuffle is a permutation; no arithmetic over- or underflows up to the 1 GiB cap; the suggestion is never over the capacity; the salt, length and payload regions don't overlap and each sample is used once.
3. **Main result:** STC correctness. For every message and cover, the syndrome of the embedder's output is the message (linear algebra over GF(2)). Not optimality: too hard, low value.
4. **Tie it to the shipped code:** generate test vectors from the Lean spec and check both builds against them in CI.
- **Kani in parallel** (cheaper, finds real bugs sooner): bounded proofs that the Rust parsers never panic or index out of range. Targets: the PNG chunk walker (`parse_chunks`), the DHT checks (`new_tables_into` / `with_new_tables`), `name_ok`.
- **Later, once the format is frozen:** Aeneas (Rust → Lean) to prove things about the real Rust code, then give the proofs to the independent reviewer (step 6).
- **Session tip:** one lemma or one function per session; keep the spec in a file to re-read rather than re-deriving it from the C each time.
