# Benchmark working notes

Lab notes moved out of `CLAUDE.md` (2026-10-31). Local data lives in `~/bench`.

## Step 1 result (JPEG: every AC coefficient)

1. **JPEG: embed in every AC coefficient** (zeros and ±1 included, UERD or J-UNIWARD costs, ±1 either way) instead of only |value| ≥ 2. UED, UERD and J-UNIWARD all do; nsF5-style skipping crowds the changes. **Merged 2026-10-31.** Prototype was branch `jpeg-all-coefs` (`b702512`; 8 test checks still expect the old rule). **DCTR result (2026-10-31, `~/bench/run-distortion/results-allcoef.txt`):** P_E old → all-coefficients, UERD 0.485/0.464/0.397/0.261 → 0.473/0.456/0.418/0.356 at 0.05/0.1/0.2/0.3; J-UNIWARD 0.496/0.468/0.382/0.232 → 0.470/0.462/0.425/0.360. A clear gain from 0.2 up, slightly worse at 0.05 (1–2 sd; maybe tune a small extra cost on zeros, as `JPEG_TWO_COST` was tuned). Histogram shifts (`hist_jpg.py`, on `jpeg-all-coefs`) all ≤ 0.1 cover sds, against up to 1.6 (UERD) and 3.2 (J-UNIWARD) for the old rule at 0.3; every cover now fits 0.3. **SRNet result:** `uerdall_0.2` (fine-tuned from `uerd_0.2`'s detector) has P_E 0.0777 on the 1,955 test images `uerd_0.2` kept, against 0.0734 (bootstrap sd 0.0039: no real difference); 0.0765 on all 2,000. The 45 smooth images the old rule couldn't fit are caught almost always (P_E 0.022). Owner's call: go ahead. **Done (merged):** C and Rust, tests updated, carriers implicit (one pointer per block; cap 14 bytes per carrier, ~50 MP for 4:2:0), `JPEG_TWO_COST` gone, docs and benchmark tables updated. Smooth covers: not the new rule's doing. At 0.2 bits per nonzero AC, SRNet's P_E by nonzero-AC share runs from 0.002 (smoothest tenth) to 0.176 (busiest quarter), the same under both rules (`benchmark/README.md`). So the "guard" belongs in step 4: the payload suggestion and embed's warning should scale with texture, calibrated on the new rule's light-payload runs (`train_queue4.sh`).

## ALASKA2 detectors and the SRNet queues

Both are finished, and their results are in `README.md` (off-the-shelf detectors, SRNet tables, the ternary prototype). Raw output: `results-srnet.txt`, `alaska2/`. The working directories are in `~/bench` (`alaska-test`, `dl`, `kaggle`).
