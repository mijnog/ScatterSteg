# Detectability benchmark

How easily can a steganalysis classifier tell a ScatterSteg image from its
cover, compared with steghide and with naive LSB embedding? This is a first,
modest measurement. Read the limitations before quoting a number.

**Current results** (HILL costs for PNG, UERD for JPEG) are in
[HILL](#content-adaptive-costs-hill), [UERD](#content-adaptive-jpeg-costs-uerd),
[BOSSbase](#second-cover-set-bossbase), [SRNet](#deep-learning-detector-srnet)
and [Classic detectors](#classic-detectors). SRNet, a deep network, is by far
the strongest detector run; read the rest as rankings.
The tables before the HILL section are the original measurements, from
before content-adaptive costs, kept as the baseline the later ones are
compared to.

## Result

Detection error **P_E** (0.5 = the detector cannot do better than guessing;
lower = easier to detect). 476 covers, 5 random 50/50 splits, standard error
about ±0.02. Payload is message bits per pixel (PNG/BMP) or per non-zero AC
coefficient (JPEG). ScatterSteg PNG figures in this section and the next two
are for uniform costs, used before HILL; see [HILL](#content-adaptive-costs-hill)
for the current ones.

**Pixel images** (SPAM features, 512×512 RGB):

| payload | LSB replacement | LSB matching | steghide (BMP) | **ScatterSteg (PNG)** |
|---|---|---|---|---|
| 0.05 | 0.342 | 0.339 | 0.143 | **0.459** |
| 0.10 | 0.253 | 0.249 | 0.123 | **0.406** |
| 0.20 | 0.163 | 0.163 | 0.099 | **0.314** |
| 0.40 | 0.094 | 0.097 | 0.071 | **0.202** |

**JPEG** (quality 75, 4:2:0; DCT co-occurrence features):

| payload | steghide | **ScatterSteg** |
|---|---|---|
| 0.05 | 0.338 | **0.423** |
| 0.10 | 0.243 | **0.396** |
| 0.20 | 0.134 | **0.228** |

ScatterSteg is harder to detect than steghide at every payload, and harder than
naive LSB matching. At low payloads (0.05 to 0.1) these SPAM and SVM detectors
are close to guessing. They are weak, though: the stronger detector in the next
section catches 65% to 75% of the same files at those payloads.

## Result with a stronger detector (SRM-style rich model)

The same 480 Wikimedia photographs and the same stego files, scored by `srm.py`
and `detect_srm.py`: about 7,000 features per channel (many linear residuals,
quantized and truncated, min/max variants, fourth-order co-occurrences) and a
Kodovsky-style ensemble of 100 regularized FLDs on random feature subsets.
Five random 50/50 splits, standard deviation 0.005 to 0.02.

| payload | LSB matching | steghide (BMP) | **ScatterSteg (PNG)** |
|---|---|---|---|
| 0.05 | 0.170 | 0.036 | **0.350** |
| 0.10 | 0.092 | 0.028 | **0.253** |
| 0.20 | 0.046 | 0.020 | **0.139** |
| 0.40 | 0.019 | 0.018 | **0.066** |

The ranking is the same as with SPAM (ScatterSteg best, then LSB matching, then
steghide), but every number is lower. This detector catches steghide 96% to 98%
of the time at every payload, and ScatterSteg about 65% of the time at 0.05
and 93% at 0.4. The SPAM table above is therefore optimistic for the user, and
this one is the better estimate. `results-srm-wikimedia.txt` has the raw output.

**JPEG, DCTR-style detector** (`dctr.py`, `detect_dctr.py`): the unrounded
decompressed luminance correlated with the 64 DCT basis patterns, quantized and
truncated at T=4, histogrammed per folded phase: 5,120 features, the same
ensemble classifier. Payload is bits per non-zero AC coefficient.

| payload | steghide | **ScatterSteg** |
|---|---|---|
| 0.05 | 0.210 | **0.467** |
| 0.10 | 0.102 | **0.402** |
| 0.20 | 0.026 | **0.261** |

Again the same ranking. steghide's error falls from 0.34/0.24/0.13 with the
compact features to 0.21/0.10/0.03 here; ScatterSteg's changes little, because
the compact features were already well matched to its changes (0.42/0.40/0.23).
Raw output is in `results-dctr-jpeg.txt`.

### Content-adaptive costs (HILL)

PNG embedding now uses HILL costs instead of uniform ones (`embed.c`,
`embed_hill_costs`). Measured on 480 Wikimedia photographs fetched on
2026-10-25 (Wikimedia's featured pictures change, so not the same set as
above), with the same payloads and splits; `results-hill-wikimedia.txt` has
the raw output. The uniform column re-measured here matches the published one
above to within 0.013, so the harness is unchanged:

| payload | SRM-style, uniform costs | **SRM-style, HILL** | SPAM, uniform | **SPAM, HILL** |
|---|---|---|---|---|
| 0.05 | 0.347 | **0.442** | 0.455 | **0.499** |
| 0.10 | 0.257 | **0.417** | 0.393 | **0.496** |
| 0.20 | 0.141 | **0.388** | 0.301 | **0.484** |
| 0.40 | 0.062 | **0.355** | 0.191 | **0.453** |

The Rust build's HILL gives 0.448, 0.418, 0.387 and 0.359 with the SRM-style
detector.

SPAM near 0.5 for HILL is the weak detector failing, not a result to quote.
`controls.py` checks it still discriminates: two disjoint halves of the covers,
one labelled stego, score 0.485-0.518 (chance), and at 1.0 bits per pixel
(476 covers; the 4 grayscale ones can't hold it) uniform costs score 0.091
with SPAM and 0.018 with SRM, HILL 0.363 and 0.235. So both detectors see
HILL at a heavy payload, and the SRM-style figures are the ones to use. HILL makes 28–41% more changes than uniform costs but puts them
where the image is busy, and more of them pair as value swaps (93–98.5%
against 48–87%). Ker's adjacency HCF-COM, the detector an earlier HILL-like
attempt lost on, moves 9 to 12 times less than with uniform costs (`hcf.py`).
BOSSbase is re-run below; JPEG costs are covered in the UERD section.

Reproduce (after `fetch_images.py 480`; needs numpy, scipy, scikit-learn,
pillow and ImageMagick, about 20 minutes on 12 cores):

    python3 embed_png.py 480 hill          # SCATTERSTEG=path/to/binary
    python3 score.py spam hill && python3 score.py srm hill
    BPP=1.0 python3 embed_png.py 480 hill  # and ss, with a uniform-cost binary
    python3 controls.py

### Content-adaptive JPEG costs (UERD)

JPEG embedding now uses UERD costs instead of the quantization step alone
(`jpeg_io.c`, `collect_carriers`). Same 480 covers (quality 75, 4:2:0), same
DCTR-style detector and splits; `results-uerd-jpeg.txt` has the raw output.
The quantization-step column re-measured here matches the published one
above to within 0.010:

| payload (bits per non-zero AC) | quantization step | UERD, \|2\| at 1.5x | **UERD, \|2\| at 1.75x (current)** |
|---|---|---|---|
| 0.05 | 0.460 | 0.487 | **0.499** |
| 0.10 | 0.408 | 0.469 | **0.478** |
| 0.20 | 0.271 | 0.396 | **0.390** |
| 0.30 | 0.132 | 0.260 | **0.262** |

Embedding in every AC coefficient, zeros and ±1 included, as UED, UERD and
J-UNIWARD were published, replaced this rule and its 1.75x factor
(`results-allcoef.txt`, build `b702512` against `d2b7c04`; P_E ± sd over
splits):

| payload | UERD, \|value\| ≥ 2 | **UERD, every AC (current)** | J-UNIWARD, \|value\| ≥ 2 | J-UNIWARD, every AC |
|---|---|---|---|---|
| 0.05 | 0.485 ± 0.006 | **0.473** ± 0.011 | 0.496 ± 0.009 | 0.470 ± 0.007 |
| 0.10 | 0.464 ± 0.011 | **0.456** ± 0.006 | 0.468 ± 0.006 | 0.462 ± 0.013 |
| 0.20 | 0.397 ± 0.014 | **0.418** ± 0.009 | 0.382 ± 0.009 | 0.425 ± 0.008 |
| 0.30 | 0.261 ± 0.010 | **0.356** ± 0.013 | 0.232 ± 0.019 | 0.360 ± 0.011 |

A clear gain from 0.2 up; at 0.05 slightly worse, within one or two
standard deviations. Every histogram shift (`hist_jpg.py`) stays under 0.1
of the covers' spread, where the old rule moved the 2:3 ratio by up to 1.6
(UERD) and 3.2 (J-UNIWARD) at 0.3. And every cover holds 0.3.

0.3 is a control at a heavy payload: the median cover holds 0.47 bits per
non-zero AC coefficient (10th to 90th percentile 0.42 to 0.54), so 0.3 is
about 63% of capacity. (0.5 was tried first; only 45 of 480 covers could hold
it.) Two disjoint halves of the covers, one labelled stego, score 0.497 to
0.523: chance. The 2:3 ratio of |2| to |3| AC coefficients moves +0.3% at 0.05
and 0.1 (quantization step: +0.6 to +0.8%), -3.0% at 0.2 (-2.5%) and -14.3%
at 0.3 (-13.2%) with the first UERD version, which kept the old 1.5x for
|value| 2.

That factor was then re-tuned under UERD (`tune_two.py`,
`results-two-cost.txt`; builds of `0f214b0` with `JPEG_TWO_COST` set). DCTR
P_E / ratio shift in units of the covers' spread (1.93, sd 0.13):

| factor | 0.05 | 0.10 | 0.20 | 0.30 |
|---|---|---|---|---|
| 1.0 | | 0.463 / 0.51 | 0.375 / 1.65 | |
| 1.25 | | 0.478 / 0.12 | 0.395 / 0.87 | |
| 1.5 | 0.489 / 0.06 | 0.464 / 0.04 | 0.400 / 0.43 | 0.263 / 2.01 |
| **1.75** | **0.499 / 0.11** | **0.478 / 0.13** | **0.390 / 0.17** | **0.262 / 1.59** |
| 2.0 | 0.488 / 0.13 | 0.465 / 0.22 | 0.412 / 0.04 | 0.274 / 1.28 |
| 3.0 | | 0.467 / 0.41 | 0.399 / 0.59 | |

DCTR doesn't separate the factors (differences within its noise, sd about
0.01); the ratio does. Over the recommended 0.05 to 0.2, 1.75 keeps the
worst-case shift smallest (0.17 of the covers' spread), so it is the
default. 2.0 is better only at 0.3, near capacity.

    python3 embed_jpg.py 480 uerd          # SCATTERSTEG=path/to/binary
    BPNZ=0.3 python3 embed_jpg.py 480 uerd
    python3 score_jpg.py uerd && python3 controls_jpg.py
    python3 tune_two.py two1.5 two1.75 two2.0  # stego/two<f>_jpg_<bp>, one build per factor

`srm.py` is not the published SRM: the construction is the same, but the
kernels and quantization steps were chosen here, and it has roughly a fifth of
the published feature count. The published model and deep networks would score
lower again.

### Distortion models: WOW, S-UNIWARD, J-UNIWARD

Three more cost functions from the literature, in `distortion.c` and
`rust/src/distortion.rs`: WOW (Holub and Fridrich, 2012) and S-UNIWARD (Holub,
Fridrich and Denemark, 2014) for PNG, J-UNIWARD (same paper) for JPEG. They
are build choices for measuring, not options: `make PNG_COSTS=wow|suniward
JPEG_COSTS=juniward` (cargo: `SCATTERSTEG_PNG_COSTS`, `SCATTERSTEG_JPEG_COSTS`).
The default stays HILL and UERD, and any build reads what any other wrote.

**Checked against the authors' code.** The Binghamton reference
implementations (WOW v1.0, S-UNIWARD v1.0, J-UNIWARD v1.1; their C++ cost
code, run on the same planes) on six benchmark photographs, crops of 37×53 and
16×24, noise and a flat image: J-UNIWARD agrees to 1.2e-7 relative (double
precision, as the reference), S-UNIWARD to 2.3e-5 and WOW to 5.3e-4. Those two
references compute in single precision, and WOW divides by its filter
outputs, which near 0 makes it sensitive to rounding. C and Rust give
bit-identical costs on real PNGs and JPEGs for all five models.

**Where ScatterSteg differs from the references**, which embed grayscale
images with a ternary (±1) coder and simulate it at the payload's entropy:

- Each colour channel (PNG) or JPEG component is costed on its own; the
  references cost one gray plane (J-UNIWARD: luminance only). Chroma is costed
  on its own plane, at its own resolution and with its own table.
- J-UNIWARD works from the decompressed plane as ScatterSteg computes it from
  the coefficients (float inverse DCT, rounded and clamped), which can differ
  by 1 from libjpeg's integer decoder at a pixel; nothing is decoded or
  re-encoded beyond what the loader already does.
- Planes smaller than the 16-tap filters are mirrored repeatedly; the
  references don't handle them.
- The coder is ScatterSteg's binary STC with ±1 changes, and JPEG carriers
  are the AC coefficients with |value| ≥ 2, as for UERD. J-UNIWARD's costs
  are its own: no extra factor for |value| 2 (UERD's 1.75).
- J-UNIWARD builds refuse a JPEG component over 2²⁶ pixels (its planes take
  about 28 bytes per pixel), with the loader's generic error, and compute
  the costs on every load, extract and `info` included.

Cost of computing the costs alone (C, one core): a 512×512 image takes 0.04 s
with HILL, 0.10 s with WOW or S-UNIWARD; 4000×3000 RGB 1.3 s (HILL, 266 MiB
peak) against 4.2–4.3 s (314 MiB). JPEG: UERD 0.08 s and 47 MiB at 12
megapixels, J-UNIWARD 2.0 s and 411 MiB. Every
embed also runs Argon2id at 256 MiB.

**Results.** Same 480 covers (fetched 2026-10-23), payloads, detectors and
splits as above; builds of `d2b7c04`; `results-distortion-models.txt` has the
raw output, `score_models.py` and `distortion_stats.py` compute it. HILL and
UERD were re-measured alongside, as the baseline. P_E, ROC-AUC, and the
detection rate at 5% false positives (P_D; lower rates aren't measurable with
240 test covers), mean of 5 splits, standard deviation about 0.01 for P_E and
AUC and 0.01–0.02 for P_D (0.04 at JPEG 0.3):

| PNG, SRM-style | HILL | WOW | S-UNIWARD |
|---|---|---|---|
| 0.05 bpp: P_E / AUC / P_D | 0.444 / 0.582 / 0.083 | 0.451 / 0.577 / 0.089 | 0.448 / 0.577 / 0.084 |
| 0.1 | 0.415 / 0.631 / 0.144 | 0.419 / 0.627 / 0.133 | 0.416 / 0.629 / 0.135 |
| 0.2 | 0.388 / 0.683 / 0.201 | 0.388 / 0.675 / 0.201 | 0.383 / 0.684 / 0.212 |
| 0.4 | 0.357 / 0.735 / 0.283 | 0.359 / 0.731 / 0.280 | 0.351 / 0.744 / 0.297 |

| JPEG, DCTR-style | UERD | J-UNIWARD |
|---|---|---|
| 0.05 bits per non-zero AC | 0.485 / 0.515 / 0.052 | 0.496 / 0.513 / 0.057 |
| 0.1 | 0.464 / 0.551 / 0.087 | 0.468 / 0.547 / 0.081 |
| 0.2 | 0.397 / 0.645 / 0.174 | **0.382 / 0.677 / 0.189** |
| 0.3 (control, 476 covers) | 0.261 / 0.816 / 0.391 | **0.232 / 0.849 / 0.464** |

The HILL and UERD rows match the published ones above (measured on a later
fetch of the covers) to within 0.002 and 0.014, so the harness is unchanged. For PNG, no model separates from the
others: every difference is within about one standard deviation, at every
payload. S-UNIWARD makes 5–11% fewer changes than HILL (2,244 against 2,369
per image at 0.05, 22,745 against 25,647 at 0.4; WOW up to 3% more), without that
showing in detection. For JPEG the two are level at the recommended 0.05–0.1,
and J-UNIWARD is easier to detect at 0.2 and 0.3 (AUC +0.03, outside the
noise). A likely cause, not yet tested: 13–25% of J-UNIWARD's changes hit a
coefficient of |value| 2, which can only become 3, against 3–19% for UERD
with its 1.75 factor; that shifts the 2:3 ratio JPEG detectors watch.

So the defaults stay. These detectors are not the published SRM, GFR or deep
networks, and one cover source is not many: what this supports is that, in
ScatterSteg's binary coder and carrier set, none of the three improves on
HILL or UERD against these detectors.

    make PNG_COSTS=wow JPEG_COSTS=juniward   # one binary per model, from one commit
    SCATTERSTEG=... python3 embed_png.py 480 wow
    SCATTERSTEG=... python3 embed_jpg.py 480 juniward   # and BPNZ=0.3
    python3 score_models.py png hill wow suniward
    python3 score_models.py jpg uerd juniward
    python3 distortion_stats.py

### Second cover set: BOSSbase

1000 grayscale 512×512 images drawn at random from BOSSbase 1.01
(`fetch_boss.py`; `embed_boss.py`, `results-srm-bossbase.txt`, and with HILL
`results-srm-bossbase-hill.txt`). Same detector.
steghide is absent: it has no grayscale PNG or PGM support, and its 8-bit BMP
mode embeds differently. One sample per pixel, so a payload of 0.05 bits per
pixel is three times heavier per sample than in the colour tables above.

| Payload (bits per pixel) | LSB matching | ScatterSteg, uniform costs | **ScatterSteg, HILL** |
|---|---|---|---|
| 0.05 | 0.18 | 0.31 | **0.46** |
| 0.10 | 0.13 | 0.22 | **0.43** |
| 0.20 | 0.08 | 0.15 | **0.35** |
| 0.40 | 0.04 | 0.08 | **0.22** |

The ranking and the trend match the Wikimedia result, with a larger training
set (500 pairs) and a different source. With HILL, ScatterSteg is caught 54%
of the time at 0.05 and 78% at 0.4 (uniform costs: 69% and 92%; LSB matching
82% and 96%). Re-measured on 2026-10-26 on the same 1000 images, from builds of
`ca1a139` (uniform) and `83603fa` (HILL): uniform gives 0.313, 0.222, 0.152
and 0.078 against the published 0.315, 0.225, 0.149 and 0.079, and LSB
matching is unchanged, so the harness is the same.

## Deep-learning detector (SRNet)

SRNet (Boroumand, Chen and Fridrich, 2019), the reference deep network for
steganalysis, reimplemented in PyTorch (`dl/`; raw output in
`results-srnet.txt`). BOSSbase 1.01's 10,000 images, resized to 256×256 as in
the paper, grayscale, as PNG and as JPEG at quality 75 (`dl/prepare.py`);
7,000 cover/stego pairs to train, 1,000 to validate, 2,000 to test, the test
images touched once at the end. Trained from scratch for 40 epochs, with
batches of pairs of the same image, flipped and rotated alike. Builds of
`cd98771`. P_E as above, with its standard error over the test pairs:

| Set | Payload | P_E | AUC | Caught at 5% false alarms |
|---|---|---|---|---|
| ScatterSteg PNG, HILL | 0.4 bits per pixel | **0.129** ± 0.008 | 0.954 | 76% |
| ScatterSteg JPEG, UERD | 0.2 bits per non-zero AC | **0.073** ± 0.006 | 0.981 | 89% |
| ScatterSteg PNG, HILL | 0.2 bits per pixel | **0.256** ± 0.010 | 0.842 | 42% |
| ScatterSteg JPEG, UERD, every AC coefficient | 0.2 bits per non-zero AC | **0.077** ± 0.006 | 0.979 | 89% |

The last two rows were trained for 15 epochs, starting from the detector of
the row above them (`hill_0.4` and the first JPEG row), with build `b702512`
for the last. A head start favours the detector, so they are if anything
pessimistic for the user.

This is far stronger than the rich models. On BOSSbase (512×512 there, so
not the same images) the SRM-style detector's P_E for HILL at 0.4 was 0.22;
SRNet's is 0.13, catching 87% of PNGs. JPEG, which DCTR barely separated at
0.2 (P_E 0.39 on Wikimedia), is caught 93% of the time. The first JPEG row
leaves out 45 of its 2,000 test images, and 171 training images, whose
cover couldn't hold the message: that version only embedded in coefficients
of magnitude 2 or more, which in a small, smooth JPEG may not be enough.

Embedding in every AC coefficient (the current rule) fits all of them. On
the same 1,955 test images its P_E is 0.078 against 0.073, a difference
within one standard error (0.004 by bootstrap): SRNet sees none. But the 45
smooth images it now fits are caught almost every time (P_E 0.022 on those
alone), so a message there isn't hidden at all.

So against a strong, well-trained detector, payloads of 0.2 to 0.4 are not
hidden. The lighter payloads (0.05 to 0.2), S-UNIWARD and J-UNIWARD are
still being trained; their rows go here. This setting favours the warden:
one cover source for training and test, the payload known, and small
images, where a given rate is easier to detect.

    python3 dl/prepare.py BOSSbase_1.01.zip DIR
    SCATTERSTEG=... python3 dl/embed.py DIR png hill 0.4    # and jpg uerd 0.2
    python3 dl/train.py DIR png hill_0.4 DIR/runs/hill_0.4 --epochs 40
    python3 dl/summarize.py DIR

## Classic detectors

Measured on the 480 benchmark photographs (512×512 RGB; `classic.py` and `hcf.py`; raw output in `results-classic.txt`) at 0.05 to 0.4 bits per pixel, against the classic detectors for LSB steganography, with builds of `ca1a139` (uniform costs) and `83603fa` (HILL, current). The baselines write the message bits directly: LSB replacement from the first pixel on (sequential) or at scattered positions, and LSB matching at scattered positions.

| Detector | LSB replacement | LSB matching | ScatterSteg, uniform costs | **ScatterSteg, HILL** |
|---|---|---|---|---|
| Changes per image (0.05 / 0.4 bits per pixel) | 6,550 / 52,400 | 6,550 / 52,400 | 1,850 / 18,200 | **2,370 / 25,600** |
| Chi-square attack, p over the first 2% of samples (cover 0.09) | 0.60–0.96 sequential, 0.10–0.12 scattered | 0.10–0.11 | 0.09 | **0.09–0.10** |
| Sample pair analysis, shift from the cover | +0.008 to +0.064, tracking the payload | 0.000 | −0.001 to −0.019 (3 cover-to-stego sd at 0.4) | **−0.0002 to −0.0012** |
| Ker's adjacency HCF-COM shift (cover 107.6, sd 10.6) | −0.45 to −1.51 | −0.56 to −4.54 | −0.15 to −1.14 | **−0.01 to −0.14** |

Chi-square only catches sequential embedding, and none of the scattered methods trigger it. Sample pair analysis did see uniform costs, in the opposite direction from LSB replacement; HILL's shift is 7 to 16 times smaller. For JPEG, the 2:3 ratio of coefficients of magnitude 2 and 3 (cover 1.93, sd 0.13 across covers) moves +0.7%, +0.9% and −1.1% with UERD at 0.05, 0.1 and 0.2 bits per non-zero AC coefficient (`tune_two.py`). An earlier version of this table, measured on two photographs, is in the git history.

`classic.py` implements chi-square and sample pair analysis and was calibrated on the LSB baselines first; `hcf.py` scores adjacency HCF-COM.

## Method

1. `fetch_images.py`: 480 photos from Wikimedia Commons, resized and cropped to
   512×512 (kept locally, not redistributed).
2. `embed_all.py`: the same random message sizes embedded by ScatterSteg and by
   steghide 0.5.1 (built by `build_steghide.sh`). steghide has no PNG support, so
   it embeds in a BMP of the same pixels. `baselines.py` adds plain LSB
   replacement and LSB matching.
3. `detect.py`: features, then an RBF SVM trained on half the cover/stego pairs
   and tested on the rest. A cover and its stego always land in the same half.

`results-raw.txt` has the output of the run above.

Reproduce:

    python3 fetch_images.py 480 && python3 embed_all.py 480 && python3 baselines.py
    gcc -O2 dumpcoef.c -o dumpcoef -ljpeg
    python3 detect.py 480          # needs numpy, scipy, scikit-learn, pillow

## Limitations

- **The rich models are not the state of the art; SRNet is closer.** The
  SRM-style detector is stronger than SPAM and showed the SPAM numbers were
  optimistic, and SRNet showed the rich-model numbers were too. Read the
  rich-model tables as rankings, and the SRNet section for how a capable
  warden would do. JPEG was tested with the compact feature set, a DCTR-style
  one (reimplemented here) and SRNet.
- **Two cover sources.** Downsampled Wikimedia JPEGs, and BOSSbase (grayscale,
  one camera pipeline). Neither is a collection of what real users would use;
  cover noise matters a great deal to detectability.
- **Small training set.** 238 pairs per split. Larger sets make detectors
  stronger.
- **The detector knows the payload size.** It is trained and tested at a single
  payload, which favours the attacker. A real one would not.
- **Gray detectors on colour images.** SPAM is computed per channel and
  averaged. A detector that models the colour channels jointly could do better.
- **Not every "RGB" cover is RGB.** `embed_all.py` makes PNG covers with
  ImageMagick, which writes a photograph that has only gray pixels as a
  grayscale PNG: 4 of the 480 fetched on 2026-10-25 were. They are scored
  with the rest, so at a given bits per pixel their payload is three times
  heavier per sample; at 1.0 bits per pixel they can't hold the message and
  `controls.py` leaves them out (476 covers).
- The JPEG test uses one quality factor and no recompression.
- Fuzzy claims such as "undetectable" are not supported by this. What it
  supports is a relative statement: against these detectors, ScatterSteg is
  harder to detect than steghide and naive LSB embedding at the same payload.
