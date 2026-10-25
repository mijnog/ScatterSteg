# Detectability benchmark

How easily can a steganalysis classifier tell a ScatterSteg image from its
cover, compared with steghide and with naive LSB embedding? This is a first,
modest measurement. Read the limitations before quoting a number.

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
BOSSbase and JPEG have not been re-run (JPEG costs are unchanged).

Reproduce (after `fetch_images.py 480`; needs numpy, scipy, scikit-learn,
pillow and ImageMagick, about 20 minutes on 12 cores):

    python3 embed_png.py 480 hill          # SCATTERSTEG=path/to/binary
    python3 score.py spam hill && python3 score.py srm hill
    BPP=1.0 python3 embed_png.py 480 hill  # and ss, with a uniform-cost binary
    python3 controls.py

`srm.py` is not the published SRM: the construction is the same, but the
kernels and quantization steps were chosen here, and it has roughly a fifth of
the published feature count. The published model and deep networks would score
lower again.

### Second cover set: BOSSbase

1000 grayscale 512×512 images drawn at random from BOSSbase 1.01
(`fetch_boss.py`; `embed_boss.py`, `results-srm-bossbase.txt`). Same detector.
steghide is absent: it has no grayscale PNG or PGM support, and its 8-bit BMP
mode embeds differently. One sample per pixel, so a payload of 0.05 bits per
pixel is three times heavier per sample than in the colour tables above.

| Payload (bits per pixel) | LSB matching | ScatterSteg |
|---|---|---|
| 0.05 | 0.18 | **0.32** |
| 0.10 | 0.13 | **0.23** |
| 0.20 | 0.08 | **0.15** |
| 0.40 | 0.04 | **0.08** |

The ranking and the trend match the Wikimedia result (ScatterSteg caught 68%
of the time at 0.05 and 92% at 0.4, LSB matching 82% and 96%), with a larger
training set (500 pairs) and a different source.

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

- **The detectors are not the state of the art.** The SRM-style detector above
  is stronger than SPAM and showed the SPAM numbers were optimistic. The
  published SRM, GFR and deep (SRNet) detectors, trained on far more images,
  would detect everything more easily still. The ranking has held so far; the
  absolute numbers will be worse. JPEG was tested with the compact feature set
  and a DCTR-style one (the latter reimplemented here).
- **Two cover sources.** Downsampled Wikimedia JPEGs, and BOSSbase (grayscale,
  one camera pipeline). Neither is a collection of what real users would use;
  cover noise matters a great deal to detectability.
- **Small training set.** 238 pairs per split. Larger sets make detectors
  stronger.
- **The detector knows the payload size.** It is trained and tested at a single
  payload, which favours the attacker. A real one would not.
- **Gray detectors on colour images.** SPAM is computed per channel and
  averaged. A detector that models the colour channels jointly could do better.
- The JPEG test uses one quality factor and no recompression.
- Fuzzy claims such as "undetectable" are not supported by this. What it
  supports is a relative statement: against these detectors, ScatterSteg is
  harder to detect than steghide and naive LSB embedding at the same payload.
