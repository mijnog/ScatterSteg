# Detectability benchmark

How easily can a steganalysis classifier tell a ScatterSteg image from its
cover, compared with steghide and with naive LSB embedding? This is a first,
modest measurement. Read the limitations before quoting a number.

## Result

Detection error **P_E** (0.5 = the detector cannot do better than guessing;
lower = easier to detect). 476 covers, 5 random 50/50 splits, standard error
about ±0.02. Payload is message bits per pixel (PNG/BMP) or per non-zero AC
coefficient (JPEG).

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
naive LSB matching. At low payloads (0.05 to 0.1) it is close to undetectable by
these detectors. At 0.4 bits per pixel a PNG is detected about 80% of the time.

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

- **The detectors are modest.** SPAM (2010) and a compact JPEG co-occurrence
  feature set are not the state of the art. Rich-model (SRM), GFR and deep
  (SRNet) detectors, trained on far more images, detect everything here more
  easily. The ranking probably holds; the absolute numbers will be worse.
- **One cover source.** Downsampled Wikimedia JPEGs, not raw camera images
  like BOSSbase. Cover noise matters a great deal to detectability.
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
