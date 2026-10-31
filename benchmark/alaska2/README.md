# Off-the-shelf detectors: Aletheia's ALASKA2 models

The scripts behind [Off-the-shelf detectors](../README.md#off-the-shelf-detectors-aletheia-alaska2): ScatterSteg's JPEGs, the published UERD and J-UNIWARD (conseal's simulators) and steghide, scored by Aletheia's pretrained EfficientNet-B0 detectors without any training. Run everything from one working directory; the covers go in `cover/` there.

Needs: Pillow (covers); `benchmark/dumpcoef` built (`gcc -O2 dumpcoef.c -o dumpcoef -ljpeg` there) and numpy (embedding); a clone of [Aletheia](https://github.com/daniellerch/aletheia) with its `aletheia-models` and TensorFlow (scoring; tested at Aletheia `1baf974`); conseal and jpeglib (reference simulators); scikit-learn (analysis).

    B=path/to/scattersteg/benchmark; mkdir -p scores
    python3 $B/fetch_images.py 480   # the raw downloads, in raw/ (needs ImageMagick)
    python3 $B/alaska2/prepare_covers.py raw   # cover/: 512x512, Pillow, quality 75
    DUMPCOEF=$B/dumpcoef python3 $B/alaska2/embed_set.py path/to/scattersteg uerd_0.05 0.05
    python3 $B/alaska2/embed_tiny.py path/to/scattersteg tiny_1byte   # a 1-byte message: the rewrite and the length alone
    python3 $B/alaska2/sim_reference.py uerd ref_uerd_0.05 0.05   # and juniward
    for s in cover uerd_0.05; do
      ls $s/*.jpg | sed 's|^.*/||' > scores/$s.files
      for m in juniw jmipod; do
        ALETHEIA=path/to/aletheia python3 $B/alaska2/score_aletheia.py $m scores/$s-$m.npy $(sed "s|^|$s/|" scores/$s.files)
      done
    done
    python3 $B/alaska2/analyse.py uerd_0.05 ref_uerd_0.05

`analyse.py` pairs each stego set with the covers by file name and prints P_E (at the best threshold over the same images, so chance reads about 0.47 with 480 pairs), ROC-AUC and the detection rate at 5% false alarms, for each detector scored.

`embed_set.py` takes a payload in bits per non-zero AC coefficient, counted over all components; `sim_reference.py` puts the same number of bits into luminance only, as ScatterSteg's changes are almost all there. The J-UNIWARD build of ScatterSteg is `make JPEG_COSTS=juniward`.
