"""Makes the deep-learning benchmark's covers from BOSSbase 1.01: each
512x512 image resized to 256x256 (as in the SRNet paper), saved as PNG and
as a JPEG at quality 75, plus a fixed train/validation/test split.
Usage: prepare.py BOSSbase_1.01.zip OUTDIR"""
import io, os, sys, zipfile
import numpy as np
from PIL import Image
from concurrent.futures import ProcessPoolExecutor

ZIP, OUT = sys.argv[1], sys.argv[2]
SPLIT = (7000, 1000, 2000)  # train, validation, test


def one(a):
    name, data = a
    base = os.path.basename(name)[:-4]
    im = Image.open(io.BytesIO(data)).convert("L").resize((256, 256), Image.BICUBIC)
    im.save(f"{OUT}/png/{base}.png")
    im.save(f"{OUT}/jpg/{base}.jpg", quality=75, subsampling=0, optimize=False)
    return base


if __name__ == "__main__":
    for d in ("png", "jpg"): os.makedirs(f"{OUT}/{d}", exist_ok=True)
    z = zipfile.ZipFile(ZIP)
    names = sorted(n for n in z.namelist() if n.endswith(".pgm"))
    assert len(names) == 10000, len(names)
    with ProcessPoolExecutor(10) as ex:
        bases = list(ex.map(one, ((n, z.read(n)) for n in names), chunksize=50))
    perm = np.random.default_rng(0).permutation(len(bases))
    a, b, _ = SPLIT
    with open(f"{OUT}/split.txt", "w") as f:
        for i, k in enumerate(perm):
            f.write(f"{bases[k]} {'train' if i < a else 'val' if i < a + b else 'test'}\n")
    print(len(bases), "covers")
