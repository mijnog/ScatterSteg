"""The classic LSB detectors from the README's first table, on the benchmark
covers: the chi-square attack (Westfeld and Pfitzmann, 2000) and sample pair
analysis (Dumitrescu, Wu and Wang, 2003), per RGB channel, averaged.

Chi-square: how well the histogram's pairs of values (2i, 2i+1) are evened
out, as LSB replacement does; the p-value goes towards 1 when they are. As in
the original attack it is taken over the start of the image (the first 2% of
samples in raster order), where sequential embedding begins, and over the
whole image.
SPA: an estimate of the fraction of samples LSB replacement flipped (at b
bits per pixel over 3 channels, about b / 6).

Usage: classic.py [--make-sequential] TOOL... (stego/TOOL_png_<bpp>/), plus
the covers. --make-sequential first writes stego/lsbs_png_<bpp>: LSB
replacement of the first b x 512 x 512 samples, the case chi-square targets."""
import glob, os, sys, zlib, numpy as np
from concurrent.futures import ProcessPoolExecutor
from PIL import Image
from scipy.stats import chi2

def chi_square_p(x):
    h = np.bincount(x.ravel(), minlength=256).astype(float)
    even, odd = h[0::2], h[1::2]
    e = (even + odd) / 2
    keep = e > 4
    stat = ((even[keep] - e[keep]) ** 2 / e[keep]).sum()
    return 1 - chi2.cdf(stat, keep.sum() - 1)

def spa(x):
    x = x.astype(np.int64)
    u = np.concatenate([x[:, :-1].ravel(), x[:-1, :].ravel()])   # horizontal and vertical pairs
    v = np.concatenate([x[:, 1:].ravel(), x[1:, :].ravel()])
    even = v % 2 == 0
    X = ((even & (u < v)) | (~even & (u > v))).sum()
    Y = ((even & (u > v)) | (~even & (u < v))).sum()
    K = (u // 2 == v // 2).sum()
    P = len(u)
    a, b, c = 2 * K, 2 * (2 * X - P), Y - X
    if a == 0: return float("nan")
    d = b * b - 4 * a * c
    if d < 0: return float("nan")
    return min((-b + np.sqrt(d)) / (2 * a), (-b - np.sqrt(d)) / (2 * a))

def stats(path):
    a = np.asarray(Image.open(path).convert("RGB"))
    start = a.reshape(-1)[: a.size // 50]
    return (chi_square_p(start),
            np.mean([chi_square_p(a[:, :, c]) for c in range(3)]),
            np.mean([spa(a[:, :, c]) for c in range(3)]))

def make_sequential(base):
    a = np.asarray(Image.open(f"cover/{base}.png").convert("RGB")).copy().reshape(-1)
    rng = np.random.default_rng(zlib.crc32(base.encode()))
    for bpp in (0.05, 0.1, 0.2, 0.4):
        n = int(bpp * 512 * 512)
        r = a.copy(); r[:n] = (r[:n] & 0xFE) | rng.integers(0, 2, n).astype(np.uint8)
        os.makedirs(f"stego/lsbs_png_{bpp}", exist_ok=True)
        Image.fromarray(r.reshape(512, 512, 3)).save(f"stego/lsbs_png_{bpp}/{base}.png")

def main():
    bases = sorted(os.path.basename(p)[:-4] for p in glob.glob("cover/*.png"))
    tools = [t for t in sys.argv[1:] if not t.startswith("--")]
    with ProcessPoolExecutor(10) as ex:
        if "--make-sequential" in sys.argv: list(ex.map(make_sequential, bases))
        c = np.array(list(ex.map(stats, [f"cover/{b}.png" for b in bases])))
        print(f"cover                chi-square p start {c[:, 0].mean():.3f} whole {c[:, 1].mean():.3f}  SPA {np.nanmean(c[:, 2]):+.4f}", flush=True)
        for tool in tools:
            for bpp in ("0.05", "0.1", "0.2", "0.4"):
                paths = [f"stego/{tool}_png_{bpp}/{b}.png" for b in bases]
                keep = [i for i, p in enumerate(paths) if os.path.exists(p)]
                s = np.array(list(ex.map(stats, [paths[i] for i in keep])))
                d = s[:, 2] - c[keep, 2]
                print(f"{tool:14} {bpp:<5} chi-square p start {s[:, 0].mean():.3f} whole {s[:, 1].mean():.3f}  "
                      f"SPA minus cover {np.nanmean(d):+.4f} (sd {np.nanstd(d):.4f}; LSB replacement: {float(bpp) / 6:.4f}) n={len(keep)}", flush=True)

if __name__ == "__main__":
    main()
