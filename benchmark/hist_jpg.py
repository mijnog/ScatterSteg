"""Histogram shifts of the AC coefficients, which first-order JPEG detectors
watch: the 0:1, 1:2 and 2:3 ratios of |value| counts and the number of
non-zero ACs, each as the mean stego-to-cover change in sds of the covers'
spread. Usage: hist_jpg.py TOOL... (stego/TOOL_jpg_<bp>/), plus the covers."""
import glob, os, sys, numpy as np
from concurrent.futures import ProcessPoolExecutor
import detect

def counts(path):
    n = np.zeros(5)
    for c in detect.read_coefs(path):
        a = np.abs(c.astype(np.int64))
        a[:, :, 0, 0] = -1  # leave the DCs out
        n += [(a == v).sum() for v in range(4)] + [(a > 0).sum()]
    return n

def stats(n):
    return np.array([n[0] / n[1], n[1] / n[2], n[2] / n[3], n[4]])

def main():
    covers = sorted(glob.glob("cover/*.jpg")); bases = [os.path.basename(c)[:-4] for c in covers]
    with ProcessPoolExecutor(10) as ex:
        cs = np.array([stats(n) for n in ex.map(counts, covers)])
        print(f"{'':10} {'bp':<4} {'0:1':>7} {'1:2':>7} {'2:3':>7} {'nonzero':>8}  (cover sds)")
        for tool in sys.argv[1:]:
            for bp in ("0.05", "0.1", "0.2", "0.3"):
                paths = [f"stego/{tool}_jpg_{bp}/{b}.jpg" for b in bases]
                keep = [i for i, x in enumerate(paths) if os.path.exists(x)]
                if not keep: continue
                ss = np.array([stats(n) for n in ex.map(counts, [paths[i] for i in keep])])
                d = (ss / cs[keep] - 1).mean(0) * cs.mean(0) / cs.std(0)
                print(f"{tool:10} {bp:<4} " + " ".join(f"{x:+7.2f}" for x in d[:3]) + f" {d[3]:+8.2f}  n={len(keep)}", flush=True)

if __name__ == "__main__":
    main()
