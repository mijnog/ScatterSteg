"""DCTR-style detection error on JPEG covers, ScatterSteg and steghide."""
import glob, os, sys, numpy as np
from concurrent.futures import ProcessPoolExecutor
import multiprocessing as mp
import dctr, srm

def cached(tag, paths):
    f = f"dctr_{tag}.npy"
    if os.path.exists(f):
        a = np.load(f)
        if len(a) == len(paths): return a
    with ProcessPoolExecutor(10, mp_context=mp.get_context("spawn")) as ex:
        a = np.array(list(ex.map(dctr.dctr, paths, chunksize=4)))
    np.save(f, a); return a

if __name__ == "__main__":
    covers = sorted(glob.glob("cover/*.jpg")); bases = [os.path.basename(c)[:-4] for c in covers]
    Xc = cached("cover", covers); print(len(covers), Xc.shape, flush=True)
    for label in ("ss", "sh"):
        for p in ("0.05", "0.1", "0.2"):
            paths = [f"stego/{label}_jpg_{p}/{b}.jpg" for b in bases]
            keep = [i for i, x in enumerate(paths) if os.path.exists(x)]
            Xs = cached(f"{label}_{p}_{len(keep)}", [paths[i] for i in keep])
            errs = [srm.ensemble_pe(Xc[keep], Xs, s) for s in range(5)]
            print(f"RESULT jpeg {label} payload={p} PE={np.mean(errs):.3f} sd={np.std(errs):.3f} n={len(keep)}", flush=True)
