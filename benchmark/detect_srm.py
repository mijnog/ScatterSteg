"""Rich-model (SRM-style) detection error with an FLD ensemble.
usage: detect_srm.py NAME COVERDIR COVEREXT TOOL:STEGODIRPATTERN:EXT ... (see main)"""
import glob, os, sys, numpy as np
from concurrent.futures import ProcessPoolExecutor
import multiprocessing as mp
from PIL import Image
import srm

def feat(path):
    return srm.srm(np.asarray(Image.open(path).convert("RGB" if path.endswith(("png","bmp")) and Image.open(path).mode in ("RGB","RGBA") else "L"))).astype(np.float32)

def cached(tag, paths):
    f = f"srm_{tag}.npy"
    if os.path.exists(f):
        a = np.load(f)
        if len(a) == len(paths): return a
    with ProcessPoolExecutor(10, mp_context=mp.get_context("spawn")) as ex:
        a = np.array(list(ex.map(feat, paths, chunksize=4)))
    np.save(f, a); return a

if __name__ == "__main__":
    name, coverdir, cext = sys.argv[1:4]
    specs = [s.split(":") for s in sys.argv[4:]]       # label:stegodir_with_{p}:ext
    payloads = ["0.05", "0.1", "0.2", "0.4"]
    covers = sorted(glob.glob(f"{coverdir}/*.{cext}"))
    bases = [os.path.basename(c).rsplit(".", 1)[0] for c in covers]
    Xc = cached(f"{name}_cover", covers)
    print(name, len(covers), "covers", Xc.shape, flush=True)
    for label, pat, ext in specs:
        for p in payloads:
            paths = [f"{pat.format(p=p)}/{b}.{ext}" for b in bases]
            ok = [os.path.exists(x) for x in paths]
            if not all(ok):
                print(label, p, "missing", ok.count(False), flush=True)
                keep = [i for i, o in enumerate(ok) if o]
            else: keep = list(range(len(paths)))
            Xs = cached(f"{name}_{label}_{p}_{len(keep)}", [paths[i] for i in keep])
            errs = [srm.ensemble_pe(Xc[keep], Xs, s) for s in range(5)]
            print(f"RESULT {name} {label} payload={p} PE={np.mean(errs):.3f} sd={np.std(errs):.3f} n={len(keep)}", flush=True)
