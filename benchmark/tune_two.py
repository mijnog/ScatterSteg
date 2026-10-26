"""DCTR P_E and 2:3 ratio shift for each |value|-2 factor build."""
import glob, os, sys, numpy as np
from concurrent.futures import ProcessPoolExecutor
import detect_dctr as DD, srm, controls_jpg as C

def main():
    covers = sorted(glob.glob("cover/*.jpg")); bases = [os.path.basename(c)[:-4] for c in covers]
    Xc = DD.cached("cover", covers)
    with ProcessPoolExecutor(10) as ex:
        cr = np.array(list(ex.map(C.ratio, covers)))
        for tool in sys.argv[1:]:
            for bp in ("0.05", "0.1", "0.2", "0.3"):
                paths = [f"stego/{tool}_jpg_{bp}/{b}.jpg" for b in bases]
                keep = [i for i, x in enumerate(paths) if os.path.exists(x)]
                Xs = DD.cached(f"{tool}_{bp}_{len(keep)}", [paths[i] for i in keep])
                e = [srm.ensemble_pe(Xc[keep], Xs, s) for s in range(5)]
                sr = np.array(list(ex.map(C.ratio, [paths[i] for i in keep])))
                d = sr / cr[keep] - 1
                print(f"{tool:9} {bp:<4} P_E={np.mean(e):.3f} sd={np.std(e):.3f}  2:3 shift {100*d.mean():+.2f}% ({abs(d.mean())*cr.mean()/cr.std():.2f} cover sds) n={len(keep)}", flush=True)

if __name__ == "__main__":
    main()
