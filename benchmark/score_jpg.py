"""DCTR-style P_E for JPEG stego dirs against their covers.
Usage: score_jpg.py TOOL... (stego/TOOL_jpg_<bp>/)"""
import glob, os, sys, time, numpy as np
import detect_dctr as DD, srm

def main():
    covers = sorted(glob.glob("cover/*.jpg")); bases = [os.path.basename(c)[:-4] for c in covers]
    t = time.time(); Xc = DD.cached("cover", covers); print(f"cover features {time.time() - t:.0f}s", flush=True)
    for tool in sys.argv[1:]:
        for bp in ("0.05", "0.1", "0.2"):
            paths = [f"stego/{tool}_jpg_{bp}/{b}.jpg" for b in bases]
            keep = [i for i, x in enumerate(paths) if os.path.exists(x)]
            if not keep: continue
            t = time.time(); Xs = DD.cached(f"{tool}_{bp}_{len(keep)}", [paths[i] for i in keep])
            e = [srm.ensemble_pe(Xc[keep], Xs, s) for s in range(5)]
            print(f"dctr {tool:6} {bp:<5} P_E={np.mean(e):.3f} sd={np.std(e):.3f} n={len(keep)} ({time.time() - t:.0f}s)", flush=True)

if __name__ == "__main__":
    main()
