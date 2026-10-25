"""Checks that the detectors still discriminate where HILL scores near 0.5.
Null: two disjoint halves of the covers, one labelled "stego" (no image in
both classes), scored by the SPAM SVM: should be ~0.5. Then uniform and
HILL at a heavy payload (stego/ss_png_1.0 and stego/hill_png_1.0, made with
BPP=1.0 embed_png.py, on the covers that hold it), by both detectors: a
detector that still can't see either there is saturated, not beaten."""
import glob, os, numpy as np
import detect as D, detect_srm as DS, srm
def main():
    bases = sorted(os.path.basename(p)[:-4] for p in glob.glob("cover/*.png")); N = len(bases)
    cov = D.cached(f"spam_cover_{N}", [f"cover/{b}.png" for b in bases], D.spam)
    for seed in (1, 2, 3):
        p = np.random.default_rng(seed).permutation(N); h = N // 2
        e = [D.pe(cov[p[:h]], cov[p[h:2 * h]], s)[0] for s in range(5)]
        print(f"spam null (cover halves, shuffle {seed})  P_E={np.mean(e):.3f} sd={np.std(e):.3f}", flush=True)
    keep = [i for i, b in enumerate(bases) if all(os.path.exists(f"stego/{t}_png_1.0/{b}.png") for t in ("ss", "hill"))]
    scov = D.cached(f"srm_cover_{N}", [f"cover/{b}.png" for b in bases], DS.feat)
    for tool in ("ss", "hill"):
        paths = [f"stego/{tool}_png_1.0/{bases[i]}.png" for i in keep]
        e = [D.pe(cov[keep], D.cached(f"spam_{tool}_1.0_{len(keep)}", paths, D.spam), s)[0] for s in range(5)]
        print(f"spam {tool:5} 1.0  P_E={np.mean(e):.3f} sd={np.std(e):.3f}  (n={len(keep)})", flush=True)
        e = [srm.ensemble_pe(scov[keep], D.cached(f"srm_{tool}_1.0_{len(keep)}", paths, DS.feat), s) for s in range(5)]
        print(f"srm  {tool:5} 1.0  P_E={np.mean(e):.3f} sd={np.std(e):.3f}  (n={len(keep)})", flush=True)
if __name__ == "__main__": main()
