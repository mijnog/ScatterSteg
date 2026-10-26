"""Controls for the JPEG comparison. Null: two disjoint halves of the JPEG
covers, one labelled stego, by the DCTR-style detector (~0.5). Heavy
payload: stego/{ss,uerd}_jpg_0.3 (BPNZ=0.3 embed_jpg.py). And the 2:3
ratio of carrier counts (|v| = 2 over |v| = 3, AC), cover against stego,
which JPEG steganalysis watches."""
import glob, os, numpy as np
import detect, detect_dctr as DD, srm

def ratio(path):
    n2 = n3 = 0
    for c in detect.read_coefs(path):
        ac = c.copy(); ac[:, :, 0, 0] = 0; a = np.abs(ac)
        n2 += int((a == 2).sum()); n3 += int((a == 3).sum())
    return n2 / max(n3, 1)

def main():
    covers = sorted(glob.glob("cover/*.jpg")); bases = [os.path.basename(c)[:-4] for c in covers]; N = len(bases)
    Xc = DD.cached("cover", covers)
    for seed in (1, 2, 3):
        p = np.random.default_rng(seed).permutation(N); h = N // 2
        e = [srm.ensemble_pe(Xc[p[:h]], Xc[p[h:2 * h]], s) for s in range(5)]
        print(f"dctr null (cover halves, shuffle {seed})  P_E={np.mean(e):.3f} sd={np.std(e):.3f}", flush=True)
    for tool in ("ss", "uerd"):
        paths = [f"stego/{tool}_jpg_0.3/{b}.jpg" for b in bases]
        keep = [i for i, x in enumerate(paths) if os.path.exists(x)]
        Xs = DD.cached(f"{tool}_0.3_{len(keep)}", [paths[i] for i in keep])
        e = [srm.ensemble_pe(Xc[keep], Xs, s) for s in range(5)]
        print(f"dctr {tool:5} 0.3  P_E={np.mean(e):.3f} sd={np.std(e):.3f} n={len(keep)}", flush=True)
    sample = bases[:120]
    rc = np.array([ratio(f"cover/{b}.jpg") for b in sample])
    print(f"2:3 ratio cover {rc.mean():.4f}", flush=True)
    for tool in ("ss", "uerd"):
        for bp in ("0.05", "0.1", "0.2", "0.3"):
            rs = np.array([ratio(f"stego/{tool}_jpg_{bp}/{b}.jpg") for b in sample])
            print(f"2:3 ratio {tool:5} {bp:<5} {rs.mean():.4f} ({100 * (rs.mean() / rc.mean() - 1):+.2f}%)", flush=True)

if __name__ == "__main__":
    main()
