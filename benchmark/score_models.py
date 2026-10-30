"""Distortion models compared: P_E, ROC-AUC and detection at a low false-
positive rate, with the same features, ensemble and splits as score.py
(SRM-style, PNG) and score_jpg.py (DCTR-style, JPEG).

Usage: score_models.py png|jpg TOOL...  (stego/TOOL_png_<bpp>/ or stego/TOOL_jpg_<bp>/)

The ensemble's score is its vote count (0-100 of 100 FLDs), so ROC-AUC and
the detection rate at 5% false positives come from that. 5% of the 240 test
covers is 12 images: lower rates aren't measurable with this many."""
import glob, os, sys, time, numpy as np
import srm

def ensemble_votes(Xc, Xs, seed, L=100, test_frac=0.5):
    """srm.ensemble_pe's classifier, returning the vote counts of the test
    covers and stegos rather than the error"""
    n, d = Xc.shape; rng = np.random.RandomState(seed); p = rng.permutation(n)
    k = int(n * (1 - test_frac)); tr, te = p[:k], p[k:]
    X0, X1 = Xc[tr], Xs[tr]
    mu = np.vstack([X0, X1]).mean(0); sd = np.vstack([X0, X1]).std(0) + 1e-12
    X0 = (X0 - mu) / sd; X1 = (X1 - mu) / sd
    Tc = (Xc[te] - mu) / sd; Ts = (Xs[te] - mu) / sd
    dsub = int(min(d, max(50, k // 2)))
    votes_c = np.zeros(len(te)); votes_s = np.zeros(len(te))
    for _ in range(L):
        S = rng.choice(d, dsub, replace=False)
        A0, A1 = X0[:, S], X1[:, S]
        m0, m1 = A0.mean(0), A1.mean(0)
        Sw = np.cov((A0 - m0).T) + np.cov((A1 - m1).T)
        Sw += 1e-3 * np.trace(Sw) / dsub * np.eye(dsub)
        w = np.linalg.solve(Sw, m1 - m0)
        p0, p1 = A0 @ w, A1 @ w
        cand = np.sort(np.r_[p0, p1]); mids = (cand[1:] + cand[:-1]) / 2
        err = [(np.mean(p0 > t) + np.mean(p1 <= t)) / 2 for t in mids[:: max(1, len(mids) // 400)]]
        t = mids[:: max(1, len(mids) // 400)][int(np.argmin(err))]
        votes_c += (Tc[:, S] @ w > t); votes_s += (Ts[:, S] @ w > t)
    return votes_c, votes_s, L

def metrics(vc, vs, L):
    pe = (np.mean(vc > L / 2) + np.mean(vs <= L / 2)) / 2
    # AUC with ties counted half (the votes are integers)
    auc = (np.mean(vs[:, None] > vc[None, :]) + 0.5 * np.mean(vs[:, None] == vc[None, :]))
    # Detection at <= 5% false positives: the lowest vote threshold that
    # flags at most 5% of covers
    pd = 0.0
    for t in range(L + 1):
        if np.mean(vc >= t) <= 0.05:
            pd = np.mean(vs >= t); break
    return pe, auc, pd

def main():
    kind, tools = sys.argv[1], sys.argv[2:]
    if kind == "png":
        import detect as D, detect_srm as DS
        bases = sorted(os.path.basename(p)[:-4] for p in glob.glob("cover/*.png"))
        N = len(bases)
        Xc = D.cached(f"srm_cover_{N}", [f"cover/{b}.png" for b in bases], DS.feat)
        loads = {}
        for tool in tools:
            for bp in (0.05, 0.1, 0.2, 0.4):
                d = f"stego/{tool}_png_{bp}"
                if os.path.isdir(d):
                    loads[(tool, bp)] = lambda d=d, tool=tool, bp=bp: (
                        np.arange(N), D.cached(f"srm_{tool}_{bp}_{N}", [f"{d}/{b}.png" for b in bases], DS.feat))
        name = "srm"
    else:
        import detect_dctr as DD
        covers = sorted(glob.glob("cover/*.jpg")); bases = [os.path.basename(c)[:-4] for c in covers]
        Xc = DD.cached("cover", covers)
        loads = {}
        for tool in tools:
            for bp in ("0.05", "0.1", "0.2", "0.3"):
                paths = [f"stego/{tool}_jpg_{bp}/{b}.jpg" for b in bases]
                keep = [i for i, x in enumerate(paths) if os.path.exists(x)]
                if keep:
                    loads[(tool, bp)] = lambda keep=keep, paths=paths, tool=tool, bp=bp: (
                        np.array(keep), DD.cached(f"{tool}_{bp}_{len(keep)}", [paths[i] for i in keep]))
        name = "dctr"
    for (tool, bp), load in loads.items():
        t = time.time()
        keep, Xs = load()
        rows = [metrics(*ensemble_votes(Xc[keep], Xs, s)) for s in range(5)]
        pe, auc, pd = (np.array(r) for r in zip(*rows))
        print(f"{name} {tool:10} {bp:<5} n={len(keep)} P_E={pe.mean():.3f} sd={pe.std():.3f}  "
              f"AUC={auc.mean():.3f} sd={auc.std():.3f}  P_D@5%FP={pd.mean():.3f} sd={pd.std():.3f}  "
              f"({time.time() - t:.0f}s)", flush=True)

if __name__ == "__main__":
    main()
