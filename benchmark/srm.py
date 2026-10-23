"""SRM-style rich-model features and the Kodovsky FLD ensemble.

Not the reference SRM implementation: the same construction (many linear
residuals, quantized and truncated, min/max and plain variants, fourth-order
co-occurrences, symmetrized), with the kernels and quantization steps chosen
here. Roughly 4,000 dimensions per channel. It is a markedly stronger detector
than SPAM, but weaker than the published SRM (34,671-D) or deep networks."""
import itertools, numpy as np
from scipy.signal import correlate2d

T = 2
NB = 2 * T + 1

def _canon():
    keys = list(itertools.product(range(NB), repeat=4))
    idx = {k: i for i, k in enumerate(keys)}
    neg = lambda k: tuple(NB - 1 - v for v in k)
    rep = {}
    cmap = np.zeros(len(keys), np.int64)
    for k in keys:
        c = min(k, k[::-1], neg(k), neg(k)[::-1])
        cmap[idx[k]] = rep.setdefault(c, len(rep))
    return cmap, len(rep)
CMAP, NCAN = _canon()

def _cooc(R, q):
    Q = np.clip(np.rint(R / q), -T, T).astype(np.int64) + T
    h = np.bincount((Q[:, :-3] * 125 + Q[:, 1:-2] * 25 + Q[:, 2:-1] * 5 + Q[:, 3:]).ravel(), minlength=625)
    v = np.bincount((Q[:-3] * 125 + Q[1:-2] * 25 + Q[2:-1] * 5 + Q[3:]).ravel(), minlength=625)
    out = np.bincount(CMAP, weights=(h + v).astype(np.float64), minlength=NCAN)
    return out / max(out.sum(), 1)

def _k(*rows): return np.array(rows, np.float64)
D1 = {"h": _k([-1, 1]), "v": _k([-1], [1]), "d": _k([-1, 0], [0, 1]), "a": _k([0, -1], [1, 0])}
D2 = {"h": _k([1, -2, 1]), "v": _k([1], [-2], [1]),
      "d": _k([1, 0, 0], [0, -2, 0], [0, 0, 1]), "a": _k([0, 0, 1], [0, -2, 0], [1, 0, 0])}
D3 = {"h": _k([-1, 3, -3, 1]), "v": _k([-1], [3], [-3], [1]),
      "d": np.diag([-1., 3, -3, 1]), "a": np.fliplr(np.diag([-1., 3, -3, 1]))}
SQ3 = _k([-1, 2, -1], [2, -4, 2], [-1, 2, -1])
SQ5 = _k([-1, 2, -2, 2, -1], [2, -6, 8, -6, 2], [-2, 8, -12, 8, -2], [2, -6, 8, -6, 2], [-1, 2, -2, 2, -1])
E3 = [_k([-1, 2, -1], [2, -4, 2], [0, 0, 0]), _k([0, 0, 0], [2, -4, 2], [-1, 2, -1]),
      _k([-1, 2, 0], [2, -4, 0], [-1, 2, 0]), _k([0, 2, -1], [0, -4, 2], [0, 2, -1])]
E5 = [_k([-1, 2, -2, 2, -1], [2, -6, 8, -6, 2], [-2, 8, -12, 8, -2], [0, 0, 0, 0, 0], [0, 0, 0, 0, 0]),
      _k([0, 0, 0, 0, 0], [0, 0, 0, 0, 0], [-2, 8, -12, 8, -2], [2, -6, 8, -6, 2], [-1, 2, -2, 2, -1])]
E5 += [e.T for e in E5]

def _res(x, k):
    return correlate2d(x, k, mode="same", boundary="symm")

def srm_channel(x):
    x = x.astype(np.float64)
    f = []
    b = 3
    crop = lambda r: r[b:-b, b:-b]
    for D, q in ((D1, 1.0), (D2, 2.0), (D3, 3.0)):
        R = {n: crop(_res(x, k)) for n, k in D.items()}
        f += [_cooc(R["h"], q), _cooc(R["v"], q), _cooc(R["d"], q), _cooc(R["a"], q)]
        for names in (("h", "v"), ("d", "a"), ("h", "v", "d", "a")):
            S = np.stack([R[n] for n in names])
            f += [_cooc(S.min(0), q), _cooc(S.max(0), q)]
    for name, ker, q in (("sq3", SQ3, 4.0), ("sq5", SQ5, 12.0)):
        r = crop(_res(x, ker))
        f += [_cooc(r, q), _cooc(r, q * 2)]
    for ks, q in ((E3, 4.0), (E5, 12.0)):
        S = np.stack([crop(_res(x, k)) for k in ks])
        f += [_cooc(S.min(0), q), _cooc(S.max(0), q), _cooc(S[0] + S[1], q * 2), _cooc(S[2] + S[3], q * 2)]
    return np.concatenate(f)

def srm(img):
    """img: HxW or HxWx3 uint8; per-channel features are averaged."""
    if img.ndim == 2: return srm_channel(img)
    return np.mean([srm_channel(img[:, :, c]) for c in range(img.shape[2])], axis=0)

def ensemble_pe(Xc, Xs, seed, L=100, test_frac=0.5):
    """Kodovsky-style ensemble of regularized FLDs on random feature subspaces,
    majority vote. Pairs stay in the same fold. Returns the detection error."""
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
        # threshold: the training error minimum on the projected values
        p0, p1 = A0 @ w, A1 @ w
        cand = np.sort(np.r_[p0, p1]); mids = (cand[1:] + cand[:-1]) / 2
        err = [(np.mean(p0 > t) + np.mean(p1 <= t)) / 2 for t in mids[:: max(1, len(mids) // 400)]]
        t = mids[:: max(1, len(mids) // 400)][int(np.argmin(err))]
        votes_c += (Tc[:, S] @ w > t); votes_s += (Ts[:, S] @ w > t)
    thr = L / 2
    err = (np.mean(votes_c > thr) + np.mean(votes_s <= thr)) / 2
    return err
