"""Cover-vs-stego detection error for each tool and payload.
Pixels: SPAM (686-D, second-order Markov of pixel differences, T=3), per RGB
channel, averaged. JPEG: DCT-domain histograms and intra-/inter-block
co-occurrences of the quantized coefficients (a compact JRM-style feature).
Classifier: standardized RBF SVM. Pairs (cover, its stego) stay in the same
fold. Error P_E = 1 - accuracy on a balanced test set; 0.5 means the detector
does no better than guessing."""
import glob, os, sys, itertools, numpy as np
from concurrent.futures import ProcessPoolExecutor
import multiprocessing as mp
from PIL import Image
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.model_selection import GridSearchCV
from sklearn.metrics import roc_auc_score

T = 3
NAMES = {'ss': 'ScatterSteg', 'sh': 'steghide', 'lsbr': 'LSB replace', 'lsbm': 'LSB match'}
def spam_channel(I):
    I = I.astype(np.int16)
    def trip(D):  # D: differences, triplets along axis 1
        D = np.clip(D, -T, T) + T
        idx = D[:, :-2] * 49 + D[:, 1:-1] * 7 + D[:, 2:]
        return np.bincount(idx.ravel(), minlength=343).astype(np.float64)
    h = (trip(I[:, :-1] - I[:, 1:]) + trip((I[:, 1:] - I[:, :-1])[:, ::-1])
         + trip((I[:-1] - I[1:]).T) + trip((I[1:] - I[:-1])[::-1].T))
    dg = lambda A: (A[:-1, :-1] - A[1:, 1:])
    d = (trip(dg(I)) + trip(-dg(I)[::-1, ::-1]) + trip(dg(I[:, ::-1])) + trip(-dg(I[:, ::-1])[::-1, ::-1]))
    return np.concatenate([h / h.sum(), d / d.sum()])

def spam(path):
    a = np.asarray(Image.open(path).convert("RGB"))
    return np.mean([spam_channel(a[:, :, c]) for c in range(3)], axis=0)

MODES = [(0, 1), (1, 0), (1, 1), (0, 2), (2, 0), (1, 2), (2, 1), (0, 3), (3, 0)]
def read_coefs(path):
    """[(bh, bw, 8, 8) int array per component], via the libjpeg dumper"""
    import subprocess
    raw = subprocess.run([os.environ.get("DUMPCOEF", os.path.join(os.path.dirname(os.path.abspath(__file__)), "dumpcoef")), path], capture_output=True, check=True).stdout
    n = int(np.frombuffer(raw, np.int32, 1, 0)[0]); pos = 4; out = []
    for _ in range(n):
        wb, hb = (int(x) for x in np.frombuffer(raw, np.int32, 2, pos)); pos += 8
        out.append(np.frombuffer(raw, np.int16, wb * hb * 64, pos).reshape(hb, wb, 8, 8).astype(np.int32)); pos += wb * hb * 128
    return out

def jpeg_feat(path):
    blocks = read_coefs(path)[0]
    m = {md: blocks[:, :, md[0], md[1]] for md in MODES}
    f = []
    for md in MODES:
        f.append(np.bincount(np.clip(m[md], -4, 4).ravel() + 4, minlength=9) / m[md].size)
    cl = lambda x: np.clip(x, -2, 2) + 2
    for a, b in itertools.combinations(MODES, 2):
        h = np.bincount((cl(m[a]) * 5 + cl(m[b])).ravel(), minlength=25)
        f.append(h / h.sum())
    for md in MODES:
        x = m[md]
        for a, b in ((x[:, :-1], x[:, 1:]), (x[:-1], x[1:])):
            h = np.bincount((cl(a) * 5 + cl(b)).ravel(), minlength=25)
            f.append(h / h.sum())
    return np.concatenate(f)

def feats(paths, fn):
    with ProcessPoolExecutor(10, mp_context=mp.get_context("spawn")) as ex:
        return np.array(list(ex.map(fn, paths, chunksize=4)))

def cached(name, paths, fn):
    f = f"feat_{name}.npy"
    if os.path.exists(f):
        a = np.load(f)
        if len(a) == len(paths): return a
    a = feats(paths, fn); np.save(f, a); return a

def pe(Xc, Xs, seed, test_frac=0.5):
    n = len(Xc); rng = np.random.RandomState(seed); p = rng.permutation(n)
    k = int(n * (1 - test_frac)); tr, te = p[:k], p[k:]
    Xtr = np.vstack([Xc[tr], Xs[tr]]); ytr = np.r_[np.zeros(k), np.ones(k)]
    Xte = np.vstack([Xc[te], Xs[te]]); yte = np.r_[np.zeros(len(te)), np.ones(len(te))]
    clf = GridSearchCV(make_pipeline(StandardScaler(), SVC(kernel="rbf", gamma="scale")),
                       {"svc__C": [1, 10, 100]}, cv=3, n_jobs=6).fit(Xtr, ytr)
    s = clf.decision_function(Xte)
    return 1 - (clf.predict(Xte) == yte).mean(), roc_auc_score(yte, s)

if __name__ == "__main__":
    N = int(sys.argv[1]); splits = 5
    bases = sorted(os.path.basename(p)[:-4] for p in glob.glob("cover/*.png"))[:N]
    for d in os.listdir("stego"):
        ext = d.split("_")[1]
        if d.startswith("lsb"): continue
        bases = [b for b in bases if os.path.exists(f"stego/{d}/{b}.{ext}")]
    print(len(bases), "images with every cover and stego", flush=True)
    N = len(bases)
    rows = []
    for kind, cext, fn, tools in (("png/bmp pixels", None, spam, [("lsbr", "png"), ("lsbm", "png"), ("ss", "png"), ("sh", "bmp")]),
                                  ("jpeg", "jpg", jpeg_feat, [("ss", "jpg"), ("sh", "jpg")])):
        for tool, ext in tools:
            tags = sorted({d.split("_", 2)[2] for d in os.listdir("stego") if d.startswith(f"{tool}_{ext}_")}, key=float)
            cov = cached(f"cover_{ext}_{N}", [f"cover/{b}.{ext}" for b in bases], fn)
            for tag in tags:
                paths = [f"stego/{tool}_{ext}_{tag}/{b}.{ext}" for b in bases]
                if not all(os.path.exists(p) for p in paths): continue
                st = cached(f"{tool}_{ext}_{tag}_{N}", paths, fn)
                r = [pe(cov, st, s) for s in range(splits)]
                e, a = np.mean([x[0] for x in r]), np.mean([x[1] for x in r])
                print(f"{NAMES[tool]:12} {ext:4} payload {tag:5} P_E={e:.3f}  AUC={a:.3f}  (n={N}, {splits} splits)", flush=True)
