"""Trains SRNet to tell covers from stego images, then scores it on the
held-out test images.
Usage: train.py DIR png|jpg STEGO_FOLDER OUT [--init CKPT] [--epochs N]
Each batch holds cover/stego pairs of the same images, flipped and rotated
alike (the paper's pairing; it keeps the image content from being a cue).
The checkpoint kept is the one with the best validation accuracy, and the
test images are touched only once, at the end. OUT gets the checkpoint,
a JSON summary (P_E, AUC, detection at 5% false positives, accuracy) and
the raw test scores."""
import argparse, json, os, sys, time
import numpy as np
import torch
import torch.nn.functional as F
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import data
from srnet import SRNet

ap = argparse.ArgumentParser()
ap.add_argument("D"); ap.add_argument("kind"); ap.add_argument("stego"); ap.add_argument("out")
ap.add_argument("--init"); ap.add_argument("--epochs", type=int, default=60)
ap.add_argument("--lr", type=float, default=1e-3); ap.add_argument("--pairs", type=int, default=16)
ap.add_argument("--seed", type=int, default=0)
ap.add_argument("--limit", type=int, help="use only this many images per set (a smoke test)")
a = ap.parse_args()
torch.manual_seed(a.seed); rng = np.random.default_rng(a.seed)
os.makedirs(a.out, exist_ok=True)
dev = "cuda"
log = open(f"{a.out}/log.txt", "a")
def say(*x):
    s = " ".join(str(v) for v in x); print(s, flush=True); log.write(s + "\n"); log.flush()

say("args", vars(a))
sets = {p: data.split(a.D, p)[:a.limit] for p in ("train", "val", "test")}
X = {p: (data.load(a.D, a.kind, a.kind, b, not a.limit), data.load(a.D, a.kind, f"stego/{a.stego}", b, not a.limit))
     for p, b in sets.items()}
for p, (c, s) in X.items():
    ch = (c != s).reshape(len(c), -1).mean(1)
    say(p, len(c), "images; change rate %.4f" % ch.mean(), "unchanged stego", int((ch == 0).sum()))
pre = (data.Decompress(data.quant_table(a.D, sets["train"][0])).to(dev) if a.kind == "jpg"
       else (lambda x: x - 128)).__call__


def tensor(x):
    return pre(torch.from_numpy(x.astype(np.float32)).to(dev)[:, None]) / 64


def d4(x, k):  # one of the 8 flips/rotations
    if k & 4: x = x.flip(-1)
    return torch.rot90(x, k & 3, (-2, -1))


model = SRNet().to(dev)
if a.init: model.load_state_dict(torch.load(a.init, map_location=dev)); say("init", a.init)
opt = torch.optim.Adamax(model.parameters(), a.lr, eps=1e-8)
# the paper: a constant rate, then a tenth of it for the last stretch
sched = torch.optim.lr_scheduler.MultiStepLR(opt, [int(a.epochs * 0.8)], 0.1)
scaler = torch.amp.GradScaler()


@torch.no_grad()
def scores(part):
    model.eval(); c, s = X[part]; out = []
    for arr in (c, s):
        r = []
        for i in range(0, len(arr), 64):
            with torch.autocast("cuda", torch.float16):
                z = model(tensor(arr[i:i + 64])).float()
            r.append((z[:, 1] - z[:, 0]).cpu().numpy())
        out.append(np.concatenate(r))
    model.train(); return out  # cover scores, stego scores


def metrics(sc, ss):
    from sklearn.metrics import roc_curve, roc_auc_score
    y = np.r_[np.zeros(len(sc)), np.ones(len(ss))]; z = np.r_[sc, ss]
    fpr, tpr, _ = roc_curve(y, z)
    return dict(PE=float(np.min(0.5 * (fpr + 1 - tpr))), AUC=float(roc_auc_score(y, z)),
                PD_at_5FP=float(np.interp(0.05, fpr, tpr)),
                acc=float(0.5 * ((sc < 0).mean() + (ss >= 0).mean())))


best = -1; c, s = X["train"]; n = len(c); t0 = time.time()
for ep in range(a.epochs):
    perm = rng.permutation(n); tot = 0.0
    for i in range(0, n - a.pairs + 1, a.pairs):
        idx = np.sort(perm[i:i + a.pairs])
        x = torch.cat([tensor(c[idx]), tensor(s[idx])])
        ks = torch.from_numpy(rng.integers(0, 8, a.pairs)).repeat(2)
        x = torch.stack([d4(x[j], int(ks[j])) for j in range(len(x))])
        y = torch.cat([torch.zeros(a.pairs), torch.ones(a.pairs)]).long().to(dev)
        with torch.autocast("cuda", torch.float16):
            loss = F.cross_entropy(model(x), y)
        opt.zero_grad(set_to_none=True); scaler.scale(loss).backward(); scaler.step(opt); scaler.update()
        tot += loss.item()
    sched.step()
    m = metrics(*scores("val"))
    say(f"epoch {ep + 1} loss {tot / (n // a.pairs):.4f} val acc {m['acc']:.4f} PE {m['PE']:.4f} "
        f"lr {opt.param_groups[0]['lr']:.0e} {time.time() - t0:.0f}s")
    if m["acc"] > best:
        best = m["acc"]; torch.save(model.state_dict(), f"{a.out}/best.pt")

model.load_state_dict(torch.load(f"{a.out}/best.pt", map_location=dev))
sc, ss = scores("test")
np.savez(f"{a.out}/test_scores.npz", cover=sc, stego=ss)
res = dict(stego=a.stego, kind=a.kind, best_val_acc=best, n_test=len(sc), **metrics(sc, ss))
json.dump(res, open(f"{a.out}/result.json", "w"), indent=1)
say("TEST", json.dumps(res))
