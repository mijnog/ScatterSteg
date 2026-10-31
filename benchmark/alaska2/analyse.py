"""P_E, AUC and detection at 5% false alarms for each stego set against the
covers, per detector, over the images both have."""
import glob, os, sys
import numpy as np
from sklearn.metrics import roc_curve, roc_auc_score
files = sorted(os.path.basename(f) for f in glob.glob("cover/*.jpg"))
def m(sc, ss):
    y = np.r_[np.zeros(len(sc)), np.ones(len(ss))]; z = np.r_[sc, ss]
    fpr, tpr, _ = roc_curve(y, z)
    return np.min(0.5 * (fpr + 1 - tpr)), roc_auc_score(y, z), np.interp(0.05, fpr, tpr)
print(f"{'set':16} {'detector':9} {'n':>4} {'P_E':>6} {'AUC':>6} {'PD@5%':>6}")
for s in sys.argv[1:]:
    for det in ("juniw", "jmipod", "nsf5", "steghide"):
        f = f"scores/{s}-{det}.npy"
        if not os.path.exists(f): continue
        ss = np.load(f); names = open(f"scores/{s}.files").read().split()
        sc = np.load(f"scores/cover-{det}.npy")[[files.index(n) for n in names]]
        pe, auc, pd = m(sc, ss)
        print(f"{s:16} {det:9} {len(ss):4} {pe:6.3f} {auc:6.3f} {pd:6.3f}")
