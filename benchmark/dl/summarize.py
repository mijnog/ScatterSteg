"""Tabulates the SRNet runs: one row per stego set, from runs/*/result.json.
P_E's standard error is about sqrt(P_E(1-P_E)/n) over the n test pairs.
Usage: summarize.py DIR"""
import glob, json, math, sys

rows = [json.load(open(f)) for f in sorted(glob.glob(f"{sys.argv[1]}/runs/*/result.json"))]
print(f"{'set':<15} {'kind':<4} {'n':>5} {'P_E':>6} {'±':>5} {'AUC':>6} {'P_D@5%FP':>9}")
for r in sorted(rows, key=lambda r: (r["kind"], r["stego"])):
    se = math.sqrt(r["PE"] * (1 - r["PE"]) / r["n_test"])
    print(f"{r['stego']:<15} {r['kind']:<4} {r['n_test']:>5} {r['PE']:>6.3f} {se:>5.3f} "
          f"{r['AUC']:>6.3f} {r['PD_at_5FP']:>9.3f}")
