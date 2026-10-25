"""P_E for PNG stego dirs against their covers. Usage: score.py spam|srm TOOL..."""
import glob, os, sys, time, numpy as np
import detect as D
def main():
    kind, tools = sys.argv[1], sys.argv[2:]
    bases = sorted(os.path.basename(p)[:-4] for p in glob.glob("cover/*.png"))
    N = len(bases)
    if kind == "spam":
        fn, score = D.spam, lambda c, s, seed: D.pe(c, s, seed)[0]
    else:
        import srm, detect_srm as DS
        fn = DS.feat
        score = lambda c, s, seed: srm.ensemble_pe(c, s, seed)
    t0 = time.time()
    cov = D.cached(f"{kind}_cover_{N}", [f"cover/{b}.png" for b in bases], fn)
    print(f"cover features {time.time() - t0:.0f}s", flush=True)
    for tool in tools:
        for bpp in (0.05, 0.1, 0.2, 0.4):
            d = f"stego/{tool}_png_{bpp}"
            if not os.path.isdir(d): continue
            t = time.time()
            st = D.cached(f"{kind}_{tool}_{bpp}_{N}", [f"{d}/{b}.png" for b in bases], fn)
            tf = time.time() - t; t = time.time()
            e = [score(cov, st, s) for s in range(5)]
            print(f"{kind} {tool:8} {bpp:<5} P_E={np.mean(e):.3f} sd={np.std(e):.3f}  (features {tf:.0f}s, classify {time.time() - t:.0f}s)", flush=True)


if __name__ == "__main__":
    main()
