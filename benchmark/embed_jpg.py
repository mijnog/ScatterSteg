"""ScatterSteg JPEG embeds only: embed_all's covers and message sizes (bits
per non-zero AC coefficient). Usage: embed_jpg.py N TOOLNAME
(stego/TOOLNAME_jpg_<bp>/); payloads from BPNZ, default 0.05,0.1,0.2."""
import glob, os, sys
from concurrent.futures import ThreadPoolExecutor
import embed_all as E

def main():
    N, tool = int(sys.argv[1]), sys.argv[2]
    bps = [float(x) for x in os.environ.get("BPNZ", "0.05,0.1,0.2").split(",")]
    raws = sorted(glob.glob("raw/*.jpg"))[:N]
    with ThreadPoolExecutor(6) as ex: bases = list(ex.map(E.make_cover, raws))
    nz = {b: E.nzac(f"cover/{b}.jpg") for b in bases}
    def job(a):
        base, bp = a
        out = f"stego/{tool}_jpg_{bp}/{base}.jpg"
        os.makedirs(os.path.dirname(out), exist_ok=True)
        if os.path.exists(out): return True
        tmp = out + ".tmp.jpg"
        rc, log = E.T.run(["embed", "-cf", f"cover/{base}.jpg", "-sf", tmp, "-Z", "-f"],  # -Z: the payload exactly as sized (compression would shrink it)
                          message=E.msg(int(bp * nz[base] / 8)), passphrases=[E.PW, E.PW], binary=E.SS)
        if rc != 0: print("FAIL", base, bp, log.strip().splitlines()[-1][:100], flush=True); return False
        os.rename(tmp, out); return True
    jobs = [(b, bp) for b in bases for bp in bps]
    with ThreadPoolExecutor(6) as ex: ok = sum(ex.map(job, jobs))
    print("done", ok, "of", len(jobs))

if __name__ == "__main__":
    main()
