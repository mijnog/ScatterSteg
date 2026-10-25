"""ScatterSteg PNG embeds only (no steghide, no JPEG): embed_all's covers and
message sizes. Usage: embed_png.py N TOOLNAME (stego/TOOLNAME_png_<bpp>/)."""
import glob, os, sys
from concurrent.futures import ThreadPoolExecutor
import embed_all as E
N, tool = int(sys.argv[1]), sys.argv[2]
raws = sorted(glob.glob("raw/*.jpg"))[:N]
with ThreadPoolExecutor(6) as ex: bases = list(ex.map(E.make_cover, raws))
def job(a):
    base, bpp = a
    out = f"stego/{tool}_png_{bpp}/{base}.png"
    os.makedirs(os.path.dirname(out), exist_ok=True)
    if os.path.exists(out): return True
    tmp = out + ".tmp.png"
    rc, log = E.T.run(["encode", "-i", f"cover/{base}.png", "-o", tmp],
                      message=E.msg(int(bpp * E.PIX / 8)), passphrases=[E.PW, E.PW], binary=E.SS)
    if rc != 0: print("FAIL", base, bpp, log.strip().splitlines()[-1][:100], flush=True); return False
    os.rename(tmp, out); return True
jobs = [(b, bpp) for b in bases for bpp in E.PNG_BPP]
with ThreadPoolExecutor(6) as ex: ok = sum(ex.map(job, jobs))
print("done", ok, "of", len(jobs))
