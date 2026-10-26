"""Grayscale BOSSbase covers: ScatterSteg PNG and LSB matching at the same
payloads (bits per pixel; one sample per pixel). steghide is not run here: it
has no grayscale PNG/PGM support, and its 8-bit BMP mode embeds differently.
TOOL names the ScatterSteg output (boss/stego/TOOL_<bpp>, default ss), so
builds with different costs can be compared on the same covers."""
import base64, glob, os, subprocess, sys
import numpy as np
from concurrent.futures import ThreadPoolExecutor
from PIL import Image
sys.path.insert(0, os.environ.get("TESTS", "/home/max/scattersteg/tests"))
import test_cli as T
SS = os.environ.get("SCATTERSTEG", "/home/max/scattersteg/rust/target/release/scattersteg")
PW = "benchmark passphrase 1234"; PIX = 512 * 512
BPP = ["0.05", "0.1", "0.2", "0.4"]
TOOL = os.environ.get("TOOL", "ss")
N = int(sys.argv[1])
pgms = sorted(glob.glob("boss/images/*.pgm"))[:N]
os.makedirs("boss/cover", exist_ok=True)
for p in BPP:
    for t in (TOOL, "lsbm"): os.makedirs(f"boss/stego/{t}_{p}", exist_ok=True)

def job(pgm):
    b = os.path.basename(pgm)[:-4]
    cov = f"boss/cover/{b}.png"
    if not os.path.exists(cov): Image.open(pgm).save(cov)
    a = np.asarray(Image.open(cov)).copy().reshape(-1)
    rng = np.random.default_rng(int(b) if b.isdigit() else 7)
    for p in BPP:
        n = int(float(p) * PIX)
        out = f"boss/stego/{TOOL}_{p}/{b}.png"
        if not os.path.exists(out):
            m = base64.b64encode(os.urandom(n // 8))[: n // 8]
            tmp = out + ".tmp.png"
            rc, log = T.run(["encode", "-i", cov, "-o", tmp], message=m, passphrases=[PW, PW], binary=SS)
            if rc == 0 and os.path.exists(tmp): os.rename(tmp, out)
            else: print("FAIL", TOOL, p, b, log.strip().splitlines()[-1][:80], flush=True)
        out = f"boss/stego/lsbm_{p}/{b}.png"
        if not os.path.exists(out):
            pos = rng.permutation(a.size)[:n]; bits = rng.integers(0, 2, n)
            v = a[pos].astype(np.int16); diff = (v & 1) != bits
            v = v + np.where(diff, rng.choice([-1, 1], n), 0); v[v < 0] = 1; v[v > 255] = 254
            r = a.copy(); r[pos] = v
            Image.fromarray(r.reshape(512, 512)).save(out)
    return b
if __name__ == "__main__":
    with ThreadPoolExecutor(6) as ex: list(ex.map(job, pgms))
    print("done")
