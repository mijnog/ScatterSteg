"""Makes covers (PNG/BMP/JPEG from the same crops) and embeds the same random
message sizes with ScatterSteg and steghide."""
import base64, glob, os, subprocess, sys, shutil
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests"))
import test_cli as T
HERE = os.path.dirname(os.path.abspath(__file__))
SS = os.environ.get("SCATTERSTEG", os.path.join(HERE, "..", "rust", "target", "release", "scattersteg"))
SH = os.environ.get("STEGHIDE", "steghide")
PW = "benchmark passphrase 1234"
PIX = 512 * 512
PNG_BPP = [0.05, 0.1, 0.2, 0.4]
JPG_BPNZ = [0.05, 0.1, 0.2]
N = int(sys.argv[1])
for d in ("cover", "stego"): os.makedirs(d, exist_ok=True)
raws = sorted(glob.glob("raw/*.jpg"))[:N]

def sh(*a):
    return subprocess.run(a, capture_output=True, text=True)

def make_cover(raw):
    base = os.path.basename(raw)[:-4]
    png, bmp, jpg = f"cover/{base}.png", f"cover/{base}.bmp", f"cover/{base}.jpg"
    if not os.path.exists(png):
        crop = ["-resize", "x640^", "-gravity", "center", "-crop", "512x512+0+0", "+repage"]
        sh("magick", raw, *crop, "-depth", "8", png)
        sh("magick", png, "-define", "bmp:format=bmp3", bmp)
        sh("magick", png, "-quality", "75", "-sampling-factor", "4:2:0", "-interlace", "none", jpg)
    return base

def msg(n):
    return base64.b64encode(os.urandom(n))[:n]

def nzac(jpg):
    sys.path.insert(0, HERE)
    import detect
    tot = 0
    for c in detect.read_coefs(jpg):
        tot += int((c != 0).sum()) - int((c[:, :, 0, 0] != 0).sum())
    return tot

def job(args):
    tool, kind, base, tag, nbytes = args
    ext = {"png": "png", "bmp": "bmp", "jpg": "jpg"}[kind]
    cover = f"cover/{base}.{ext}"
    out = f"stego/{tool}_{kind}_{tag}/{base}.{ext}"
    os.makedirs(os.path.dirname(out), exist_ok=True)
    if os.path.exists(out): return True
    m = msg(nbytes)
    if tool == "ss":
        tmp = out + ".tmp." + ext
        rc, log = T.run(["encode", "-i", cover, "-o", tmp], message=m, passphrases=[PW, PW], binary=SS)
        if rc != 0 or not os.path.exists(tmp):
            print("FAIL", tool, kind, tag, base, log.strip().splitlines()[-1][:80], flush=True); return False
        os.rename(tmp, out); return True
    mf = f"/tmp/scattersteg_bench_msg_{os.getpid()}_{kind}_{base}_{tag}.txt"
    open(mf, "wb").write(m)
    r = sh(SH, "embed", "-cf", cover, "-ef", mf, "-sf", out, "-p", PW, "-q", "-f")
    os.unlink(mf)
    if r.returncode != 0:
        print("FAIL", tool, kind, tag, base, (r.stderr or "").strip()[:80], flush=True); return False
    return True

if __name__ == "__main__":
    with ThreadPoolExecutor(6) as ex: bases = list(ex.map(make_cover, raws))
    jobs = []
    nz = {}
    for b in bases:
        nz[b] = nzac(f"cover/{b}.jpg")
    for b in bases:
        for bpp in PNG_BPP:
            nbytes = int(bpp * PIX / 8); tag = f"{bpp}"
            jobs += [("ss", "png", b, tag, nbytes), ("sh", "bmp", b, tag, nbytes)]
        for bp in JPG_BPNZ:
            nbytes = int(bp * nz[b] / 8); tag = f"{bp}"
            jobs += [("ss", "jpg", b, tag, nbytes), ("sh", "jpg", b, tag, nbytes)]
    print(len(jobs), "embeds", flush=True)
    with ThreadPoolExecutor(6) as ex:
        ok = sum(ex.map(job, jobs))
    print("done", ok, "of", len(jobs))
