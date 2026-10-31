"""Embeds a random message of PAYLOAD bits per nonzero AC coefficient into every
cover in cover/, with BINARY (a ScatterSteg build, or "steghide"), into NAME/.
Usage: embed_set.py BINARY NAME PAYLOAD   (DUMPCOEF=path to ../dumpcoef; STEGHIDE=path)"""
import base64, os, subprocess, sys
from concurrent.futures import ThreadPoolExecutor
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "tests"))
sys.path.insert(0, os.path.join(HERE, ".."))
import test_cli as T, detect
binary, name, payload = sys.argv[1], sys.argv[2], float(sys.argv[3])
os.makedirs(name, exist_ok=True)
PW = "benchmark passphrase 1234"
def job(f):
    src, dst = f"cover/{f}", f"{name}/{f}"
    if os.path.exists(dst): return True
    nz = sum(int((c != 0).sum()) - int((c[:, :, 0, 0] != 0).sum()) for c in detect.read_coefs(src))
    n = int(payload * nz / 8)
    m = base64.b64encode(os.urandom(n))[:n]
    tmp = dst + ".tmp.jpg"
    if binary == "steghide":
        open(dst + ".msg", "wb").write(m)
        r = subprocess.run([os.environ.get("STEGHIDE", "steghide"), "embed", "-cf", src, "-ef", dst + ".msg",
                            "-sf", tmp, "-p", PW, "-Z", "-q", "-f"], capture_output=True)
        os.remove(dst + ".msg"); ok = r.returncode == 0
    else:
        code, log = T.run(["embed", "-cf", src, "-sf", tmp, "-Z", "-f"], message=m, passphrases=[PW, PW], binary=binary)
        ok = code == 0
    if ok and os.path.exists(tmp): os.rename(tmp, dst)
    return ok
files = sorted(f for f in os.listdir("cover") if f.endswith(".jpg"))
with ThreadPoolExecutor(10) as ex: res = list(ex.map(job, files))
print(name, payload, "ok", sum(res), "of", len(res))
