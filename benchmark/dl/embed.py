"""Embeds random messages into the deep-learning benchmark's covers.
Usage: embed.py DIR png|jpg NAME PAYLOAD (SCATTERSTEG names the binary).
PAYLOAD is bits per pixel (png) or per non-zero AC coefficient (jpg); the
message length is set per image from it. Stego images go to
DIR/stego/NAME_PAYLOAD/, with a log of the message sizes."""
import base64, os, subprocess, sys
from concurrent.futures import ThreadPoolExecutor
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "tests"))
sys.path.insert(0, os.path.join(HERE, ".."))
import test_cli as T
import detect

D, kind, name, payload = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])
SS = os.environ["SCATTERSTEG"]
PW = "benchmark passphrase 1234"
out = f"{D}/stego/{name}_{payload}"
os.makedirs(out, exist_ok=True)
bases = [l.split()[0] for l in open(f"{D}/split.txt")]


def carriers(base):
    if kind == "png": return 256 * 256
    return sum(int((c != 0).sum()) - int((c[:, :, 0, 0] != 0).sum())
               for c in detect.read_coefs(f"{D}/jpg/{base}.jpg"))


def job(base):
    dst = f"{out}/{base}.{kind}"
    if os.path.exists(dst): return base, -1
    n = int(payload * carriers(base) / 8)
    m = base64.b64encode(os.urandom(n))[:n]
    tmp = dst + ".tmp." + kind
    rc, log = T.run(["embed", "-cf", f"{D}/{kind}/{base}.{kind}", "-sf", tmp, "-Z", "-f"],
                    message=m, passphrases=[PW, PW], binary=SS)  # -Z: exactly n bytes
    if rc != 0 or not os.path.exists(tmp):
        print("FAIL", base, log.strip().splitlines()[-1][:100], flush=True); return base, None
    os.rename(tmp, dst); return base, n


with ThreadPoolExecutor(int(os.environ.get("JOBS", "10"))) as ex:
    res = list(ex.map(job, bases))
with open(f"{out}.log", "a") as f:
    f.write(f"binary {os.path.basename(SS)}\n")
    for b, n in res: f.write(f"{b} {n}\n")
print(name, payload, "ok", sum(n is not None for _, n in res), "fail", sum(n is None for _, n in res))
