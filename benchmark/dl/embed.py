"""Embeds random messages into the deep-learning benchmark's covers.
Usage: embed.py DIR png|jpg NAME PAYLOAD (SCATTERSTEG names the binary).
PAYLOAD is bits per pixel (png) or per non-zero AC coefficient (jpg); the
message length is set per image from it. Stego images go to
DIR/stego/NAME_PAYLOAD/, with a log of the message sizes. SCATTERSTEG=hstego
embeds with HStego instead (../hstego_batch.py, run by HSTEGO_PY, one
process per job over many covers; JPEG only).

SCATTERSTEG=phasm embeds with phasm-core's CLI in Ghost mode (PHASM names
the binary, default `phasm`; JPEG only), matched to ScatterSteg on the
total embedded: ScatterSteg stores the message plus CODEC_FIXED_BYTES
(codec.h), phasm the Brotli-compressed message plus PHASM_FIXED, so phasm's
compressed message is the same message size plus the difference. phasm
takes UTF-8 text only and compresses it, so each cover gets random base64
text, its length searched for the longest whose compressed size (phasm's
"payload: N B") is at most that target. phasm doesn't enforce its own
"max" (nzAC/5 frame bits); the target can pass it by up to the difference.
The log line per cover is "BASE TARGET PAYLOAD", also printed as "ok BASE
TARGET PAYLOAD" when each cover is done."""
import base64, json, os, re, subprocess, sys
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


def hstego(jobs):
    """HStego over every cover not done yet: JOBS processes, each a list"""
    todo = [b for b in bases if not os.path.exists(f"{out}/{b}.{kind}")]
    lists = [f"{out}.hstego-{i}.list" for i in range(jobs)]
    sizes = {}
    with ThreadPoolExecutor(jobs) as ex:  # the sizes need the coefficients
        for b, n in zip(todo, ex.map(lambda b: int(payload * carriers(b) / 8), todo)): sizes[b] = n
    for i, path in enumerate(lists):
        with open(path, "w") as f:
            for b in todo[i::jobs]: f.write(f"{D}/{kind}/{b}.{kind} {out}/{b}.{kind} {sizes[b]}\n")
    procs = [subprocess.Popen([os.environ["HSTEGO_PY"], "-I", os.path.join(HERE, "..", "hstego_batch.py"), p],
                              stdout=subprocess.PIPE, text=True) for p in lists]
    failed = set()
    for p in procs:
        for line in p.stdout:
            if line.startswith("FAIL"):
                print(line.strip(), flush=True); failed.add(os.path.basename(line.split()[1]).split(".")[0])
        p.wait()
    for path in lists: os.remove(path)
    return [(b, None if b in failed or not os.path.exists(f"{out}/{b}.{kind}") else sizes.get(b, -1)) for b in bases]


SS_FIXED = int(re.search(r"#define CODEC_FIXED_BYTES (\d+)",
                          open(os.path.join(HERE, "..", "..", "codec.h")).read()).group(1))
PHASM_FIXED = 50  # phasm 0.5.1: its "ghost" capacity is nzAC/5 frame bits less 50 bytes, checked per cover


def phasm_try(cover, text, dst):
    """phasm's compressed payload size for TEXT, or None if it refused"""
    r = subprocess.run([os.environ.get("PHASM", "phasm"), "encode", "--mode", "ghost", "-p", PW,
                        "-m", text, "-o", dst, cover], capture_output=True, text=True, timeout=120)
    m = re.search(r"payload: (\d+) B", r.stderr + r.stdout)  # the size line goes to stderr
    return int(m.group(1)) if r.returncode == 0 and m and os.path.exists(dst) else None


def phasm_job(base):
    dst = f"{out}/{base}.{kind}"
    if os.path.exists(dst): return base, -1
    cover, nz = f"{D}/{kind}/{base}.{kind}", carriers(base)
    cap = json.loads(subprocess.run([os.environ.get("PHASM", "phasm"), "capacity", cover, "--json"],
                                    capture_output=True, text=True, check=True).stdout)["ghost"]
    if nz // 5 // 8 - cap != PHASM_FIXED:
        print("FAIL", base, "phasm overhead", nz // 5 // 8 - cap, flush=True); return base, None
    target = int(payload * nz / 8) + SS_FIXED - PHASM_FIXED
    text = base64.b64encode(os.urandom(target * 2 + 16)).decode()
    tmp = dst + ".tmp." + kind
    lo, hi, best = 1, len(text), None  # longest prefix whose compressed size is at most target
    while lo <= hi:
        mid = (lo + hi) // 2
        got = phasm_try(cover, text[:mid], tmp)
        if got is not None and got <= target: lo, best = mid + 1, (mid, got)
        else: hi = mid - 1
    if best is None or phasm_try(cover, text[:best[0]], tmp) != best[1]:
        print("FAIL", base, "no fit", flush=True); return base, None
    os.rename(tmp, dst)
    print("ok", base, target, best[1], flush=True)  # as it goes: a run stopped early keeps them
    return base, f"{target} {best[1]}"


if SS == "hstego":
    assert kind == "jpg", "HStego here is J-UNIWARD (JPEG)"
    res = hstego(int(os.environ.get("JOBS", "10")))
elif SS == "phasm":
    assert kind == "jpg", "phasm's Ghost mode is JPEG"
    with ThreadPoolExecutor(int(os.environ.get("JOBS", "10"))) as ex:
        res = list(ex.map(phasm_job, bases))
else:
    with ThreadPoolExecutor(int(os.environ.get("JOBS", "10"))) as ex:
        res = list(ex.map(job, bases))
with open(f"{out}.log", "a") as f:
    f.write(f"binary {os.path.basename(SS)}\n")
    if SS == "phasm":
        v = subprocess.run([os.environ.get("PHASM", "phasm"), "--version"], capture_output=True, text=True).stdout.strip()
        f.write(f"phasm {v}, fixed bytes ScatterSteg {SS_FIXED} phasm {PHASM_FIXED}\n")
    for b, n in res: f.write(f"{b} {n}\n")
print(name, payload, "ok", sum(n is not None for _, n in res), "fail", sum(n is None for _, n in res))
