"""Embeds a 1-byte message into every cover with BINARY, into NAME/: the rewrite with almost no changes.
Usage: embed_tiny.py BINARY NAME"""
import os, sys
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tests"))
import test_cli as T
binary, name = sys.argv[1], sys.argv[2]
os.makedirs(name, exist_ok=True)
PW = "benchmark passphrase 1234"
def job(f):
    tmp, dst = f"{name}/{f}.tmp.jpg", f"{name}/{f}"
    code, _ = T.run(["embed", "-cf", f"cover/{f}", "-sf", tmp, "-Z", "-f"], message=b"x", passphrases=[PW, PW], binary=binary)
    if code == 0: os.rename(tmp, dst)
    return code == 0
files = sorted(f for f in os.listdir("cover") if f.endswith(".jpg"))
with ThreadPoolExecutor(10) as ex: res = list(ex.map(job, files))
print(name, "ok", sum(res), "of", len(res))
