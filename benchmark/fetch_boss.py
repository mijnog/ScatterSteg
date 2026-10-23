"""Fetches N images of BOSSbase 1.01 (512x512 grayscale PGM) from the project's
server by HTTP range requests, without downloading the whole 1.6 GB archive."""
import io, os, random, sys, urllib.request, zipfile
from concurrent.futures import ThreadPoolExecutor
U = "http://dde.binghamton.edu/download/ImageDB/BOSSbase_1.01.zip"
class Http(io.RawIOBase):
    def __init__(self):
        self.pos = 0
        r = urllib.request.urlopen(urllib.request.Request(U, method="HEAD"), timeout=60)
        self.size = int(r.headers["Content-Length"])
    def seekable(self): return True
    def readable(self): return True
    def tell(self): return self.pos
    def seek(self, off, whence=0):
        self.pos = off if whence == 0 else self.pos + off if whence == 1 else self.size + off
        return self.pos
    def read(self, n=-1):
        if n < 0: n = self.size - self.pos
        n = min(n, self.size - self.pos)
        if n <= 0: return b""
        for attempt in range(5):
            try:
                req = urllib.request.Request(U, headers={"Range": f"bytes={self.pos}-{self.pos+n-1}"})
                d = urllib.request.urlopen(req, timeout=60).read(); break
            except Exception:
                if attempt == 4: raise
        self.pos += len(d); return d
    def readinto(self, b):
        d = self.read(len(b)); b[:len(d)] = d; return len(d)
N = int(sys.argv[1]); out = "boss/images"; os.makedirs(out, exist_ok=True)
names = sorted(n for n in zipfile.ZipFile(io.BufferedReader(Http(), 1 << 16)).namelist() if n.endswith(".pgm"))
random.Random(0).shuffle(names); names = names[:N]
def get(n):
    for attempt in range(6):
        try: return get1(n)
        except Exception as e: print("retry", n, e, flush=True)
def get1(n):
    dst = f"{out}/{os.path.basename(n)}"
    if os.path.exists(dst): return
    z = zipfile.ZipFile(io.BufferedReader(Http(), 1 << 16))
    open(dst + ".part", "wb").write(z.read(n)); os.rename(dst + ".part", dst)
with ThreadPoolExecutor(16) as ex: list(ex.map(get, names))
print(len(os.listdir(out)), "images")
