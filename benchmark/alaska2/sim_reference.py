"""Reference content-adaptive embedding (conseal's simulators, ternary at the
rate-distortion bound), luma only, as ScatterSteg's changes are almost all in
luma: the same bits as embed_set.py (PAYLOAD bits per nonzero AC coefficient
of all components), carried by the Y channel.
Usage: sim_reference.py juniward|uerd NAME PAYLOAD"""
import os, sys, zlib
import numpy as np, jpeglib, conseal
from concurrent.futures import ProcessPoolExecutor
method, name, payload = sys.argv[1], sys.argv[2], float(sys.argv[3])
os.makedirs(name, exist_ok=True)
def job(f):
    src, dst = f"cover/{f}", f"{name}/{f}"
    if os.path.exists(dst): return True
    im = jpeglib.read_dct(src)
    nz = lambda c: int((c != 0).sum() - (c[:, :, 0, 0] != 0).sum())
    total = nz(im.Y) + (nz(im.Cb) + nz(im.Cr) if im.has_chrominance else 0)
    alpha = payload * total / nz(im.Y)
    seed = zlib.crc32(f.encode())
    if method == "juniward":
        x0 = jpeglib.read_spatial(src, jpeglib.JCS_GRAYSCALE).spatial[..., 0]
        y1 = conseal.juniward.simulate_single_channel(x0, im.Y, im.qt[0], alpha, seed=seed)
    else:
        y1 = conseal.uerd.simulate_single_channel(im.Y, im.qt[0], alpha, seed=seed)
    im.Y = y1
    im.write_dct(dst)
    return True
files = sorted(f for f in os.listdir("cover") if f.endswith(".jpg"))
with ProcessPoolExecutor(8) as ex: res = list(ex.map(job, files))
print(name, payload, "ok", sum(res), "of", len(res))
