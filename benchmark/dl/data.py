"""Loads the benchmark's covers and stego images into memory as arrays the
detectors take: pixels for PNG; for JPEG, the quantized DCT coefficients,
decompressed on the GPU without rounding (as J-domain SRNet is trained),
since rounding to pixels would throw away part of the stego signal."""
import os, subprocess, zlib
import numpy as np
import torch
from PIL import Image
from concurrent.futures import ThreadPoolExecutor

DUMPCOEF = os.environ.get("DUMPCOEF", "/home/max/bench/dumpcoef")


def split(D, part):
    return [b for b, p in (l.split() for l in open(f"{D}/split.txt")) if p == part]


def _png(path):
    return np.asarray(Image.open(path), dtype=np.uint8)


def _jpg(path):
    raw = subprocess.run([DUMPCOEF, path], capture_output=True, check=True).stdout
    assert np.frombuffer(raw, np.int32, 1, 0)[0] == 1, "grayscale only"
    wb, hb = np.frombuffer(raw, np.int32, 2, 4)
    c = np.frombuffer(raw, np.int16, wb * hb * 64, 12).reshape(hb, wb, 8, 8)
    return c.transpose(0, 2, 1, 3).reshape(hb * 8, wb * 8)  # the 8x8 blocks laid out as an image


def load(D, kind, folder, bases, cache):
    """(n, 256, 256) array (uint8 pixels or int16 coefficients), cached."""
    f = f"{D}/cache/{folder.replace('/', '_')}_{kind}_{len(bases)}_{zlib.crc32(' '.join(bases).encode()):08x}.npy"
    if os.path.exists(f) and cache: return np.load(f)
    rd = _png if kind == "png" else _jpg
    with ThreadPoolExecutor(10) as ex:
        a = np.stack(list(ex.map(rd, [f"{D}/{folder}/{b}.{kind}" for b in bases])))
    os.makedirs(f"{D}/cache", exist_ok=True)
    if cache: np.save(f, a)
    return a


def quant_table(D, base):
    return np.array(Image.open(f"{D}/jpg/{base}.jpg").quantization[0], dtype=np.float32).reshape(8, 8)


class Decompress(torch.nn.Module):
    """Coefficients laid out as 8x8 blocks -> pixel values minus 128, unrounded."""
    def __init__(self, q):
        super().__init__()
        k = np.arange(8)
        c = np.sqrt(np.where(k == 0, 1, 2) / 8)[:, None] * np.cos((2 * k[None] + 1) * k[:, None] * np.pi / 16)
        self.register_buffer("A", torch.tensor(c, dtype=torch.float32))  # A[u, x]
        self.register_buffer("q", torch.tensor(q))

    def forward(self, x):  # (n, 1, H, W) coefficients
        n, _, H, W = x.shape
        b = x.view(n, H // 8, 8, W // 8, 8).permute(0, 1, 3, 2, 4) * self.q
        p = self.A.T @ b @ self.A
        return p.permute(0, 1, 3, 2, 4).reshape(n, 1, H, W)
