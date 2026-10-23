"""DCTR-style features for JPEG (after Holub and Fridrich): the unrounded
decompressed luminance is correlated with all 64 8x8 DCT basis patterns,
the absolute residual is quantized and truncated at T=4, and histograms are
taken per phase (position within the 8x8 grid, folded by symmetry)."""
import numpy as np
from scipy.fft import idctn
from scipy.ndimage import correlate1d
from PIL import Image
import detect

T = 4
def basis():
    k = np.arange(8)
    B = np.zeros((8, 8))
    for u in range(8):
        B[u] = np.cos((2 * k + 1) * u * np.pi / 16) * (np.sqrt(1 / 8) if u == 0 else np.sqrt(2 / 8))
    return B

def decompress(path):
    img = Image.open(path)
    qt = np.array(img.quantization[0], np.float64).reshape(8, 8)
    c = detect.read_coefs(path)[0].astype(np.float64)          # (hb, wb, 8, 8)
    px = idctn(c * qt, axes=(2, 3), norm="ortho")
    hb, wb = c.shape[:2]
    return px.transpose(0, 2, 1, 3).reshape(hb * 8, wb * 8) + 128.0

def dctr(path, q=4.0):
    x = decompress(path)
    B = basis()
    rows = [correlate1d(x, B[u], axis=1, mode="constant", origin=-0)[:, :] for u in range(8)]
    f = []
    H, W = x.shape
    ii = np.arange(H)[:, None] % 8; jj = np.arange(W)[None, :] % 8
    fold = lambda a: np.minimum(a, 7 - a)
    ph = (fold(ii) * 4 + fold(jj)).astype(np.int64)             # 16 folded phases
    for u in range(8):
        for v in range(8):
            U = correlate1d(rows[v], B[u], axis=0, mode="constant")
            R = np.minimum(np.rint(np.abs(U) / q), T).astype(np.int64)
            h = np.bincount((ph * (T + 1) + R)[8:-8, 8:-8].ravel(), minlength=16 * (T + 1)).reshape(16, T + 1).astype(np.float64)
            f.append(h / h.sum(1, keepdims=True))
    return np.concatenate([a.ravel() for a in f]).astype(np.float32)
