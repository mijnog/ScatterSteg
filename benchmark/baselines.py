import glob, os, numpy as np
from PIL import Image
rng = np.random.default_rng(1)
PIX = 512 * 512
for bpp in (0.05, 0.1, 0.2, 0.4):
    for tool in ("lsbr", "lsbm"):
        os.makedirs(f"stego/{tool}_png_{bpp}", exist_ok=True)
    for f in sorted(glob.glob("cover/*.png")):
        b = os.path.basename(f)
        a = np.asarray(Image.open(f).convert("RGB")).copy().reshape(-1)
        n = int(bpp * PIX)               # message bits (same count as the real tools carry)
        pos = rng.permutation(a.size)[:n]
        bits = rng.integers(0, 2, n).astype(np.uint8)
        r = a.copy(); r[pos] = (r[pos] & 0xFE) | bits
        m = a.astype(np.int16)
        diff = (m[pos] & 1) != bits
        step = rng.choice([-1, 1], n)
        v = m[pos] + np.where(diff, step, 0)
        v[(v < 0)] = 1; v[v > 255] = 254
        m[pos] = v
        Image.fromarray(r.reshape(512, 512, 3)).save(f"stego/lsbr_png_{bpp}/{b}")
        Image.fromarray(m.astype(np.uint8).reshape(512, 512, 3)).save(f"stego/lsbm_png_{bpp}/{b}")
print("done")
