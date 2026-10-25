"""Ker's adjacency HCF-COM (2005): centre of mass of the 2-D DFT of the
histogram of horizontally adjacent value pairs, per RGB channel, averaged.
LSB matching smooths that histogram, lowering the COM. Reports the mean
stego-minus-cover shift and how many covers' own spread it is."""
import glob, os, sys, numpy as np
from concurrent.futures import ProcessPoolExecutor
from PIL import Image
def com(path):
    a = np.asarray(Image.open(path).convert("RGB")).astype(np.int64)
    out = []
    for c in range(3):
        x = a[:, :, c]
        h = np.bincount((x[:, :-1] * 256 + x[:, 1:]).ravel(), minlength=65536).reshape(256, 256).astype(float)
        H = np.abs(np.fft.fft2(h))[:129, :129]
        k = np.arange(129)
        out.append(((k[:, None] + k[None, :]) * H).sum() / H.sum())
    return np.mean(out)
if __name__ == "__main__":
    bases = sorted(os.path.basename(p)[:-4] for p in glob.glob("cover/*.png"))
    with ProcessPoolExecutor(10) as ex:
        cov = np.array(list(ex.map(com, [f"cover/{b}.png" for b in bases])))
        print(f"cover COM mean {cov.mean():.3f} sd {cov.std():.3f}")
        for bpp in (0.05, 0.1, 0.2, 0.4):
            for tool in ("ss", "hill"):
                st = np.array(list(ex.map(com, [f"stego/{tool}_png_{bpp}/{b}.png" for b in bases])))
                d = st - cov
                print(f"{tool:5} {bpp:<5} shift {d.mean():+.3f} (sd {d.std():.3f}; {abs(d.mean())/cov.std():.3f} cover sds)", flush=True)
