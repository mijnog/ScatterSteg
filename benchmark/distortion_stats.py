"""Changes per image and PSNR (PNG), changed coefficients and the share at
|value| 2 (JPEG), for the stego dirs score_models.py scores. Run in the
benchmark directory, after embed_png.py / embed_jpg.py."""
import glob, os, sys, numpy as np
from PIL import Image
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import detect
bases = sorted(os.path.basename(p)[:-4] for p in glob.glob("cover/*.png"))
for tool in ("hill", "wow", "suniward"):
    for bp in ("0.05", "0.1", "0.2", "0.4"):
        ch, ps = [], []
        for b in bases:
            c = np.asarray(Image.open(f"cover/{b}.png"), dtype=np.int16); s = np.asarray(Image.open(f"stego/{tool}_png_{bp}/{b}.png"), dtype=np.int16)
            d = s - c; ch.append(np.count_nonzero(d)); mse = np.mean(d.astype(float) ** 2)
            ps.append(10 * np.log10(255 ** 2 / mse) if mse else np.inf)
        print(f"png {tool:9s} {bp:5s} changes/image {np.mean(ch):8.0f}  PSNR {np.median(ps):.1f} dB (median)")
for tool in ("uerd", "juniward"):
    for bp in ("0.05", "0.1", "0.2", "0.3"):
        ch, two = [], []
        for b in bases:
            p = f"stego/{tool}_jpg_{bp}/{b}.jpg"
            if not os.path.exists(p): continue
            cc = detect.read_coefs(f"cover/{b}.jpg"); ss = detect.read_coefs(p)
            ch.append(sum(int(np.count_nonzero(x != y)) for x, y in zip(cc, ss)))
            two.append(sum(int(np.count_nonzero((x != y) & (np.abs(x) == 2))) for x, y in zip(cc, ss)))
        print(f"jpg {tool:9s} {bp:5s} changed coefficients/image {np.mean(ch):7.0f}  of them at |2| {100*np.sum(two)/np.sum(ch):4.1f}%")
