"""The covers: each JPEG in RAW (fetch_images.py's downloads), resized with
Lanczos so its short side is 512, the centre 512x512 cropped, and saved by
Pillow at quality 75 (4:2:0, no metadata), into cover/ here.
Usage: prepare_covers.py RAW"""
import os, sys
from PIL import Image
src = sys.argv[1]
os.makedirs("cover", exist_ok=True)
for f in sorted(os.listdir(src)):
    if not f.endswith(".jpg"): continue
    im = Image.open(os.path.join(src, f)).convert("RGB")
    s = 512 / min(im.size)
    im = im.resize((max(512, round(im.width * s)), max(512, round(im.height * s))), Image.LANCZOS)
    l, t = (im.width - 512) // 2, (im.height - 512) // 2
    im.crop((l, t, l + 512, t + 512)).save(os.path.join("cover", f), quality=75)
