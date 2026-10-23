"""Downloads photos from Wikimedia Commons (for local benchmarking only, not
redistributed) and makes 512x512 grayscale crops, like BOSSbase."""
import json, os, sys, time, urllib.parse, urllib.request, subprocess
UA = {"User-Agent": "scattersteg-benchmark/0.1 (local research; mc.demontbron@gmail.com)"}
def get(url):
    return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60).read()
cats = ["Category:Featured_pictures_of_landscapes", "Category:Featured_pictures_of_animals",
        "Category:Featured_pictures_of_architecture", "Category:Featured_pictures_of_plants",
        "Category:Featured_pictures_of_people", "Category:Featured_pictures_of_objects"]
want = int(sys.argv[1]); out = "images"; os.makedirs(out, exist_ok=True); os.makedirs("raw", exist_ok=True)
n = len(os.listdir(out))
for cat in cats:
    cont = ""
    while n < want:
        q = {"action": "query", "format": "json", "generator": "categorymembers", "gcmtitle": cat, "gcmtype": "file",
             "gcmlimit": "50", "prop": "imageinfo", "iiprop": "url|mime", "iiurlwidth": "1000"}
        if cont: q["gcmcontinue"] = cont
        d = json.loads(get("https://commons.wikimedia.org/w/api.php?" + urllib.parse.urlencode(q)))
        for p in d.get("query", {}).get("pages", {}).values():
            ii = (p.get("imageinfo") or [{}])[0]
            if ii.get("mime") != "image/jpeg" or not ii.get("thumburl"): continue
            raw = f"raw/{p['pageid']}.jpg"
            try:
                if not os.path.exists(raw): open(raw, "wb").write(get(ii["thumburl"])); time.sleep(0.3)
            except Exception as e:
                print("skip", p["pageid"], e); continue
            dst = f"{out}/{p['pageid']}.pgm"
            if subprocess.run(["convert", raw, "-colorspace", "Gray", "-resize", "x640^", "-gravity", "center", "-crop", "512x512+0+0", "+repage", "-depth", "8", dst]).returncode == 0:
                n += 1
            if n >= want: break
        cont = d.get("continue", {}).get("gcmcontinue", "")
        print(cat, n, flush=True)
        if not cont: break
    if n >= want: break
print("images:", n)
