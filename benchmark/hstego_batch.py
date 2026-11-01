"""Embeds with HStego (github.com/daniellerch/hstego) for many covers in one
process, so numba compiles J-UNIWARD's costs once rather than per image (a
few seconds each). Each line of LIST is "COVER OUT BYTES"; the message is
BYTES random bytes, as in hstego_embed.py (which explains why random, and
why HStego's 0.05 cap is lifted). Prints "ok OUT" or "FAIL OUT why" per line.
Usage (HStego's own environment, e.g. python -I): hstego_batch.py LIST"""
import os, sys, tempfile
import hstegolib

hstegolib.MAX_PAYLOAD = 1.0
for line in open(sys.argv[1]):
    cover, out, n = line.split()
    tmp = out + ".tmp.jpg"
    try:
        with tempfile.NamedTemporaryFile(dir=os.path.dirname(os.path.abspath(out)), suffix=".msg") as m:
            m.write(os.urandom(int(n)))
            m.flush()
            tool = hstegolib.J_UNIWARD() if cover.lower().endswith((".jpg", ".jpeg")) else hstegolib.S_UNIWARD()
            tool.embed(cover, m.name, "benchmark passphrase 1234", tmp)
        os.rename(tmp, out)
        print("ok", out, flush=True)
    except Exception as e:  # a cover HStego can't take: reported, left out
        print("FAIL", out, repr(e)[:100], flush=True)
