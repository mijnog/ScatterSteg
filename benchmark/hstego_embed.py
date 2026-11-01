"""Embeds N random bytes into COVER with HStego (github.com/daniellerch/hstego),
for the benchmarks' comparison: J-UNIWARD with cost polarization for JPEG,
S-UNIWARD for PNG, STC for both.
Usage (HStego's own environment, e.g. python -I): hstego_embed.py COVER OUT N

HStego caps a message at 0.05 bits per non-zero coefficient (or pixel); the
cap is lifted here so it can be measured at the same payloads as ScatterSteg.
It compresses every message, so the bytes are random: they don't shrink, and
the payload is N bytes plus its own overhead, as ScatterSteg's is with -Z."""
import os, sys, tempfile
import hstegolib

hstegolib.MAX_PAYLOAD = 1.0
cover, out, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
with tempfile.NamedTemporaryFile(dir=os.path.dirname(os.path.abspath(out)), suffix=".msg") as m:
    m.write(os.urandom(n))
    m.flush()
    tool = hstegolib.J_UNIWARD() if cover.lower().endswith((".jpg", ".jpeg")) else hstegolib.S_UNIWARD()
    tool.embed(cover, m.name, "benchmark passphrase 1234", out)
