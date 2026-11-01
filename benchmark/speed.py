"""Wall time, CPU time and peak memory of one scattersteg embed or extract,
for the "Speed" note in README.md. Each case runs in a fresh process, so
RUSAGE_CHILDREN is that run's own (what GNU time -v prints as "Maximum
resident set size" and the CPU times; wait4 gives the same figures).

Usage: speed.py BINARY embed COVER OUT BYTES    (a random BYTES-byte message, -Z;
                                                 kept in OUT.msg)
       speed.py BINARY extract STEGO OUT         (checked against STEGO.msg)
Prints one line: wall seconds, user+system CPU seconds, peak MiB, exit code,
and for extract whether the message came back exactly."""
import os, resource, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tests"))
import test_cli as T

T.TIMEOUT = 3600
PW = ["benchmark passphrase 1234"]
binary, op = sys.argv[1], sys.argv[2]
t0 = time.monotonic()
if op == "embed":
    cover, out, n = sys.argv[3], sys.argv[4], int(sys.argv[5])
    msg = os.urandom(n)
    with open(out + ".msg", "wb") as f: f.write(msg)
    code, log = T.run(["embed", "-cf", cover, "-sf", out, "-Z", "-f", "-q"],
                      message=msg, passphrases=PW * 2, binary=binary)
else:
    stego, out = sys.argv[3], sys.argv[4]
    code, log = T.run(["extract", "-sf", stego, "-xf", out, "-f", "-q"], passphrases=PW, binary=binary)
wall = time.monotonic() - t0
r = resource.getrusage(resource.RUSAGE_CHILDREN)
exact = ""
if op == "extract" and code == 0:
    same = open(out, "rb").read() == open(stego + ".msg", "rb").read()
    exact = ", message back exactly" if same else ", MESSAGE DIFFERS"
print("%.1f s wall, %.1f s CPU, %d MiB peak, exit %d%s%s" % (
    wall, r.ru_utime + r.ru_stime, r.ru_maxrss // 1024, code, exact,
    "" if code == 0 else " " + log.strip().splitlines()[-1][:80]))
