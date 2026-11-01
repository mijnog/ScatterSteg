"""How many coefficients each build changes, on the same JPEG covers: embeds a
random message of PAYLOAD bits per non-zero AC coefficient into each of the
first N covers with each build, and counts the coefficients that differ.
Changes are what the coder minimizes; detection is what counts, so read the
numbers as a guide to the coder, not as stealth.

Usage: count_changes.py COVERDIR N PAYLOAD,PAYLOAD,... NAME=BINARY ...
       (DUMPCOEF=path to ../dumpcoef; the first NAME is the baseline)
Prints, per payload, each build's total and its saving against the baseline."""
import glob, os, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tests"))
sys.path.insert(0, HERE)
import test_cli as T, detect

coverdir, n_covers, payloads = sys.argv[1], int(sys.argv[2]), [float(x) for x in sys.argv[3].split(",")]
builds = dict(a.split("=", 1) for a in sys.argv[4:])
covers = sorted(glob.glob(os.path.join(coverdir, "*.jpg")))[:n_covers]
base_name = next(iter(builds))
for bp in payloads:
    total = {}
    for name, binary in builds.items():
        total[name] = 0
        for f in covers:
            before = detect.read_coefs(f)
            nz = sum(int((c != 0).sum()) - int((c[:, :, 0, 0] != 0).sum()) for c in before)
            out = tempfile.mktemp(suffix=".jpg")
            code, log = T.run(["embed", "-cf", f, "-sf", out, "-Z", "-f", "-q"], message=os.urandom(int(bp * nz / 8)),
                              passphrases=["benchmark passphrase 1234"] * 2, binary=binary)
            if code:
                print("FAIL", name, f, log.strip().splitlines()[-1][:60])
                continue
            after = detect.read_coefs(out)
            os.remove(out)
            total[name] += sum(int((a != b).sum()) for a, b in zip(before, after))
    base = total[base_name]
    print("%.2f bits per non-zero AC, %d covers: " % (bp, len(covers)) + "; ".join(
        "%s %d%s" % (n, t, "" if n == base_name else " (%.1f%% fewer)" % (100 * (1 - t / base)))
        for n, t in total.items()), flush=True)
