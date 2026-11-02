#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (C) 2026 Maxime de Montbron
"""Runs tests/test_cli.py in N shards, as parallel processes.

Each shard is `python3 tests/test_cli.py <test ids>`, with this process's
environment (SCATTERSTEG, SCATTERSTEG_FAULT, ...), so every test runs exactly
once, as it would alone: its own temp directory and terminal, the same
assertions. Tests go to shards longest first, by the times recorded in
tests/durations.json for the profile (c: the sanitizer builds; rust: the
Rust release builds); a test with no recorded time counts as 1 s. Exits 1
if any shard fails, or if the shards didn't run every test once.

Usage: run_sharded.py [-j N] [--profile c|rust] [--record]
  -j N       shards (default 6); 1 runs test_cli.py as one process
  --record   also time every test, and write those times to the profile
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SUITE = os.path.join(HERE, "test_cli.py")
TIMES = os.path.join(HERE, "durations.json")


def test_ids():
    """Every test in test_cli.py, as Class.method"""
    sys.path.insert(0, HERE)
    import test_cli
    suite = unittest.defaultTestLoader.loadTestsFromModule(test_cli)
    ids = []

    def walk(s):
        for t in s:
            if isinstance(t, unittest.TestSuite):
                walk(t)
            else:
                ids.append(t.id().split(".", 1)[1])  # drop the module name
    walk(suite)
    return ids


def shard(ids, times, n):
    """Longest first, each to the shard with the least time so far"""
    shards = [[] for _ in range(n)]
    load = [0.0] * n
    for t in sorted(ids, key=lambda t: -times.get(t, 1.0)):
        i = load.index(min(load))
        shards[i].append(t)
        load[i] += times.get(t, 1.0)
    return [s for s in shards if s], load


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("-j", type=int, default=6)
    ap.add_argument("--profile", default="c")
    ap.add_argument("--record", action="store_true")
    a = ap.parse_args()
    if a.j < 1:
        sys.exit("-j must be at least 1")
    if a.j == 1 and not a.record:
        sys.exit(subprocess.call([sys.executable, SUITE]))

    ids = test_ids()
    profiles = {}
    if os.path.exists(TIMES):
        with open(TIMES) as f:
            profiles = json.load(f)
    shards, load = shard(ids, profiles.get(a.profile, {}), a.j)

    start = time.monotonic()
    procs = []
    for i, s in enumerate(shards):
        out = tempfile.TemporaryFile()
        args = [sys.executable, SUITE] + (["--durations", "0"] if a.record else []) + s
        procs.append((i, s, out, subprocess.Popen(args, stdout=out, stderr=subprocess.STDOUT)))
    failed, ran, recorded = [], 0, {}
    for i, s, out, p in procs:
        code = p.wait()
        out.seek(0)
        text = out.read().decode(errors="replace")
        m = re.search(r"^Ran (\d+) tests? in ([\d.]+)s$", text, re.M)
        n = int(m.group(1)) if m else 0
        ran += n
        status = "ok" if code == 0 and n == len(s) else "FAILED"
        print("== shard %d/%d: %d tests, %s s, %s" % (i + 1, len(shards), n, m.group(2) if m else "?", status))
        if status != "ok":
            failed.append(i + 1)
            print(text)
        if a.record:
            part = text.split("Slowest test durations", 1)[-1]
            for secs, name, cls in re.findall(r"^([\d.]+)s\s+(\S+) \(__main__\.(\w+)\.", part, re.M):
                recorded["%s.%s" % (cls, name)] = float(secs)
    wall = time.monotonic() - start
    print("%d tests in %d shards, %.1f s (longest shard planned %.1f s)" % (ran, len(shards), wall, max(load)))

    if ran != len(ids):
        print("ran %d tests, the suite has %d" % (ran, len(ids)))
        return 1
    if failed:
        print("FAILED shards: %s" % ", ".join(map(str, failed)))
        return 1
    if a.record:
        if set(recorded) != set(ids):
            print("--record: no time for %s" % sorted(set(ids) - set(recorded)))
            return 1
        profiles[a.profile] = {t: recorded[t] for t in sorted(recorded)}
        with open(TIMES, "w") as f:
            json.dump(profiles, f, indent=1, sort_keys=True)
            f.write("\n")
        print("recorded %d times in %s (%s)" % (len(recorded), TIMES, a.profile))
    return 0


if __name__ == "__main__":
    sys.exit(main())
