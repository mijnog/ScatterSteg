#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Maxime de Montbron
"""Runs the C and Rust binaries on the same odd covers and checks they agree
on whether each loads. An image written by one must decode with the other,
and that starts with both reading the same files.

    SCATTERSTEG_C=./scattersteg SCATTERSTEG_RUST=rust/target/release/scattersteg \\
        JPEG_FIXTURE=tests/build/jpeg_fixture python3 tests/differential.py

Each file is given to `decode` with a wrong passphrase: "could not load" means
the file was refused, anything else means it loaded.
"""

import os
import random
import struct
import subprocess
import sys
import tempfile
import zlib
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_cli as T  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
C = os.environ.get("SCATTERSTEG_C", os.path.join(HERE, "..", "scattersteg"))
RUST = os.environ.get("SCATTERSTEG_RUST", os.path.join(HERE, "..", "rust", "target", "release", "scattersteg"))

# Where the two are known to differ, on purpose (see rust/README.md)
# Rust loads these and C refuses (never the reverse)
EXPECTED = {
    "bad_adler": "the png crate doesn't check the zlib Adler-32",
    "name_61626364": "newer libpng refuses a lowercase third letter; Rust loads and drops the chunk",
    "name_70726956": "likewise",
}

SIG = b"\x89PNG\r\n\x1a\n"
ch = T._chunk
W = H = 64


def ihdr(w=W, h=H, depth=8, ctype=2, interlace=0):
    return ch(b"IHDR", struct.pack(">IIBBBBB", w, h, depth, ctype, 0, 0, interlace))


def raw(w=W, h=H, c=3):
    return b"".join(b"\0" + bytes((x * 7 + y * 3 + k) & 255 for x in range(w) for k in range(c)) for y in range(h))


def idat(w=W, h=H, c=3):
    return ch(b"IDAT", zlib.compress(raw(w, h, c)))


def png(pre=b"", post=b"", **kw):
    return SIG + ihdr(**kw) + pre + idat() + post + ch(b"IEND", b"")


def png_cases():
    z = zlib.compress(raw())
    acTL = lambda n: ch(b"acTL", struct.pack(">II", n, 0))
    fcTL = lambda seq, w, h, x=0, y=0: ch(b"fcTL", struct.pack(">IIIIIHHBB", seq, w, h, x, y, 1, 10, 0, 0))
    c = {
        "base": png(),
        "gray": SIG + ihdr(ctype=0) + idat(c=1) + ch(b"IEND", b""),
        "no_iend": SIG + ihdr() + idat(),
        "truncated": png()[:-20],
        "extra_zlib": SIG + ihdr() + ch(b"IDAT", zlib.compress(raw() + b"\0" * 500)) + ch(b"IEND", b""),
        "short_zlib": SIG + ihdr() + ch(b"IDAT", zlib.compress(raw(h=H - 3))) + ch(b"IEND", b""),
        "bad_adler": SIG + ihdr() + ch(b"IDAT", z[:-1] + bytes([z[-1] ^ 1])) + ch(b"IEND", b""),
        "bad_filter": SIG + ihdr() + ch(b"IDAT", zlib.compress(b"".join(b"\x09" + b"\0" * (W * 3) for _ in range(H)))) + ch(b"IEND", b""),
        "two_ihdr": SIG + ihdr() + ihdr() + idat() + ch(b"IEND", b""),
        "ihdr_after_idat": png(post=ch(b"IHDR", b"\0" * 13)),
        "idat_split_gap": SIG + ihdr() + ch(b"IDAT", z[:50]) + ch(b"tEXt", b"a\0b") + ch(b"IDAT", z[50:]) + ch(b"IEND", b""),
        "idat_len0": SIG + ihdr() + ch(b"IDAT", b"") + idat() + ch(b"IEND", b""),
        "ihdr_badcrc": SIG + ihdr()[:-1] + b"\0" + idat() + ch(b"IEND", b""),
        "idat_badcrc": SIG + ihdr() + idat()[:-1] + b"\0" + ch(b"IEND", b""),
        "iend_badcrc": SIG + ihdr() + idat() + ch(b"IEND", b"")[:-1] + b"\0",
        "trailing_junk": png() + b"junk" * 10,
        "crit_unknown": png(pre=ch(b"ABCD", b"xx")),
        "crit_unknown_badcrc": png(pre=ch(b"JECt", b"xx")[:-1] + b"\0"),
        "interlace2": png(interlace=2),
        "depth3": png(depth=3),
        "ihdr_w0": SIG + ihdr(0, H) + idat() + ch(b"IEND", b""),
        "plte_in_rgb": png(pre=ch(b"PLTE", b"\0" * 30)),
        "plte_bad_len_rgb": png(pre=ch(b"PLTE", b"\0" * 31)),
        "plte_dup": png(pre=ch(b"PLTE", b"\0" * 30) * 2),
        "plte_not_whole_entries_idx": SIG + ihdr(ctype=3) + ch(b"PLTE", b"\0" * 13) + ch(b"tRNS", b"\xff\x80\0") + idat(c=1) + ch(b"IEND", b""),
        "plte_empty_idx": SIG + ihdr(ctype=3) + ch(b"PLTE", b"") + idat(c=1) + ch(b"IEND", b""),
        "plte_too_big_idx": SIG + ihdr(ctype=3, depth=1) + ch(b"PLTE", b"\0" * 9) + idat(c=1) + ch(b"IEND", b""),
        "trns_rgb": png(pre=ch(b"tRNS", b"\0" * 6)),
        "trns_bad_len": png(pre=ch(b"tRNS", b"\0" * 3)),
        "trns_dup": png(pre=ch(b"tRNS", b"\0" * 6) * 2),
        "rgba": SIG + ihdr(ctype=6) + idat(c=4) + ch(b"IEND", b""),
        "gray16": SIG + ihdr(depth=16, ctype=0) + ch(b"IDAT", zlib.compress(raw(c=2))) + ch(b"IEND", b""),
        "chunk_after_iend": png() + ch(b"tEXt", b"a\0b"),
    }
    for name, data in {
        "gAMA_bad": ch(b"gAMA", b"\0\0"), "gAMA_dup": ch(b"gAMA", b"\0\0\0\1") * 2,
        "cHRM_bad": ch(b"cHRM", b"\0" * 5), "pHYs_bad": ch(b"pHYs", b"\0"),
        "pHYs_unit9": ch(b"pHYs", b"\0" * 8 + b"\x09"), "sRGB_val9": ch(b"sRGB", b"\x09"),
        "sBIT_bad": ch(b"sBIT", b"\x09\x09\x09"), "tIME_bad": ch(b"tIME", b"\0"),
        "iCCP_bad": ch(b"iCCP", b"junk"), "zTXt_bad": ch(b"zTXt", b"k\0\0garbage"),
        "tEXt_empty": ch(b"tEXt", b""), "sPLT_bad": ch(b"sPLT", b"n\0\x07"),
        "acTL_short": ch(b"acTL", b"\0\0"), "acTL_zero": acTL(0), "acTL_dup": acTL(1) * 2,
        "fcTL_first_ok": acTL(1) + fcTL(0, W, H), "fcTL_first_small": acTL(1) + fcTL(0, 32, 32),
        "fcTL_offset": acTL(1) + fcTL(0, W, H, 5, 5), "fcTL_short": acTL(1) + ch(b"fcTL", b"\0" * 5),
    }.items():
        c[name] = png(pre=data)
    for nm in (b"abcd", b"abCd", b"a_cd", b"ab\0d", b"te1t", b"priV", b"a\xe9bc"):
        c["name_" + nm.hex()] = png(pre=ch(nm, b"xx"))
    return c


def mutated_pngs(n=60, seed=7):
    base = png(pre=ch(b"gAMA", b"\0\0\xb1\x8f") + ch(b"pHYs", b"\0\0\x0e\xc4\0\0\x0e\xc4\1") + ch(b"tEXt", b"k\0value"))
    rng = random.Random(seed)
    out = {}
    for i in range(n):
        b = bytearray(base)
        r = rng.random()
        if r < .5:
            for _ in range(rng.randint(1, 3)):
                b[rng.randrange(8, 140)] = rng.randrange(256)
        elif r < .75:
            p = rng.randrange(8, 140)
            del b[p:p + rng.randint(1, 12)]
        else:
            p = rng.randrange(8, 140)
            b[p:p] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 12)))
        out[f"mutated_png_{i}"] = bytes(b)
    return out


def jpeg_cases(tmp):
    fixture = os.environ.get("JPEG_FIXTURE", os.path.join(HERE, "build", "jpeg_fixture"))
    out = {}
    rng = random.Random(5)
    for nm, opts in (("base", []), ("progressive", ["progressive", "markers"]), ("restart", ["restart"])):
        p = os.path.join(tmp, nm + ".jpg")
        subprocess.run([fixture, p, "200", "150", "3", "90", *opts], check=True)
        d = open(p, "rb").read()
        out[f"jpeg_{nm}"] = d
        for frac in (0.3, 0.6, 0.99):
            out[f"jpeg_{nm}_trunc{frac}"] = d[:int(len(d) * frac)]
        out[f"jpeg_{nm}_noeoi"] = d[:-2]
        out[f"jpeg_{nm}_eoi_junk"] = d + b"\xff\xd9junk"
        for i in range(6):
            b = bytearray(d)
            b[rng.randrange(len(b) // 3, len(b) - 2)] = rng.randrange(256)
            out[f"jpeg_{nm}_flip{i}"] = bytes(b)
    p = os.path.join(tmp, "many.jpg")
    subprocess.run([fixture, p, "64", "64", "3", "90", "progressive", "manyscans"], check=True)
    out["jpeg_manyscans"] = open(p, "rb").read()
    # Regressions the fuzzers found, both implementations
    for d in (os.path.join(HERE, "fuzz", "regressions", "jpeg_load"),
              os.path.join(HERE, "..", "rust", "fuzz", "regressions", "jpeg_load")):
        if os.path.isdir(d):
            for f in sorted(os.listdir(d)):
                out["fuzzreg_" + f] = open(os.path.join(d, f), "rb").read()
    return out


def loads(binary, path):
    code, log = T.run(["decode", "-i", path], passphrases=["wrong-passphrase-12"], binary=binary)
    return "could not load" not in log, code


def main():
    with tempfile.TemporaryDirectory() as tmp:
        cases = {**png_cases(), **mutated_pngs(), **jpeg_cases(tmp)}
        files = {}
        for name, data in cases.items():
            ext = ".jpg" if name.startswith(("jpeg_", "fuzzreg_")) else ".png"
            files[name] = os.path.join(tmp, name + ext)
            with open(files[name], "wb") as f:
                f.write(data)

        def one(name):
            return name, loads(C, files[name]), loads(RUST, files[name])

        bad = []
        with ThreadPoolExecutor(4) as ex:
            for name, c, r in ex.map(one, files):
                if c != r:
                    if name in EXPECTED and not c[0] and r[0]:
                        print(f"expected  {name}: C={c} Rust={r}  ({EXPECTED[name]})")
                    else:
                        bad.append(name)
                        print(f"MISMATCH  {name}: C={c} Rust={r}")
        print(f"{len(files)} files, {len(bad)} unexpected differences")
        return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
