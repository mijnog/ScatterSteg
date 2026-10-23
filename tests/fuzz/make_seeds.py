#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Maxime de Montbron
"""Writes a seed corpus for fuzz_png_load: small valid PNGs of every color
type, bit depth and interlace mode, plus ancillary chunks (tRNS, gAMA,
tEXt), so the fuzzer starts from inputs that reach every decode path."""

import os
import struct
import sys
import zlib

DEPTHS = {0: (1, 2, 4, 8, 16), 2: (8, 16), 3: (1, 2, 4, 8), 4: (8, 16), 6: (8, 16)}
CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
ADAM7 = [(0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4),
         (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2)]  # x0, y0, dx, dy


def chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def pack_row(samples, depth):
    if depth == 16:
        return b"".join(struct.pack(">H", s) for s in samples)
    if depth == 8:
        return bytes(samples)
    out, acc, nbits = bytearray(), 0, 0
    for s in samples:
        acc = (acc << depth) | s
        nbits += depth
        if nbits == 8:
            out.append(acc)
            acc = nbits = 0
    if nbits:
        out.append(acc << (8 - nbits))
    return bytes(out)


def scanlines(w, h, ctype, depth, coords):
    """coords: list of rows, each a list of (x, y) pixels in that scanline"""
    maxv = (1 << depth) - 1
    raw = b""
    for row in coords:
        samples = []
        for x, y in row:
            for c in range(CHANNELS[ctype]):
                samples.append((x * 37 + y * 11 + c * 101) % (maxv + 1) if ctype != 3
                               else (x + y) % min(4, maxv + 1))
        raw += b"\x00" + pack_row(samples, depth)
    return raw


def make(w, h, ctype, depth, interlace, extras=b""):
    if interlace:
        raw = b""
        for x0, y0, dx, dy in ADAM7:
            xs, ys = range(x0, w, dx), range(y0, h, dy)
            if xs and ys:
                raw += scanlines(w, h, ctype, depth, [[(x, y) for x in xs] for y in ys])
    else:
        raw = scanlines(w, h, ctype, depth, [[(x, y) for x in range(w)] for y in range(h)])
    out = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, depth, ctype, 0, 0, interlace))
    if ctype == 3:
        out += chunk(b"PLTE", bytes([255, 0, 0, 0, 255, 0, 0, 0, 255, 10, 20, 30]))
    out += extras + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")
    return out


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    n = 0
    for ctype, depths in DEPTHS.items():
        for depth in depths:
            for interlace in (0, 1):
                for w, h in ((1, 1), (5, 3), (13, 9)):
                    with open(os.path.join(outdir, f"c{ctype}_d{depth}_i{interlace}_{w}x{h}.png"), "wb") as f:
                        f.write(make(w, h, ctype, depth, interlace))
                    n += 1
    extras = {
        "trns_palette": (3, 8, chunk(b"tRNS", bytes([255, 128, 0]))),
        "trns_gray": (0, 8, chunk(b"tRNS", struct.pack(">H", 5))),
        "trns_rgb": (2, 8, chunk(b"tRNS", struct.pack(">HHH", 1, 2, 3))),
        "gama_text": (2, 8, chunk(b"gAMA", struct.pack(">I", 45455)) + chunk(b"tEXt", b"Comment\x00hi")),
    }
    for name, (ctype, depth, ex) in extras.items():
        with open(os.path.join(outdir, name + ".png"), "wb") as f:
            f.write(make(7, 5, ctype, depth, 0, ex))
        n += 1
    print(f"wrote {n} seeds to {outdir}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "tests/build/corpus/png_load")
