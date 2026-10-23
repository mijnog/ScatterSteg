#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Maxime de Montbron
"""End-to-end tests for the scattersteg binary.

The passphrase is read from /dev/tty, so each run gets a pseudo-terminal
and the test answers the prompts on it; the message goes in on stdin.
Uses only the standard library (PNGs are written and parsed by hand).
"""

import ctypes
import ctypes.util
import hashlib
import os
import pty
import select
import signal
import stat
import struct
import sys
import tempfile
import termios
import time
import unittest
import zlib

BINARY = os.environ.get(
    "SCATTERSTEG",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scattersteg"))
TIMEOUT = 60  # seconds per run; Argon2id takes a fraction of that


FAULT_BINARY = os.environ.get("SCATTERSTEG_FAULT")  # built with tests/fault.h
JPEG_FIXTURE = os.environ.get(
    "JPEG_FIXTURE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "build", "jpeg_fixture"))


def make_jpeg(path, w, h, comps=3, quality=85, *options):
    """A test JPEG from tests/jpeg_fixture.c (see there for the options)"""
    import subprocess
    subprocess.run([JPEG_FIXTURE, path, str(w), str(h), str(comps), str(quality), *options],
                   check=True)


def jpeg_segments(path):
    """[(marker, payload), ...] for the header segments before the first scan"""
    with open(path, "rb") as f:
        data = f.read()
    assert data[:2] == b"\xff\xd8"
    out, pos = [], 2
    while pos + 4 <= len(data) and data[pos] == 0xFF:
        marker = data[pos + 1]
        length = int.from_bytes(data[pos + 2:pos + 4], "big")
        out.append((marker, data[pos + 4:pos + 2 + length]))
        if marker == 0xDA:  # start of scan: entropy-coded data follows
            break
        pos += 2 + length
    return out


def run(args, message=b"", passphrases=(), env=None, binary=None, typed=None,
        stdin_path=None, stdout_path=None):
    """Run scattersteg, answer each passphrase prompt in order. The message
    goes in on stdin (from the file stdin_path, if given), or with `typed`,
    is typed at the terminal instead. stdout goes to the terminal, or to
    the file stdout_path.
    Returns (exit_code, combined stdout+stderr as text)."""
    binary = binary or BINARY
    with tempfile.TemporaryFile() as stdin:
        stdin.write(message)
        stdin.flush()
        stdin.seek(0)
        pid, master = pty.fork()
        if pid == 0:
            if stdin_path is not None:
                os.dup2(os.open(stdin_path, os.O_RDONLY), 0)
            elif typed is None:
                os.dup2(stdin.fileno(), 0)
            if stdout_path is not None:
                os.dup2(os.open(stdout_path, os.O_WRONLY), 1)
            os.execve(binary, [binary] + list(args), {**os.environ, **(env or {})})

    answers = list(passphrases)
    out = b""
    answered = 0
    typed_done = False
    deadline = time.monotonic() + TIMEOUT
    while True:
        if time.monotonic() > deadline:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
            os.close(master)
            raise TimeoutError("scattersteg timed out; output so far: %r" % out)
        ready, _, _ = select.select([master], [], [], 0.5)
        if not ready:
            continue
        try:
            chunk = os.read(master, 4096)
        except OSError:  # EIO: child closed the terminal
            break
        if not chunk:
            break
        out += chunk
        # Answer only once the prompt is shown: echo is turned off (and
        # pending input flushed) just before it is printed.
        if out.count(b"assphrase: ") > answered:
            answered += 1
            if answers:
                os.write(master, answers.pop(0).encode() + b"\n")
            else:
                os.write(master, b"\x04")  # EOF: no more passphrases to give
        if typed is not None and not typed_done and b"Ctrl+D when done" in out:
            typed_done = True
            os.write(master, typed + b"\n\x04")
    os.close(master)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status), out.decode(errors="surrogateescape").replace("\r\n", "\n")


# ---- minimal PNG writer / reader (8-bit RGB only) ------------------------

def _chunk(kind, data):
    return (struct.pack(">I", len(data)) + kind + data
            + struct.pack(">I", zlib.crc32(kind + data)))


def write_png(path, width, height, pixel, channels=3, extra=b""):
    """pixel(x, y) -> (r, g, b), or (gray,) with channels=1. `extra` is
    raw chunks to put before the image data."""
    raw = b"".join(
        b"\x00" + bytes(c for x in range(width) for c in pixel(x, y))
        for y in range(height))
    ctype = 2 if channels == 3 else 0
    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n"
                + _chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, ctype, 0, 0, 0))
                + extra
                + _chunk(b"IDAT", zlib.compress(raw))
                + _chunk(b"IEND", b""))


def png_chunks(path):
    """[(type, data), ...] for every chunk in the file"""
    with open(path, "rb") as f:
        data = f.read()
    out, pos = [], 8
    while pos < len(data):
        length, kind = struct.unpack(">I4s", data[pos:pos + 8])
        out.append((kind, data[pos + 8:pos + 8 + length]))
        pos += 12 + length
    return out


def read_png(path):
    """Returns (width, height, list of row bytes) for 8-bit RGB or gray,
    non-interlaced. Rows hold width * channels bytes."""
    with open(path, "rb") as f:
        data = f.read()
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    pos, idat = 8, b""
    while pos < len(data):
        length, kind = struct.unpack(">I4s", data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + length]
        if kind == b"IHDR":
            width, height, depth, ctype, _, _, interlace = struct.unpack(">IIBBBBB", body)
            assert depth == 8 and ctype in (0, 2) and interlace == 0
            bpp = 3 if ctype == 2 else 1
        elif kind == b"IDAT":
            idat += body
        pos += 12 + length
    raw = zlib.decompress(idat)
    stride = width * bpp
    rows, prev = [], bytearray(stride)
    for y in range(height):
        ftype = raw[y * (stride + 1)]
        line = bytearray(raw[y * (stride + 1) + 1:(y + 1) * (stride + 1)])
        for i in range(stride):
            a = line[i - bpp] if i >= bpp else 0
            b = prev[i]
            c = prev[i - bpp] if i >= bpp else 0
            if ftype == 1:
                line[i] = (line[i] + a) & 0xFF
            elif ftype == 2:
                line[i] = (line[i] + b) & 0xFF
            elif ftype == 3:
                line[i] = (line[i] + (a + b) // 2) & 0xFF
            elif ftype == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pred = a if pa <= pb and pa <= pc else (b if pb <= pc else c)
                line[i] = (line[i] + pred) & 0xFF
        rows.append(bytes(line))
        prev = line
    return width, height, rows


# ---- independent implementation (libsodium via ctypes) -------------------
# Reimplements the payload format, to build images the binary itself won't
# produce (e.g. an empty message) and to cross-check it in both directions.

_sodium_path = ctypes.util.find_library("sodium")
sodium = ctypes.CDLL(_sodium_path) if _sodium_path else None
if sodium:
    sodium.sodium_init()
    for level in ("interactive", "moderate"):
        getattr(sodium, "crypto_pwhash_opslimit_" + level).restype = ctypes.c_ulonglong
        getattr(sodium, "crypto_pwhash_memlimit_" + level).restype = ctypes.c_size_t
    sodium.crypto_pwhash.argtypes = [
        ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_ulonglong,
        ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_size_t, ctypes.c_int]
    sodium.crypto_stream_chacha20.argtypes = [
        ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_char_p]
    sodium.crypto_stream_chacha20_ietf.argtypes = [
        ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_char_p]
    sodium.crypto_kdf_derive_from_key.argtypes = [
        ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint64, ctypes.c_char_p, ctypes.c_char_p]
    sodium.crypto_secretbox_easy.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_char_p]
    sodium.crypto_secretbox_open_easy.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_char_p]

SALT, NONCE, MAC = 16, 24, 16
SALT_PIXELS = 43  # v2, RGB: 128 salt bits, 3 per pixel (gray: 128)
V2_OVERHEAD = NONCE + MAC


def argon2id(pw, salt, level):
    key = ctypes.create_string_buffer(32)
    assert sodium.crypto_pwhash(
        key, 32, pw, len(pw), salt,
        getattr(sodium, "crypto_pwhash_opslimit_" + level)(),
        getattr(sodium, "crypto_pwhash_memlimit_" + level)(), 2) == 0  # ALG_ARGON2ID13
    return key.raw


def embed_bits(rows, w, order, bits, ch=3):
    for pos, bit in enumerate(bits):
        p = order[pos // ch]
        i = (p % w) * ch + pos % ch
        rows[p // w][i] = (rows[p // w][i] & 0xFE) | bit


def read_bits(rows, w, order, start, n, ch=3):
    out = 0
    for b in range(n):
        p = order[(start + b) // ch]
        out |= (rows[p // w][(p % w) * ch + (start + b) % ch] & 1) << b
    return out


def to_bits(data):
    return [(byte >> b) & 1 for byte in data for b in range(8)]


def length_prefixed(payload):
    return [(len(payload) >> b) & 1 for b in range(32)] + to_bits(payload)


def open_box(box, key):
    nonce, ct = box[:NONCE], box[NONCE:]
    pt = ctypes.create_string_buffer(max(1, len(ct) - MAC))
    if sodium.crypto_secretbox_open_easy(pt, ct, len(ct), nonce, key) != 0:
        return None
    return pt.raw[:len(ct) - MAC]


def seal(message, key):
    nonce = os.urandom(NONCE)
    ct = ctypes.create_string_buffer(MAC + len(message))
    sodium.crypto_secretbox_easy(ct, message, len(message), nonce, key)
    return nonce + ct.raw


def read_payload(rows, w, order, min_len, ch=3):
    n = read_bits(rows, w, order, 0, 32, ch)
    if n < min_len or 32 + n * 8 > len(order) * ch:
        return None
    return bytes(read_bits(rows, w, order, 32 + i * 8, 8, ch) for i in range(n))


# -- v2 (the format encode writes)

class KeyStream:
    """ChaCha20-IETF keystream (zero nonce) read as little-endian uint32s"""

    def __init__(self, key):
        self.key, self.data, self.pos = key, b"", 0

    def u32(self):
        if self.pos + 4 > len(self.data):
            n = max(4096, 2 * len(self.data))
            buf = ctypes.create_string_buffer(n)
            sodium.crypto_stream_chacha20_ietf(buf, n, bytes(12), self.key)
            self.data = buf.raw
        v = int.from_bytes(self.data[self.pos:self.pos + 4], "little")
        self.pos += 4
        return v

    def uniform(self, bound):
        floor = (2**32 - bound) % bound
        while True:
            r = self.u32()
            if r >= floor:
                return r % bound


def permutation_v2(key, count):
    """Forward Fisher-Yates with unbiased draws: prng_permutation"""
    a, s = list(range(count)), KeyStream(key)
    for i in range(count - 1):
        j = i + s.uniform(count - i)
        a[i], a[j] = a[j], a[i]
    return a


def salt_pixel_count(ch):
    return (SALT * 8 + ch - 1) // ch


def salt_pixels_v2(count, ch=3):
    key = hashlib.blake2b(b"ScatterSteg v2 salt positions", digest_size=32).digest()
    return permutation_v2(key, count)[:salt_pixel_count(ch)]


def keys_v2(pw, salt):
    master = argon2id(pw, salt, "moderate")
    subkeys = []
    for subkey_id in (1, 2):  # scatter, encryption
        k = ctypes.create_string_buffer(32)
        sodium.crypto_kdf_derive_from_key(k, 32, subkey_id, b"ScatStg2", master)
        subkeys.append(k.raw)
    return subkeys


def payload_order_v2(scatter_key, count, salt_px):
    taken = set(salt_px)
    return [p for p in permutation_v2(scatter_key, count) if p not in taken]


def layout_v2(rows, w, h, pw):
    """(salt pixels, payload order, encryption key) for an image and passphrase"""
    ch = len(rows[0]) // w
    salt_px = salt_pixels_v2(w * h, ch)
    salt = read_bits(rows, w, salt_px, 0, SALT * 8, ch).to_bytes(SALT, "little")
    scatter_key, enc_key = keys_v2(pw, salt)
    return salt_px, payload_order_v2(scatter_key, w * h, salt_px), enc_key


# -- v3: STC syndrome coding (see stc.h)

STC_H, STC_MAX_W, STC_CHUNK = 7, 64, 1 << 20


def stc_carriers(n_avail, mlen):
    if mlen == 0 or n_avail < mlen:
        return 0
    return mlen * STC_MAX_W if n_avail // mlen >= STC_MAX_W else n_avail


def stc_submatrix(width):
    """splitmix64 columns, top and bottom rows set"""
    mask, s, cols = (1 << 64) - 1, 0x5354432D48415431 ^ width, []
    for _ in range(width):
        s = (s + 0x9E3779B97F4A7C15) & mask
        z = s
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & mask
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & mask
        z ^= z >> 31
        cols.append((z & ((1 << STC_H) - 1)) | 1 | (1 << (STC_H - 1)))
    return cols


def stc_blocks(mlen, n):
    """(first, end) carrier of each message bit's block, and the run length"""
    starts = [i * n // mlen for i in range(mlen + 1)]
    per = max(1, STC_CHUNK // (n // mlen + 1))
    return starts, per


def stc_extract(y, mlen, n):
    cols = stc_submatrix(n // mlen + 1)
    starts, per = stc_blocks(mlen, n)
    m, state = [], 0
    for i in range(mlen):
        if i % per == 0:
            state = 0
        for k in range(starts[i], starts[i + 1]):
            if y[k]:
                state ^= cols[k - starts[i]]
        m.append(state & 1)
        state >>= 1
    return m


def stc_solve(x, m, n):
    """Some y with syndrome m (not the cheapest: a greedy forward pass that
    flips a block's first carrier when its row comes out wrong). Enough to
    build v3 images independently of the binary's Viterbi."""
    y = list(x[:n])
    mlen = len(m)
    cols = stc_submatrix(n // mlen + 1)
    starts, per = stc_blocks(mlen, n)
    state = 0
    for i in range(mlen):
        if i % per == 0:
            state = 0
        for k in range(starts[i], starts[i + 1]):
            if y[k]:
                state ^= cols[k - starts[i]]
        if (state & 1) != m[i]:  # every column has the bottom row set
            y[starts[i]] ^= 1
            state ^= cols[0]
        state >>= 1
    return y


def forge(src, dst, message, passphrase):
    """Embed `message` as v2, the way scattersteg encode does, without its
    checks (so an empty message is allowed). Overwrites LSBs; decoding
    can't tell the difference from LSB matching."""
    w, h, rows = read_png(src)
    rows = [bytearray(r) for r in rows]
    ch = len(rows[0]) // w
    pw = passphrase.encode()
    salt = os.urandom(SALT)
    salt_px = salt_pixels_v2(w * h, ch)
    scatter_key, enc_key = keys_v2(pw, salt)
    embed_bits(rows, w, salt_px, to_bits(salt), ch)
    embed_bits(rows, w, payload_order_v2(scatter_key, w * h, salt_px),
               length_prefixed(seal(message, enc_key)), ch)
    write_png(dst, w, h, lambda x, y: rows[y][x * ch:x * ch + ch], channels=ch)


def forge_v3(src, dst, message, passphrase):
    """Embed `message` in the v3 format encode writes: salt as in v2, a
    32-bit length straight into the first 32 samples, then the box as the
    STC syndrome of the rest"""
    w, h, rows = read_png(src)
    rows = [bytearray(r) for r in rows]
    ch = len(rows[0]) // w
    pw = passphrase.encode()
    salt = os.urandom(SALT)
    salt_px = salt_pixels_v2(w * h, ch)
    scatter_key, enc_key = keys_v2(pw, salt)
    order = payload_order_v2(scatter_key, w * h, salt_px)
    box = seal(message, enc_key)
    embed_bits(rows, w, salt_px, to_bits(salt), ch)
    embed_bits(rows, w, order, [(len(box) >> b) & 1 for b in range(32)], ch)
    samples = len(order) * ch - 32
    mlen = len(box) * 8
    n = stc_carriers(samples, mlen)
    assert n, "message too long"
    x = [read_bits(rows, w, order, 32 + i, 1, ch) for i in range(n)]
    y = stc_solve(x, to_bits(box), n)
    for i in range(n):
        p = order[(32 + i) // ch]
        k = (p % w) * ch + (32 + i) % ch
        rows[p // w][k] = (rows[p // w][k] & 0xFE) | y[i]
    write_png(dst, w, h, lambda x, y: rows[y][x * ch:x * ch + ch], channels=ch)


def reveal(src, passphrase):
    """Extract and decrypt a message independently of the binary: v3 (what
    encode writes), else v2. Returns the plaintext bytes, or None."""
    w, h, rows = read_png(src)
    ch = len(rows[0]) // w
    _, order, enc_key = layout_v2(rows, w, h, passphrase.encode())
    length = read_bits(rows, w, order, 0, 32, ch)
    samples = len(order) * ch - 32
    if V2_OVERHEAD <= length and length * 8 <= samples:
        mlen = length * 8
        n = stc_carriers(samples, mlen)
        y = [read_bits(rows, w, order, 32 + i, 1, ch) for i in range(n)]
        m = stc_extract(y, mlen, n)
        box = bytes(sum(m[i * 8 + b] << b for b in range(8)) for i in range(length))
        pt = open_box(box, enc_key)
        if pt is not None:
            return pt
    payload = read_payload(rows, w, order, V2_OVERHEAD, ch)
    return None if payload is None else open_box(payload, enc_key)


# -- v1 (legacy, decode only in the binary)

def scatter_order_v1(pw, count):
    """Fisher-Yates driven by ChaCha20 keyed on BLAKE2b(pw), with modulo bias"""
    scatter_key = hashlib.blake2b(pw, key=b"scatter", digest_size=32).digest()
    stream = ctypes.create_string_buffer(count * 4)
    sodium.crypto_stream_chacha20(stream, count * 4, bytes(8), scatter_key)
    idx = list(range(count))
    for i in range(count - 1, 0, -1):
        j = int.from_bytes(stream.raw[i * 4:i * 4 + 4], "little") % (i + 1)
        idx[i], idx[j] = idx[j], idx[i]
    return idx


def forge_v1(src, dst, message, passphrase):
    """Embed `message` in the v1 format older versions wrote"""
    w, h, rows = read_png(src)
    rows = [bytearray(r) for r in rows]
    pw = passphrase.encode()
    salt = os.urandom(SALT)
    payload = salt + seal(message, argon2id(pw, salt, "interactive"))
    embed_bits(rows, w, scatter_order_v1(pw, w * h), length_prefixed(payload))
    write_png(dst, w, h, lambda x, y: rows[y][x * 3:x * 3 + 3])


def capacity_v2(w, h, ch=3):
    """Largest message encode accepts for a w x h cover"""
    return ((w * h - salt_pixel_count(ch)) * ch - 32) // 8 - V2_OVERHEAD


def cover_pixel(x, y):
    return ((x * 7) & 0xFF, (y * 5) & 0xFF, ((x ^ y) * 3) & 0xFF)


# ---- tests ---------------------------------------------------------------

class CliBase(unittest.TestCase):
    """Temp dir, cover image and encode/decode helpers; no tests of its own."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.cover = self.path("cover.png")
        write_png(self.cover, 64, 64, cover_pixel)

    def tearDown(self):
        self.tmp.cleanup()

    def path(self, name):
        return os.path.join(self.dir, name)

    def encode(self, message, out, passphrase="correct horse", confirm=None, src=None):
        return run(["encode", "-i", src or self.cover, "-o", out], message,
                   [passphrase, passphrase if confirm is None else confirm])

    def decode(self, src, passphrase="correct horse"):
        return run(["decode", "-i", src], passphrases=[passphrase])

    def assertDecodes(self, src, message, passphrase="correct horse"):
        code, out = self.decode(src, passphrase)
        self.assertEqual(code, 0, out)
        # decode prints the plaintext followed by a newline
        self.assertIn(message + "\n", out)



class CliTest(CliBase):
    # -- happy paths

    def test_roundtrip(self):
        out = self.path("steg.png")
        code, log = self.encode(b"meet at the old bridge\n", out)
        self.assertEqual(code, 0, log)
        self.assertDecodes(out, "meet at the old bridge")

    def test_roundtrip_multiline_utf8(self):
        msg = "line one\nligne deux — été\n\tthird ✓"
        out = self.path("steg.png")
        self.assertEqual(self.encode(msg.encode(), out)[0], 0)
        self.assertDecodes(out, msg)

    def test_roundtrip_binary(self):
        # Every byte value, NUL included, goes in and comes back out
        msg = bytes(range(256)) + b"after the NULs"
        out = self.path("steg.png")
        self.assertEqual(self.encode(msg, out)[0], 0)
        code, log = self.decode(out)
        self.assertEqual(code, 0, log)
        # The pty turns "\n" into "\r\n" (undone by run) and keeps the rest
        self.assertIn(msg.decode(errors="surrogateescape").replace("\r\n", "\n") + "\n", log)

    def test_in_place(self):
        # -i and -o the same file: the atomic save must not clobber the input
        target = self.path("same.png")
        write_png(target, 64, 64, cover_pixel)
        self.assertEqual(self.encode(b"in place", target, src=target)[0], 0)
        self.assertDecodes(target, "in place")

    def test_near_capacity(self):
        # 64x64: 4096 - 43 salt pixels = 4053 px * 3 bits; minus the 32-bit
        # header -> 1515 payload bytes; minus nonce 24 + MAC 16 = 1475
        self.assertEqual(capacity_v2(64, 64), 1475)
        out = self.path("full.png")
        msg = ("x" * 1475).encode()
        code, log = self.encode(msg, out)
        self.assertEqual(code, 0, log)
        self.assertDecodes(out, "x" * 1475)

    def test_samples_change_by_at_most_one(self):
        out = self.path("steg.png")
        self.assertEqual(self.encode(b"some secret", out)[0], 0)
        w, h, before = read_png(self.cover)
        w2, h2, after = read_png(out)
        self.assertEqual((w, h), (w2, h2))
        changed = 0
        for rb, ra in zip(before, after):
            for b, a in zip(rb, ra):
                self.assertLessEqual(abs(a - b), 1)
                changed += b != a
        self.assertGreater(changed, 0)

    def test_scattered_not_sequential(self):
        # Sequential LSB embedding would only touch the first rows
        out = self.path("steg.png")
        self.assertEqual(self.encode(b"spread me out please", out)[0], 0)
        _, h, before = read_png(self.cover)
        _, _, after = read_png(out)
        touched_rows = [y for y in range(h) if before[y] != after[y]]
        self.assertGreater(max(touched_rows), h // 2)

    def test_random_nonce(self):
        a, b = self.path("a.png"), self.path("b.png")
        self.assertEqual(self.encode(b"same message", a)[0], 0)
        self.assertEqual(self.encode(b"same message", b)[0], 0)
        with open(a, "rb") as fa, open(b, "rb") as fb:
            self.assertNotEqual(fa.read(), fb.read())
        self.assertDecodes(a, "same message")
        self.assertDecodes(b, "same message")

    def test_gray_cover_stays_gray(self):
        # A grayscale cover carries 1 bit per pixel and comes out grayscale
        gray = self.path("gray.png")
        write_png(gray, 48, 48, lambda x, y: ((x * 4 + y) & 0xFF,), channels=1)
        out = self.path("steg.png")
        code, log = self.encode(b"from gray", out, src=gray)
        self.assertEqual(code, 0, log)
        ihdr = dict(png_chunks(out))[b"IHDR"]
        self.assertEqual(ihdr[8:10], bytes([8, 0]))  # 8-bit gray
        self.assertDecodes(out, "from gray")
        _, _, before = read_png(gray)
        _, _, after = read_png(out)
        self.assertTrue(all(abs(a - b) <= 1 for rb, ra in zip(before, after) for a, b in zip(ra, rb)))

    def test_gray_capacity(self):
        gray = self.path("gray.png")
        write_png(gray, 40, 40, lambda x, y: ((x * 9 + y * 5) & 0xFF,), channels=1)
        cap = capacity_v2(40, 40, 1)  # (1600 - 128 - 32) / 8 - 40 = 140
        self.assertEqual(cap, 140)
        out = self.path("steg.png")
        self.assertEqual(self.encode(b"g" * cap, out, src=gray)[0], 0)
        self.assertDecodes(out, "g" * cap)
        code, log = self.encode(b"g" * (cap + 1), self.path("over.png"), src=gray)
        self.assertEqual(code, 1, log)
        self.assertIn("too long", log)

    def test_unsuitable_covers_refused(self):
        def raw_png(path, depth, ctype, rows, extra=b""):
            with open(path, "wb") as f:
                f.write(b"\x89PNG\r\n\x1a\n"
                        + _chunk(b"IHDR", struct.pack(">IIBBBBB", 32, 32, depth, ctype, 0, 0, 0))
                        + extra + _chunk(b"IDAT", zlib.compress(rows)) + _chunk(b"IEND", b""))
        palette = _chunk(b"PLTE", bytes([255, 0, 0, 0, 255, 0, 0, 0, 255, 9, 9, 9]))
        cases = {
            "palette": (8, 3, b"".join(b"\x00" + bytes((x + y) % 4 for x in range(32)) for y in range(32)),
                        palette, "has a color palette"),
            "gray 1-bit": (1, 0, b"".join(b"\x00" + bytes([0xAA if y % 2 else 0x55] * 4) for y in range(32)),
                           b"", "has fewer than 8 bits per sample"),
            "gray + tRNS": (8, 0, b"".join(b"\x00" + bytes(range(32)) for y in range(32)),
                            _chunk(b"tRNS", struct.pack(">H", 5)), "has transparency"),
        }
        for name, (depth, ctype, rows, extra, message) in cases.items():
            with self.subTest(cover=name):
                src = self.path("cover-%s.png" % name.replace(" ", "_"))
                raw_png(src, depth, ctype, rows, extra)
                out = self.path("out.png")
                code, log = self.encode(b"x", out, src=src)
                self.assertEqual(code, 1, log)
                self.assertIn(message, log)
                self.assertFalse(os.path.exists(out))

    def test_metadata_kept(self):
        # The output carries the cover's ancillary chunks, so it looks like the
        # same file; unknown chunks not marked safe to copy must be dropped
        # A minimal valid ICC profile: 132-byte header (RGB, XYZ PCS, D50) and
        # an empty tag table. Stored uncompressed: libpng rejects a compressed
        # profile this tiny as "too short", which real profiles never are.
        icc = bytearray(136)
        struct.pack_into(">I", icc, 0, 136)
        icc[8:12] = bytes([2, 0x10, 0, 0])
        icc[12:24] = b"mntrRGB XYZ "
        icc[36:40] = b"acsp"
        struct.pack_into(">iii", icc, 68, 0xF6D6, 0x10000, 0xD32D)
        keep = [
            (b"gAMA", struct.pack(">I", 45455)),
            (b"cHRM", struct.pack(">8I", 31270, 32900, 64000, 33000, 30000, 60000, 15000, 6000)),
            (b"iCCP", b"test profile\x00\x00" + zlib.compress(bytes(icc), 0)),
            (b"pHYs", struct.pack(">IIB", 2835, 2835, 1)),
            (b"tEXt", b"Comment\x00holiday snaps"),
            (b"iTXt", b"Title\x00\x00\x00en\x00Titel\x00Vakantie \xe2\x9c\x93"),
            (b"tIME", struct.pack(">HBBBBB", 2024, 7, 14, 9, 30, 0)),
            (b"eXIf", b"MM\x00\x2a\x00\x00\x00\x08\x00\x00"),
            (b"prVt", b"private, safe to copy"),
        ]
        drop = [(b"prVT", b"private, unsafe to copy")]
        src = self.path("meta.png")
        write_png(src, 64, 64, cover_pixel,
                  extra=b"".join(_chunk(k, d) for k, d in keep + drop))
        out = self.path("steg.png")
        code, log = self.encode(b"with metadata", out, src=src)
        self.assertEqual(code, 0, log)
        chunks = png_chunks(out)
        def normalized(kind, data):
            # Compare the profile decompressed, however it is stored
            if kind == b"iCCP":
                name, rest = data.split(b"\x00", 1)
                return kind, name, zlib.decompress(rest[1:])
            return kind, data
        got = [normalized(k, d) for k, d in chunks]
        for kind, data in keep:
            with self.subTest(chunk=kind):
                self.assertIn(normalized(kind, data), got)
        self.assertNotIn(b"prVT", [k for k, _ in chunks])
        self.assertDecodes(out, "with metadata")

    def test_srgb_kept(self):
        # sRGB and iCCP are alternatives (a file has one or the other)
        src = self.path("srgb.png")
        write_png(src, 32, 32, cover_pixel, extra=_chunk(b"sRGB", bytes([0])))
        out = self.path("steg.png")
        self.assertEqual(self.encode(b"m", out, src=src)[0], 0)
        self.assertIn((b"sRGB", bytes([0])), png_chunks(out))

    def test_odd_text_chunk_copied_verbatim(self):
        # libpng reads a tEXt chunk with an empty keyword but won't write one
        # it made itself (found by fuzzing); copied as raw bytes, it is kept
        # as the cover had it
        src = self.path("badtext.png")
        write_png(src, 64, 64, cover_pixel,
                  extra=_chunk(b"tEXt", b"\x00no keyword") + _chunk(b"tEXt", b"Fine\x00kept"))
        out = self.path("steg.png")
        code, log = self.encode(b"despite bad text", out, src=src)
        self.assertEqual(code, 0, log)
        chunks = png_chunks(out)
        self.assertIn((b"tEXt", b"Fine\x00kept"), chunks)
        self.assertIn((b"tEXt", b"\x00no keyword"), chunks)
        self.assertDecodes(out, "despite bad text")

    def test_all_ancillary_chunks_kept_in_place(self):
        # Chunks the PNG spec defines beyond the common ones (several marked
        # unsafe to copy, like cICP), and chunks after the image data, come
        # out in the same order and place as in the cover
        before = [
            (b"cICP", bytes([9, 16, 0, 1])),
            (b"sBIT", bytes([8, 8, 8])),
            (b"bKGD", struct.pack(">HHH", 10, 20, 30)),
            (b"oFFs", struct.pack(">iiB", 5, 7, 0)),
            (b"zTXt", b"Note\x00\x00" + zlib.compress(b"compressed, kept as is")),
        ]
        after = [
            (b"tEXt", b"Comment\x00written after the pixels"),
            (b"tIME", struct.pack(">HBBBBB", 2025, 1, 2, 3, 4, 5)),
            (b"prVt", b"private, safe to copy"),
        ]
        src = self.path("rich.png")
        write_png(src, 64, 64, cover_pixel, extra=b"".join(_chunk(k, d) for k, d in before))
        with open(src, "rb") as f:
            data = f.read()
        tail = b"".join(_chunk(k, d) for k, d in after) + _chunk(b"IEND", b"")
        with open(src, "wb") as f:
            f.write(data[:-12] + tail)  # in place of the IEND chunk
        out = self.path("steg.png")
        code, log = self.encode(b"rich metadata", out, src=src)
        self.assertEqual(code, 0, log)
        chunks = [(k, d) for k, d in png_chunks(out) if k not in (b"IHDR", b"IDAT", b"IEND")]
        self.assertEqual(chunks, before + after)
        kinds = [k for k, _ in png_chunks(out)]
        self.assertLess(kinds.index(b"zTXt"), kinds.index(b"IDAT"))
        self.assertGreater(kinds.index(b"tEXt"), len(kinds) - 1 - kinds[::-1].index(b"IDAT"))
        self.assertDecodes(out, "rich metadata")

    def test_empty_message_writes_nothing(self):
        out = self.path("steg.png")
        code, log = self.encode(b"", out)
        self.assertEqual(code, 0, log)
        self.assertFalse(os.path.exists(out))
        # A lone newline is stripped, so it counts as empty too
        self.assertEqual(self.encode(b"\n", out)[0], 0)
        self.assertFalse(os.path.exists(out))

    def test_one_byte_message(self):
        out = self.path("steg.png")
        self.assertEqual(self.encode(b"x", out)[0], 0)
        self.assertDecodes(out, "x")

    @unittest.skipUnless(sodium, "libsodium not loadable via ctypes")
    def test_forged_message_decodes(self):
        # Proves forge() matches the real format, so the empty case is meaningful
        out = self.path("forged.png")
        forge(self.cover, out, b"forged hello", "correct horse")
        self.assertDecodes(out, "forged hello")

    @unittest.skipUnless(sodium, "libsodium not loadable via ctypes")
    def test_decode_empty_message_prints_nothing(self):
        out = self.path("empty.png")
        forge(self.cover, out, b"", "correct horse")
        code, log = self.decode(out)
        self.assertEqual(code, 0, log)
        self.assertTrue(log.endswith("Deriving keys...\n"), repr(log))

    @unittest.skipUnless(sodium, "libsodium not loadable via ctypes")
    def test_v1_image_decodes_with_warning(self):
        # Images written before format v2 still decode, with a nudge to re-encode
        out = self.path("v1.png")
        forge_v1(self.cover, out, b"from the old days", "correct horse")
        code, log = self.decode(out)
        self.assertEqual(code, 0, log)
        self.assertIn("from the old days\n", log)
        self.assertIn("old v1 format", log)
        code, log = self.decode(out, "wrong horse")
        self.assertEqual(code, 1, log)
        self.assertNotIn("from the old days", log)

    @unittest.skipUnless(sodium, "libsodium not loadable via ctypes")
    def test_v1_empty_message_prints_nothing(self):
        out = self.path("v1empty.png")
        forge_v1(self.cover, out, b"", "correct horse")
        code, log = self.decode(out)
        self.assertEqual(code, 0, log)
        self.assertTrue(log.rstrip("\n").endswith("re-encode it"), repr(log))

    def test_v2_image_has_no_v1_message(self):
        # A v2 image read the v1 way must not decode: the formats don't overlap
        out = self.path("steg.png")
        self.assertEqual(self.encode(b"v2 only", out)[0], 0)
        code, log = self.decode(out)
        self.assertNotIn("old v1 format", log)

    @unittest.skipUnless(sodium, "libsodium not loadable via ctypes")
    def test_salt_at_public_positions(self):
        # The salt is readable by anyone from the public positions, and the
        # encryption key derived from it opens the message
        out = self.path("steg.png")
        self.assertEqual(self.encode(b"salted", out)[0], 0)
        w, h, rows = read_png(out)
        salt_px, order, enc_key = layout_v2(rows, w, h, b"correct horse")
        self.assertEqual(len(set(salt_px)), SALT_PIXELS)
        self.assertFalse(set(salt_px) & set(order))
        self.assertEqual(len(order), w * h - SALT_PIXELS)
        self.assertEqual(reveal(out, "correct horse"), b"salted")

    @unittest.skipUnless(sodium, "libsodium not loadable via ctypes")
    def test_syndrome_coding_changes_less(self):
        # v3 hides the box as an STC syndrome: far fewer samples change than
        # writing its bits straight in (about half of them) would need
        noise = __import__("random").Random(3)
        px = [noise.getrandbits(24) for _ in range(96 * 96)]
        write_png(self.cover, 96, 96, lambda x, y: tuple((px[y * 96 + x] >> s) & 0xFF for s in (0, 8, 16)))
        out = self.path("steg.png")
        msg = b"m" * 150
        self.assertEqual(self.encode(msg, out)[0], 0)
        _, _, before = read_png(self.cover)
        _, _, after = read_png(out)
        changed = sum(a != b for ra, rb in zip(before, after) for a, b in zip(ra, rb))
        direct = (len(msg) + V2_OVERHEAD) * 8 // 2 + 16 + 64  # payload, header, salt
        self.assertLess(changed, direct * 0.5, (changed, direct))
        self.assertEqual(reveal(out, "correct horse"), msg)

    @unittest.skipUnless(sodium, "libsodium not loadable via ctypes")
    def test_v2_image_still_decodes(self):
        # v2 images (written before syndrome coding) decode without a warning:
        # same salt and keys, only the payload layout differs
        out = self.path("v2.png")
        forge(self.cover, out, b"plain bits", "correct horse")
        code, log = self.decode(out)
        self.assertEqual(code, 0, log)
        self.assertIn("plain bits\n", log)
        self.assertNotIn("Warning", log)

    @unittest.skipUnless(sodium, "libsodium not loadable via ctypes")
    def test_decode_empty_message_wrong_passphrase(self):
        # Still authenticated: a wrong passphrase must not "succeed" silently
        out = self.path("empty.png")
        forge(self.cover, out, b"", "correct horse")
        code, log = self.decode(out, "wrong horse")
        self.assertNotEqual(code, 0, log)
        self.assertIn("Error:", log)

    def test_large_image_full_capacity(self):
        # 800x600: 1.44M bits -> 179,928 message bytes, through stdin, the
        # pty and the 1 KiB-doubling read buffer
        write_png(self.cover, 800, 600, cover_pixel)
        cap = capacity_v2(800, 600)
        msg = bytes(65 + i % 26 for i in range(cap))
        out = self.path("big.png")
        code, log = self.encode(msg, out)
        self.assertEqual(code, 0, log)
        self.assertDecodes(out, msg.decode())
        self.assertEqual(self.encode(msg + b"!", self.path("over.png"))[0], 1)

    def test_extreme_aspect_ratios(self):
        for w, h in ((1, 400), (400, 1), (2, 199)):
            with self.subTest(size=(w, h)):
                write_png(self.cover, w, h, cover_pixel)
                out = self.path("steg.png")
                self.assertEqual(self.encode(b"thin", out)[0], 0)
                self.assertDecodes(out, "thin")

    def test_long_passphrase_not_truncated(self):
        # Past the initial 256-byte buffer, the tail must still count
        out = self.path("steg.png")
        base = "a" * 255
        code, log = self.encode(b"long pass", out, passphrase=base + "X")
        if code != 0:
            self.assertIn("Error:", log)
            self.assertFalse(os.path.exists(out))
            return
        code, log = self.decode(out, base + "Y")
        self.assertNotEqual(code, 0, "passphrase beyond 255 bytes was ignored")
        self.assertNotIn("long pass", log)

    def test_long_passphrases(self):
        # The buffer starts at 256 bytes and grows by 256: test both sides of
        # each boundary, and that the last character still matters
        for n in (255, 256, 257, 511, 512, 513, 4094):
            with self.subTest(length=n):
                pw = "k" * (n - 1) + "1"
                out = self.path("steg.png")
                code, log = self.encode(b"long pass", out, passphrase=pw)
                self.assertEqual(code, 0, log)
                self.assertDecodes(out, "long pass", passphrase=pw)
                code, log = self.decode(out, pw[:-1] + "2")
                self.assertNotEqual(code, 0, log)
                self.assertNotIn("long pass", log)

    def test_passphrase_over_terminal_limit_rejected(self):
        # The terminal drops input past 4095 bytes per line, so a passphrase
        # that long may be truncated: both commands must refuse it
        steg = self.path("steg.png")
        self.assertEqual(self.encode(b"m", steg)[0], 0)
        for n in (4095, 4096, 5000):
            with self.subTest(length=n):
                out = self.path("long.png")
                code, log = self.encode(b"m", out, passphrase="k" * n)
                self.assertEqual(code, 1, log)
                self.assertIn("passphrase too long (max 4094 bytes)", log)
                self.assertFalse(os.path.exists(out))
                code, log = self.decode(steg, "k" * n)
                self.assertEqual(code, 1, log)
                self.assertIn("passphrase too long", log)

    def test_passphrase_charset(self):
        for pw in ("with spaces  inside", "ünïcødé ✓ 秘密", "tab\there and more", "exactly12byt"):
            with self.subTest(passphrase=pw):
                out = self.path("steg.png")
                self.assertEqual(self.encode(b"charset", out, passphrase=pw)[0], 0)
                self.assertDecodes(out, "charset", passphrase=pw)

    def test_short_passphrase_refused(self):
        out = self.path("steg.png")
        code, log = self.encode(b"m", out, passphrase="elevenbytes")
        self.assertEqual(code, 1, log)
        self.assertIn("passphrase too short (min 12 bytes)", log)
        self.assertNotIn("Confirm", log)  # refused before asking again
        self.assertFalse(os.path.exists(out))

    @unittest.skipUnless(sodium, "libsodium not loadable via ctypes")
    def test_short_passphrase_still_decodes_old_images(self):
        # The minimum is for new images; old ones may have shorter passphrases
        out = self.path("v1.png")
        forge_v1(self.cover, out, b"short and old", "pw")
        code, log = self.decode(out, "pw")
        self.assertEqual(code, 0, log)
        self.assertIn("short and old\n", log)

    def test_generated_passphrase(self):
        import re
        seen = set()
        for _ in range(3):
            code, log = run(["passphrase"])
            self.assertEqual(code, 0, log)
            pw = log.strip()
            self.assertRegex(pw, r"^[a-hjkmnp-z2-9]{5}(-[a-hjkmnp-z2-9]{5}){4}$")
            seen.add(pw)
        self.assertEqual(len(seen), 3)
        out = self.path("steg.png")
        self.assertEqual(self.encode(b"generated", out, passphrase=pw)[0], 0)
        self.assertDecodes(out, "generated", passphrase=pw)

    def test_process_protected_while_holding_secrets(self):
        # At the prompt: no core dumps, and (as a non-root user) /proc files
        # owned by root because the process is not dumpable, which also
        # stops same-user debuggers from attaching
        pid, master = pty.fork()
        if pid == 0:
            os.execv(BINARY, [BINARY, "decode", "-i", self.cover])
        out, deadline = b"", time.monotonic() + TIMEOUT
        while b"Passphrase: " not in out and time.monotonic() < deadline:
            if select.select([master], [], [], 0.5)[0]:
                out += os.read(master, 1024)
        try:
            with open(f"/proc/{pid}/limits") as f:
                core = [l for l in f if l.startswith("Max core file size")][0].split()
            self.assertEqual(core[4:6], ["0", "0"])
            if os.geteuid() != 0:
                self.assertEqual(os.stat(f"/proc/{pid}/environ").st_uid, 0)
        finally:
            os.kill(pid, signal.SIGTERM)
            os.waitpid(pid, 0)
            os.close(master)

    # -- failures

    def test_message_typed_at_terminal(self):
        out = self.path("steg.png")
        code, log = run(["encode", "-i", self.cover, "-o", out],
                        passphrases=["correct horse"] * 2, typed=b"typed by hand")
        self.assertEqual(code, 0, log)
        self.assertIn("Message (Ctrl+D when done)", log)
        self.assertDecodes(out, "typed by hand")

    @unittest.skipUnless(sodium, "libsodium not loadable via ctypes")
    def test_tampered_ciphertext_fails_mac(self):
        # Flip one ciphertext bit, leaving the length header intact, so the
        # failure has to come from the MAC check and not the length check
        out = self.path("steg.png")
        self.assertEqual(self.encode(b"authenticated", out)[0], 0)
        w, h, rows = read_png(out)
        rows = [bytearray(r) for r in rows]
        _, order, _ = layout_v2(rows, w, h, b"correct horse")
        pos = 32 + (NONCE + MAC + 3) * 8  # a bit of the 4th plaintext byte
        p = order[pos // 3]
        rows[p // w][(p % w) * 3 + pos % 3] ^= 1
        write_png(out, w, h, lambda x, y: rows[y][x * 3:x * 3 + 3])
        code, log = self.decode(out)
        self.assertEqual(code, 1, log)
        self.assertIn("decryption failed", log)
        self.assertNotIn("authenticated", log)

    def test_decode_image_too_small_for_header(self):
        tiny = self.path("tiny.png")
        write_png(tiny, 3, 3, cover_pixel)  # 27 bits: not even the length header
        code, log = self.decode(tiny)
        self.assertEqual(code, 1)
        self.assertIn("too small", log)

    def test_unknown_option(self):
        code, log = run(["encode", "-x", "-i", self.cover])
        self.assertEqual(code, 1)
        self.assertIn("Usage:", log)

    def test_cover_with_transparency_refused(self):
        rgba = self.path("rgba.png")
        raw = b"".join(b"\x00" + b"".join(bytes([200, 50, 50, 0 if x < 16 else 255])
                                          for x in range(32)) for y in range(32))
        with open(rgba, "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\n"
                    + _chunk(b"IHDR", struct.pack(">IIBBBBB", 32, 32, 8, 6, 0, 0, 0))
                    + _chunk(b"IDAT", zlib.compress(raw)) + _chunk(b"IEND", b""))
        out = self.path("out.png")
        code, log = self.encode(b"x", out, src=rgba)
        self.assertEqual(code, 1, log)
        self.assertIn("has transparency", log)
        self.assertFalse(os.path.exists(out))

    def test_cover_with_16_bit_color_refused(self):
        rgb16 = self.path("rgb16.png")
        raw = b"".join(b"\x00" + b"".join(struct.pack(">HHH", x * 2000, y * 2000, 0x1234)
                                          for x in range(32)) for y in range(32))
        with open(rgb16, "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\n"
                    + _chunk(b"IHDR", struct.pack(">IIBBBBB", 32, 32, 16, 2, 0, 0, 0))
                    + _chunk(b"IDAT", zlib.compress(raw)) + _chunk(b"IEND", b""))
        out = self.path("out.png")
        code, log = self.encode(b"x", out, src=rgb16)
        self.assertEqual(code, 1, log)
        self.assertIn("has 16-bit color", log)
        self.assertFalse(os.path.exists(out))

    def test_output_keeps_mode_and_symlink(self):
        out = self.path("private.png")
        with open(out, "wb") as f:
            f.write(b"x")
        os.chmod(out, 0o600)
        self.assertEqual(self.encode(b"private", out)[0], 0)
        self.assertEqual(stat.S_IMODE(os.stat(out).st_mode), 0o600)

        link = self.path("link.png")
        os.symlink(out, link)
        self.assertEqual(self.encode(b"via link", link)[0], 0)
        self.assertTrue(os.path.islink(link))
        self.assertDecodes(out, "via link")

    def test_non_regular_output_left_alone(self):
        # A FIFO (or device, or directory) at the output path is neither
        # written to nor replaced by a regular file
        fifo = self.path("out.png")
        os.mkfifo(fifo)
        code, log = self.encode(b"x", fifo)
        self.assertEqual(code, 1, log)
        self.assertIn("is not a regular file", log)
        self.assertTrue(stat.S_ISFIFO(os.stat(fifo).st_mode))

    def test_signal_at_prompt_restores_echo(self):
        # Killed while echo is off, the terminal must get echo back, and the
        # process must still die from that signal
        for name, how in (("Ctrl+C", b"\x03"), ("Ctrl+\\", b"\x1c"),
                          ("SIGTERM", signal.SIGTERM), ("SIGHUP", signal.SIGHUP)):
            with self.subTest(signal=name):
                pid, master = pty.fork()
                if pid == 0:
                    os.execv(BINARY, [BINARY, "decode", "-i", self.cover])
                out, deadline = b"", time.monotonic() + TIMEOUT
                while b"Passphrase: " not in out and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.5)[0]:
                        out += os.read(master, 1024)
                self.assertFalse(termios.tcgetattr(master)[3] & termios.ECHO)
                if isinstance(how, bytes):
                    os.write(master, how)
                else:
                    os.kill(pid, how)
                _, status = os.waitpid(pid, 0)
                self.assertTrue(termios.tcgetattr(master)[3] & termios.ECHO)
                self.assertTrue(os.WIFSIGNALED(status))
                os.close(master)

    def test_ignored_signal_stays_ignored_at_prompt(self):
        # Under nohup (SIGHUP ignored), a hangup at the prompt mustn't kill it
        pid, master = pty.fork()
        if pid == 0:
            signal.signal(signal.SIGHUP, signal.SIG_IGN)  # inherited across exec
            os.execv(BINARY, [BINARY, "decode", "-i", self.cover])
        out, deadline = b"", time.monotonic() + TIMEOUT
        while b"Passphrase: " not in out and time.monotonic() < deadline:
            if select.select([master], [], [], 0.5)[0]:
                out += os.read(master, 1024)
        os.kill(pid, signal.SIGHUP)
        os.write(master, b"correct horse\n")
        while True:  # drain until it exits
            try:
                if not os.read(master, 4096):
                    break
            except OSError:
                break
        _, status = os.waitpid(pid, 0)
        os.close(master)
        self.assertFalse(os.WIFSIGNALED(status))
        self.assertEqual(os.waitstatus_to_exitcode(status), 1)  # no message in it

    def test_wrong_passphrase(self):
        out = self.path("steg.png")
        self.assertEqual(self.encode(b"top secret", out)[0], 0)
        code, log = self.decode(out, "wrong horse")
        self.assertNotEqual(code, 0)
        self.assertNotIn("top secret", log)
        self.assertIn("Error:", log)

    def test_tampered_image(self):
        # Flip every LSB: the MAC must catch it (or the length must be invalid)
        out = self.path("steg.png")
        self.assertEqual(self.encode(b"integrity", out)[0], 0)
        w, h, rows = read_png(out)
        write_png(out, w, h, lambda x, y: tuple(c ^ 1 for c in rows[y][x * 3:x * 3 + 3]))
        code, log = self.decode(out)
        self.assertNotEqual(code, 0)
        self.assertNotIn("integrity", log)

    def test_decode_plain_cover(self):
        code, log = self.decode(self.cover)
        self.assertNotEqual(code, 0)
        self.assertIn("Error:", log)

    def test_passphrase_mismatch(self):
        out = self.path("steg.png")
        code, log = self.encode(b"x", out, confirm="different")
        self.assertEqual(code, 1)
        self.assertIn("do not match", log)
        self.assertFalse(os.path.exists(out))

    def test_message_too_long(self):
        out = self.path("steg.png")
        code, log = self.encode(("x" * 1476).encode(), out)
        self.assertEqual(code, 1)
        self.assertIn("too long", log)
        self.assertFalse(os.path.exists(out))

    def test_endless_message_refused(self):
        # Reading stops past the image's capacity: an endless stdin is
        # refused quickly, rather than read until memory runs out (or, past
        # 4 GiB, its 32-bit length wrapping)
        out = self.path("steg.png")
        code, log = run(["encode", "-i", self.cover, "-o", out],
                        passphrases=["correct horse"] * 2, stdin_path="/dev/zero")
        self.assertEqual(code, 1, log)
        self.assertIn("message too long for this image", log)
        self.assertFalse(os.path.exists(out))

    def test_message_read_error(self):
        # A read error isn't the end of the message: nothing partial is hidden
        out = self.path("steg.png")
        code, log = run(["encode", "-i", self.cover, "-o", out],
                        passphrases=["correct horse"] * 2, stdin_path=self.dir)
        self.assertEqual(code, 1, log)
        self.assertIn("could not read message: Is a directory", log)
        self.assertFalse(os.path.exists(out))

    def test_output_write_error(self):
        # A message (or passphrase) that couldn't be written out is an error,
        # or the user might delete the image thinking it was saved
        out = self.path("steg.png")
        self.assertEqual(self.encode(b"keep me", out)[0], 0)
        code, log = run(["decode", "-i", out], passphrases=["correct horse"],
                        stdout_path="/dev/full")
        self.assertEqual(code, 1, log)
        self.assertIn("could not write the message: No space left on device", log)
        code, log = run(["passphrase"], stdout_path="/dev/full")
        self.assertEqual(code, 1, log)
        self.assertIn("could not write the passphrase", log)

    def test_failed_encode_keeps_existing_output(self):
        out = self.path("steg.png")
        with open(out, "wb") as f:
            f.write(b"precious")
        self.assertEqual(self.encode(("x" * 5000).encode(), out)[0], 1)
        with open(out, "rb") as f:
            self.assertEqual(f.read(), b"precious")
        self.assertEqual(sorted(os.listdir(self.dir)), ["cover.png", "steg.png"])

    def test_unwritable_output(self):
        code, log = self.encode(b"x", os.path.join(self.dir, "missing", "out.png"))
        self.assertEqual(code, 1)
        self.assertIn("could not write", log)
        self.assertIn("No such file or directory", log)

    def test_missing_input(self):
        code, log = self.encode(b"x", self.path("out.png"), src=self.path("nope.png"))
        self.assertEqual(code, 1)
        self.assertIn("could not load", log)

    def test_input_not_png(self):
        bogus = self.path("bogus.png")
        with open(bogus, "wb") as f:
            f.write(b"definitely not a png")
        code, log = self.decode(bogus)
        self.assertEqual(code, 1)
        self.assertIn("could not load", log)

    def test_image_too_small(self):
        tiny = self.path("tiny.png")
        write_png(tiny, 4, 4, cover_pixel)  # 16 px: not even room for the salt
        code, log = self.encode(b"hi", self.path("out.png"), src=tiny)
        self.assertEqual(code, 1)
        self.assertIn("too small", log)
        small = self.path("small.png")
        write_png(small, 9, 9, cover_pixel)  # 81 px: salt + header, 4 payload bytes
        code, log = self.encode(b"hi", self.path("out.png"), src=small)
        self.assertEqual(code, 1)
        self.assertIn("too long", log)
        code, log = self.decode(tiny)
        self.assertEqual(code, 1)

    def test_usage_errors(self):
        self.assertEqual(run([])[0], 1)
        code, log = run(["encode", "-i", self.cover])
        self.assertEqual(code, 1)
        self.assertIn("requires -i and -o", log)
        code, log = run(["decode"])
        self.assertEqual(code, 1)
        self.assertIn("requires -i", log)
        code, log = run(["frobnicate", "-i", self.cover])
        self.assertEqual(code, 1)
        self.assertIn("unknown command", log)

    def test_no_passphrase_given(self):
        # EOF at the prompt must fail cleanly, not encode with an empty key
        code, log = run(["encode", "-i", self.cover, "-o", self.path("out.png")], b"x", [])
        self.assertEqual(code, 1)
        self.assertIn("could not read passphrase", log)


@unittest.skipUnless(sodium, "libsodium not loadable via ctypes")
class CrossCheckTest(CliBase):
    """Randomized round trips between the binary and the independent Python
    implementation, in both directions. Seeded, so failures reproduce;
    set SCATTERSTEG_SEED to explore other cases."""

    SEED = int(os.environ.get("SCATTERSTEG_SEED", "20261022"))
    CASES = int(os.environ.get("SCATTERSTEG_CASES", "12"))

    def random_case(self, rng):
        ch = rng.choice([3, 3, 1])
        lo = 16 if ch == 3 else 40  # gray holds 1 bit per pixel
        w, h = rng.randint(lo, 72), rng.randint(lo, 72)
        capacity = capacity_v2(w, h, ch)
        n = rng.choice([1, 2, rng.randint(1, capacity), capacity])
        # No NUL (printing stops there), no CR (the pty's \n -> \r\n
        # translation is undone on output) and no trailing newline (stripped)
        msg = bytes(rng.choice([b for b in range(1, 256) if b != 13]) for _ in range(n))
        msg = msg.rstrip(b"\n") or b"z"
        pw = "".join(rng.choice("abcxyz019 !é✓") for _ in range(rng.randint(12, 60)))
        return w, h, ch, msg, pw

    def cover_for(self, w, h, ch, rng):
        noise = [rng.getrandbits(24) for _ in range(w * h)]
        write_png(self.cover, w, h,
                  lambda x, y: tuple((noise[y * w + x] >> s) & 0xFF for s in (0, 8, 16)[:ch]),
                  channels=ch)

    def test_binary_encode_python_decode(self):
        import random
        rng = random.Random(self.SEED)
        for case in range(self.CASES):
            w, h, ch, msg, pw = self.random_case(rng)
            with self.subTest(case=case, size=(w, h), channels=ch, length=len(msg), seed=self.SEED):
                self.cover_for(w, h, ch, rng)
                out = self.path("steg.png")
                code, log = self.encode(msg, out, passphrase=pw)
                self.assertEqual(code, 0, log)
                self.assertEqual(reveal(out, pw), msg)
                self.assertIsNone(reveal(out, pw + "!"))

    def test_python_encode_binary_decode(self):
        import random
        rng = random.Random(self.SEED + 1)
        for case in range(self.CASES):
            w, h, ch, msg, pw = self.random_case(rng)
            with self.subTest(case=case, size=(w, h), channels=ch, length=len(msg), seed=self.SEED + 1):
                self.cover_for(w, h, ch, rng)
                out = self.path("forged.png")
                forge_v3(self.cover, out, msg, pw)
                code, log = run(["decode", "-i", out], passphrases=[pw])
                self.assertEqual(code, 0, log)
                # Byte-exact: the output is the raw message plus "\n"
                self.assertIn(msg + b"\n", log.encode(errors="surrogateescape"))


@unittest.skipUnless(os.access(JPEG_FIXTURE, os.X_OK), "jpeg_fixture not built")
class JpegTest(CliBase):
    """JPEG covers: data goes into DCT coefficients, read and written
    losslessly, and the output is a JPEG like the cover"""

    def setUp(self):
        super().setUp()
        self.jpeg = self.path("cover.jpg")
        make_jpeg(self.jpeg, 256, 192)

    def test_roundtrip(self):
        out = self.path("steg.jpg")
        code, log = self.encode(b"in the coefficients", out, src=self.jpeg)
        self.assertEqual(code, 0, log)
        self.assertDecodes(out, "in the coefficients")
        code, log = self.decode(out, "wrong horse!")
        self.assertEqual(code, 1, log)
        self.assertNotIn("in the coefficients", log)

    def test_random_messages(self):
        import random
        rng = random.Random(7)
        for case in range(4):
            msg = bytes(rng.choice(range(32, 127)) for _ in range(rng.randint(1, 300)))
            with self.subTest(case=case, length=len(msg)):
                out = self.path("steg.jpg")
                self.assertEqual(self.encode(msg, out, src=self.jpeg)[0], 0)
                self.assertDecodes(out, msg.decode())

    def test_format_and_markers_kept(self):
        src = self.path("fancy.jpg")
        make_jpeg(src, 200, 150, 3, 80, "progressive", "markers", "restart")
        out = self.path("steg.jpg")
        self.assertEqual(self.encode(b"keep it all", out, src=src)[0], 0)
        before, after = jpeg_segments(src), jpeg_segments(out)
        app_and_com = lambda segs: [s for s in segs if 0xE0 <= s[0] <= 0xEF or s[0] == 0xFE]
        self.assertEqual(app_and_com(before), app_and_com(after))
        markers = [m for m, _ in after]
        self.assertIn(0xC2, markers)  # still progressive
        self.assertIn(0xDD, markers)  # still has a restart interval
        self.assertDecodes(out, "keep it all")

    def test_no_jfif_header_added(self):
        # A camera file starts SOI, APP1 (Exif) with no JFIF APP0; adding
        # one in front of the Exif would show the file was rewritten
        src = self.path("camera.jpg")
        make_jpeg(src, 200, 150, 3, 90, "nojfif", "markers")
        out = self.path("steg.jpg")
        self.assertEqual(self.encode(b"no jfif", out, src=src)[0], 0)
        markers = [m for m, _ in jpeg_segments(out)]
        self.assertEqual(markers[0], 0xE1)
        self.assertNotIn(0xE0, markers)
        self.assertDecodes(out, "no jfif")

    def test_data_after_image_refused(self):
        # An MPO or Ultra HDR file has more images after the first one's EOI;
        # they'd be lost while the MPF marker indexing them was kept
        src = self.path("mpo.jpg")
        make_jpeg(src, 200, 150)
        with open(src, "ab") as f:
            f.write(open(self.jpeg, "rb").read())  # a second image
        out = self.path("steg.jpg")
        code, log = self.encode(b"x", out, src=src)
        self.assertEqual(code, 1, log)
        self.assertIn("data after the end of the image", log)
        self.assertFalse(os.path.exists(out))

    def test_gray(self):
        src = self.path("gray.jpg")
        make_jpeg(src, 200, 150, 1)
        out = self.path("steg.jpg")
        self.assertEqual(self.encode(b"gray jpeg", out, src=src)[0], 0)
        sof = dict(jpeg_segments(out))[0xC0]
        self.assertEqual(sof[5], 1)  # one component
        self.assertDecodes(out, "gray jpeg")

    def test_too_long_and_too_small(self):
        out = self.path("steg.jpg")
        code, log = self.encode(b"x" * 100000, out, src=self.jpeg)
        self.assertEqual(code, 1, log)
        self.assertIn("too long", log)
        self.assertFalse(os.path.exists(out))
        tiny = self.path("tiny.jpg")
        make_jpeg(tiny, 8, 8, 1, 50)  # one block: nowhere near 160 carriers
        code, log = self.encode(b"x", out, src=tiny)
        self.assertEqual(code, 1, log)
        self.assertIn("too small", log)

    def test_output_name_must_match_format(self):
        code, log = self.encode(b"x", self.path("out.png"), src=self.jpeg)
        self.assertEqual(code, 1, log)
        self.assertIn("give it a .jpg name", log)
        code, log = self.encode(b"x", self.path("out.jpeg"))  # PNG cover
        self.assertEqual(code, 1, log)
        self.assertIn("give it a .png name", log)
        self.assertEqual(sorted(os.listdir(self.dir)), ["cover.jpg", "cover.png"])

    def test_unrewritable_jpeg_refused(self):
        # A JPEG libjpeg decodes but won't re-encode (found by fuzzing):
        # refused up front, before any key derivation
        src = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "fuzz", "regressions", "jpeg_load", "oversampled-progressive.jpg")
        out = self.path("steg.jpg")
        code, log = self.encode(b"x", out, src=src)
        self.assertEqual(code, 1, log)
        self.assertIn("can't be rewritten losslessly", log)
        self.assertNotIn("Deriving keys", log)
        self.assertFalse(os.path.exists(out))

    def test_decode_cover_without_message(self):
        out = self.path("steg.jpg")
        self.assertEqual(self.encode(b"m", out, src=self.jpeg)[0], 0)
        code, log = self.decode(self.jpeg)  # the cover holds nothing
        self.assertEqual(code, 1, log)
        self.assertIn("Error:", log)


SANITIZER_MARKERS = ("AddressSanitizer", "LeakSanitizer", "runtime error:")


@unittest.skipUnless(FAULT_BINARY, "set SCATTERSTEG_FAULT to the fault-injection build")
class FaultSweepTest(CliBase):
    """Fail each faultable libc call of a whole run, one at a time. Every run
    must either succeed correctly or fail with an error and no damage."""

    # Abort on sanitizer reports so they can't hide behind exit code 1
    ENV = {"ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
           "UBSAN_OPTIONS": "halt_on_error=1:abort_on_error=1"}

    def setUp(self):
        super().setUp()
        # 16x16: room for a short message, few row allocations
        write_png(self.cover, 16, 16, cover_pixel)

    def sweep(self, args, message, passphrases, check):
        n = 0
        while True:
            n += 1
            self.assertLess(n, 500, "sweep did not terminate")
            code, log = run(args, message, passphrases,
                            env={**self.ENV, "FAULT_AT": str(n)}, binary=FAULT_BINARY)
            with self.subTest(fault=n):
                for marker in SANITIZER_MARKERS:
                    self.assertNotIn(marker, log)
                self.assertIn(code, (0, 1), log)
                if code == 1:
                    self.assertIn("Error:", log)
                check(code, log)
            if "FAULT_NOT_REACHED" in log:
                self.assertEqual(code, 0, log)
                return n - 1

    def encode_sweep(self, message):
        out = self.path("steg.png")

        def check(code, log):
            if code == 0:
                self.assertDecodes(out, message.decode())
            else:
                with open(out, "rb") as f:
                    self.assertEqual(f.read(), b"precious")
            self.assertEqual(sorted(os.listdir(self.dir)), ["cover.png", "steg.png"])
            with open(out, "wb") as f:  # reset for the next run
                f.write(b"precious")

        with open(out, "wb") as f:
            f.write(b"precious")
        return self.sweep(["encode", "-i", self.cover, "-o", out], message,
                          ["correct horse"] * 2, check)

    def test_encode_sweep(self):
        self.assertGreater(self.encode_sweep(b"fault sweep"), 10)

    def test_encode_sweep_long_message(self):
        # Over read_message's initial 1 KiB buffer, so its realloc can fail too
        write_png(self.cover, 64, 64, cover_pixel)
        self.assertGreater(self.encode_sweep(b"y" * 1400), 60)

    def test_decode_sweep(self):
        steg = self.path("steg.png")
        self.assertEqual(self.encode(b"fault sweep", steg)[0], 0)

        def check(code, log):
            if code == 0:
                self.assertIn("fault sweep\n", log)
            else:
                self.assertNotIn("fault sweep", log)

        faults = self.sweep(["decode", "-i", steg], b"", ["correct horse"], check)
        self.assertGreater(faults, 5)

    def test_encode_sweep_long_passphrase(self):
        # Over 256 bytes, so the passphrase buffer has to grow (and that can fail)
        out = self.path("steg.png")
        with open(out, "wb") as f:
            f.write(b"precious")
        pw = "p" * 600

        def check(code, log):
            if code == 0:
                self.assertDecodes(out, "grow", passphrase=pw)
            else:
                with open(out, "rb") as f:
                    self.assertEqual(f.read(), b"precious")
            with open(out, "wb") as f:
                f.write(b"precious")

        self.sweep(["encode", "-i", self.cover, "-o", out], b"grow", [pw, pw], check)

    @unittest.skipUnless(sodium, "libsodium not loadable via ctypes")
    def test_decode_sweep_v1_image(self):
        # The v1 fallback only runs once v2 fails, so sweep a v1 image too
        steg = self.path("v1.png")
        forge_v1(self.cover, steg, b"old sweep", "correct horse")

        def check(code, log):
            if code == 0:
                self.assertIn("old sweep\n", log)
            else:
                self.assertNotIn("old sweep", log)

        faults = self.sweep(["decode", "-i", steg], b"", ["correct horse"], check)
        self.assertGreater(faults, 5)

    @unittest.skipUnless(os.access(JPEG_FIXTURE, os.X_OK), "jpeg_fixture not built")
    def test_encode_and_decode_sweep_jpeg(self):
        src = self.path("cover.jpg")
        make_jpeg(src, 128, 96)
        out = self.path("steg.jpg")
        with open(out, "wb") as f:
            f.write(b"precious")

        def check_encode(code, log):
            if code == 0:
                self.assertDecodes(out, "jpeg sweep")
            else:
                with open(out, "rb") as f:
                    self.assertEqual(f.read(), b"precious")
            self.assertEqual(sorted(os.listdir(self.dir)), ["cover.jpg", "cover.png", "steg.jpg"])
            with open(out, "wb") as f:
                f.write(b"precious")

        faults = self.sweep(["encode", "-i", src, "-o", out], b"jpeg sweep",
                            ["correct horse"] * 2, check_encode)
        self.assertGreater(faults, 10)

        self.assertEqual(self.encode(b"jpeg sweep", out, src=src)[0], 0)

        def check_decode(code, log):
            if code == 0:
                self.assertIn("jpeg sweep\n", log)

        self.assertGreater(self.sweep(["decode", "-i", out], b"", ["correct horse"], check_decode), 5)

    def test_sweep_reaches_key_derivation(self):
        # Argon2id's 256 MiB allocation happens inside libsodium; the sweep
        # fails crypto_pwhash as a whole to cover running out of memory there
        code, log = None, ""
        for n in range(1, 500):
            code, log = run(["encode", "-i", self.cover, "-o", self.path("o.png")], b"m",
                            ["p" * 12] * 2, env={**self.ENV, "FAULT_AT": str(n)}, binary=FAULT_BINARY)
            if "FAULT_FIRED crypto_pwhash" in log or "FAULT_NOT_REACHED" in log:
                break
        self.assertIn("FAULT_FIRED crypto_pwhash", log)
        self.assertEqual(code, 1)
        self.assertIn("key derivation failed", log)


if __name__ == "__main__":
    if not os.access(BINARY, os.X_OK):
        sys.exit("scattersteg binary not found at %s (run make first)" % BINARY)
    unittest.main(verbosity=2)
