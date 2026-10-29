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
import re
import resource
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
# Faultable calls the long-message sweep must reach. The C version allocates
# every image row separately; the Rust one reads the pixels into one buffer,
# so it makes far fewer (set 15 there).
FAULT_LONG_MIN = int(os.environ.get("FAULT_LONG_MIN", "60"))
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


def exec_or_exit(argv):
    """In a forked child: become argv, or exit; never go on to run the rest of
    the tests in the child"""
    try:
        os.execv(argv[0], argv)
    finally:
        os._exit(127)


def run(args, message=b"", passphrases=(), env=None, binary=None, typed=None,
        stdin_path=None, stdout_path=None, memlock=None, cwd=None):
    """Run scattersteg, answer each passphrase prompt in order. The message
    goes in on stdin (from the file stdin_path, if given), or with `typed`,
    is typed at the terminal instead. stdout goes to the terminal, or to
    the file stdout_path. It runs in cwd, if given (where extract restores
    a file under its stored name).
    Returns (exit_code, combined stdout+stderr as text)."""
    binary = os.path.abspath(binary or BINARY)  # it may run in another directory (cwd)
    with tempfile.TemporaryFile() as stdin:
        stdin.write(message)
        stdin.flush()
        stdin.seek(0)
        pid, master = pty.fork()
        if pid == 0:
            try:
                if stdin_path is not None:
                    os.dup2(os.open(stdin_path, os.O_RDONLY), 0)
                elif typed is None:
                    os.dup2(stdin.fileno(), 0)
                if stdout_path is not None:
                    os.dup2(os.open(stdout_path, os.O_WRONLY), 1)
                if memlock is not None:  # the locked memory limit, soft and hard
                    resource.setrlimit(resource.RLIMIT_MEMLOCK, (memlock, memlock))
                if cwd is not None:
                    os.chdir(cwd)
                os.execve(binary, [binary] + list(args), {**os.environ, **(env or {})})
            finally:
                os._exit(127)  # never go on to run the rest of the tests in the child

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
# Reimplements the format (FORMAT.md), to build images the binary itself
# won't produce (e.g. an empty message) and to cross-check it in both
# directions.

_sodium_path = ctypes.util.find_library("sodium")
sodium = ctypes.CDLL(_sodium_path) if _sodium_path else None
if sodium:
    sodium.sodium_init()
    sodium.crypto_pwhash_opslimit_moderate.restype = ctypes.c_ulonglong
    sodium.crypto_pwhash_memlimit_moderate.restype = ctypes.c_size_t
    sodium.crypto_pwhash.argtypes = [
        ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_ulonglong,
        ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_size_t, ctypes.c_int]
    sodium.crypto_stream_chacha20_ietf.argtypes = [
        ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_char_p]
    sodium.crypto_kdf_derive_from_key.argtypes = [
        ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint64, ctypes.c_char_p, ctypes.c_char_p]
    sodium.crypto_secretbox_easy.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_char_p]
    sodium.crypto_secretbox_open_easy.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_char_p]

SALT, NONCE, MAC = 16, 24, 16
BOX_OVERHEAD = NONCE + MAC
MESSAGE_MAX = 64 << 20  # CODEC_MESSAGE_MAX


def argon2id(pw, salt):
    key = ctypes.create_string_buffer(32)
    assert sodium.crypto_pwhash(
        key, 32, pw, len(pw), salt,
        sodium.crypto_pwhash_opslimit_moderate(),
        sodium.crypto_pwhash_memlimit_moderate(), 2) == 0  # ALG_ARGON2ID13
    return key.raw


def read_bits(rows, w, order, start, n, ch=3):
    out = 0
    for b in range(n):
        p = order[(start + b) // ch]
        out |= (rows[p // w][(p % w) * ch + (start + b) % ch] & 1) << b
    return out


def set_bits(rows, w, order, start, bits, ch):
    for i, bit in enumerate(bits):
        p = order[(start + i) // ch]
        k = (p % w) * ch + (start + i) % ch
        rows[p // w][k] = (rows[p // w][k] & 0xFE) | bit


def to_bits(data):
    return [(byte >> b) & 1 for byte in data for b in range(8)]


def open_box(box, key):
    nonce, ct = box[:NONCE], box[NONCE:]
    pt = ctypes.create_string_buffer(max(1, len(ct) - MAC))
    if sodium.crypto_secretbox_open_easy(pt, ct, len(ct), nonce, key) != 0:
        return None
    return pt.raw[:len(ct) - MAC]


NAME_MAX = 255
RECORD_MAX = MESSAGE_MAX + 1 + NAME_MAX


def name_ok(name):
    """A file name a record may carry: a bare name"""
    return (0 < len(name) <= NAME_MAX and name not in (b".", b"..")
            and not any(b == 0x2F or b < 0x20 or b == 0x7F for b in name))


def pack(message, name=b"", level=9):
    """The secretbox's plaintext: [encoding | body], the body raw DEFLATE
    (encoding 1) of the record if that is shorter, else the record as is
    (0). The record is [name length | name | message]."""
    record = bytes([len(name)]) + name + message
    if level:
        c = zlib.compressobj(level, zlib.DEFLATED, -15, 9)
        body = c.compress(record) + c.flush()
        if len(body) < len(record):
            return b"\1" + body
    return b"\0" + record


def unpack(pt):
    """(name, message) from the secretbox's plaintext, or None if it's
    malformed"""
    if not pt or pt[0] not in (0, 1):
        return None
    record = pt[1:]
    if pt[0] == 1:
        d = zlib.decompressobj(-15)
        record = d.decompress(pt[1:], RECORD_MAX + 1)
        if not d.eof or d.unused_data or d.unconsumed_tail or len(record) > RECORD_MAX:
            return None
    if not record or 1 + record[0] > len(record):
        return None
    name = record[1:1 + record[0]]
    if name and not name_ok(name):
        return None
    return name, record[1 + record[0]:]


def seal(message, key):
    nonce = os.urandom(NONCE)
    ct = ctypes.create_string_buffer(MAC + len(message))
    sodium.crypto_secretbox_easy(ct, message, len(message), nonce, key)
    return nonce + ct.raw


# -- keys and orders

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


def permutation(key, count):
    """Forward Fisher-Yates with unbiased draws: prng_permutation"""
    a, s = list(range(count)), KeyStream(key)
    for i in range(count - 1):
        j = i + s.uniform(count - i)
        a[i], a[j] = a[j], a[i]
    return a


def keys(pw, salt):
    master = argon2id(pw, salt)
    subkeys = []
    for subkey_id in (1, 2):  # scatter, encryption
        k = ctypes.create_string_buffer(32)
        sodium.crypto_kdf_derive_from_key(k, 32, subkey_id, b"ScatStg2", master)
        subkeys.append(k.raw)
    return subkeys


def payload_order(scatter_key, count, salt_px):
    taken = set(salt_px)
    return [p for p in permutation(scatter_key, count) if p not in taken]


# -- STC syndrome coding (see stc.h)

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
    build images independently of the binary's Viterbi."""
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


# -- the format

SALT_SAMPLES = 8192


def salt_region_pixels(count, ch):
    want = (SALT_SAMPLES + ch - 1) // ch
    return max(min(want, count // 16), (SALT * 8 + ch - 1) // ch)


def salt_region(count, ch):
    """The salt pixels, and how many of their samples carry the salt"""
    key = hashlib.blake2b(b"ScatterSteg v2 salt positions", digest_size=32).digest()
    k = salt_region_pixels(count, ch)
    return permutation(key, count)[:k], stc_carriers(k * ch, SALT * 8)


def layout(rows, w, h, pw):
    """(salt pixels, payload order, encryption key) for an image"""
    ch = len(rows[0]) // w
    salt_px, used = salt_region(w * h, ch)
    y = [read_bits(rows, w, salt_px, i, 1, ch) for i in range(used)]
    m = stc_extract(y, SALT * 8, used)
    salt = bytes(sum(m[i * 8 + b] << b for b in range(8)) for i in range(SALT))
    scatter_key, enc_key = keys(pw, salt)
    return salt_px, payload_order(scatter_key, w * h, salt_px), enc_key


def forge(src, dst, message, passphrase, plaintext=None, name=b""):
    """Embed `message` (stored with `name`) the way scattersteg embed does,
    without its checks (so an empty message or a bad name are allowed), or
    the secretbox's `plaintext` as given. Overwrites LSBs; decoding can't tell the difference from LSB
    matching."""
    w, h, rows = read_png(src)
    rows = [bytearray(r) for r in rows]
    ch = len(rows[0]) // w
    pw = passphrase.encode()
    salt = os.urandom(SALT)
    salt_px, used = salt_region(w * h, ch)
    x = [read_bits(rows, w, salt_px, i, 1, ch) for i in range(used)]
    set_bits(rows, w, salt_px, 0, stc_solve(x, to_bits(salt), used), ch)
    scatter_key, enc_key = keys(pw, salt)
    order = payload_order(scatter_key, w * h, salt_px)
    box = seal(pack(message, name) if plaintext is None else plaintext, enc_key)
    set_bits(rows, w, order, 0, [(len(box) >> b) & 1 for b in range(32)], ch)
    n = stc_carriers(len(order) * ch - 32, len(box) * 8)
    assert n, "message too long"
    x = [read_bits(rows, w, order, 32 + i, 1, ch) for i in range(n)]
    set_bits(rows, w, order, 32, stc_solve(x, to_bits(box), n), ch)
    write_png(dst, w, h, lambda x, y: rows[y][x * ch:x * ch + ch], channels=ch)


def read_box(rows, w, order, ch, enc_key):
    """The payload: a 32-bit length, then the box as an STC syndrome"""
    length = read_bits(rows, w, order, 0, 32, ch)
    samples = len(order) * ch - 32
    if not (BOX_OVERHEAD <= length and length * 8 <= samples):
        return None
    mlen = length * 8
    n = stc_carriers(samples, mlen)
    y = [read_bits(rows, w, order, 32 + i, 1, ch) for i in range(n)]
    m = stc_extract(y, mlen, n)
    box = bytes(sum(m[i * 8 + b] << b for b in range(8)) for i in range(length))
    return open_box(box, enc_key)


def reveal(src, passphrase, name=False):
    """Extract and decrypt a message independently of the binary. Returns
    the message's bytes, or None. With name=True, (name, message)."""
    w, h, rows = read_png(src)
    ch = len(rows[0]) // w
    _, order, enc_key = layout(rows, w, h, passphrase.encode())
    pt = read_box(rows, w, order, ch, enc_key)
    found = None if pt is None else unpack(pt)
    return found if name or found is None else found[1]


def capacity(w, h, ch=3):
    """Largest message embed accepts for a w x h cover, stored as is with no
    file name (one that compresses can be longer; a name takes its length)"""
    return ((w * h - salt_region_pixels(w * h, ch)) * ch - 32) // 8 - BOX_OVERHEAD - 2


SUGGESTED_UNITS_PER_BYTE = 160  # 0.05 bits per pixel, the lightest payload measured


def suggested(w, h, ch=3):
    """The most `info` suggests storing in a PNG: a byte per 160 pixels"""
    return min(w * h // SUGGESTED_UNITS_PER_BYTE, capacity(w, h, ch))


def noise(n, seed=1):
    """n bytes that don't compress, so a message of them is stored as is:
    capacity limits are exact for them"""
    import random
    return random.Random(seed).randbytes(n)


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

    def embed(self, message, out, passphrase="correct horse", confirm=None, src=None):
        """Embed message, from standard input, in src (the cover by default),
        replacing out if it exists"""
        return run(["embed", "-cf", src or self.cover, "-sf", out, "-f"], message,
                   [passphrase, passphrase if confirm is None else confirm])

    def extract(self, src, passphrase="correct horse"):
        return run(["extract", "-sf", src], passphrases=[passphrase])

    def extract_bytes(self, src, *flags, passphrase="correct horse"):
        """What extract wrote to stdout, byte for byte"""
        out = self.path("extracted.bin")
        open(out, "wb").close()
        code, log = run(["extract", *flags, "-sf", src, "-xf", "-"], passphrases=[passphrase], stdout_path=out)
        self.assertEqual(code, 0, log)
        with open(out, "rb") as f:
            return f.read()

    def assertDecodes(self, src, message, passphrase="correct horse"):
        code, out = self.extract(src, passphrase)
        self.assertEqual(code, 0, out)
        # A message from standard input has no name: it goes to stdout, last
        self.assertTrue(out.endswith(message), (out, message))



class CliTest(CliBase):
    # -- happy paths

    def test_roundtrip(self):
        out = self.path("steg.png")
        code, log = self.embed(b"meet at the old bridge\n", out)
        self.assertEqual(code, 0, log)
        self.assertDecodes(out, "meet at the old bridge\n")

    def test_warns_when_message_cannot_be_locked(self):
        # Past the locked memory limit, the message can reach swap: say so
        with open(BINARY, "rb") as f:
            if b"__asan_init" in f.read():
                self.skipTest("ASan makes mlock a no-op that succeeds")
        cover = self.path("big.png")
        write_png(cover, 800, 800, lambda x, y: ((x * 7 + y * 13) & 255, (x * y) & 255, (x ^ y) & 255))
        message = os.urandom(200_000)
        out = self.path("steg.png")
        limit = 64 << 10
        code, log = run(["embed", "-cf", cover, "-sf", out], message, ["correct horse"] * 2,
                        memlock=limit)
        self.assertEqual(code, 0, log)
        self.assertIn("may be written to swap", log)
        decoded = self.path("decoded.bin")
        open(decoded, "wb").close()
        code, log = run(["extract", "-sf", out, "-xf", "-"], passphrases=["correct horse"],
                        stdout_path=decoded, memlock=limit)
        self.assertEqual(code, 0, log)
        self.assertIn("may be written to swap", log)
        with open(decoded, "rb") as f:
            self.assertEqual(f.read(), message)
        # A short message fits
        code, log = run(["embed", "-cf", self.cover, "-sf", self.path("short.png")], b"short",
                        ["correct horse"] * 2, memlock=limit)
        self.assertEqual(code, 0, log)
        self.assertNotIn("swap", log)

    def test_every_byte_kept(self):
        # Nothing is stripped on the way in or added on the way out
        for msg in (b"no newline", b"one newline\n", b"two newlines\n\n", b"\x00\xff\n\x00", b"\n"):
            with self.subTest(msg=msg):
                out = self.path("raw.png")
                code, log = self.embed(msg, out)
                self.assertEqual(code, 0, log)
                self.assertEqual(self.extract_bytes(out), msg)

    def test_option_forms(self):
        # The short and long forms are the same options, in any order
        out = self.path("forms.png")
        code, log = run(["embed", "--embedfile", "-", "--stegofile", out, "--coverfile", self.cover,
                         "--compress", "5", "--force", "--verbose"], b"long forms", ["correct horse"] * 2)
        self.assertEqual(code, 0, log)
        self.assertIn("compressed", log)
        self.assertEqual(self.extract_bytes(out), b"long forms")
        code, log = run(["--embed", "-sf", out, "-f", "-cf", self.cover, "-Z", "-v"], b"short forms",
                        ["correct horse"] * 2)
        self.assertEqual(code, 0, log)
        self.assertIn("not compressed", log)
        decoded = self.path("decoded.bin")
        open(decoded, "wb").close()
        code, log = run(["--extract", "--stegofile", out, "--extractfile", "-"], passphrases=["correct horse"],
                        stdout_path=decoded)
        self.assertEqual(code, 0, log)
        with open(decoded, "rb") as f:
            self.assertEqual(f.read(), b"short forms")

    def test_newline_counts_toward_capacity(self):
        # A final newline is a byte like any other
        out = self.path("long.png")
        cap = capacity(64, 64)
        code, log = self.embed(noise(cap) + b"\n", out)
        self.assertNotEqual(code, 0)
        self.assertIn("too long", log)
        code, log = self.embed(noise(cap - 1) + b"\n", out)
        self.assertEqual(code, 0, log)
        self.assertEqual(self.extract_bytes(out), noise(cap - 1) + b"\n")

    def test_nul_in_passphrase(self):
        # A NUL typed or pasted would end the passphrase, as a C string does,
        # silently: both commands refuse it
        out = self.path("steg.png")
        pw = "correct horse\x00ignored"
        code, log = self.embed(b"nul message", out, pw)
        self.assertEqual(code, 1, log)
        self.assertIn("NUL byte", log)
        self.assertFalse(os.path.exists(out))
        code, log = self.embed(b"nul message", out, "correct horse")
        self.assertEqual(code, 0, log)
        code, log = self.extract(out, pw)
        self.assertEqual(code, 1, log)
        self.assertIn("NUL byte", log)
        self.assertNotIn("nul message", log)
        self.assertDecodes(out, "nul message", "correct horse")

    def test_oversized_chunk_dropped_not_fatal(self):
        # Past the 16 MiB per-chunk cap a chunk is left out, but the cover loads
        for kind in (b"abCd", b"sPLT", b"zTXt"):
            src = self.path("big.png")
            write_png(src, 64, 64, cover_pixel, extra=_chunk(kind, bytes(80 << 20)))
            out = self.path("steg.png")
            code, log = self.embed(b"big chunk", out, src=src)
            self.assertEqual(code, 0, log)
            self.assertNotIn(kind, [k for k, _ in png_chunks(out)])
            self.assertDecodes(out, "big chunk")

    def test_malformed_ancillary_chunks_still_load(self):
        # libpng only warns about these; a cover (or an image C wrote from
        # one) carrying them must load in every implementation
        bad = [(b"gAMA", b"\0\0"), (b"cHRM", b"\0" * 5), (b"pHYs", b"\0" * 8 + b"\x09"),
               (b"sRGB", b"\x09"), (b"tRNS", b"\0\0"), (b"acTL", b"\0\0")]
        for kind, data in bad:
            src = self.path("bad.png")
            write_png(src, 64, 64, cover_pixel, extra=_chunk(kind, data))
            out = self.path("steg.png")
            code, log = self.embed(b"odd chunk", out, src=src)
            self.assertEqual(code, 0, (kind, log))
            self.assertDecodes(out, "odd chunk")

    def test_invalid_chunk_name_refused(self):
        # libpng rejects such a file, so writing the chunk back out would
        # make an image C can't read
        for name in (b"te1t", b"a\xe9bc"):
            src = self.path("name.png")
            write_png(src, 64, 64, cover_pixel, extra=_chunk(name, b"xx"))
            code, log = self.embed(b"x", self.path("steg.png"), src=src)
            self.assertEqual(code, 1, (name, log))
            self.assertIn("could not load", log)

    def test_reserved_bit_chunk_name(self):
        # Newer libpng refuses a name with a lowercase third letter, older
        # accepts it (and the C version writes it back; the Rust one never
        # does, see rust/tests/fuzz_regressions.rs). Either way: refused, or
        # the result decodes.
        src = self.path("rsv.png")
        write_png(src, 64, 64, cover_pixel, extra=_chunk(b"abcd", b"xx"))
        out = self.path("steg.png")
        code, log = self.embed(b"x", out, src=src)
        if code == 0:
            self.assertDecodes(out, "x")
        else:
            self.assertIn("could not load", log)

    def test_critical_chunk_bad_crc_refused(self):
        src = self.path("crc.png")
        chunk = bytearray(_chunk(b"JECt", b"xx"))
        chunk[-1] ^= 1
        write_png(src, 64, 64, cover_pixel, extra=bytes(chunk))
        code, log = self.embed(b"x", self.path("steg.png"), src=src)
        self.assertEqual(code, 1, log)
        self.assertIn("could not load", log)

    def test_unwritable_stderr_is_not_a_crash(self):
        # A diagnostic that can't be printed must not turn into a panic (101)
        import subprocess
        with open("/dev/full", "wb") as full:
            code = subprocess.run([BINARY, "bogus"], stderr=full).returncode
        self.assertEqual(code, 1)

    def test_non_image_refused_without_reading_it_all(self):
        for src in ("/dev/zero", self.path("text.png")):
            if src != "/dev/zero":
                with open(src, "wb") as f:
                    f.write(b"not an image" * 1000)
            code, log = run(["extract", "-sf", src], passphrases=["correct horse"])
            self.assertEqual(code, 1, log)
            self.assertIn("could not load", log)

    def test_roundtrip_multiline_utf8(self):
        msg = "line one\nligne deux — été\n\tthird ✓"
        out = self.path("steg.png")
        self.assertEqual(self.embed(msg.encode(), out)[0], 0)
        self.assertDecodes(out, msg)

    def test_roundtrip_binary(self):
        # Every byte value, NUL included, goes in and comes back out
        msg = bytes(range(256)) + b"after the NULs"
        out = self.path("steg.png")
        self.assertEqual(self.embed(msg, out)[0], 0)
        self.assertEqual(self.extract_bytes(out), msg)

    def test_in_place(self):
        # -cf and -sf the same file: the atomic save must not clobber the input
        target = self.path("same.png")
        write_png(target, 64, 64, cover_pixel)
        self.assertEqual(self.embed(b"in place", target, src=target)[0], 0)
        self.assertDecodes(target, "in place")
        # No -sf: embed writes over the cover, with no -f needed
        write_png(target, 64, 64, cover_pixel)
        code, log = run(["embed", "-cf", target], b"no -sf", ["correct horse"] * 2)
        self.assertEqual(code, 0, log)
        self.assertIn("Wrote '%s'" % target, log)
        self.assertDecodes(target, "no -sf")

    @unittest.skipUnless(sodium, "libsodium not loadable via ctypes")
    def test_file_name_restored(self):
        # -ef's name is stored with it, encrypted; extract without -xf
        # restores the file under that name, in the current directory
        secret = self.path("secret.txt")
        with open(secret, "wb") as f:
            f.write(b"the file itself\n")
        out = self.path("steg.png")
        code, log = run(["embed", "-cf", self.cover, "-ef", secret, "-sf", out], passphrases=["correct horse"] * 2)
        self.assertEqual(code, 0, log)
        self.assertEqual(reveal(out, "correct horse", name=True), (b"secret.txt", b"the file itself\n"))
        here = self.path("restore")
        os.mkdir(here)
        restored = os.path.join(here, "secret.txt")
        code, log = run(["extract", "-sf", out], passphrases=["correct horse"], cwd=here)
        self.assertEqual(code, 0, log)
        self.assertIn("Wrote 'secret.txt'", log)
        with open(restored, "rb") as f:
            self.assertEqual(f.read(), b"the file itself\n")
        # Never over an existing file, unless -f
        with open(restored, "wb") as f:
            f.write(b"mine")
        code, log = run(["extract", "-sf", out], passphrases=["correct horse"], cwd=here)
        self.assertEqual(code, 1, log)
        self.assertIn("'secret.txt' already exists; use -f", log)
        with open(restored, "rb") as f:
            self.assertEqual(f.read(), b"mine")
        code, log = run(["extract", "-sf", out, "-f"], passphrases=["correct horse"], cwd=here)
        self.assertEqual(code, 0, log)
        with open(restored, "rb") as f:
            self.assertEqual(f.read(), b"the file itself\n")
        # -xf chooses the file, and -xf - standard output
        code, log = run(["extract", "-sf", out, "-xf", "other.txt"], passphrases=["correct horse"], cwd=here)
        self.assertEqual(code, 0, log)
        with open(os.path.join(here, "other.txt"), "rb") as f:
            self.assertEqual(f.read(), b"the file itself\n")
        self.assertEqual(self.extract_bytes(out), b"the file itself\n")
        # -N stores no name, so extract prints the message
        code, log = run(["embed", "-cf", self.cover, "-ef", secret, "-sf", out, "-f", "-N"],
                        passphrases=["correct horse"] * 2)
        self.assertEqual(code, 0, log)
        self.assertEqual(reveal(out, "correct horse", name=True), (b"", b"the file itself\n"))
        code, log = run(["extract", "-sf", out], passphrases=["correct horse"], cwd=here)
        self.assertEqual(code, 0, log)
        self.assertTrue(log.endswith("the file itself\n"), log)
        self.assertNotIn("Wrote", log)

    def test_existing_output_needs_force(self):
        # Refused before the passphrase is asked for, and left as it was
        taken = self.path("taken.png")
        with open(taken, "wb") as f:
            f.write(b"precious")
        for args in (["embed", "-cf", self.cover, "-sf", taken],
                     ["extract", "-sf", self.cover, "-xf", taken]):
            code, log = run(args, b"x", ["correct horse"] * 2)
            self.assertEqual(code, 1, (args, log))
            self.assertIn("already exists; use -f", log)
            self.assertNotIn("Passphrase", log)
            with open(taken, "rb") as f:
                self.assertEqual(f.read(), b"precious")
        code, log = run(["embed", "-cf", self.cover, "-sf", taken, "-f"], b"replaced", ["correct horse"] * 2)
        self.assertEqual(code, 0, log)
        self.assertDecodes(taken, "replaced")

    def test_unstorable_file_name(self):
        # A name extract couldn't print or create safely isn't stored: -N
        odd = self.path("bad\nname.txt")
        with open(odd, "wb") as f:
            f.write(b"x")
        out = self.path("steg.png")
        code, log = run(["embed", "-cf", self.cover, "-ef", odd, "-sf", out], passphrases=["correct horse"] * 2)
        self.assertEqual(code, 1, log)
        self.assertIn("rename it, or use -N", log)
        self.assertNotIn("Passphrase", log)
        code, log = run(["embed", "-cf", self.cover, "-ef", odd, "-sf", out, "-N"], passphrases=["correct horse"] * 2)
        self.assertEqual(code, 0, log)

    @unittest.skipUnless(sodium, "libsodium not loadable via ctypes")
    def test_forged_file_names_refused(self):
        # Only a sender with the passphrase can make these, but extract must
        # never write outside the current directory or print control codes
        here = self.path("restore")
        os.mkdir(here)
        out = self.path("forged.png")
        for name in (b"../escaped", b"sub/dir", b"/etc/passwd", b".", b"..", b"esc\x1b[31m", b"line\nbreak"):
            with self.subTest(name=name):
                forge(self.cover, out, b"payload", "correct horse", name=name)
                code, log = run(["extract", "-sf", out, "-f"], passphrases=["correct horse"], cwd=here)
                self.assertEqual(code, 1, log)
                self.assertIn("the message is malformed", log)
                self.assertNotIn("payload", log)
        self.assertEqual(os.listdir(here), [])
        self.assertFalse(os.path.exists(self.path("escaped")))

    def test_near_capacity(self):
        # 64x64: 4096 - 256 salt-region pixels (1/16 of the image) = 3840
        # px * 3 bits; minus the 32-bit header -> 1436 payload bytes; minus
        # nonce 24 + MAC 16, the encoding byte and the name length = 1394
        self.assertEqual(capacity(64, 64), 1394)
        out = self.path("full.png")
        msg = noise(1394)
        code, log = self.embed(msg, out)
        self.assertEqual(code, 0, log)
        self.assertEqual(self.extract_bytes(out), msg)
        code, log = self.embed(noise(1395), self.path("over.png"))
        self.assertEqual(code, 1, log)
        self.assertIn("message too long for this image, which holds 1394 bytes", log)

    def test_info(self):
        # The capacity, with no passphrase asked: exactly what embed takes
        code, log = run(["info", self.cover])
        self.assertEqual((code, log), (0, "Format:    PNG, 64x64, RGB\nCapacity:  %d bytes (more if the message compresses)\n"
                                         "Suggested: at most %d bytes; less is harder to detect\n"
                                         % (capacity(64, 64), suggested(64, 64))))
        gray = self.path("gray.png")
        write_png(gray, 50, 40, lambda x, y: (cover_pixel(x, y)[0],), channels=1)
        code, log = run(["info", gray])
        self.assertEqual((code, log), (0, "Format:    PNG, 50x40, gray\nCapacity:  %d bytes (more if the message compresses)\n"
                                         "Suggested: at most %d bytes; less is harder to detect\n"
                                         % (capacity(50, 40, 1), suggested(50, 40, 1))))
        # On stdout, for scripts
        out = self.path("info.txt")
        open(out, "w").close()
        code, log = run(["info", self.cover], stdout_path=out)
        self.assertEqual((code, log), (0, ""))
        with open(out) as f:
            self.assertIn("Capacity:  %d bytes" % capacity(64, 64), f.read())

    def test_suggested_payload_warning(self):
        # Advice, not a limit: past the suggestion embed still works, with a
        # warning; within it, or with -q, nothing extra
        write_png(self.cover, 200, 160, cover_pixel)
        sug = suggested(200, 160)
        self.assertEqual(sug, 200)  # 32000 pixels at a byte per 160
        out = self.path("steg.png")
        code, log = run(["info", self.cover])
        self.assertIn("Suggested: at most 200 bytes", log)
        code, log = run(["embed", "-cf", self.cover, "-sf", out, "-f", "-Z"], noise(sug), ["correct horse"] * 2)
        self.assertEqual(code, 0, log)
        self.assertNotIn("Warning", log)
        code, log = run(["embed", "-cf", self.cover, "-sf", out, "-f", "-Z"], noise(sug + 1), ["correct horse"] * 2)
        self.assertEqual(code, 0, log)
        self.assertIn("Warning: 201 bytes stored, more than the 200 suggested", log)
        self.assertEqual(self.extract_bytes(out), noise(sug + 1))
        code, log = run(["embed", "-cf", self.cover, "-sf", out, "-f", "-Z", "-q"], noise(sug + 1), ["correct horse"] * 2)
        self.assertEqual((code, log), (0, "Passphrase: \nConfirm passphrase: \n"))
        # What counts is what is stored: text that compresses to under it is fine
        text = (b"the same words again and again " * 40)[:sug * 3]
        code, log = run(["embed", "-cf", self.cover, "-sf", out, "-f"], text, ["correct horse"] * 2)
        self.assertEqual(code, 0, log)
        self.assertNotIn("Warning", log)

    def test_info_refuses_what_encode_refuses(self):
        # The same checks and messages as embed, and no prompt
        gray_rgb = self.path("gray-rgb.png")
        write_png(gray_rgb, 64, 64, lambda x, y: (cover_pixel(x, y)[0],) * 3)
        # Past the salt and length, but no room for a byte of message:
        # refused as too small, not left to fail as "too long" (embed too)
        full = self.path("full.png")
        write_png(full, 13, 13, lambda x, y: (cover_pixel(x, y)[0],), channels=1)
        self.assertLessEqual(capacity(13, 13, 1), 0)
        for src, why in [(gray_rgb, "has only gray pixels, stored as RGB"),
                         (full, "too small to hide a message"),
                         (self.path("missing.png"), "could not load")]:
            code, log = run(["info", src])
            self.assertEqual(code, 1, log)
            self.assertIn(why, log)
            self.assertNotIn("assphrase", log)
            if os.path.exists(src):
                code, log = self.embed(b"x", self.path("out.png"), src=src)
                self.assertEqual(code, 1, log)
                self.assertIn(why, log)
        for args, why in [(["info"], "info needs an image"),
                          (["info", self.cover, "-q"], "-q is not an option of info"),
                          (["info", self.cover, "-sf", self.path("x.png")], "-sf is not an option of info"),
                          (["info", self.cover, "stray"], "unexpected argument 'stray'")]:
            code, log = run(args)
            self.assertEqual(code, 1, (args, log))
            self.assertIn(why, log, args)

    def test_quiet(self):
        # -q leaves the passphrase prompts, warnings and errors, and nothing else
        out = self.path("steg.png")
        code, log = run(["embed", "-q", "-cf", self.cover, "-sf", out], b"hush", ["correct horse"] * 2)
        self.assertEqual((code, log), (0, "Passphrase: \nConfirm passphrase: \n"))
        msg = self.path("msg.txt")
        open(msg, "w").close()
        code, log = run(["extract", "-q", "-sf", out, "-xf", "-"], passphrases=["correct horse"], stdout_path=msg)
        self.assertEqual((code, log), (0, "Passphrase: \n"))
        with open(msg, "rb") as f:
            self.assertEqual(f.read(), b"hush")
        code, log = run(["extract", "-q", "-sf", out, "-xf", self.path("hushed.txt")], passphrases=["correct horse"])
        self.assertEqual((code, log), (0, "Passphrase: \n"))  # no "Wrote"
        code, log = run(["extract", "-q", "-sf", out], passphrases=["wrong horse!"])
        self.assertEqual(code, 1, log)
        self.assertIn("decryption failed", log)
        self.assertNotIn("Deriving keys", log)
        for args, why in [(["info", "-q", self.cover], "-q is not an option of info"),
                          (["passphrase", "-q"], "passphrase takes no options")]:
            code, log = run(args)
            self.assertEqual(code, 1, (args, log))
            self.assertIn(why, log, args)

    def test_help_and_version(self):
        cargo = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rust", "Cargo.toml")
        with open(cargo) as f:
            version = re.search(r'^version = "(.*)"', f.read(), re.M).group(1)
        out = self.path("stdout.txt")
        for args, want in [(["version"], "scattersteg %s\n" % version),
                           (["--version"], "scattersteg %s\n" % version),
                           (["help"], "Usage:"), (["-h"], "Usage:"), (["--help"], "Usage:")]:
            open(out, "w").close()
            code, log = run(args, stdout_path=out)  # on stdout, nothing on stderr
            self.assertEqual((code, log), (0, ""), args)
            with open(out) as f:
                got = f.read()
            if want == "Usage:":
                self.assertTrue(got.startswith("Usage:"), got)
                self.assertIn(" info <image", got)
            else:
                self.assertEqual(got, want)
        for cmd, want in (("encinfo", "XSalsa20-Poly1305"), ("--license", "GNU Affero General Public License")):
            code, log = run([cmd])
            self.assertEqual(code, 0, log)
            self.assertIn(want, log)
        for args, why in [(["help", "-q"], "help takes no options"),
                          (["version", "-sf", self.cover], "version takes no options"),
                          (["--version", "stray"], "version takes no options or arguments")]:
            code, log = run(args)
            self.assertEqual(code, 1, (args, log))
            self.assertIn(why, log, args)

    def test_samples_change_by_at_most_one(self):
        out = self.path("steg.png")
        self.assertEqual(self.embed(b"some secret", out)[0], 0)
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
        self.assertEqual(self.embed(b"spread me out please", out)[0], 0)
        _, h, before = read_png(self.cover)
        _, _, after = read_png(out)
        touched_rows = [y for y in range(h) if before[y] != after[y]]
        self.assertGreater(max(touched_rows), h // 2)

    def test_random_nonce(self):
        a, b = self.path("a.png"), self.path("b.png")
        self.assertEqual(self.embed(b"same message", a)[0], 0)
        self.assertEqual(self.embed(b"same message", b)[0], 0)
        with open(a, "rb") as fa, open(b, "rb") as fb:
            self.assertNotEqual(fa.read(), fb.read())
        self.assertDecodes(a, "same message")
        self.assertDecodes(b, "same message")

    def test_gray_cover_stays_gray(self):
        # A grayscale cover carries 1 bit per pixel and comes out grayscale
        gray = self.path("gray.png")
        write_png(gray, 48, 48, lambda x, y: ((x * 4 + y) & 0xFF,), channels=1)
        out = self.path("steg.png")
        code, log = self.embed(b"from gray", out, src=gray)
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
        cap = capacity(40, 40, 1)  # salt region 128 px: (1600 - 128 - 32) / 8 - 40 - 2 = 138
        self.assertEqual(cap, 138)
        out = self.path("steg.png")
        self.assertEqual(self.embed(noise(cap), out, src=gray)[0], 0)
        self.assertEqual(self.extract_bytes(out), noise(cap))
        code, log = self.embed(noise(cap + 1), self.path("over.png"), src=gray)
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
            # Embedding would make some pixels' R, G and B differ
            "gray as RGB": (8, 2, b"".join(b"\x00" + bytes(v for x in range(32) for v in [(x * 8 + y) & 0xFF] * 3)
                                           for y in range(32)),
                            b"", "has only gray pixels, stored as RGB"),
            # Low bits structured (and the chunk says so)
            "sBIT 5": (8, 2, b"".join(b"\x00" + bytes((x * 8 + y + k) & 0xF8 for x in range(32) for k in range(3))
                                      for y in range(32)),
                       _chunk(b"sBIT", bytes([5, 5, 5])), "has fewer than 8 significant bits"),
            # The output would keep only the first frame
            "APNG": (8, 2, b"".join(b"\x00" + bytes(cover_pixel(x, y)[k] for x in range(32) for k in range(3))
                                    for y in range(32)),
                     _chunk(b"acTL", struct.pack(">II", 1, 0))
                     + _chunk(b"fcTL", struct.pack(">IIIIIHHBB", 0, 32, 32, 0, 0, 1, 10, 0, 0)),
                     "has an animation (APNG)"),
        }
        for name, (depth, ctype, rows, extra, message) in cases.items():
            with self.subTest(cover=name):
                src = self.path("cover-%s.png" % name.replace(" ", "_"))
                raw_png(src, depth, ctype, rows, extra)
                out = self.path("out.png")
                code, log = self.embed(b"x", out, src=src)
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
        code, log = self.embed(b"with metadata", out, src=src)
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
        self.assertEqual(self.embed(b"m", out, src=src)[0], 0)
        self.assertIn((b"sRGB", bytes([0])), png_chunks(out))

    def test_odd_text_chunk_copied_verbatim(self):
        # libpng reads a tEXt chunk with an empty keyword but won't write one
        # it made itself (found by fuzzing); copied as raw bytes, it is kept
        # as the cover had it
        src = self.path("badtext.png")
        write_png(src, 64, 64, cover_pixel,
                  extra=_chunk(b"tEXt", b"\x00no keyword") + _chunk(b"tEXt", b"Fine\x00kept"))
        out = self.path("steg.png")
        code, log = self.embed(b"despite bad text", out, src=src)
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
        code, log = self.embed(b"rich metadata", out, src=src)
        self.assertEqual(code, 0, log)
        chunks = [(k, d) for k, d in png_chunks(out) if k not in (b"IHDR", b"IDAT", b"IEND")]
        self.assertEqual(chunks, before + after)
        kinds = [k for k, _ in png_chunks(out)]
        self.assertLess(kinds.index(b"zTXt"), kinds.index(b"IDAT"))
        self.assertGreater(kinds.index(b"tEXt"), len(kinds) - 1 - kinds[::-1].index(b"IDAT"))
        self.assertDecodes(out, "rich metadata")

    def test_empty_message_refused(self):
        # Almost always a mistake (nothing piped in, an empty file): it fails,
        # so a script can't take it for a written output
        out = self.path("steg.png")
        code, log = self.embed(b"", out)
        self.assertEqual(code, 1, log)
        self.assertIn("the message is empty", log)
        self.assertFalse(os.path.exists(out))
        # Byte for byte: a lone newline is a one-byte message
        self.assertEqual(self.embed(b"\n", out)[0], 0)
        self.assertEqual(self.extract_bytes(out), b"\n")

    def test_one_byte_message(self):
        out = self.path("steg.png")
        self.assertEqual(self.embed(b"x", out)[0], 0)
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
        code, log = self.extract(out)
        self.assertEqual(code, 0, log)
        self.assertTrue(log.endswith("Deriving keys...\n"), repr(log))

    @unittest.skipUnless(sodium, "libsodium not loadable via ctypes")
    def test_salt_at_public_positions(self):
        # The salt is readable by anyone from the public salt region, and the
        # encryption key derived from it opens the message
        out = self.path("steg.png")
        self.assertEqual(self.embed(b"salted", out)[0], 0)
        w, h, rows = read_png(out)
        salt_px, order, enc_key = layout(rows, w, h, b"correct horse")
        k = salt_region_pixels(w * h, 3)
        self.assertEqual(len(set(salt_px)), k)
        self.assertFalse(set(salt_px) & set(order))
        self.assertEqual(len(order), w * h - k)
        self.assertEqual(reveal(out, "correct horse"), b"salted")

    @unittest.skipUnless(sodium, "libsodium not loadable via ctypes")
    def test_salt_positions_barely_change(self):
        # The first pixels of the public order are where a warden would look.
        # Writing the 128 salt bits straight into the first 43 (as an earlier
        # format did) changed about 64 of their samples in every image; as a
        # syndrome of the whole region, the salt barely touches them.
        noise = __import__("random").Random(9)
        px = [noise.getrandbits(24) for _ in range(96 * 96)]
        write_png(self.cover, 96, 96, lambda x, y: tuple((px[y * 96 + x] >> s) & 0xFF for s in (0, 8, 16)))
        out = self.path("steg.png")
        self.assertEqual(self.embed(b"m" * 20, out)[0], 0)
        _, _, before = read_png(self.cover)
        _, _, after = read_png(out)
        old = salt_region(96 * 96, 3)[0][:43]
        changed = sum(before[p // 96][(p % 96) * 3 + c] != after[p // 96][(p % 96) * 3 + c]
                      for p in old for c in range(3))
        self.assertLess(changed, 16, changed)  # written straight in: about 64

    @unittest.skipUnless(sodium, "libsodium not loadable via ctypes")
    def test_syndrome_coding_changes_less(self):
        # The box is an STC syndrome: far fewer samples change than
        # writing its bits straight in (about half of them) would need
        noise = __import__("random").Random(3)
        px = [noise.getrandbits(24) for _ in range(96 * 96)]
        write_png(self.cover, 96, 96, lambda x, y: tuple((px[y * 96 + x] >> s) & 0xFF for s in (0, 8, 16)))
        out = self.path("steg.png")
        msg = b"m" * 150
        self.assertEqual(self.embed(msg, out)[0], 0)
        _, _, before = read_png(self.cover)
        _, _, after = read_png(out)
        changed = sum(a != b for ra, rb in zip(before, after) for a, b in zip(ra, rb))
        direct = (len(msg) + BOX_OVERHEAD) * 8 // 2 + 16 + 64  # payload, header, salt
        self.assertLess(changed, direct * 0.5, (changed, direct))
        self.assertEqual(reveal(out, "correct horse"), msg)

    @unittest.skipUnless(sodium, "libsodium not loadable via ctypes")
    def test_compressed_beyond_capacity(self):
        # Text compresses: half again what the image holds stored as is fits,
        # and comes back byte for byte, read by the binary and by Python
        text = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "THREAT_MODEL.md"), "rb").read()
        msg = b" ".join(text.split())[:capacity(64, 64) * 3 // 2]
        self.assertLessEqual(len(pack(msg)), capacity(64, 64) + 2)
        out = self.path("steg.png")
        code, log = self.embed(msg, out)
        self.assertEqual(code, 0, log)
        self.assertEqual(self.extract_bytes(out), msg)
        self.assertEqual(reveal(out, "correct horse"), msg)

    @unittest.skipUnless(sodium, "libsodium not loadable via ctypes")
    def test_forged_compressed_message_decodes(self):
        # Python's zlib compresses, the binary inflates
        msg = b"meet at the old bridge at noon " * 40
        self.assertEqual(pack(msg)[0], 1)
        out = self.path("forged.png")
        forge(self.cover, out, msg, "correct horse")
        self.assertEqual(self.extract_bytes(out), msg)

    @unittest.skipUnless(sodium, "libsodium not loadable via ctypes")
    def test_malformed_message_refused(self):
        # Only a sender who knows the passphrase can make these (they
        # authenticate), but decode must refuse them cleanly, not crash or
        # print part of them
        c = zlib.compressobj(9, zlib.DEFLATED, -15)
        hello = c.compress(b"hello") + c.flush()
        for name, plaintext in [("empty", b""), ("unknown encoding", b"\x02hello"),
                                ("not deflate", b"\x01hello"), ("cut short", b"\x01" + hello[:-1]),
                                ("data after the stream", b"\x01" + hello + b"!")]:
            with self.subTest(name):
                out = self.path("forged.png")
                forge(self.cover, out, b"", "correct horse", plaintext=plaintext)
                code, log = self.extract(out)
                self.assertEqual(code, 1, log)
                self.assertIn("the message is malformed", log)
                self.assertNotIn("hello", log)

    @unittest.skipUnless(sodium, "libsodium not loadable via ctypes")
    def test_decompression_bomb_refused(self):
        # A record of 64 MiB + 257 zeros, one past the most a message and
        # its name can be, deflates to ~65 KB; decode stops inflating there
        # rather than fill memory
        c = zlib.compressobj(9, zlib.DEFLATED, -15)
        bomb = b"\x01" + c.compress(bytes(RECORD_MAX + 1)) + c.flush()
        write_png(self.cover, 512, 512, cover_pixel)
        self.assertLess(len(bomb), capacity(512, 512))
        out = self.path("bomb.png")
        forge(self.cover, out, b"", "correct horse", plaintext=bomb)
        code, log = self.extract(out)
        self.assertEqual(code, 1, log)
        self.assertIn("the message is malformed", log)

    @unittest.skipUnless(sodium, "libsodium not loadable via ctypes")
    def test_decode_empty_message_wrong_passphrase(self):
        # Still authenticated: a wrong passphrase must not "succeed" silently
        out = self.path("empty.png")
        forge(self.cover, out, b"", "correct horse")
        code, log = self.extract(out, "wrong horse")
        self.assertNotEqual(code, 0, log)
        self.assertIn("Error:", log)

    def test_large_image_full_capacity(self):
        # 800x600: 1.44M bits -> 179,926 message bytes, through stdin and
        # the 1 KiB-doubling read buffer
        write_png(self.cover, 800, 600, cover_pixel)
        cap = capacity(800, 600)
        msg = noise(cap)
        out = self.path("big.png")
        code, log = self.embed(msg, out)
        self.assertEqual(code, 0, log)
        self.assertEqual(self.extract_bytes(out), msg)
        self.assertEqual(self.embed(noise(cap + 1), self.path("over.png"))[0], 1)

    def test_extreme_aspect_ratios(self):
        for w, h in ((1, 400), (400, 1), (2, 199)):
            with self.subTest(size=(w, h)):
                write_png(self.cover, w, h, cover_pixel)
                out = self.path("steg.png")
                self.assertEqual(self.embed(b"thin", out)[0], 0)
                self.assertDecodes(out, "thin")

    def test_long_passphrase_not_truncated(self):
        # Past the initial 256-byte buffer, the tail must still count
        out = self.path("steg.png")
        base = "a" * 255
        code, log = self.embed(b"long pass", out, passphrase=base + "X")
        if code != 0:
            self.assertIn("Error:", log)
            self.assertFalse(os.path.exists(out))
            return
        code, log = self.extract(out, base + "Y")
        self.assertNotEqual(code, 0, "passphrase beyond 255 bytes was ignored")
        self.assertNotIn("long pass", log)

    def test_long_passphrases(self):
        # The buffer starts at 256 bytes and grows by 256: test both sides of
        # each boundary, and that the last character still matters
        for n in (255, 256, 257, 511, 512, 513, 4094):
            with self.subTest(length=n):
                pw = "k" * (n - 1) + "1"
                out = self.path("steg.png")
                code, log = self.embed(b"long pass", out, passphrase=pw)
                self.assertEqual(code, 0, log)
                self.assertDecodes(out, "long pass", passphrase=pw)
                code, log = self.extract(out, pw[:-1] + "2")
                self.assertNotEqual(code, 0, log)
                self.assertNotIn("long pass", log)

    def test_passphrase_over_terminal_limit_rejected(self):
        # The terminal drops input past 4095 bytes per line, so a passphrase
        # that long may be truncated: both commands must refuse it
        steg = self.path("steg.png")
        self.assertEqual(self.embed(b"m", steg)[0], 0)
        for n in (4095, 4096, 5000):
            with self.subTest(length=n):
                out = self.path("long.png")
                code, log = self.embed(b"m", out, passphrase="k" * n)
                self.assertEqual(code, 1, log)
                self.assertIn("passphrase too long (max 4094 bytes)", log)
                self.assertFalse(os.path.exists(out))
                code, log = self.extract(steg, "k" * n)
                self.assertEqual(code, 1, log)
                self.assertIn("passphrase too long", log)

    def test_passphrase_charset(self):
        for pw in ("with spaces  inside", "ünïcødé ✓ 秘密", "tab\there and more", "exactly12byt"):
            with self.subTest(passphrase=pw):
                out = self.path("steg.png")
                self.assertEqual(self.embed(b"charset", out, passphrase=pw)[0], 0)
                self.assertDecodes(out, "charset", passphrase=pw)

    def test_short_passphrase_refused(self):
        out = self.path("steg.png")
        code, log = self.embed(b"m", out, passphrase="elevenbytes")
        self.assertEqual(code, 1, log)
        self.assertIn("passphrase too short (min 12 bytes)", log)
        self.assertNotIn("Confirm", log)  # refused before asking again
        self.assertFalse(os.path.exists(out))

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
        self.assertEqual(self.embed(b"generated", out, passphrase=pw)[0], 0)
        self.assertDecodes(out, "generated", passphrase=pw)

    def test_process_protected_while_holding_secrets(self):
        # At the prompt: no core dumps, and (as a non-root user) /proc files
        # owned by root because the process is not dumpable, which also
        # stops same-user debuggers from attaching
        pid, master = pty.fork()
        if pid == 0:
            exec_or_exit([BINARY, "extract", "-sf", self.cover])
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
        code, log = run(["embed", "-cf", self.cover, "-sf", out],
                        passphrases=["correct horse"] * 2, typed=b"typed by hand")
        self.assertEqual(code, 0, log)
        self.assertIn("Message (Ctrl+D when done)", log)
        self.assertDecodes(out, "typed by hand\n")  # with the Enter typed before Ctrl+D

    @unittest.skipUnless(sodium, "libsodium not loadable via ctypes")
    def test_tampered_ciphertext_fails_mac(self):
        # Flip one ciphertext bit, leaving the length header intact, so the
        # failure has to come from the MAC check and not the length check
        out = self.path("steg.png")
        self.assertEqual(self.embed(b"authenticated", out)[0], 0)
        w, h, rows = read_png(out)
        rows = [bytearray(r) for r in rows]
        _, order, _ = layout(rows, w, h, b"correct horse")
        pos = 32 + (NONCE + MAC + 3) * 8  # a bit of the 4th plaintext byte
        p = order[pos // 3]
        rows[p // w][(p % w) * 3 + pos % 3] ^= 1
        write_png(out, w, h, lambda x, y: rows[y][x * 3:x * 3 + 3])
        code, log = self.extract(out)
        self.assertEqual(code, 1, log)
        self.assertIn("decryption failed", log)
        self.assertNotIn("authenticated", log)

    def test_decode_image_too_small_for_header(self):
        tiny = self.path("tiny.png")
        write_png(tiny, 3, 3, cover_pixel)  # 27 bits: not even the length header
        code, log = self.extract(tiny)
        self.assertEqual(code, 1)
        self.assertIn("too small", log)

    def test_unknown_option(self):
        code, log = run(["embed", "-x", "-cf", self.cover])
        self.assertEqual(code, 1)
        self.assertIn("unknown option '-x'", log)
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
        code, log = self.embed(b"x", out, src=rgba)
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
        code, log = self.embed(b"x", out, src=rgb16)
        self.assertEqual(code, 1, log)
        self.assertIn("has 16-bit color", log)
        self.assertFalse(os.path.exists(out))

    def test_output_keeps_mode_and_symlink(self):
        out = self.path("private.png")
        with open(out, "wb") as f:
            f.write(b"x")
        os.chmod(out, 0o600)
        self.assertEqual(self.embed(b"private", out)[0], 0)
        self.assertEqual(stat.S_IMODE(os.stat(out).st_mode), 0o600)

        link = self.path("link.png")
        os.symlink(out, link)
        self.assertEqual(self.embed(b"via link", link)[0], 0)
        self.assertTrue(os.path.islink(link))
        self.assertDecodes(out, "via link")

    def test_non_regular_output_left_alone(self):
        # A FIFO (or device, or directory) at the output path is neither
        # written to nor replaced by a regular file
        fifo = self.path("out.png")
        os.mkfifo(fifo)
        code, log = self.embed(b"x", fifo)
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
                    exec_or_exit([BINARY, "extract", "-sf", self.cover])
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
            exec_or_exit([BINARY, "extract", "-sf", self.cover])
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
        self.assertEqual(self.embed(b"top secret", out)[0], 0)
        code, log = self.extract(out, "wrong horse")
        self.assertNotEqual(code, 0)
        self.assertNotIn("top secret", log)
        self.assertIn("Error:", log)

    def test_tampered_image(self):
        # Flip every LSB: the MAC must catch it (or the length must be invalid)
        out = self.path("steg.png")
        self.assertEqual(self.embed(b"integrity", out)[0], 0)
        w, h, rows = read_png(out)
        write_png(out, w, h, lambda x, y: tuple(c ^ 1 for c in rows[y][x * 3:x * 3 + 3]))
        code, log = self.extract(out)
        self.assertNotEqual(code, 0)
        self.assertNotIn("integrity", log)

    def test_decode_plain_cover(self):
        code, log = self.extract(self.cover)
        self.assertNotEqual(code, 0)
        self.assertIn("Error:", log)

    def test_passphrase_mismatch(self):
        out = self.path("steg.png")
        code, log = self.embed(b"x", out, confirm="different")
        self.assertEqual(code, 1)
        self.assertIn("do not match", log)
        self.assertFalse(os.path.exists(out))

    def test_message_too_long(self):
        out = self.path("steg.png")
        code, log = self.embed(noise(1476), out)
        self.assertEqual(code, 1)
        self.assertIn("too long", log)
        self.assertFalse(os.path.exists(out))

    def test_endless_message_refused(self):
        # Reading stops past CODEC_MESSAGE_MAX (64 MiB): an endless stdin is
        # refused, rather than read until memory runs out (or, past 4 GiB,
        # its 32-bit length wrapping)
        out = self.path("steg.png")
        code, log = run(["embed", "-cf", self.cover, "-sf", out],
                        passphrases=["correct horse"] * 2, stdin_path="/dev/zero")
        self.assertEqual(code, 1, log)
        self.assertIn("message too long (max 64 MiB)", log)
        self.assertFalse(os.path.exists(out))

    def test_message_read_error(self):
        # A read error isn't the end of the message: nothing partial is hidden
        out = self.path("steg.png")
        code, log = run(["embed", "-cf", self.cover, "-sf", out],
                        passphrases=["correct horse"] * 2, stdin_path=self.dir)
        self.assertEqual(code, 1, log)
        self.assertIn("could not read the message: Is a directory", log)
        self.assertFalse(os.path.exists(out))

    def test_output_write_error(self):
        # A message (or passphrase) that couldn't be written out is an error,
        # or the user might delete the image thinking it was saved
        out = self.path("steg.png")
        self.assertEqual(self.embed(b"keep me", out)[0], 0)
        code, log = run(["extract", "-sf", out], passphrases=["correct horse"],
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
        self.assertEqual(self.embed(noise(5000), out)[0], 1)  # too long
        with open(out, "rb") as f:
            self.assertEqual(f.read(), b"precious")
        self.assertEqual(sorted(os.listdir(self.dir)), ["cover.png", "steg.png"])

    def test_unwritable_output(self):
        code, log = self.embed(b"x", os.path.join(self.dir, "missing", "out.png"))
        self.assertEqual(code, 1)
        self.assertIn("could not write", log)
        self.assertIn("No such file or directory", log)

    def test_missing_input(self):
        # Said plainly, before the passphrase, whatever the names: a missing
        # .jpg used to be called a PNG by the output name check
        for name in ("nope.png", "nope.jpg"):
            out = self.path("out" + os.path.splitext(name)[1])
            code, log = self.embed(b"x", out, src=self.path(name))
            self.assertEqual(code, 1, log)
            self.assertIn("could not load", log)
            self.assertIn("No such file or directory", log)
            self.assertNotIn("Passphrase", log)

    def test_input_not_png(self):
        bogus = self.path("bogus.png")
        with open(bogus, "wb") as f:
            f.write(b"definitely not a png")
        code, log = self.extract(bogus)
        self.assertEqual(code, 1)
        self.assertIn("could not load", log)

    def test_image_too_small(self):
        tiny = self.path("tiny.png")
        write_png(tiny, 4, 4, cover_pixel)  # 16 px: not even room for the salt
        code, log = self.embed(b"hi", self.path("out.png"), src=tiny)
        self.assertEqual(code, 1)
        self.assertIn("too small", log)
        # 81 px: salt + header, but 4 payload bytes, short of the 40 the
        # nonce and MAC take: no room for a byte of message
        small = self.path("small.png")
        write_png(small, 9, 9, cover_pixel)
        self.assertLessEqual(capacity(9, 9), 0)
        code, log = self.embed(b"hi", self.path("out.png"), src=small)
        self.assertEqual(code, 1)
        self.assertIn("too small", log)
        roomy = self.path("roomy.png")
        write_png(roomy, 16, 16, cover_pixel)
        self.assertEqual(capacity(16, 16), 33)
        code, log = self.embed(noise(34), self.path("out.png"), src=roomy)
        self.assertEqual(code, 1)
        self.assertIn("too long", log)
        code, log = self.extract(tiny)
        self.assertEqual(code, 1)

    def test_usage_errors(self):
        self.assertEqual(run([])[0], 1)
        code, log = run(["embed"])
        self.assertEqual(code, 1)
        self.assertIn("embed needs a cover image", log)
        code, log = run(["extract"])
        self.assertEqual(code, 1)
        self.assertIn("extract needs an image", log)
        code, log = run(["frobnicate", "-sf", self.cover])
        self.assertEqual(code, 1)
        self.assertIn("unknown command", log)
        # Leftovers, options a command doesn't use, and ones ScatterSteg
        # doesn't have are refused, not ignored, before any prompt
        out = self.path("out.png")
        for args, why in [
            (["embed", "-cf", self.cover, "-sf", out, "stray"], "unexpected argument 'stray'"),
            (["extract", "-sf", self.cover, "stray"], "unexpected argument 'stray'"),
            (["extract", "-sf", self.cover, "-r"], "unknown option '-r'"),
            (["extract", "-sf", self.cover, "-xf"], "-xf needs a value"),
            (["passphrase", "stray"], "passphrase takes no options or arguments"),
            (["passphrase", "-q"], "passphrase takes no options or arguments"),
            (["extract", "-sf", self.cover, "-cf", out], "-cf is not an option of extract"),
            (["embed", "-cf", self.cover, "-sf", out, "-xf", out], "-xf is not an option of embed"),
            (["embed", "-cf", self.cover, "-sf", out, "-p", "correct horse"], "-p isn't supported"),
            (["extract", "-sf", self.cover, "--passphrase", "correct horse"], "--passphrase isn't supported"),
            (["info", self.cover, "-p", "correct horse"], "-p isn't supported"),
            (["embed", "-cf", self.cover, "-sf", out, "-e", "none"], "-e isn't supported"),
            (["embed", "-cf", self.cover, "-sf", out, "-K"], "-K isn't supported"),
        ]:
            code, log = run(args, passphrases=["correct horse"] * 2)
            self.assertEqual(code, 1, (args, log))
            self.assertIn(why, log, args)
            self.assertNotIn("Passphrase", log, args)
        self.assertFalse(os.path.exists(out))

    def test_no_passphrase_given(self):
        # EOF at the prompt must fail cleanly, not embed with an empty key
        code, log = run(["embed", "-cf", self.cover, "-sf", self.path("out.png")], b"x", [])
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
        room = capacity(w, h, ch)
        n = rng.choice([1, 2, rng.randint(1, room), room])
        # No NUL (printing stops there), no CR (the pty's \n -> \r\n
        # translation is undone on output) and no trailing newline (stripped)
        msg = bytes(rng.choice([b for b in range(1, 256) if b != 13]) for _ in range(n))
        if rng.random() < 0.4:  # text that compresses, past the room stored as is
            words = [b"bridge", b"the", b"old", b"meet", b"at", b"noon", b"\xc3\xa9t\xc3\xa9"]
            msg = b" ".join(rng.choice(words) for _ in range(rng.randint(1, room)))[:3 * room]
            while len(pack(msg)) > room + 2:  # the binaries' zlib compresses the same
                msg = msg[:len(msg) * 3 // 4]
            msg = msg.strip() or b"z"
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
                code, log = self.embed(msg, out, passphrase=pw)
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
                forge(self.cover, out, msg, pw)
                self.assertEqual(self.extract_bytes(out, passphrase=pw), msg)


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
        code, log = self.embed(b"in the coefficients", out, src=self.jpeg)
        self.assertEqual(code, 0, log)
        self.assertDecodes(out, "in the coefficients")
        code, log = self.extract(out, "wrong horse!")
        self.assertEqual(code, 1, log)
        self.assertNotIn("in the coefficients", log)

    def test_random_messages(self):
        import random
        rng = random.Random(7)
        for case in range(4):
            msg = bytes(rng.choice(range(32, 127)) for _ in range(rng.randint(1, 300)))
            with self.subTest(case=case, length=len(msg)):
                out = self.path("steg.jpg")
                self.assertEqual(self.embed(msg, out, src=self.jpeg)[0], 0)
                self.assertDecodes(out, msg.decode())

    def test_format_and_markers_kept(self):
        src = self.path("fancy.jpg")
        make_jpeg(src, 200, 150, 3, 80, "progressive", "markers", "restart")
        out = self.path("steg.jpg")
        self.assertEqual(self.embed(b"keep it all", out, src=src)[0], 0)
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
        self.assertEqual(self.embed(b"no jfif", out, src=src)[0], 0)
        markers = [m for m, _ in jpeg_segments(out)]
        self.assertEqual(markers[0], 0xE1)
        self.assertNotIn(0xE0, markers)
        self.assertDecodes(out, "no jfif")

    def test_data_after_image_refused(self):
        # An MPO or Ultra HDR file has more images after the first one's EOI;
        # they'd be lost while the MPF marker indexing them was kept
        src = self.path("mpo.jpg")
        make_jpeg(src, 200, 150)
        with open(src, "ab") as f, open(self.jpeg, "rb") as second:
            f.write(second.read())  # a second image
        out = self.path("steg.jpg")
        code, log = self.embed(b"x", out, src=src)
        self.assertEqual(code, 1, log)
        self.assertIn("data after the end of the image", log)
        self.assertFalse(os.path.exists(out))

    def test_gray(self):
        src = self.path("gray.jpg")
        make_jpeg(src, 200, 150, 1)
        out = self.path("steg.jpg")
        self.assertEqual(self.embed(b"gray jpeg", out, src=src)[0], 0)
        sof = dict(jpeg_segments(out))[0xC0]
        self.assertEqual(sof[5], 1)  # one component
        self.assertDecodes(out, "gray jpeg")

    def test_too_long_and_too_small(self):
        out = self.path("steg.jpg")
        code, log = self.embed(noise(100000), out, src=self.jpeg)
        self.assertEqual(code, 1, log)
        self.assertIn("too long", log)
        self.assertFalse(os.path.exists(out))
        tiny = self.path("tiny.jpg")
        make_jpeg(tiny, 8, 8, 1, 50)  # one block: nowhere near 160 carriers
        code, log = self.embed(b"x", out, src=tiny)
        self.assertEqual(code, 1, log)
        self.assertIn("too small", log)

    def test_info(self):
        # The capacity info gives is exactly what embed takes
        code, log = run(["info", self.jpeg])
        self.assertEqual(code, 0, log)
        m = re.fullmatch(r"Format:    JPEG, 256x192\nCapacity:  (\d+) bytes \(more if the message compresses\)\n"
                         r"Suggested: at most (\d+) bytes; less is harder to detect\n", log)
        self.assertTrue(m, log)
        n, sug = int(m.group(1)), int(m.group(2))
        self.assertTrue(0 < sug < n, (sug, n))  # a byte per 160 non-zero AC coefficients
        # The warning starts just past the suggestion
        code, log = self.embed(noise(sug), self.path("w.jpg"), src=self.jpeg)
        self.assertEqual(code, 0, log)
        self.assertNotIn("Warning", log)
        code, log = self.embed(noise(sug + 1), self.path("w.jpg"), src=self.jpeg)
        self.assertEqual(code, 0, log)
        self.assertIn("Warning: %d bytes stored, more than the %d suggested" % (sug + 1, sug), log)
        out = self.path("steg.jpg")
        code, log = self.embed(noise(n + 1), out, src=self.jpeg)
        self.assertEqual(code, 1, log)
        self.assertIn("too long", log)
        code, log = self.embed(noise(n), out, src=self.jpeg)
        self.assertEqual(code, 0, log)
        self.assertEqual(self.extract_bytes(out), noise(n))
        tiny = self.path("tiny.jpg")
        make_jpeg(tiny, 8, 8, 1, 50)
        code, log = run(["info", tiny])
        self.assertEqual(code, 1, log)
        self.assertIn("too small", log)

    def test_output_name_must_match_format(self):
        code, log = self.embed(b"x", self.path("out.png"), src=self.jpeg)
        self.assertEqual(code, 1, log)
        self.assertIn("give it a .jpg name", log)
        code, log = self.embed(b"x", self.path("out.jpeg"))  # PNG cover
        self.assertEqual(code, 1, log)
        self.assertIn("give it a .png name", log)
        self.assertEqual(sorted(os.listdir(self.dir)), ["cover.jpg", "cover.png"])

    def test_unrewritable_jpeg_refused(self):
        # A JPEG libjpeg decodes but won't re-encode (found by fuzzing):
        # refused up front, before any key derivation. It has almost no
        # carriers, so it's refused as too small before the rewrite check
        # runs (which the unit tests cover).
        src = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "fuzz", "regressions", "jpeg_load", "oversampled-progressive.jpg")
        out = self.path("steg.jpg")
        code, log = self.embed(b"x", out, src=src)
        self.assertEqual(code, 1, log)
        self.assertIn("image too small to hide a message", log)
        self.assertNotIn("Deriving keys", log)
        self.assertFalse(os.path.exists(out))

    def test_decode_cover_without_message(self):
        out = self.path("steg.jpg")
        self.assertEqual(self.embed(b"m", out, src=self.jpeg)[0], 0)
        code, log = self.extract(self.jpeg)  # the cover holds nothing
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

    def check_verified(self, log, seen):
        # The faulted comparison stands in for an encoder that changed a
        # sample on the way out: refused, and nothing written
        if "FAULT_FIRED sodium_memcmp" in log:
            self.assertIn("didn't read back as written", log)
            seen.append(log)

    def encode_sweep(self, message):
        out = self.path("steg.png")
        verified = []

        def check(code, log):
            self.check_verified(log, verified)
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
        faults = self.sweep(["embed", "-cf", self.cover, "-sf", out, "-f"], message,
                            ["correct horse"] * 2, check)
        self.assertEqual(len(verified), 1)
        return faults

    def test_encode_sweep(self):
        self.assertGreater(self.encode_sweep(b"fault sweep"), 10)

    def test_encode_sweep_long_message(self):
        # Over read_message's initial 1 KiB buffer, so its realloc can fail too
        write_png(self.cover, 64, 64, cover_pixel)
        self.assertGreater(self.encode_sweep(b"y" * 1300), FAULT_LONG_MIN)

    def test_decode_sweep(self):
        steg = self.path("steg.png")
        self.assertEqual(self.embed(b"fault sweep", steg)[0], 0)

        def check(code, log):
            if code == 0:
                self.assertIn("fault sweep", log)
            else:
                self.assertNotIn("fault sweep", log)

        faults = self.sweep(["extract", "-sf", steg], b"", ["correct horse"], check)
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

        self.sweep(["embed", "-cf", self.cover, "-sf", out, "-f"], b"grow", [pw, pw], check)

    @unittest.skipUnless(os.access(JPEG_FIXTURE, os.X_OK), "jpeg_fixture not built")
    def test_encode_and_decode_sweep_jpeg(self):
        src = self.path("cover.jpg")
        make_jpeg(src, 128, 96)
        out = self.path("steg.jpg")
        with open(out, "wb") as f:
            f.write(b"precious")
        verified = []

        def check_encode(code, log):
            self.check_verified(log, verified)
            if code == 0:
                self.assertDecodes(out, "jpeg sweep")
            else:
                with open(out, "rb") as f:
                    self.assertEqual(f.read(), b"precious")
            self.assertEqual(sorted(os.listdir(self.dir)), ["cover.jpg", "cover.png", "steg.jpg"])
            with open(out, "wb") as f:
                f.write(b"precious")

        faults = self.sweep(["embed", "-cf", src, "-sf", out, "-f"], b"jpeg sweep",
                            ["correct horse"] * 2, check_encode)
        self.assertGreater(faults, 10)
        self.assertEqual(len(verified), 1)

        self.assertEqual(self.embed(b"jpeg sweep", out, src=src)[0], 0)

        def check_decode(code, log):
            if code == 0:
                self.assertIn("jpeg sweep", log)

        self.assertGreater(self.sweep(["extract", "-sf", out], b"", ["correct horse"], check_decode), 5)

    def test_sweep_reaches_key_derivation(self):
        # Argon2id's 256 MiB allocation happens inside libsodium; the sweep
        # fails crypto_pwhash as a whole to cover running out of memory there
        code, log = None, ""
        for n in range(1, 500):
            code, log = run(["embed", "-cf", self.cover, "-sf", self.path("o.png"), "-f"], b"m",
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
