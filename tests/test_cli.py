#!/usr/bin/env python3
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


def run(args, message=b"", passphrases=(), env=None, binary=None, typed=None):
    """Run scattersteg, answer each passphrase prompt in order. The message
    goes in on stdin, or with `typed`, is typed at the terminal instead.
    Returns (exit_code, combined stdout+stderr as text)."""
    binary = binary or BINARY
    with tempfile.TemporaryFile() as stdin:
        stdin.write(message)
        stdin.flush()
        stdin.seek(0)
        pid, master = pty.fork()
        if pid == 0:
            if typed is None:
                os.dup2(stdin.fileno(), 0)
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


def write_png(path, width, height, pixel):
    """pixel(x, y) -> (r, g, b)"""
    raw = b"".join(
        b"\x00" + bytes(c for x in range(width) for c in pixel(x, y))
        for y in range(height))
    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n"
                + _chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
                + _chunk(b"IDAT", zlib.compress(raw))
                + _chunk(b"IEND", b""))


def read_png(path):
    """Returns (width, height, list of row bytes) for 8-bit RGB, non-interlaced."""
    with open(path, "rb") as f:
        data = f.read()
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    pos, idat = 8, b""
    while pos < len(data):
        length, kind = struct.unpack(">I4s", data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + length]
        if kind == b"IHDR":
            width, height, depth, ctype, _, _, interlace = struct.unpack(">IIBBBBB", body)
            assert (depth, ctype, interlace) == (8, 2, 0)
        elif kind == b"IDAT":
            idat += body
        pos += 12 + length
    raw = zlib.decompress(idat)
    stride, bpp = width * 3, 3
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
SALT_PIXELS = 43  # v2: 128 salt bits, 3 per pixel
V2_OVERHEAD = NONCE + MAC


def argon2id(pw, salt, level):
    key = ctypes.create_string_buffer(32)
    assert sodium.crypto_pwhash(
        key, 32, pw, len(pw), salt,
        getattr(sodium, "crypto_pwhash_opslimit_" + level)(),
        getattr(sodium, "crypto_pwhash_memlimit_" + level)(), 2) == 0  # ALG_ARGON2ID13
    return key.raw


def embed_bits(rows, w, order, bits):
    for pos, bit in enumerate(bits):
        p = order[pos // 3]
        i = (p % w) * 3 + pos % 3
        rows[p // w][i] = (rows[p // w][i] & 0xFE) | bit


def read_bits(rows, w, order, start, n):
    out = 0
    for b in range(n):
        p = order[(start + b) // 3]
        out |= (rows[p // w][(p % w) * 3 + (start + b) % 3] & 1) << b
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


def read_payload(rows, w, order, min_len):
    n = read_bits(rows, w, order, 0, 32)
    if n < min_len or 32 + n * 8 > len(order) * 3:
        return None
    return bytes(read_bits(rows, w, order, 32 + i * 8, 8) for i in range(n))


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


def salt_pixels_v2(count):
    key = hashlib.blake2b(b"ScatterSteg v2 salt positions", digest_size=32).digest()
    return permutation_v2(key, count)[:SALT_PIXELS]


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
    salt_px = salt_pixels_v2(w * h)
    salt = read_bits(rows, w, salt_px, 0, SALT * 8).to_bytes(SALT, "little")
    scatter_key, enc_key = keys_v2(pw, salt)
    return salt_px, payload_order_v2(scatter_key, w * h, salt_px), enc_key


def forge(src, dst, message, passphrase):
    """Embed `message` as v2, the way scattersteg encode does, without its
    checks (so an empty message is allowed). Overwrites LSBs; decoding
    can't tell the difference from LSB matching."""
    w, h, rows = read_png(src)
    rows = [bytearray(r) for r in rows]
    pw = passphrase.encode()
    salt = os.urandom(SALT)
    salt_px = salt_pixels_v2(w * h)
    scatter_key, enc_key = keys_v2(pw, salt)
    embed_bits(rows, w, salt_px, to_bits(salt))
    embed_bits(rows, w, payload_order_v2(scatter_key, w * h, salt_px),
               length_prefixed(seal(message, enc_key)))
    write_png(dst, w, h, lambda x, y: rows[y][x * 3:x * 3 + 3])


def reveal(src, passphrase):
    """Extract and decrypt a v2 message independently of the binary.
    Returns the plaintext bytes, or None if it does not authenticate."""
    w, h, rows = read_png(src)
    _, order, enc_key = layout_v2(rows, w, h, passphrase.encode())
    payload = read_payload(rows, w, order, V2_OVERHEAD)
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


def capacity_v2(w, h):
    """Largest message encode accepts for a w x h cover"""
    return ((w * h - SALT_PIXELS) * 3 - 32) // 8 - V2_OVERHEAD


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

    def test_roundtrip_binary_safe_up_to_nul(self):
        # Plaintext is printed with %s, so it is truncated at the first NUL;
        # pin that behaviour so a change is noticed.
        out = self.path("steg.png")
        self.assertEqual(self.encode(b"before\x00after", out)[0], 0)
        code, log = self.decode(out)
        self.assertEqual(code, 0, log)
        self.assertIn("before\n", log)
        self.assertNotIn("after", log)

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

    def test_non_rgb_cover(self):
        # A grayscale cover is converted to RGB on load; the output still decodes
        gray = self.path("gray.png")
        raw = b"".join(b"\x00" + bytes((x * 4 + y) & 0xFF for x in range(48)) for y in range(48))
        with open(gray, "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\n"
                    + _chunk(b"IHDR", struct.pack(">IIBBBBB", 48, 48, 8, 0, 0, 0, 0))
                    + _chunk(b"IDAT", zlib.compress(raw))
                    + _chunk(b"IEND", b""))
        out = self.path("steg.png")
        code, log = self.encode(b"from gray", out, src=gray)
        self.assertEqual(code, 0, log)
        self.assertDecodes(out, "from gray")

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
        self.assertEqual(open_box(read_payload(rows, w, order, V2_OVERHEAD), enc_key), b"salted")

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
        for pw in ("with spaces  inside", "ünïcødé ✓ 秘密", "tab\there", "x"):
            with self.subTest(passphrase=pw):
                out = self.path("steg.png")
                self.assertEqual(self.encode(b"charset", out, passphrase=pw)[0], 0)
                self.assertDecodes(out, "charset", passphrase=pw)

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
        w, h = rng.randint(16, 72), rng.randint(16, 72)
        capacity = capacity_v2(w, h)
        n = rng.choice([1, 2, rng.randint(1, capacity), capacity])
        # No NUL (printing stops there), no CR (the pty's \n -> \r\n
        # translation is undone on output) and no trailing newline (stripped)
        msg = bytes(rng.choice([b for b in range(1, 256) if b != 13]) for _ in range(n))
        msg = msg.rstrip(b"\n") or b"z"
        pw = "".join(rng.choice("abcxyz019 !é✓") for _ in range(rng.randint(1, 60)))
        return w, h, msg, pw

    def cover_for(self, w, h, rng):
        noise = [rng.getrandbits(24) for _ in range(w * h)]
        write_png(self.cover, w, h,
                  lambda x, y: tuple((noise[y * w + x] >> s) & 0xFF for s in (0, 8, 16)))

    def test_binary_encode_python_decode(self):
        import random
        rng = random.Random(self.SEED)
        for case in range(self.CASES):
            w, h, msg, pw = self.random_case(rng)
            with self.subTest(case=case, size=(w, h), length=len(msg), seed=self.SEED):
                self.cover_for(w, h, rng)
                out = self.path("steg.png")
                code, log = self.encode(msg, out, passphrase=pw)
                self.assertEqual(code, 0, log)
                self.assertEqual(reveal(out, pw), msg)
                self.assertIsNone(reveal(out, pw + "!"))

    def test_python_encode_binary_decode(self):
        import random
        rng = random.Random(self.SEED + 1)
        for case in range(self.CASES):
            w, h, msg, pw = self.random_case(rng)
            with self.subTest(case=case, size=(w, h), length=len(msg), seed=self.SEED + 1):
                self.cover_for(w, h, rng)
                out = self.path("forged.png")
                forge(self.cover, out, msg, pw)
                code, log = run(["decode", "-i", out], passphrases=[pw])
                self.assertEqual(code, 0, log)
                # Byte-exact: the output is the raw message plus "\n"
                self.assertIn(msg + b"\n", log.encode(errors="surrogateescape"))


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

    def test_sweep_reaches_key_derivation(self):
        # Argon2id's 256 MiB allocation happens inside libsodium; the sweep
        # fails crypto_pwhash as a whole to cover running out of memory there
        code, log = None, ""
        for n in range(1, 500):
            code, log = run(["encode", "-i", self.cover, "-o", self.path("o.png")], b"m",
                            ["p", "p"], env={**self.ENV, "FAULT_AT": str(n)}, binary=FAULT_BINARY)
            if "FAULT_FIRED crypto_pwhash" in log or "FAULT_NOT_REACHED" in log:
                break
        self.assertIn("FAULT_FIRED crypto_pwhash", log)
        self.assertEqual(code, 1)
        self.assertIn("key derivation failed", log)


if __name__ == "__main__":
    if not os.access(BINARY, os.X_OK):
        sys.exit("scattersteg binary not found at %s (run make first)" % BINARY)
    unittest.main(verbosity=2)
