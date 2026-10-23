// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Maxime de Montbron

//! Keyed permutations of [0, count), driven by ChaCha20.

use crate::sodium;

const KEY: usize = sodium::CHACHA_KEY_BYTES;

/// Format v1 (legacy, decode only): Fisher-Yates driven by a ChaCha20
/// stream read in host byte order, with modulo bias. Kept unchanged so
/// images written by older versions still decode.
pub fn scatter(key: &[u8; KEY], count: u32) -> Option<Vec<u32>> {
    if count == 0 || count > u32::MAX / 4 { return None; }
    let mut stream = vec![0u8; count as usize * 4];
    sodium::chacha20_stream(&mut stream, key);
    let mut indices: Vec<u32> = (0..count).collect();
    for i in (1..count as usize).rev() {
        let r = u32::from_ne_bytes(stream[i * 4..i * 4 + 4].try_into().unwrap());
        indices.swap(i, (r as usize) % (i + 1));
    }
    Some(indices)
}

const CHUNK: usize = 4096; // keystream bytes generated at a time (64 blocks)

struct Stream<'a> {
    key: &'a [u8; KEY],
    block: u32,
    pos: usize,
    buf: [u8; CHUNK],
}

impl<'a> Stream<'a> {
    fn new(key: &'a [u8; KEY]) -> Self {
        Stream { key, block: 0, pos: CHUNK, buf: [0; CHUNK] }
    }

    /// Next 4 keystream bytes as a little-endian u32, from one long
    /// keystream starting at block 0
    fn next_u32(&mut self) -> u32 {
        if self.pos == CHUNK {
            self.buf.fill(0);
            sodium::chacha20_ietf_xor_ic(&mut self.buf, self.block, self.key);
            self.block += (CHUNK / 64) as u32;
            self.pos = 0;
        }
        let v = u32::from_le_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        v
    }

    /// Uniform in [0, bound) by rejection: values below 2^32 mod bound are
    /// redrawn, so every result has exactly floor(2^32 / bound) preimages
    fn uniform(&mut self, bound: u32) -> u32 {
        let min = bound.wrapping_neg() % bound;
        loop {
            let r = self.next_u32();
            if r >= min { return r % bound; }
        }
    }
}

impl Drop for Stream<'_> {
    fn drop(&mut self) { sodium::memzero(&mut self.buf); }
}

/// Format v2: a permutation of [0, count), from an unbiased forward
/// Fisher-Yates shuffle driven by the ChaCha20-IETF keystream of `key`
/// (zero nonce), read as little-endian u32s. None if count == 0.
pub fn permutation(key: &[u8; KEY], count: u32) -> Option<Vec<u32>> {
    if count == 0 { return None; }
    let mut a: Vec<u32> = (0..count).collect();
    let mut s = Stream::new(key);
    // Slot i is final after step i, which is what lets `sample` produce a
    // prefix without the whole array
    for i in 0..count - 1 {
        let j = i + s.uniform(count - i);
        a.swap(i as usize, j as usize);
    }
    Some(a)
}

/// The first k entries of `permutation(key, count)`, in O(k^2) time without
/// the full array. None if k > count.
pub fn sample(key: &[u8; KEY], count: u32, k: u32) -> Option<Vec<u32>> {
    if k > count { return None; }
    // The same shuffle, keeping only the slots it has touched: at most 2k
    // (slot, value) pairs; every other slot still holds its index
    let mut touched: Vec<(u32, u32)> = Vec::with_capacity(2 * k as usize);
    let mut out = Vec::with_capacity(k as usize);
    let mut s = Stream::new(key);
    for i in 0..k {
        let j = if i + 1 < count { i + s.uniform(count - i) } else { i };
        let (mut vi, mut vj) = (i, j);
        let (mut pi, mut pj) = (None, None);
        for (m, &(slot, val)) in touched.iter().enumerate() {
            if slot == i { vi = val; pi = Some(m); }
            if slot == j { vj = val; pj = Some(m); }
        }
        let pi = pi.unwrap_or_else(|| { touched.push((i, vi)); touched.len() - 1 });
        if pj.is_none() && j != i {
            touched.push((j, vj));
            pj = Some(touched.len() - 1);
        }
        touched[pi].1 = vj;
        if let Some(pj) = pj { touched[pj].1 = vi; }
        out.push(vj);
    }
    Some(out)
}
