// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Maxime de Montbron

//! Where the bits go: positions of one or more samples each, in an order the
//! caller's permutation picks. Either a PNG image (a position is a pixel,
//! with one sample per channel) or a list of JPEG DCT coefficients (a
//! position is one coefficient). Bits go LSB first.
//!
//! Writing is two-phase: `write_bit` and friends record which samples must
//! change in a plan, and `apply` changes them all at once, pairing them up
//! so the histogram is preserved.

use crate::sodium;
use zeroize::Zeroize;

pub enum Samples<'a> {
    U8(&'a mut [u8]),
    Coef(&'a mut [i16]),
}

pub struct Carrier<'a> {
    samples: Samples<'a>,
    channels: u32,
    positions: u32,
    /// JPEG: carrier k's index into the coefficients
    map: &'a [u32],
    /// JPEG: cost of changing each carrier
    costs: &'a [f32],
}

impl<'a> Carrier<'a> {
    /// `pixels` is `channels` interleaved samples per pixel; `count` pixels
    pub fn png(pixels: &'a mut [u8], count: u32, channels: u32) -> Self {
        Carrier { samples: Samples::U8(pixels), channels, positions: count, map: &[], costs: &[] }
    }

    pub fn jpeg(coefs: &'a mut [i16], map: &'a [u32], costs: &'a [f32]) -> Self {
        Carrier { samples: Samples::Coef(coefs), channels: 1, positions: map.len() as u32, map, costs }
    }

    /// Pixels, or coefficients
    pub fn positions(&self) -> u32 { self.positions }
    /// Whether this carries JPEG coefficients rather than pixels
    pub fn is_coef(&self) -> bool { matches!(self.samples, Samples::Coef(_)) }
    /// Samples per position
    pub fn channels(&self) -> u32 { self.channels }

    /// A digest of all a decoder reads: the carrier's size and every
    /// sample, in order
    pub fn digest(&self) -> [u8; 32] {
        let mut h = sodium::Hasher::new();
        h.update(&self.positions.to_ne_bytes());
        h.update(&self.channels.to_ne_bytes());
        match &self.samples {
            Samples::U8(s) => h.update(&s[..self.positions as usize * self.channels as usize]),
            Samples::Coef(s) => {
                for part in self.map.chunks(4096) {
                    let bytes: Vec<u8> = part.iter().flat_map(|&i| s[i as usize].to_ne_bytes()).collect();
                    h.update(&bytes);
                }
            }
        }
        h.finish()
    }

    /// The sample holding bit `pos` of the data written in `indices` order
    fn flat(&self, indices: &[u32], pos: u32) -> usize {
        match self.samples {
            Samples::Coef(_) => self.map[indices[pos as usize] as usize] as usize,
            Samples::U8(_) => {
                let ch = self.channels;
                (indices[(pos / ch) as usize] as usize) * ch as usize + (pos % ch) as usize
            }
        }
    }

    fn value(&self, flat: usize) -> i32 {
        match &self.samples {
            Samples::U8(s) => s[flat] as i32,
            Samples::Coef(s) => s[flat] as i32,
        }
    }

    fn set_value(&mut self, flat: usize, v: i32) {
        match &mut self.samples {
            Samples::U8(s) => s[flat] = v as u8,
            Samples::Coef(s) => s[flat] = v as i16,
        }
    }

    fn read_bit(&self, indices: &[u32], pos: u32) -> u8 {
        (self.value(self.flat(indices, pos)) & 1) as u8
    }
}

/// Samples whose LSB has to flip, recorded as indices and changed together
/// by `apply`
#[derive(Default)]
pub struct EmbedPlan {
    samples: Vec<usize>,
}

#[derive(Default, Debug, Clone, Copy)]
pub struct EmbedStats {
    /// samples whose LSB had to flip
    pub changes: usize,
    /// of those, how many swapped values in pairs
    pub exchanged: usize,
}

impl EmbedPlan {
    pub fn new() -> Self { Self::default() }

    /// Record that bit `pos`'s sample must have LSB `bit` (nothing to do if it has)
    fn write_bit(&mut self, c: &Carrier, indices: &[u32], pos: u32, bit: u8) {
        let flat = c.flat(indices, pos);
        if (c.value(flat) & 1) as u8 != bit & 1 {
            self.samples.push(flat);
        }
    }
}

/// Random coin flips, drawn from libsodium 64 at a time
struct Coins {
    bits: u64,
    left: u32,
}

impl Coins {
    fn flip(&mut self) -> bool {
        if self.left == 0 {
            let mut b = [0u8; 8];
            sodium::random_bytes(&mut b);
            self.bits = u64::from_ne_bytes(b);
            self.left = 64;
        }
        let heads = self.bits & 1 != 0;
        self.bits >>= 1;
        self.left -= 1;
        heads
    }
}

/// LSB matching: change the value by +-1 at random rather than overwriting
/// the LSB. Pixel values stay in 0..255. JPEG coefficients must keep
/// |c| >= 2 so the decoder finds the same carriers: +-2 can only move
/// outwards.
fn nudged(coef: bool, v: i32, coins: &mut Coins) -> i32 {
    if !coef {
        if v == 0 { return 1; }
        if v == 255 { return 254; }
    } else {
        // Stay within what a JPEG encoder can write (|AC| <= 1023)
        if v == 2 { return 3; }
        if v == -2 { return -3; }
        if v >= 1023 { return v - 1; }
        if v <= -1023 { return v + 1; }
    }
    if coins.flip() { v + 1 } else { v - 1 }
}

/// Exchange embedding (after Hetzl & Mutzel, "A Graph-Theoretic Approach to
/// Steganography", 2005, the idea behind steghide). Two samples that both
/// need flipping and hold values v and v+1 swap values instead of each
/// taking a +-1 nudge: both LSBs come out right, each still moves by just 1,
/// and the histogram doesn't change at all.
///
/// Only samples one value apart can pair, so the pairing graph is a chain of
/// value buckets, where greedily pairing each bucket's leftovers with the
/// next bucket gives a maximum matching. Shuffling first makes which samples
/// pair up random. The rest get a +-1 nudge. For JPEG, buckets -1, 0 and 1
/// hold no carriers, so no swap ever breaks |c| >= 2.
///
/// Decoding only reads LSBs, so it can't tell how they were set.
pub fn apply(c: &mut Carrier, plan: &mut EmbedPlan) -> EmbedStats {
    let n = plan.samples.len();
    let coef = matches!(c.samples, Samples::Coef(_));
    let lo: i32 = if coef { -32768 } else { 0 };
    let buckets: usize = if coef { 65536 } else { 256 };

    // Shuffle, then a stable counting sort by value: random order per bucket
    for i in (2..=n).rev() {
        let j = sodium::random_uniform(i as u32) as usize;
        plan.samples.swap(i - 1, j);
    }
    let mut start = vec![0usize; buckets + 1];
    for &s in &plan.samples { start[(c.value(s) - lo) as usize + 1] += 1; }
    for b in 0..buckets { start[b + 1] += start[b]; }
    let mut fill = start[..buckets].to_vec();
    let mut sorted = vec![0usize; n];
    for &s in &plan.samples {
        let b = (c.value(s) - lo) as usize;
        sorted[fill[b]] = s;
        fill[b] += 1;
    }

    // Walk the chain: bucket b's leftovers pair with the start of bucket b+1.
    // Values were only read for sorting, so they can be changed as we go.
    let mut pairs = 0;
    let mut left_from = 0; // bucket b's samples from here on are unpaired
    let mut coins = Coins { bits: 0, left: 0 };
    for b in 0..buckets {
        let v = b as i32 + lo;
        let leftovers = start[b + 1] - left_from;
        let next = if b + 1 < buckets { start[b + 2] - start[b + 1] } else { 0 };
        let k = leftovers.min(next);
        for i in 0..k {
            c.set_value(sorted[left_from + i], v + 1);
            c.set_value(sorted[start[b + 1] + i], v);
        }
        pairs += k;
        for i in k..leftovers {
            let nv = nudged(coef, v, &mut coins);
            c.set_value(sorted[left_from + i], nv);
        }
        left_from = start[b + 1] + k;
    }
    coins.bits.zeroize();
    plan.samples.clear();
    EmbedStats { changes: n, exchanged: 2 * pairs }
}

/// A 32-bit length, then the data. Err if it doesn't fit in `count` positions.
pub fn encode(c: &Carrier, indices: &[u32], count: u32, data: &[u8], plan: &mut EmbedPlan) -> Result<(), ()> {
    let bits_needed = 32 + data.len() as u64 * 8;
    if bits_needed > count as u64 * c.channels as u64 { return Err(()); }
    let len = data.len() as u32;
    let mut pos = 0;
    for b in 0..32 {
        plan.write_bit(c, indices, pos, ((len >> b) & 1) as u8);
        pos += 1;
    }
    for &byte in data {
        for b in 0..8 {
            plan.write_bit(c, indices, pos, (byte >> b) & 1);
            pos += 1;
        }
    }
    Ok(())
}

/// Reads up to `out.len()` bytes of a length-prefixed payload
pub fn decode(c: &Carrier, indices: &[u32], count: u32, out: &mut [u8]) {
    let ch = c.channels;
    let mut pos = 0u32;
    let mut data_len = 0u32;
    for b in 0..32 {
        if pos / ch >= count { return; }
        data_len |= (c.read_bit(indices, pos) as u32) << b;
        pos += 1;
    }
    let data_len = (data_len as usize).min(out.len());
    for byte in out.iter_mut().take(data_len) {
        let mut v = 0u8;
        for b in 0..8 {
            if pos / ch >= count { break; }
            v |= c.read_bit(indices, pos) << b;
            pos += 1;
        }
        *byte = v;
    }
}

pub fn peek_len(c: &Carrier, indices: &[u32], count: u32) -> u32 {
    let ch = c.channels;
    let mut data_len = 0u32;
    for b in 0..32u32 {
        if b / ch >= count { return 0; }
        data_len |= (c.read_bit(indices, b) as u32) << b;
    }
    data_len
}

/// Raw bytes with no length header. Err if they don't fit in `count` positions.
pub fn write_raw(c: &Carrier, indices: &[u32], count: u32, data: &[u8], plan: &mut EmbedPlan) -> Result<(), ()> {
    if data.len() as u64 * 8 > count as u64 * c.channels as u64 { return Err(()); }
    for pos in 0..data.len() as u32 * 8 {
        plan.write_bit(c, indices, pos, (data[(pos / 8) as usize] >> (pos % 8)) & 1);
    }
    Ok(())
}

pub fn read_raw(c: &Carrier, indices: &[u32], count: u32, out: &mut [u8]) -> Result<(), ()> {
    if out.len() as u64 * 8 > count as u64 * c.channels as u64 { return Err(()); }
    out.fill(0);
    for pos in 0..out.len() as u32 * 8 {
        out[(pos / 8) as usize] |= c.read_bit(indices, pos) << (pos % 8);
    }
    Ok(())
}

// For syndrome coding (format v3). Sample k is the one bit position k of
// data written in `indices` order goes to, as above.

/// The LSBs of samples start .. start+n-1
pub fn get_bits(c: &Carrier, indices: &[u32], start: usize, bits: &mut [u8]) {
    for (i, b) in bits.iter_mut().enumerate() {
        *b = c.read_bit(indices, (start + i) as u32);
    }
}

/// Record the changes that give those samples these LSBs
pub fn set_bits(c: &Carrier, indices: &[u32], start: usize, bits: &[u8], plan: &mut EmbedPlan) {
    for (i, &b) in bits.iter().enumerate() {
        plan.write_bit(c, indices, (start + i) as u32, b);
    }
}

/// How costly a change to each of those samples would be to hide.
///
/// PNG: uniform. Content-adaptive costs (cheap in texture, dear in flat
/// areas, like HILL) did worse than uniform on the detectors available, since
/// they buy cheaper locations with more changes.
///
/// JPEG: a change of 1 to a coefficient changes its block's pixels in
/// proportion to the quantization step, so that is the cost (precomputed per
/// carrier by the loader, which also makes changes to |value| == 2 dearer).
pub fn costs(c: &Carrier, indices: &[u32], start: usize, out: &mut [f32]) {
    for (i, o) in out.iter_mut().enumerate() {
        *o = match c.samples {
            Samples::U8(_) => 1.0,
            Samples::Coef(_) => c.costs[indices[start + i] as usize],
        };
    }
}
