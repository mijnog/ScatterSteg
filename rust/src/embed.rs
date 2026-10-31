// SPDX-License-Identifier: MIT OR Apache-2.0
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
    /// JPEG: cost of changing each carrier; PNG: of each sample, or empty
    /// for uniform
    costs: &'a [f32],
    /// PNG: pixels per row (HILL needs the layout)
    width: u32,
}

impl<'a> Carrier<'a> {
    /// `pixels` is `channels` interleaved samples per pixel, row by row
    pub fn png(pixels: &'a mut [u8], width: u32, height: u32, channels: u32) -> Self {
        Carrier { samples: Samples::U8(pixels), channels, positions: width * height, costs: &[], width }
    }

    /// `coefs` is 8x8 blocks of 64 DCT coefficients each, DC first. Carrier
    /// k is AC coefficient k % 63 + 1 of block k / 63, and costs[k] its cost.
    pub fn jpeg(coefs: &'a mut [i16], costs: &'a [f32]) -> Self {
        assert!(costs.len().div_ceil(63) * 64 <= coefs.len());
        Carrier { samples: Samples::Coef(coefs), channels: 1, positions: costs.len() as u32, costs, width: 0 }
    }

    /// JPEG carrier k's index into the coefficients
    fn coef_index(k: u32) -> usize {
        (k / 63) as usize * 64 + (k % 63) as usize + 1
    }

    /// The same samples, with these costs if a PNG (see `costs`); a JPEG
    /// keeps its own
    pub fn with_png_costs<'b>(&'b mut self, png_costs: &'b [f32]) -> Carrier<'b> {
        let (samples, costs) = match &mut self.samples {
            Samples::U8(s) => (Samples::U8(s), png_costs),
            Samples::Coef(s) => (Samples::Coef(s), self.costs),
        };
        Carrier { samples, channels: self.channels, positions: self.positions, costs, width: self.width }
    }

    /// PNG: HILL costs (Li et al., 2014) for every sample, in pixel order:
    /// the reciprocal of the local high-pass energy, smoothed, so changes go
    /// where the image is busy. Empty for JPEG.
    pub fn hill_costs(&self) -> Vec<f32> {
        let Samples::U8(px) = &self.samples else { return Vec::new() };
        let (w, h, ch) = (self.width as usize, (self.positions / self.width.max(1)) as usize, self.channels as usize);
        let plane = w * h;
        let mut costs = vec![0f32; plane * ch];
        let mut a = vec![0f32; plane];
        let mut tmp = vec![0f32; plane];
        const KB: [[i32; 3]; 3] = [[-1, 2, -1], [2, -4, 2], [-1, 2, -1]];
        for c in 0..ch {
            // |KB high-pass residual|, edges repeated
            for y in 0..h {
                for x in 0..w {
                    let mut r = 0;
                    for (dy, row) in KB.iter().enumerate() {
                        for (dx, k) in row.iter().enumerate() {
                            let yy = (y + dy).saturating_sub(1).min(h - 1);
                            let xx = (x + dx).saturating_sub(1).min(w - 1);
                            r += k * px[(yy * w + xx) * ch + c] as i32;
                        }
                    }
                    a[y * w + x] = r.abs() as f32;
                }
            }
            box_mean(&mut a, &mut tmp, w, h, 1);
            for v in a.iter_mut() { *v = 1.0 / (*v + 1e-10); }
            box_mean(&mut a, &mut tmp, w, h, 7);
            for (i, v) in a.iter().enumerate() { costs[i * ch + c] = *v; }
        }
        costs
    }

    /// PNG: the build's cost model, HILL unless built with another (see
    /// `distortion`). Empty for JPEG.
    pub fn png_costs(&self) -> Vec<f32> {
        let Samples::U8(px) = &self.samples else { return Vec::new() };
        let (w, h, ch) = (self.width as usize, (self.positions / self.width.max(1)) as usize, self.channels as usize);
        if cfg!(png_costs = "wow") {
            crate::distortion::wow(px, w, h, ch)
        } else if cfg!(png_costs = "suniward") {
            crate::distortion::suniward(px, w, h, ch)
        } else {
            self.hill_costs()
        }
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
                for part in (0..self.positions).collect::<Vec<u32>>().chunks(4096) {
                    let bytes: Vec<u8> = part.iter().flat_map(|&k| s[Self::coef_index(k)].to_ne_bytes()).collect();
                    h.update(&bytes);
                }
            }
        }
        h.finish()
    }

    /// The sample holding bit `pos` of the data written in `indices` order
    fn flat(&self, indices: &[u32], pos: u32) -> usize {
        match self.samples {
            Samples::Coef(_) => Self::coef_index(indices[pos as usize]),
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
/// the LSB. Pixel values stay in 0..255, JPEG coefficients within what an
/// encoder can write. Every AC coefficient is a carrier, whatever its value,
/// so a decoder finds the same carriers however they change.
fn nudged(coef: bool, v: i32, coins: &mut Coins) -> i32 {
    if !coef {
        if v == 0 { return 1; }
        if v == 255 { return 254; }
    } else {
        // Stay within what a JPEG encoder can write (|AC| <= 1023)
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
/// pair up random. The rest get a +-1 nudge.
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
#[allow(clippy::result_unit_err)] // one way to fail, which the caller knows
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
#[allow(clippy::result_unit_err)] // one way to fail, which the caller knows
pub fn write_raw(c: &Carrier, indices: &[u32], count: u32, data: &[u8], plan: &mut EmbedPlan) -> Result<(), ()> {
    if data.len() as u64 * 8 > count as u64 * c.channels as u64 { return Err(()); }
    for pos in 0..data.len() as u32 * 8 {
        plan.write_bit(c, indices, pos, (data[(pos / 8) as usize] >> (pos % 8)) & 1);
    }
    Ok(())
}

#[allow(clippy::result_unit_err)] // one way to fail, which the caller knows
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
/// PNG: HILL (see `Carrier::hill_costs`), or uniform if the carrier has no
/// costs. HILL makes about 30-40% more changes than uniform but puts them
/// where the image is busy; against the rich-model detector in benchmark/
/// that cut detection from 65-94% to 56-65% (0.05-0.4 bits per pixel), and
/// more of its changes pair up as value swaps (93-98% against 48-87%).
///
/// JPEG: UERD, precomputed per carrier by the loader (collect_carriers): the
/// quantization step over the energy of the block and its neighbours, for
/// every AC coefficient. Against the DCTR-style detector in benchmark/ that
/// gives P_E 0.47-0.36 at 0.05-0.3 bits per non-zero AC coefficient, where
/// the earlier rule (only |value| >= 2) gave 0.49-0.26.
pub fn costs(c: &Carrier, indices: &[u32], start: usize, out: &mut [f32]) {
    let ch = c.channels as usize;
    for (i, o) in out.iter_mut().enumerate() {
        let pos = start + i;
        *o = match c.samples {
            Samples::U8(_) if c.costs.is_empty() => 1.0,
            Samples::U8(_) => c.costs[indices[pos / ch] as usize * ch + pos % ch],
            Samples::Coef(_) => c.costs[indices[pos] as usize],
        };
    }
}

/// Mean over 2r+1 samples along one line (n samples, `step` apart),
/// mirrored at the ends as MATLAB's 'symmetric' padding
fn box_line(src: &[f32], dst: &mut [f32], n: usize, step: usize, r: isize) {
    for i in 0..n {
        let mut sum = 0f64;
        for k in -r..=r {
            let mut j = i as isize + k;
            while j < 0 || j >= n as isize { j = if j < 0 { -j - 1 } else { 2 * n as isize - j - 1 }; }
            sum += src[j as usize * step] as f64;
        }
        dst[i * step] = (sum / (2 * r + 1) as f64) as f32;
    }
}

/// In place: the (2r+1) x (2r+1) mean of a w x h plane, using tmp
fn box_mean(a: &mut [f32], tmp: &mut [f32], w: usize, h: usize, r: isize) {
    for y in 0..h { box_line(&a[y * w..], &mut tmp[y * w..], w, 1, r); }
    for x in 0..w { box_line(&tmp[x..], &mut a[x..], h, w, r); }
}

#[cfg(test)]
mod tests {
    use super::Carrier;

    /// A cover half flat, half noise
    fn half_flat(w: usize, h: usize) -> Vec<u8> {
        (0..w * h).map(|i| if i % w < w / 2 { 128 } else { ((i * 2654435761usize) >> 13) as u8 }).collect()
    }

    #[test]
    fn hill_costs_flat_areas_dear() {
        let (w, h) = (32, 32);
        let mut px = half_flat(w, h);
        let costs = Carrier::png(&mut px, w as u32, h as u32, 1).hill_costs();
        let (flat, busy) = (costs[16 * w + 2], costs[16 * w + 29]);
        assert!(flat > 1000.0 * busy, "flat {flat}, busy {busy}");
    }

    #[test]
    #[allow(clippy::excessive_precision)]
    fn hill_costs_match_c() {
        // From embed_hill_costs (embed.c) on the same 6 x 5 RGB image
        const C: [f32; 90] = [
        0.00683680223, 0.00641664118, 0.00677840924, 0.00658305874, 0.00642893789, 0.00646255771,
        0.00637436006, 0.00645358069, 0.00618662871, 0.00664012833, 0.00644997461, 0.00641232543,
        0.00689299125, 0.00646903226, 0.00721625192, 0.0071008089, 0.00647574337, 0.00798025634,
        0.00669349683, 0.00689680781, 0.0069045308, 0.00643629488, 0.00689336937, 0.00657953694,
        0.00622127904, 0.00689548859, 0.00629495969, 0.00646991283, 0.00688447943, 0.00652665691,
        0.0067053223, 0.00689723529, 0.00731762405, 0.00689854566, 0.00690443302, 0.00806817506,
        0.00642301748, 0.00750904903, 0.00734927412, 0.00615266617, 0.00750428857, 0.00699928263,
        0.00591401989, 0.00750279147, 0.00668596383, 0.00610962324, 0.00747773331, 0.00691316975,
        0.00631841179, 0.00749003887, 0.00768700102, 0.00649549486, 0.00749908015, 0.00842416007,
        0.00615253812, 0.00812129118, 0.0077940179, 0.00586903794, 0.00811520778, 0.00741902832,
        0.0056067612, 0.00811009482, 0.00707696844, 0.00574933365, 0.00807098765, 0.00729968213,
        0.00593150081, 0.00808284245, 0.00805637799, 0.00609244406, 0.00809372775, 0.00878014416,
        0.00600923225, 0.00860145781, 0.00792013947, 0.00572227361, 0.00857963972, 0.00753600756,
        0.00545368018, 0.00855200272, 0.00718529942, 0.00557911815, 0.00850549247, 0.00741401361,
        0.00574383186, 0.00851104502, 0.00815775059, 0.00589018036, 0.00852241646, 0.0088680638
        ];
        let mut px: Vec<u8> = (0..5u32)
            .flat_map(|y| (0..18u32).map(move |i| ((y * 37 + i * 11 + (i * y) % 7) * 13) as u8))
            .collect();
        let costs = Carrier::png(&mut px, 6, 5, 3).hill_costs();
        for (i, (r, c)) in costs.iter().zip(C).enumerate() {
            assert!((r - c).abs() <= 1e-5 * c, "sample {i}: Rust {r}, C {c}");
        }
    }
}
