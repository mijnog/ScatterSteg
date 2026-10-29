// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Maxime de Montbron

//! Syndrome-trellis codes (Filler, Judas & Fridrich, "Minimizing Additive
//! Distortion in Steganography Using Syndrome-Trellis Codes", 2011).
//!
//! The message is not written into the carriers' bits y directly: it is
//! their syndrome m = H y, for a band matrix H made of copies of a small
//! public submatrix. Many y have the same syndrome, so the encoder picks the
//! one cheapest to reach from the cover's bits x (Viterbi over the trellis
//! of partial syndromes), given a cost per carrier.
//!
//! Message bit i is the syndrome of a block of carriers starting at
//! floor(i * n / mlen), so blocks are w or w+1 wide and any payload uses all
//! n carriers. Decoding is the matrix product. Bits are stored one per byte.

/// Constraint height: the trellis has 2^STC_H states
const STC_H: u32 = 7;
const STATES: usize = 1 << STC_H;
/// Carriers per message bit, at most
const STC_MAX_W: usize = 64;
/// Message bits per trellis run are chosen so a run spans at most about this
/// many carriers, which bounds the path memory
const STC_CHUNK_CARRIERS: usize = 1 << 20;

/// How many carriers to use for mlen message bits when n_avail are there:
/// all of them, up to a cap that bounds the work. 0 if they don't fit, or
/// mlen is 2^32 or more.
pub fn carriers(n_avail: usize, mlen: usize) -> usize {
    if mlen == 0 || n_avail < mlen || mlen > u32::MAX as usize { return 0; }
    if n_avail / mlen >= STC_MAX_W { mlen * STC_MAX_W } else { n_avail }
}

/// The public submatrix, as columns of STC_H bits (bit r = row r), enough
/// for the widest block. Pseudo-random from that width (splitmix64), with
/// the top and bottom rows set in every column.
fn submatrix(width: usize, cols: &mut [u32]) {
    let mut s: u64 = 0x5354432d48415431 ^ width as u64; // "STC-HAT1"
    for col in cols.iter_mut().take(width) {
        s = s.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = s;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^= z >> 31;
        *col = ((z as u32) & (STATES as u32 - 1)) | 1 | (1 << (STC_H - 1));
    }
}

/// First carrier of message bit i's block: floor(i * n / mlen)
fn block_start(i: usize, mlen: usize, n: usize) -> usize {
    (i as u64 * (n / mlen) as u64 + i as u64 * (n % mlen) as u64 / mlen as u64) as usize
}

/// Message bits per trellis run
fn chunk_bits(mlen: usize, n: usize) -> usize {
    (STC_CHUNK_CARRIERS / (n / mlen + 1)).max(1)
}

/// Viterbi over message bits [a, b). The state is the partial syndrome of the
/// next STC_H rows; choosing y = 1 for a carrier XORs its column in. After a
/// block, its row is complete and must equal its message bit; the window
/// then shifts down a row. x, costs and y start at block a's first carrier.
fn embed_chunk(x: &[u8], costs: &[f32], m: &[u8], a: usize, b: usize, mlen: usize, n: usize,
               cols: &[u32], y: &mut [u8]) -> Result<(), ()> {
    let base = block_start(a, mlen, n);
    let len = block_start(b, mlen, n) - base;
    let mut path: Vec<u8> = Vec::new();
    path.try_reserve_exact(len.max(1) * (STATES / 8)).map_err(|_| ())?;
    path.resize(len.max(1) * (STATES / 8), 0);
    let mut cost = [f64::INFINITY; STATES];
    let mut next = [0f64; STATES];
    cost[0] = 0.0;

    for i in a..b {
        let from = block_start(i, mlen, n) - base;
        let to = block_start(i + 1, mlen, n) - base;
        for k in from..to {
            let col = cols[k - from] as usize;
            let flip = costs[k] as f64;
            let (c0, c1) = if x[k] != 0 { (flip, 0.0) } else { (0.0, flip) }; // cost of y = 0 / 1
            let p = &mut path[k * (STATES / 8)..(k + 1) * (STATES / 8)];
            p.fill(0);
            for s in 0..STATES {
                let keep = cost[s] + c0;
                let take = cost[s ^ col] + c1;
                if take < keep {
                    next[s] = take;
                    p[s >> 3] |= 1 << (s & 7);
                } else {
                    next[s] = keep;
                }
            }
            std::mem::swap(&mut cost, &mut next);
        }
        // Row i is done: keep states whose low bit is m[i], and shift
        for s in 0..STATES / 2 { next[s] = cost[(s << 1) | m[i] as usize]; }
        for s in STATES / 2..STATES { next[s] = f64::INFINITY; }
        std::mem::swap(&mut cost, &mut next);
    }

    // Rows past the run don't exist (H is truncated): any end state will do,
    // so take the cheapest, and walk the path back
    let mut s = 0usize;
    for t in 1..STATES { if cost[t] < cost[s] { s = t; } }
    for i in (a..b).rev() {
        s = (s << 1) | m[i] as usize;
        let from = block_start(i, mlen, n) - base;
        let to = block_start(i + 1, mlen, n) - base;
        for k in (from..to).rev() {
            y[k] = (path[k * (STATES / 8) + (s >> 3)] >> (s & 7)) & 1;
            if y[k] != 0 { s ^= cols[k - from] as usize; }
        }
    }
    Ok(())
}

/// Finds stego bits y (n of them, from `carriers`) with syndrome m,
/// minimizing the sum of costs[i] over the i where y[i] != x[i]. Costs must
/// be positive. Err if out of memory.
pub fn embed(x: &[u8], costs: &[f32], m: &[u8], mlen: usize, n: usize, y: &mut [u8]) -> Result<(), ()> {
    let widest = n / mlen + 1;
    let mut cols = vec![0u32; widest];
    submatrix(widest, &mut cols);
    let per = chunk_bits(mlen, n);
    let mut a = 0;
    while a < mlen {
        let b = if mlen - a < per { mlen } else { a + per };
        let at = block_start(a, mlen, n);
        embed_chunk(&x[at..], &costs[at..], m, a, b, mlen, n, &cols, &mut y[at..])?;
        a += per;
    }
    Ok(())
}

/// The syndrome of y (n carriers): the mlen message bits
pub fn extract(y: &[u8], mlen: usize, n: usize, m: &mut [u8]) {
    let widest = n / mlen + 1;
    if widest > STC_MAX_W + 1 { // `carriers` never gives this
        m[..mlen].fill(0);
        return;
    }
    let mut cols = [0u32; STC_MAX_W + 1];
    submatrix(widest, &mut cols);
    let per = chunk_bits(mlen, n);
    let mut state = 0u32;
    for i in 0..mlen {
        if i % per == 0 { state = 0; } // each run starts afresh
        let from = block_start(i, mlen, n);
        let to = block_start(i + 1, mlen, n);
        for k in from..to {
            if y[k] != 0 { state ^= cols[k - from]; }
        }
        m[i] = (state & 1) as u8;
        state >>= 1;
    }
}
