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
const STC_MAX_W: usize = 1024;
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
#[allow(clippy::too_many_arguments)] // the pieces of one chunk of the Viterbi search
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
        #[allow(clippy::needless_range_loop)] // s also picks the cost entry, as in the C code
        for s in 0..STATES / 2 { next[s] = cost[(s << 1) | m[i] as usize]; }
        next[STATES / 2..].fill(f64::INFINITY);
        std::mem::swap(&mut cost, &mut next);
    }

    // Rows past the run don't exist (H is truncated): any end state will do,
    // so take the cheapest, and walk the path back
    let mut s = 0usize;
    for t in 1..STATES { if cost[t] < cost[s] { s = t; } }
    // No finite way through (infinite costs): the path from s isn't one, and
    // walking it would leave the trellis
    if !cost[s].is_finite() { return Err(()); }
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
/// be positive. Err if out of memory or if every y with syndrome m costs
/// infinity.
#[allow(clippy::result_unit_err)] // one way to fail, which the caller knows
pub fn embed(x: &[u8], costs: &[f32], m: &[u8], mlen: usize, n: usize, y: &mut [u8]) -> Result<(), ()> {
    let widest = n / mlen + 1;
    let mut cols = vec![0u32; widest];
    submatrix(widest, &mut cols);
    let per = chunk_bits(mlen, n);
    // The chunks are independent (each starts from state 0 and ends where it
    // likes), so they can run on several threads at once and give the same
    // y: each gets its own slice of y, and workers take the next chunk in
    // turn. At most parallel::MAX threads: each running chunk holds up to
    // 16 MiB of path. As C's stc_embed.
    let mut jobs = Vec::new();
    let mut rest = &mut y[..n];
    let mut a = 0;
    while a < mlen {
        let b = if mlen - a < per { mlen } else { a + per };
        let (at, end) = (block_start(a, mlen, n), block_start(b, mlen, n));
        let (mine, tail) = rest.split_at_mut(end - at);
        jobs.push(std::sync::Mutex::new(Some((a, b, at, mine))));
        rest = tail;
        a += per;
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let failed = std::sync::atomic::AtomicBool::new(false);
    let work = || {
        use std::sync::atomic::Ordering::Relaxed;
        loop {
            let c = next.fetch_add(1, Relaxed);
            if c >= jobs.len() || failed.load(Relaxed) { return; }
            let (a, b, at, mine) = jobs[c].lock().unwrap().take().unwrap();
            if embed_chunk(&x[at..], &costs[at..], m, a, b, mlen, n, &cols, mine).is_err() {
                failed.store(true, Relaxed);
            }
        }
    };
    let threads = crate::parallel::threads(jobs.len());
    std::thread::scope(|scope| {
        for _ in 1..threads { scope.spawn(work); }
        work();
    });
    if failed.into_inner() { Err(()) } else { Ok(()) }
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
    #[allow(clippy::needless_range_loop)] // i is the row number, not just an index into m
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fnv(bytes: &[u8]) -> u64 {
        bytes.iter().fold(1469598103934665603u64, |h, &b| (h ^ b as u64).wrapping_mul(1099511628211))
    }

    #[test]
    fn carriers_bounds() {
        // As tests/test_stc.c's test_carriers
        assert_eq!(carriers(10239, 10), 10239);
        assert_eq!(carriers(10245, 10), 10240); // exactly 1024 per bit, and some over
        assert_eq!(carriers(1000000, 10), 10240);
        #[cfg(target_pointer_width = "64")]
        {
            let max = u32::MAX as usize;
            assert_eq!(carriers(max, max), max); // the largest mlen
            assert_eq!(carriers(max + 1, max + 1), 0);
        }
    }

    #[test]
    fn edge_embeds() {
        // As tests/test_stc.c's test_edge_embeds
        let mut y = [9u8];
        assert!(embed(&[0], &[1.0], &[0], 1, 1, &mut y).is_ok() && y[0] == 0);
        let mut y = [9u8];
        assert!(embed(&[0], &[1.0], &[1], 1, 1, &mut y).is_ok() && y[0] == 1);
        let (n, mlen) = (5000, 500);
        let mut yy = vec![9u8; n];
        embed(&vec![0; n], &vec![1.0; n], &vec![0; mlen], mlen, n, &mut yy).unwrap();
        assert!(yy.iter().all(|&b| b == 0));
        let mut y = [9u8];
        assert!(embed(&[0], &[f32::INFINITY], &[1], 1, 1, &mut y).is_err());
    }

    #[test]
    fn many_chunks() {
        // More runs than parallel::MAX threads: width 2, 524288 bits per run,
        // 9 runs (as tests/test_stc.c's test_many_chunks)
        let (navail, mlen) = (4500000, 4300000);
        let n = carriers(navail, mlen);
        let mut r: u32 = 12345;
        let mut bit = || { r ^= r << 13; r ^= r >> 17; r ^= r << 5; (r & 1) as u8 };
        let x: Vec<u8> = (0..n).map(|_| bit()).collect();
        let m: Vec<u8> = (0..mlen).map(|_| bit()).collect();
        let mut y = vec![0u8; n];
        embed(&x, &vec![1.0; n], &m, mlen, n, &mut y).unwrap();
        let mut back = vec![0u8; mlen];
        extract(&y, mlen, n, &mut back);
        assert_eq!(m, back);
    }

    #[test]
    fn known_answer_runs() {
        // Three runs (2^20 / 31 = 33825 bits each); values from test_cli.py's
        // stc_extract, as tests/test_stc.c's test_known_answer_runs
        let (n, mlen) = (3000000, 100000);
        let mut s: u32 = 7;
        let y: Vec<u8> = (0..n).map(|_| { s = s.wrapping_mul(1103515245).wrapping_add(12345); ((s >> 16) & 1) as u8 }).collect();
        let mut m = vec![0u8; mlen];
        extract(&y, mlen, n, &mut m);
        let pack = |from: usize| (0..32).fold(0u32, |p, i| p | (m[from + i] as u32) << i);
        assert_eq!((pack(0), pack(33825)), (0xb27e28d5, 0x80cd8639));
        assert_eq!(m.iter().map(|&b| b as u32).sum::<u32>(), 49962);
        assert_eq!(fnv(&m), 6591896953287329387);
    }
}
