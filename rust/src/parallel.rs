// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Maxime de Montbron

//! Loops whose iterations are independent, run on several threads. Each
//! iteration computes what it would alone, so the result is the same, bit for
//! bit, on any number of threads. As C's parallel.h.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

/// Threads to use at most: the trellis holds up to 16 MiB of path per running
/// chunk (stc.rs), and past 8 the loops gain little. As C's PARALLEL_MAX.
pub const MAX: usize = 8;

/// Threads for `jobs` independent jobs: one per CPU, at most MAX and one per
/// job. One in fault-injection and fuzzing builds, as C's parallel_threads.
pub fn threads(jobs: usize) -> usize {
    if cfg!(feature = "fault-injection") || cfg!(fuzzing) { return 1; }
    std::thread::available_parallelism().map_or(1, |t| t.get()).min(MAX).min(jobs).max(1)
}

/// Where piece i of t starts, over n items: the first n % t pieces one longer
fn bound(n: usize, t: usize, i: usize) -> usize { n / t * i + i.min(n % t) }

/// Runs each job on up to `t` threads, workers taking the next in turn. A
/// thread that can't start leaves its jobs to the others.
pub fn run<J: Send>(jobs: Vec<J>, t: usize, f: impl Fn(J) + Sync) {
    let jobs: Vec<Mutex<Option<J>>> = jobs.into_iter().map(|j| Mutex::new(Some(j))).collect();
    let next = AtomicUsize::new(0);
    let work = || loop {
        let i = next.fetch_add(1, Relaxed);
        let Some(slot) = jobs.get(i) else { return };
        if let Some(j) = slot.lock().unwrap().take() { f(j); }
    };
    std::thread::scope(|scope| {
        for _ in 1..t.min(jobs.len()) {
            if std::thread::Builder::new().spawn_scoped(scope, work).is_err() { break; }
        }
        work();
    });
}

/// f(first unit, piece) over `out` in pieces of whole units (`unit` items
/// each, e.g. a row), at least `least` units a piece, so a small loop stays
/// on one thread
pub fn pieces<T: Send>(out: &mut [T], unit: usize, least: usize, f: impl Fn(usize, &mut [T]) + Sync) {
    let n = out.len().checked_div(unit).unwrap_or(0);
    if n == 0 { return; }
    let t = threads(n.div_ceil(least.max(1)));
    let mut jobs = Vec::with_capacity(t);
    let mut rest = out;
    for i in 0..t {
        let (mine, tail) = std::mem::take(&mut rest).split_at_mut((bound(n, t, i + 1) - bound(n, t, i)) * unit);
        jobs.push((bound(n, t, i), mine));
        rest = tail;
    }
    run(jobs, t, |(from, mine)| f(from, mine));
}

/// The same over two slices of the same length, split alike, one item a unit
pub fn pieces2<A: Send, B: Send>(a: &mut [A], b: &mut [B], least: usize,
                                 f: impl Fn(usize, &mut [A], &mut [B]) + Sync) {
    let n = a.len().min(b.len());
    if n == 0 { return; }
    let t = threads(n.div_ceil(least.max(1)));
    let mut jobs = Vec::with_capacity(t);
    let (mut ra, mut rb) = (&mut a[..n], &mut b[..n]);
    for i in 0..t {
        let len = bound(n, t, i + 1) - bound(n, t, i);
        let (ma, ta) = std::mem::take(&mut ra).split_at_mut(len);
        let (mb, tb) = std::mem::take(&mut rb).split_at_mut(len);
        jobs.push((bound(n, t, i), ma, mb));
        (ra, rb) = (ta, tb);
    }
    run(jobs, t, |(from, ma, mb)| f(from, ma, mb));
}

#[cfg(test)]
mod tests {
    #[test]
    fn pieces_cover_every_item_once() {
        for n in [0usize, 1, 7, 8, 9, 1000, 65537] {
            let mut out = vec![0u32; n * 3];
            super::pieces(&mut out, 3, 1, |from, p| {
                for (k, row) in p.chunks_mut(3).enumerate() { for v in row { *v += (from + k) as u32 + 1; } }
            });
            assert!(out.chunks(3).enumerate().all(|(i, r)| r.iter().all(|&v| v == i as u32 + 1)), "n {n}");
            let (mut a, mut b) = (vec![0usize; n], vec![0u8; n]);
            super::pieces2(&mut a, &mut b, 1, |from, pa, pb| {
                for (k, (x, y)) in pa.iter_mut().zip(pb.iter_mut()).enumerate() { *x = from + k; *y += 1; }
            });
            assert!(a.iter().enumerate().all(|(i, &x)| x == i) && b.iter().all(|&y| y == 1), "n {n}");
        }
    }
}
