//! Outputs checked against the C implementation's (FNV-1a of the bytes).
use scattersteg::{prng, sodium, stc};

fn fnv(bytes: &[u8]) -> u64 {
    bytes.iter().fold(1469598103934665603u64, |h, &b| (h ^ b as u64).wrapping_mul(1099511628211))
}
fn fnv32(v: &[u32]) -> u64 {
    fnv(&v.iter().flat_map(|x| x.to_ne_bytes()).collect::<Vec<_>>())
}
fn key() -> [u8; 32] {
    std::array::from_fn(|i| (i * 7 + 3) as u8)
}

#[test]
fn prng_matches_c() {
    sodium::init().unwrap();
    let a = prng::permutation(&key(), 100003).unwrap();
    assert_eq!((fnv32(&a), a[0], a[99999]), (5751850905229347223, 71343, 25739));
    assert_eq!(fnv32(&prng::sample(&key(), 100003, 300).unwrap()), 13580493453081099827);
    assert_eq!(prng::sample(&key(), 100003, 300).unwrap(), a[..300]);
}

#[test]
fn stc_matches_c() {
    let cases: [(usize, usize, usize, u64); 4] = [
        (1000, 100, 1000, 11783339882688702857),
        (50000, 300, 19200, 17081218232135005402),
        (20000, 20000, 20000, 12041373877459508547),
        (3000000, 5000, 320000, 721137837011292038),
    ];
    for (c, &(navail, mlen, want_n, want_hash)) in cases.iter().enumerate() {
        let n = stc::carriers(navail, mlen);
        assert_eq!(n, want_n);
        let mut r: u64 = 12345 + c as u64;
        let mut step = || { r = r.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407); r };
        let (mut x, mut co) = (vec![0u8; n], vec![0f32; n]);
        for i in 0..n { let v = step(); x[i] = ((v >> 33) & 1) as u8; co[i] = 1.0 + ((v >> 40) & 7) as f32 * 0.5; }
        let m: Vec<u8> = (0..mlen).map(|_| ((step() >> 35) & 1) as u8).collect();
        let mut y = vec![0u8; n];
        stc::embed(&x, &co, &m, mlen, n, &mut y).unwrap();
        assert_eq!(fnv(&y), want_hash, "case {c}");
        let mut m2 = vec![0u8; mlen];
        stc::extract(&y, mlen, n, &mut m2);
        assert_eq!(m, m2);
    }
}
