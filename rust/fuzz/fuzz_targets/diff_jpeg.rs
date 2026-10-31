//! The C and Rust JPEG loaders on the same bytes: the same carriers (so a
//! message hidden by one is found by the other), the same verdict on whether
//! the file can be rewritten, what one writes the other reads back
//! identically, and both write the same bytes, before and after some
//! coefficients change (as embedding changes them: new values may need
//! Huffman codes the cover's tables lack).
#![no_main]
mod c_api;
use c_api::CJpeg;
use libfuzzer_sys::fuzz_target;
use scattersteg::jpeg_io::JpegImage;
use std::path::PathBuf;
use std::sync::OnceLock;

fn paths() -> &'static [PathBuf; 3] {
    static P: OnceLock<[PathBuf; 3]> = OnceLock::new();
    P.get_or_init(|| {
        let pid = std::process::id();
        ["in", "c_out", "r_out"].map(|n| PathBuf::from(format!("/dev/shm/dfuzz-jpeg-{n}-{pid}.jpg")))
    })
}

fn values(j: &JpegImage) -> Vec<i16> { j.coefs.chunks_exact(64).flat_map(|b| b[1..].iter().copied()).collect() }

fuzz_target!(|data: &[u8]| {
    // The CLI only loads a file that starts with the JPEG signature (cover.rs)
    if !data.starts_with(&[0xFF, 0xD8, 0xFF]) { return; }
    let [input, c_out, r_out] = paths();
    std::fs::write(input, data).unwrap();
    let c = CJpeg::load(input);
    let r = JpegImage::load(input);
    assert_eq!(c.is_some(), r.is_some(), "C loads: {}, Rust loads: {}", c.is_some(), r.is_some());
    let (Some(mut c), Some(mut r)) = (c, r) else { return };

    assert!(c.carrier_values() == values(&r), "different carriers");
    // The same costs, so both versions embed alike (UERD; float sums in the
    // same order, so equal up to rounding)
    for (a, b) in c.carrier_costs().iter().zip(&r.costs) {
        assert!((a - b).abs() <= 1e-5 * a.abs().max(*b), "different costs: C {a}, Rust {b}");
    }
    assert_eq!(c.unsuitable(), r.unsuitable().is_some());
    let (cw, rw) = (c.writable(), r.check_writable());
    assert_eq!(cw, rw, "C writable: {cw}, Rust writable: {rw}");
    if !cw { return; }

    assert!(c.save(c_out));
    let back = JpegImage::load(c_out).expect("Rust can't read what C wrote");
    assert!(values(&back) == values(&r), "Rust reads different carriers from C's output");

    r.save(r_out).unwrap();
    let back = CJpeg::load(r_out).expect("C can't read what Rust wrote");
    assert!(back.carrier_values() == values(&r), "C reads different carriers from Rust's output");
    assert!(std::fs::read(c_out).unwrap() == std::fs::read(r_out).unwrap(), "C and Rust write different bytes");

    // Change every 5th carrier by +-1, alike in both, as embedding would
    for k in (data.len() % 5..r.costs.len()).step_by(5) {
        let at = k / 63 * 64 + k % 63 + 1;
        let v = r.coefs[at];
        let v = if v >= 1023 { v - 1 } else if v <= -1023 || k % 2 == 0 { v + 1 } else { v - 1 };
        r.coefs[at] = v;
        c.set_carrier(k, v);
    }
    let (cw, rw) = (c.writable(), r.check_writable());
    assert_eq!(cw, rw, "after changes, C writable: {cw}, Rust writable: {rw}");
    if !cw { return; }
    assert!(c.save(c_out));
    r.save(r_out).unwrap();
    assert!(std::fs::read(c_out).unwrap() == std::fs::read(r_out).unwrap(), "after changes, C and Rust write different bytes");
    let back = JpegImage::load(r_out).expect("changed coefficients must still read back");
    assert!(values(&back) == values(&r), "the changed coefficients don't read back");
});
