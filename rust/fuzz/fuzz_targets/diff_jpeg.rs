//! The C and Rust JPEG loaders on the same bytes: the same carriers (so a
//! message hidden by one is found by the other), the same verdict on whether
//! the file can be rewritten, and what one writes the other reads back
//! identically.
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

fn values(j: &JpegImage) -> Vec<i16> { j.carriers.iter().map(|&i| j.coefs[i as usize]).collect() }

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
});
