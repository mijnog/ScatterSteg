//! JpegImage::load on arbitrary bytes, like tests/fuzz/fuzz_jpeg_load.c:
//! every carrier must have |value| >= 2, and a JPEG that check_writable
//! accepts must save and reload with the same coefficients.
#![no_main]
use libfuzzer_sys::fuzz_target;
use scattersteg::jpeg_io::JpegImage;
use std::path::PathBuf;
use std::sync::OnceLock;

fn paths() -> &'static (PathBuf, PathBuf) {
    static P: OnceLock<(PathBuf, PathBuf)> = OnceLock::new();
    P.get_or_init(|| {
        let pid = std::process::id();
        (PathBuf::from(format!("/dev/shm/rfuzz-jpeg-load-{pid}.jpg")),
         PathBuf::from(format!("/dev/shm/rfuzz-jpeg-save-{pid}.jpg")))
    })
}

fuzz_target!(|data: &[u8]| {
    let (path, out_path) = paths();
    std::fs::write(path, data).unwrap();
    let Some(mut j) = JpegImage::load(path) else { return };
    for &i in &j.carriers {
        let c = j.coefs[i as usize];
        assert!(c <= -2 || c >= 2);
    }
    if !j.check_writable() { return; }
    j.save(out_path).unwrap();
    let back = JpegImage::load(out_path).expect("saved JPEG must reload");
    assert!(back.coefs == j.coefs && back.carriers == j.carriers);
});
