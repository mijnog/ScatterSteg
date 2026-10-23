//! png_io::load on arbitrary bytes, like tests/fuzz/fuzz_png_load.c: chunk
//! CRCs are recomputed first so mutations reach the decoder, and whatever
//! loads is saved and must reload with the same pixels.
#![no_main]
use libfuzzer_sys::fuzz_target;
use scattersteg::png_io;
use std::path::PathBuf;
use std::sync::OnceLock;

fn paths() -> &'static (PathBuf, PathBuf) {
    static P: OnceLock<(PathBuf, PathBuf)> = OnceLock::new();
    P.get_or_init(|| {
        let pid = std::process::id();
        (PathBuf::from(format!("/dev/shm/rfuzz-png-load-{pid}.png")),
         PathBuf::from(format!("/dev/shm/rfuzz-png-save-{pid}.png")))
    })
}

fn fix_crcs(d: &mut [u8]) {
    let mut pos = 8;
    while pos + 12 <= d.len() {
        let len = u32::from_be_bytes(d[pos..pos + 4].try_into().unwrap()) as usize;
        if len > d.len() - pos - 12 { break; }
        let crc = crc32fast::hash(&d[pos + 4..pos + 8 + len]);
        d[pos + 8 + len..pos + 12 + len].copy_from_slice(&crc.to_be_bytes());
        pos += 12 + len;
    }
}

fuzz_target!(|data: &[u8]| {
    let (path, out_path) = paths();
    let mut buf = data.to_vec();
    fix_crcs(&mut buf);
    std::fs::write(path, &buf).unwrap();
    let Some(img) = png_io::load(path) else { return };
    assert!(img.width > 0 && img.height > 0);
    assert!(img.channels == 1 || img.channels == 3);
    assert_eq!(img.pixels.len(), img.width as usize * img.height as usize * img.channels as usize);
    png_io::save(&img, out_path).unwrap();
    let back = png_io::load(out_path).expect("saved PNG must reload");
    assert!(back.unsuitable.is_none());
    assert_eq!((back.width, back.height, back.channels), (img.width, img.height, img.channels));
    assert!(back.pixels == img.pixels);
});
