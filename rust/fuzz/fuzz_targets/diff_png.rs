//! The C and Rust PNG loaders on the same bytes. An image written by one must
//! read with the other, so:
//!  - what C loads, Rust loads, with the same pixels (Rust may load more:
//!    it doesn't check the zlib Adler-32, and ignores a reserved-bit chunk
//!    name that newer libpng refuses);
//!  - what C saves, Rust reads back with the same pixels, and the reverse.
#![no_main]
mod c_api;
use c_api::CPng;
use libfuzzer_sys::fuzz_target;
use scattersteg::png_io;
use std::path::PathBuf;
use std::sync::OnceLock;

fn paths() -> &'static [PathBuf; 3] {
    static P: OnceLock<[PathBuf; 3]> = OnceLock::new();
    P.get_or_init(|| {
        let pid = std::process::id();
        ["in", "c_out", "r_out"].map(|n| PathBuf::from(format!("/dev/shm/dfuzz-png-{n}-{pid}.png")))
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

/// libpng stops once the last row is decoded, so it loads a file whose
/// compressed data goes bad after that; the png crate reads to the end and
/// fails. Is this such a file?
fn zlib_stream_damaged(d: &[u8]) -> bool {
    use std::io::Read;
    let (mut idat, mut pos) = (Vec::new(), 8);
    while pos + 12 <= d.len() {
        let len = u32::from_be_bytes(d[pos..pos + 4].try_into().unwrap()) as usize;
        if len > d.len() - pos - 12 { break; }
        if &d[pos + 4..pos + 8] == b"IDAT" { idat.extend_from_slice(&d[pos + 8..pos + 8 + len]); }
        pos += 12 + len;
    }
    flate2::read::ZlibDecoder::new(&idat[..]).read_to_end(&mut Vec::new()).is_err()
}

fuzz_target!(|data: &[u8]| {
    let [input, c_out, r_out] = paths();
    let mut buf = data.to_vec();
    if buf.len() % 2 == 0 { fix_crcs(&mut buf); } // half the inputs keep their (probably bad) CRCs
    std::fs::write(input, &buf).unwrap();
    let c = CPng::load(input);
    let r = png_io::load(input);

    if let Some(c) = &c {
        let Some(r) = r.as_ref() else {
            assert!(zlib_stream_damaged(&buf), "C loads this, Rust doesn't");
            return;
        };
        assert_eq!((c.width(), c.height(), c.channels()), (r.width, r.height, r.channels));
        assert_eq!(c.unsuitable().is_some(), r.unsuitable.is_some(), "{:?} vs {:?}", c.unsuitable(), r.unsuitable);
        assert!(c.pixels() == r.pixels, "pixels differ");
        // C writes it, Rust reads it
        if c.unsuitable().is_none() {
            assert!(c.save(c_out), "C can't save what it loaded");
            let back = png_io::load(c_out).expect("Rust can't read what C wrote");
            assert!(back.pixels == r.pixels);
        }
    }
    if let Some(r) = &r {
        // Rust writes it, C reads it
        if r.unsuitable.is_none() {
            png_io::save(r, r_out).unwrap();
            let back = CPng::load(r_out).expect("C can't read what Rust wrote");
            assert_eq!((back.width(), back.height(), back.channels()), (r.width, r.height, r.channels));
            assert!(back.pixels() == r.pixels, "C reads different pixels from Rust's output");
            assert!(back.unsuitable().is_none());
        }
    }
});
