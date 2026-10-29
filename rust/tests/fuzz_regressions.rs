// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Maxime de Montbron

//! Replays every input the fuzzers once broke the loaders with (the C ones in
//! tests/fuzz/regressions, the Rust ones in fuzz/regressions) and checks what
//! fuzz/fuzz_targets check: no panic, and whatever loads saves and reloads
//! identically.

use scattersteg::jpeg_io::JpegImage;
use scattersteg::png_io;
use std::fs;
use std::path::{Path, PathBuf};

fn inputs(kind: &str) -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    for dir in [root.join("../tests/fuzz/regressions").join(kind), root.join("fuzz/regressions").join(kind)] {
        if let Ok(rd) = fs::read_dir(dir) {
            out.extend(rd.flatten().map(|e| e.path()).filter(|p| p.is_file()));
        }
    }
    out
}

fn scratch(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("scattersteg-regress-{}-{name}", std::process::id()))
}

#[test]
fn png_regressions() {
    let files = inputs("png_load");
    assert!(!files.is_empty());
    let out = scratch("out.png");
    for f in files {
        // The C fuzz target recomputes CRCs first; do the same so these reach the decoder
        let mut d = fs::read(&f).unwrap();
        let mut pos = 8;
        while pos + 12 <= d.len() {
            let len = u32::from_be_bytes(d[pos..pos + 4].try_into().unwrap()) as usize;
            if len > d.len() - pos - 12 { break; }
            let crc = crc32fast::hash(&d[pos + 4..pos + 8 + len]);
            d[pos + 8 + len..pos + 12 + len].copy_from_slice(&crc.to_be_bytes());
            pos += 12 + len;
        }
        let input = scratch("in.png");
        fs::write(&input, &d).unwrap();
        let Some(img) = png_io::load(&input) else { continue };
        png_io::save(&img, &out).unwrap_or_else(|e| panic!("{}: save: {e}", f.display()));
        let back = png_io::load(&out).unwrap_or_else(|| panic!("{}: saved PNG must reload", f.display()));
        // It may still be refused for its content, never for its format
        let format_ok = back.unsuitable.is_none_or(|u| u == png_io::LOW_SBIT || u == png_io::GRAY_AS_RGB);
        assert!(back.pixels == img.pixels && format_ok, "{}", f.display());
    }
}

#[test]
fn jpeg_regressions() {
    let files = inputs("jpeg_load");
    assert!(!files.is_empty());
    let out = scratch("out.jpg");
    for f in files {
        let Some(mut j) = JpegImage::load(&f) else { continue };
        if !j.check_writable() { continue; }
        j.save(&out).unwrap_or_else(|e| panic!("{}: save: {e}", f.display()));
        let back = JpegImage::load(&out).unwrap_or_else(|| panic!("{}: saved JPEG must reload", f.display()));
        assert!(back.coefs == j.coefs && back.carriers == j.carriers, "{}", f.display());
    }
}

/// Each decodes, but libjpeg writes it back wrong or not at all (found by
/// fuzzing): the rewrite check refuses it. Encode now refuses these as too
/// small first, so the CLI tests can't see this.
#[test]
fn unrewritable_refused() {
    for name in ["oversampled-progressive.jpg", "redefined-quant-table.jpg", "truncated-progressive-al1.jpg"] {
        let f = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fuzz/regressions/jpeg_load").join(name);
        let mut j = JpegImage::load(&f).unwrap_or_else(|| panic!("{name} must load"));
        assert!(!j.check_writable(), "{name}");
    }
}

/// 500 empty scans of an 8192x8192 frame, 5 KB: each scan is a pass over the
/// frame, so it took seconds to read (at 23000x23000, 16 s). Past the cap on
/// blocks visited, it is refused.
#[test]
fn many_scans_refused() {
    let f = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fuzz/regressions/jpeg_load/many-scans-large-frame.jpg");
    assert!(JpegImage::load(&f).is_none());
}

/// 330 bytes declaring a 15144x32800 gray frame with no entropy data: libjpeg
/// filled it with zeros, 1.5 s and ~1 GB. Fewer bits than blocks, so refused.
#[test]
fn hollow_frame_refused() {
    let f = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fuzz/regressions/jpeg_load/hollow-huge-frame.jpg");
    assert!(JpegImage::load(&f).is_none());
}

/// Newer libpng refuses a chunk name with a lowercase third letter, so we load
/// such a file but never write the chunk back.
#[test]
fn reserved_bit_chunk_name_not_written() {
    fn chunk(name: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut out = (data.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(name);
        out.extend_from_slice(data);
        let mut c = crc32fast::Hasher::new();
        c.update(name);
        c.update(data);
        out.extend_from_slice(&c.finalize().to_be_bytes());
        out
    }
    let (w, h) = (8u32, 8u32);
    let mut raw = Vec::new();
    for _ in 0..h { raw.push(0); raw.extend(std::iter::repeat_n(7u8, w as usize * 3)); }
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut z, &raw).unwrap();
    let mut ihdr = [w.to_be_bytes(), h.to_be_bytes()].concat();
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    let mut file = b"\x89PNG\r\n\x1a\n".to_vec();
    for c in [chunk(b"IHDR", &ihdr), chunk(b"abcd", b"xx"), chunk(b"tEXt", b"k\0v"), chunk(b"IDAT", &z.finish().unwrap()), chunk(b"IEND", b"")] {
        file.extend(c);
    }
    let (input, out) = (scratch("rsv-in.png"), scratch("rsv-out.png"));
    fs::write(&input, &file).unwrap();
    let img = png_io::load(&input).expect("loads");
    png_io::save(&img, &out).unwrap();
    let written = fs::read(&out).unwrap();
    assert!(!written.windows(4).any(|w| w == b"abcd"));
    assert!(written.windows(4).any(|w| w == b"tEXt"), "other chunks are kept");
}
