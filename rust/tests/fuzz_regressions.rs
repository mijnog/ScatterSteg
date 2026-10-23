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
        assert!(back.pixels == img.pixels && back.unsuitable.is_none(), "{}", f.display());
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
