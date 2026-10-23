// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Maxime de Montbron

use std::env;
use std::path::PathBuf;

fn main() {
    let lib = pkg_config::Config::new().probe("libjpeg").expect("libjpeg (libjpeg-turbo) not found");
    let mut builder = bindgen::Builder::default()
        .header_contents("wrapper.h", "#include <stdio.h>\n#include <stddef.h>\n#include <jpeglib.h>\n")
        .allowlist_function("jpeg_.*")
        .allowlist_type("j_(common|compress|decompress)_ptr")
        .allowlist_type("jpeg_(decompress|compress)_struct")
        .allowlist_var("JPEG_.*|DCTSIZE.*|NUM_.*_TBLS|JPEG_LIB_VERSION")
        .override_abi(bindgen::Abi::CUnwind, ".*")
        .default_enum_style(bindgen::EnumVariation::Consts)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));
    for p in lib.include_paths {
        builder = builder.clang_arg(format!("-I{}", p.display()));
    }
    let bindings = builder.generate().expect("bindgen failed on jpeglib.h");
    bindings.write_to_file(PathBuf::from(env::var("OUT_DIR").unwrap()).join("jpeg_bindings.rs")).unwrap();
}
