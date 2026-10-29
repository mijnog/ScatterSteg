// SPDX-License-Identifier: MIT OR Apache-2.0
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
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out.join("jpeg_bindings.rs")).unwrap();

    // zlib, as the C version uses it: its buffers hold the message, so they
    // must come from sodium_malloc (see compress.rs)
    let z = pkg_config::Config::new().probe("zlib").expect("zlib not found");
    let mut builder = bindgen::Builder::default()
        .header_contents("zwrapper.h", "#include <zlib.h>\n")
        .allowlist_function("(deflate|inflate)(Init2_|End)?|deflateBound")
        .allowlist_type("z_stream")
        .allowlist_var("Z_(OK|STREAM_END|MEM_ERROR|NO_FLUSH|FINISH|DEFLATED|BEST_COMPRESSION|DEFAULT_STRATEGY)|MAX_WBITS|ZLIB_VERSION")
        .default_enum_style(bindgen::EnumVariation::Consts)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));
    for p in z.include_paths {
        builder = builder.clang_arg(format!("-I{}", p.display()));
    }
    builder.generate().expect("bindgen failed on zlib.h").write_to_file(out.join("zlib_bindings.rs")).unwrap();
}
