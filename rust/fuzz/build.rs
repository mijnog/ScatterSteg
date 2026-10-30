// The differential targets run the C loaders (png_io.c, jpeg_io.c) and file
// format (codec.c) beside the Rust ones, so build the C sources into the
// fuzz binaries. codec.c gets the fuzzing build's BLAKE2b in place of
// Argon2id, as the Rust side does under cfg(fuzzing).
fn main() {
    let root = std::path::Path::new("../..");
    let mut b = cc::Build::new();
    b.include(root).std("c17").warnings(false).opt_level(1).debug(true)
        .define("FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION", None);
    for f in ["png_io.c", "jpeg_io.c", "atomic_write.c", "codec.c", "embed.c", "prng.c", "stc.c", "distortion.c"] {
        let p = root.join(f);
        println!("cargo:rerun-if-changed={}", p.display());
        b.file(p);
    }
    b.compile("scattersteg_c");
    for l in ["png", "jpeg", "z", "sodium", "m"] { println!("cargo:rustc-link-lib={l}"); }
}
