// The differential targets run the C loaders (png_io.c, jpeg_io.c) beside the
// Rust ones, so build the C sources into the fuzz binaries.
fn main() {
    let root = std::path::Path::new("../..");
    let mut b = cc::Build::new();
    b.include(root).std("c17").warnings(false).opt_level(1).debug(true);
    for f in ["png_io.c", "jpeg_io.c", "atomic_write.c"] {
        let p = root.join(f);
        println!("cargo:rerun-if-changed={}", p.display());
        b.file(p);
    }
    b.compile("scattersteg_c");
    for l in ["png", "jpeg", "z"] { println!("cargo:rustc-link-lib={l}"); }
}
