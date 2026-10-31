//! Embeds the source digest of the tree being compiled.
//! No git hash and no absolute paths are embedded, so two builds of the same
//! source from different directories can produce the same binary.

#[path = "src/sha256.rs"]
#[allow(dead_code)]
mod sha256;

use std::path::Path;

fn main() {
    let root = std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    let digest = sha256::source_tree_digest(Path::new(&root)).expect("source digest");
    println!("cargo:rustc-env=HERCULES_SOURCE_DIGEST={digest}");
    for p in ["Cargo.toml", "Cargo.lock", "build.rs", "rust-toolchain.toml", "src"] {
        println!("cargo:rerun-if-changed={p}");
    }
}
