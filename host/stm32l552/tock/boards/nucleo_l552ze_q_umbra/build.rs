//! Build script: stage `layout.ld` for the linker on this crate only.
//!
//! The `-Tlayout.ld` flag MUST NOT live in the workspace `.cargo/config.toml`
//! because that would also apply to the libtock-rs TBF app, which supplies
//! its own `libtock_layout.ld` via libtock-rs's build_scripts.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    fs::copy("layout.ld", out_dir.join("layout.ld")).unwrap();
    fs::copy(
        "../../chips/stm32l552/src/memory.x",
        out_dir.join("memory.x"),
    )
    .unwrap();

    println!("cargo:rustc-link-search={}", out_dir.display());
    println!("cargo:rustc-link-arg=-Tlayout.ld");

    println!("cargo:rerun-if-changed=layout.ld");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../chips/stm32l552/src/memory.x");
}
