//! Stage `layout.ld` (and the `tock_kernel_layout.ld` it INCLUDEs) for the
//! linker on THIS crate only. We deliberately do not use `tock_build_scripts`
//! (its `rustflags_check()` panics unless Tock's own RUSTFLAGS sentinel is set);
//! mirroring host/stm32l552/tock/boards/nucleo_l552ze_q_umbra/build.rs, we copy
//! the scripts into OUT_DIR and add it to the linker search path, so the board
//! `INCLUDE tock_kernel_layout.ld` resolves. `-Tlayout.ld` must not live in the
//! workspace `.cargo/config` or it would apply to every crate.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    fs::copy("layout.ld", out_dir.join("layout.ld")).unwrap();
    // tock_kernel_layout.ld is packaged inside the build_scripts crate in the
    // pinned submodule (../../lib/tock/boards/build_scripts/).
    fs::copy(
        "../../lib/tock/boards/build_scripts/tock_kernel_layout.ld",
        out_dir.join("tock_kernel_layout.ld"),
    )
    .unwrap();

    println!("cargo:rustc-link-search={}", out_dir.display());
    println!("cargo:rustc-link-arg=-Tlayout.ld");

    println!("cargo:rerun-if-changed=layout.ld");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../lib/tock/boards/build_scripts/tock_kernel_layout.ld");
}
