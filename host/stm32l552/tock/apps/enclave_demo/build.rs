//! `cargo:rustc-link-arg` is a per-package directive — libtock-rs's own
//! build.rs only wires `auto_layout()` for bin/example targets inside the
//! libtock-rs package, so a separate TBF app must call it itself or the
//! linker drops every allocatable section.
//!
//! The auto_layout call is gated on the Makefile-supplied env vars so a
//! bare `cargo check --workspace` (no link step) still resolves.

fn main() {
    let has_addrs = std::env::var("LIBTOCK_LINKER_FLASH").is_ok()
        && std::env::var("LIBTOCK_LINKER_RAM").is_ok();
    let has_platform = std::env::var("LIBTOCK_PLATFORM").is_ok();

    if has_addrs || has_platform {
        libtock_build_scripts::auto_layout();
    } else {
        println!("cargo:rerun-if-env-changed=LIBTOCK_LINKER_FLASH");
        println!("cargo:rerun-if-env-changed=LIBTOCK_LINKER_RAM");
        println!("cargo:rerun-if-env-changed=LIBTOCK_PLATFORM");
    }
}
