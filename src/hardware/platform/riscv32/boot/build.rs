// Pass the linker script as an absolute path (the workspace runs the linker
// from outside this crate, so a relative `-T` would not resolve). Centralized
// in the bin crate's build.rs because `cargo:rustc-link-arg` is ignored for
// rlibs — same pattern as the STM32 boot crates.
//
// The master key (`src/master_key.bin`, included by `crypto_impl::MASTER_KEY`
// and read by the signer) is generated UP-FRONT by rebuild_all.sh's riscv32
// branch — the RISC-V analog of L552's `gen_key.py` step — so it already exists
// when this crate compiles. `include_bytes!` then tracks it for rebuilds.
use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let link_script = manifest.join("link.ld");
    println!("cargo:rustc-link-arg=-T{}", link_script.display());
    println!("cargo:rerun-if-changed=link.ld");
    println!("cargo:rerun-if-changed=src/main.rs");
}
