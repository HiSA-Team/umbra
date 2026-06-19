// Emit MEMORY_BLOCK_SIZE from the same size knob the rest of Umbra uses
// (UMBRA_SLOT_SIZE_BYTES; default in workspace .cargo/config.toml [env]). Kept in
// sync with umbra-ess-core's SLOT_SIZE so the logical block size is one value.
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let block_size: u32 = env::var("UMBRA_SLOT_SIZE_BYTES")
        .unwrap_or_else(|_| "256".to_string())
        .parse()
        .expect("UMBRA_SLOT_SIZE_BYTES must be a positive integer");
    println!("cargo:rerun-if-env-changed=UMBRA_SLOT_SIZE_BYTES");
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let generated = out_dir.join("block_size_generated.rs");
    fs::write(
        &generated,
        format!("pub const MEMORY_BLOCK_SIZE: u32 = {block_size};\n"),
    )
    .expect("failed to write block_size_generated.rs");
}
