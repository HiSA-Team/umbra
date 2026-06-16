// Mirror of src/kernel/build.rs: emit the size-knob constants from the
// environment (defaults in workspace .cargo/config.toml [env]). Kept in sync so
// the extracted model and the kernel use identical knobs. See issue #58.
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let slot_size: u32 = env::var("UMBRA_SLOT_SIZE_BYTES")
        .unwrap_or_else(|_| "256".to_string())
        .parse()
        .expect("UMBRA_SLOT_SIZE_BYTES must be a positive integer");
    let cache_limit: usize = env::var("UMBRA_CACHE_LIMIT")
        .unwrap_or_else(|_| "64".to_string())
        .parse()
        .expect("UMBRA_CACHE_LIMIT must be a non-negative integer");
    let max_enclaves_ctx: usize = env::var("UMBRA_MAX_ENCLAVES_CTX")
        .unwrap_or_else(|_| "2".to_string())
        .parse()
        .expect("UMBRA_MAX_ENCLAVES_CTX must be a positive integer");
    let psp_stack_bytes: u32 = env::var("UMBRA_ENCLAVE_PSP_STACK_BYTES")
        .unwrap_or_else(|_| "8192".to_string())
        .parse()
        .expect("UMBRA_ENCLAVE_PSP_STACK_BYTES must be a positive integer");
    let max_keys: usize = env::var("UMBRA_MAX_KEYS")
        .unwrap_or_else(|_| "8".to_string())
        .parse()
        .expect("UMBRA_MAX_KEYS must be a positive integer");

    println!("cargo:rerun-if-env-changed=UMBRA_SLOT_SIZE_BYTES");
    println!("cargo:rerun-if-env-changed=UMBRA_CACHE_LIMIT");
    println!("cargo:rerun-if-env-changed=UMBRA_MAX_ENCLAVES_CTX");
    println!("cargo:rerun-if-env-changed=UMBRA_ENCLAVE_PSP_STACK_BYTES");
    println!("cargo:rerun-if-env-changed=UMBRA_MAX_KEYS");
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let generated = out_dir.join("sizes_generated.rs");
    let body = format!(
        "pub const SLOT_SIZE: u32 = {slot_size};\n\
pub const SLOT_SIZE_USIZE: usize = {slot_size};\n\
pub const CACHE_LIMIT_PER_ENCLAVE: usize = {cache_limit};\n\
pub const MAX_ENCLAVES_CTX: usize = {max_enclaves_ctx};\n\
pub const ENCLAVE_PSP_STACK_SIZE: u32 = {psp_stack_bytes};\n\
pub const MAX_KEYS: usize = {max_keys};\n"
    );
    fs::write(&generated, body).expect("failed to write sizes_generated.rs");
}
