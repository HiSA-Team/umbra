#![crate_name = "kernel"]
#![crate_type = "rlib"]
#![no_std]
// SAFETY-comment discipline for unsafe blocks. Existing offenders raise warnings
// pending file-by-file scrub; new code is expected to be clean.
#![warn(clippy::undocumented_unsafe_blocks)]

pub mod common;
pub mod memory_protection_server;
pub mod panic;
pub mod platform;
pub mod umbra_nsc_api;

pub mod key_storage_server;

// `umbra_enclave_create` is an `extern "C"` NSC veneer symbol — only
// linkable in bare-metal ARM builds. Host builds skip the re-export
// so `cargo test -p kernel` works against the platform-agnostic kernel
// logic without needing the linker to resolve the veneer.
#[cfg(all(target_arch = "arm", target_os = "none"))]
pub use crate::umbra_nsc_api::umbra_enclave_create;
