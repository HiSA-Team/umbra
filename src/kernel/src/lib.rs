#![crate_name = "kernel"]
#![crate_type = "rlib"]
#![no_std]
// SAFETY-comment discipline for unsafe blocks. Existing offenders raise warnings
// pending file-by-file scrub; new code is expected to be clean.
#![warn(clippy::undocumented_unsafe_blocks)]


pub mod common;
pub mod memory_protection_server;
pub mod umbra_nsc_api;
pub mod panic;
pub mod platform;

pub mod key_storage_server;

pub use crate::umbra_nsc_api::umbra_enclave_create;
