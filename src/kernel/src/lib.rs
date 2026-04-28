#![crate_name = "kernel"]
#![crate_type = "rlib"]
#![no_std]


pub mod common;
pub mod memory_protection_server;
pub mod umbra_nsc_api;
pub mod panic;

pub mod key_storage_server;

pub use crate::umbra_nsc_api::umbra_tee_create;
