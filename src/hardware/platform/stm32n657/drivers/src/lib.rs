#![crate_type = "rlib"]
#![no_std]
// SAFETY-comment discipline for unsafe blocks. Existing offenders raise warnings
// pending file-by-file scrub; new code is expected to be clean.
#![warn(clippy::undocumented_unsafe_blocks)]

pub mod aes;
pub mod bkpsram;
pub mod cryp;
pub mod crypto_wait;
pub mod dma;
pub mod gpio;
pub mod hash;
pub mod mce;
pub mod rcc;
pub mod risaf;
pub mod saes;
pub mod state_anchor;
pub mod state_flash;
pub mod state_store;
pub mod tamp_store;
pub mod uart;
