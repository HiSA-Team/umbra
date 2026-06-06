#![crate_type = "rlib"]
#![no_std]
// SAFETY-comment discipline for unsafe blocks. Existing offenders raise warnings
// pending file-by-file scrub; new code is expected to be clean.
#![warn(clippy::undocumented_unsafe_blocks)]

pub mod aes;
pub mod cryp;
pub mod dma;
pub mod gpio;
pub mod hash;
pub mod mce;
pub mod rcc;
pub mod risaf;
pub mod saes;
pub mod uart;
