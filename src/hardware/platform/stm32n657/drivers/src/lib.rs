#![crate_name = "drivers"]
#![crate_type = "rlib"]
#![no_std]
// SAFETY-comment discipline for unsafe blocks. Existing offenders raise warnings
// pending file-by-file scrub; new code is expected to be clean.
#![warn(clippy::undocumented_unsafe_blocks)]

pub mod rcc;
pub mod gpio;
pub mod uart;
pub mod hash;
pub mod aes;
pub mod cryp;
pub mod mce;
pub mod risaf;
