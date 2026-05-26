//! STM32L552 chip glue. Re-exports the family-wide [`stm32l5xx`] crate and
//! adds L552-specific items: interrupt vector table and memory-map constants.
//! The board crate layers `layout.ld` + `main.rs` on top of this.

#![no_std]

pub use stm32l5xx::*;

pub mod vectors;

/// NS flash alias base (both banks combined, RM0438 §4.3.1).
pub const FLASH_BASE_NS: u32 = 0x0800_0000;

/// Total flash size: 512 KB (two 256 KB banks).
pub const FLASH_SIZE: u32 = 0x0008_0000;

/// Host-accessible NS flash region start — Umbra Secure occupies 0x08000000
/// through 0x0803FFFF (256 KB).
pub const FLASH_NS_BASE: u32 = 0x0804_0000;

/// Host-accessible NS flash region size: 256 KB.
pub const FLASH_NS_SIZE: u32 = 0x0004_0000;

/// SRAM1 NS-accessible base (RM0438 §4.3.2). SRAM2 (0x20030000+) is reserved
/// for Umbra Secure and MUST NOT be mapped from the host NS world.
pub const SRAM1_NS_BASE: u32 = 0x2000_0000;

/// SRAM1 size available to the host NS world: 192 KB.
pub const SRAM1_NS_SIZE: u32 = 0x0003_0000;
