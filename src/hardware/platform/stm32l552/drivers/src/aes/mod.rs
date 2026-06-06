// Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>

//! AES driver for STM32L5xxxx — **software T-table on L552, HW peripheral on L562**.
//! # Silicon-level split (L552 vs L562)
//! STM32L552 has **no AES peripheral**: only STM32L562 ships with the AES
//! block. They share the package but differ at the die. The `AesHardware`
//! struct is therefore gated on `#[cfg(feature = "stm32l562")]`. Do NOT
//! widen the gate or invent a `hw_aes_l552` feature — the MMIO at
//! `0x520C_0000` does not exist on L552 and any access faults.
//! Reference: CJ1 in the threat model and the upstream paper text
//! "on the STM32L552, it is a software AES implementation executed by the CPU".
//! # T-table choice (`AesEmulated`)
//! 4× 1 KB T-tables generated at runtime in `AesEmulated::new()` from the
//! S-box (stored per-instance in `.bss`). `encrypt_block` ~8× faster than
//! the byte-wise reference; PLL @ 110 MHz + this engine gives the 17.6×
//! statemate wall-time speedup measured during the performance work.
//! State is packed column-major LE-u32; `expanded_key` is BE so a
//! `.swap_bytes()` lands on every key word at XOR time. Cortex-M33 has
//! no D-cache → no cache-timing side channel from the T-tables.
//! `decrypt_block` deliberately stays byte-wise (only `boot_tests` exercises
//! it; CTR-mode runtime encrypts only — decrypt is the same primitive on the
//! keystream side).
//! NIST FIPS-197 Appendix A.1 vectors verified MATCH on L552 hardware.

// STM32L5xxxx AES Driver
// This driver supports AES 128/256 hardware engine and emulated software implementation.

mod adapter;
mod emulated;
mod engine;
#[cfg(feature = "stm32l562")]
mod hw;

pub use adapter::{Aes128Engine, Aes128Error};
pub use emulated::AesEmulated;
pub use engine::AesEngine;
#[cfg(feature = "stm32l562")]
pub use hw::AesHardware;
