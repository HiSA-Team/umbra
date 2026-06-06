//! Umbra HAL — trait surface for hardware peripherals.
//! # Scope
//! These traits are **Secure-side aware**: their semantics assume operation
//! from the Secure world of an ARMv8-M (Cortex-M33 / M55) TrustZone-enabled
//! microcontroller. Unlike `embedded-hal`, they do NOT abstract over generic
//! embedded targets — they're focused on the cryptographic + memory-protection
//! peripherals that Umbra's TEE depends on.
//! # Trait surface
//! `Hash`, `Aes`, `Dma`, `Rcc`, `Uart`, `Gpio` cover the cryptographic
//! and memory-protection peripherals the TEE relies on.
//! # Implementation crates
//! - `umbra-l552-drivers` implements these for STM32L552 / L562
//! - `umbra-n657-drivers` implements these for STM32N657
//! - `umbra-pal-test` implements these for host-side testing

#![no_std]

pub mod aes;
pub mod dma;
pub mod gpio;
pub mod hash;
pub mod rcc;
pub mod uart;

pub use aes::{Aes, AesKey, AesMode};
pub use dma::Dma;
pub use gpio::Gpio;
pub use hash::Hash;
pub use rcc::Rcc;
pub use uart::Uart;
