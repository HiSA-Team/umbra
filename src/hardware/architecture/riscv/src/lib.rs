#![cfg_attr(not(test), no_std)]
//! Umbra RISC-V (RV32) architecture layer
//!
//! Parallels `architecture/arm/` (mmio/mpu/sau) but for the RISC-V isolation
//! mechanism: PMP (M-mode outer fence), SPMP (S-mode enclave fence), and the
//! trap interface. This crate is deliberately decoupled from `kernel` so its
//! pure policy logic is host-testable in isolation.
//!
//! Phase 1 lands the [`spmp`] arbitration policy model. PMP/CSR/trap modules
//! arrive with the M-mode monitor (later phases).

pub mod aes_kat;
pub mod csr;
pub mod pmp;
pub mod spmp;
pub mod trap;
