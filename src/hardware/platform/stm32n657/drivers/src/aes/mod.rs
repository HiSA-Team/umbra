//! AES engine for STM32N657.
//! Two implementations are provided: `AesEmulated`, a pure-software AES-128
//! and `AesHardware` which performs block operations via CRYP1 at 14 cycles
//! per 16-byte block (RM0486 Table 426).
//! # Key path: SW-load, not DHUK shared bus
//! `AesHardware` currently writes the master key directly into CRYP
//! K2LR/K2RR/K3LR/K3RR (driver in `cryp.rs`). The SAES1 → CRYP shared-key
//! bus would be the preferred path because the key never appears in CPU
//! registers, but per RM0486 §48.4.15 it **requires a DHUK-wrapped blob**
//! first: the SAES key-prep path raises CRYP KERF without that wrap.
//! The SAES infrastructure in `saes.rs` is intentionally preserved for the
//! future DHUK-wrap migration. See `cryp.rs` module docs for the full
//! key-write sequence and the seven CRYP1 register-layout pitfalls that
//! were uncovered during PR #44 bring-up (ALGOMODE encoding, ascending
//! K2→K3 write order, DATATYPE timing, ECB block feed, native CTR LSB
//! increment, HPDMA pitfalls, CRYPEN re-enable after algorithm switch).
//! NOTE: All loops use `while` instead of `for` ranges because Rust nightly
//! UB checks in `core::iter::range` panic on ARMv8-M.

mod ctr;
mod ecb;
mod gcm;
mod hal_adapter;
mod keyreg;

pub use ecb::*;
// `ctr` is impl-only (`impl AesEngine for AesHardware<M>`); impls travel
// with the type, so no re-export needed.
pub use gcm::*;
pub use hal_adapter::*;
pub use keyreg::*;
