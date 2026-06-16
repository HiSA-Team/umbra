//! Enclave Swapping Set (ESS) — re-export shim.
//!
//! The ESS cache **logic** (the `EnclaveSwapSpace` bookkeeping, first-fit
//! allocator, LFU eviction, address map, `EnclaveDescriptor`) now lives in the
//! `umbra-ess-core` leaf crate so it can be machine-checked (issue #58). This
//! module re-exports it unchanged, so every existing `crate::common::ess::…`
//! path still resolves and behavior is identical. Platform features are
//! forwarded from the kernel's `Cargo.toml` so the per-board address map is the
//! same as before.
//!
//! The hardware-ordering invariants that this cache must be used with (and that
//! took real bugs to find) live with the code that enforces them — the
//! per-platform boot crates' `handle_ess_miss` / `evict_block`:
//! ## 1. Secure-alias execution would bypass MPCBB without the UDF trap
//! On STM32L5, executing from the Secure alias `0x300x_xxxx` bypasses the
//! MPCBB slot-level check that protects the NS alias `0x200x_xxxx`; demand
//! paging therefore traps via a UDF (`0xDEDE`) stamp in every non-resident
//! slot. EXC_RETURN for the recovery path must be `0xFFFF_FFFD`.
//! ## 2. Page replacement during SysTick preemption is fragile
//! With two enclaves loaded, a SysTick mid-context-switch can resume a PC in a
//! since-evicted slot. Mitigated by the globals-bypass pattern + the
//! `lookup_faulting_block` fix using `descriptor.code_size`.
//! ## 3. DMA → MPCBB ordering (the ndes / statemate crash)
//! `handle_ess_miss` MUST `mpcbb_set_slot_secure(addr, false)` BEFORE the DMA
//! that fetches the new page, or GTZC silently drops the NS-alias writes.

pub use umbra_ess_core::*;

// Property-based tests for the ESS allocator. They exercise the re-exported
// `EnclaveSwapSpace` (now defined in `umbra-ess-core`) via `super::*`. Sibling
// file so the parent stays under the file-size cap and proptest's std-only
// dependency does not leak into the firmware build path.
#[cfg(test)]
#[path = "ess_proptests.rs"]
mod proptests;
