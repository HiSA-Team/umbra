//! Memory-layout — re-export shim.
//!
//! Umbra's logical memory-block model (`MemoryBlock`, `MemoryBlockList`, the
//! access/security attributes) and the region math (`create_from_range`) now
//! live in the verifiable `umbra-mem-core` crate (issue #58), where
//! `create_from_range` is proved to cover the requested range (T5,
//! `formal/rocq/mem-core`). This module re-exports it unchanged, so every
//! `common::memory_layout::…` path still resolves and behavior is identical.
//!
//! `MEMORY_BLOCK_SIZE` is the same `UMBRA_SLOT_SIZE_BYTES` knob as
//! `ess::SLOT_SIZE` (both build-script-generated from the same env var).

pub use umbra_mem_core::*;
