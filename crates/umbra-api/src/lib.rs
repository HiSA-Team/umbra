//! Umbra API — leaf contract for the TEE.
//! # Why this crate exists
//! Before, the kernel crate (`src/kernel`) exposed its trait
//! surface via `lib.rs` re-exports. Driver and boot crates imported the
//! kernel crate to know what to implement, which made the kernel a central
//! hub instead of a peer. `umbra-api` breaks that asymmetry: it is a LEAF
//! crate containing only trait definitions, shared newtypes, and
//! constants. Everyone — kernel, drivers, boot, host tests — depends on
//! `umbra-api`. The dependency graph becomes a tree.
//! # migration plan (incremental)
//! The kernel surface that PAL crates currently consume is non-trivial
//! (`PlatformBoot`, `CryptoEngine`, `MemorySecurityGuardTrait`,
//! `EnclaveState`, `EnclaveContext`, `UmbraEnclaveHeader`,
//! `MemoryBlockList`, `MemoryBlockSecurityAttribute`,
//! `MEMORY_BLOCK_SIZE`). Moving everything in a single commit risks a
//! noisy bisect surface and possible firmware regressions.
//! Strategy: scaffold the submodules empty here, then migrate one
//! trait/type at a time in subsequent commits, each independently
//! reviewable. Order chosen by leaf-depth — smallest, least-coupled
//! moves first.

#![no_std]

pub mod constants;
pub mod crypto;
pub mod memory_guard;
pub mod platform;
pub mod security;
pub mod types;

pub use crypto::CryptoEngine;
pub use platform::PlatformBoot;
pub use types::{BlockAddr, EnclaveId, Measurement};
