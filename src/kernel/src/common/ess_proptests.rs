//! Property-based tests for the Enclave Swap Space allocator.
//!
//! Wired into `ess.rs` via
//! `#[cfg(test)] #[path = "ess_proptests.rs"] mod proptests;`.
//!
//! ## Why properties here
//!
//! `EnclaveSwapSpace::allocate` / `release` are pure arithmetic over a
//! fixed-size bitmap, with three invariants that are easy to state and
//! hard to reason about by example:
//!
//! 1. **Bound-correctness** — any successful `allocate(size)` returns
//!    an address inside `[EFBC_BASE, EFBC_BASE + ESS_SIZE)` and aligned
//!    to `SLOT_SIZE`.
//! 2. **Round-trip safety** — on a fresh allocator, `allocate → release
//!    → allocate` returns the same address, because the first-fit walk
//!    restarts at slot 0.
//! 3. **Out-of-range rejection** — `allocate(size)` for any `size`
//!    exceeding `ESS_SIZE` returns `None`, even when
//!    `size + SLOT_SIZE - 1` would wrap around `u32`.
//!
//! Each `proptest!` block runs 256 cases per `cargo test` invocation
//! (proptest's default). The fast unit `allocate_zero_returns_none`
//! covers the singular `size = 0` case that proptest's range
//! generators exclude by construction.

use super::*;
use crate::common::enclave::EnclaveDescriptor;
use proptest::prelude::*;
use umbra_error::UmbraError;

#[test]
fn allocate_zero_returns_err() {
    let mut ess = EnclaveSwapSpace::new();
    assert_eq!(ess.allocate(0), Err(UmbraError::LengthMismatch));
}

proptest! {
    /// Any successful `allocate(size)` returns an address that is at
    /// or above `EFBC_BASE`, below `EFBC_BASE + ESS_SIZE`, and aligned
    /// to `SLOT_SIZE`. Inputs span the full single-allocation range
    /// `[1, ESS_SIZE]`; if the allocator returns `Some`, the address
    /// must obey all three properties; if it returns `None`, the
    /// property holds vacuously.
    #[test]
    fn allocate_returns_aligned_address_within_efbc(size in 1u32..=ESS_SIZE) {
        let mut ess = EnclaveSwapSpace::new();
        if let Ok(addr) = ess.allocate(size) {
            prop_assert!(
                addr >= EFBC_BASE,
                "addr {addr:#x} below EFBC_BASE {EFBC_BASE:#x}",
            );
            prop_assert!(
                addr < EFBC_BASE + ESS_SIZE,
                "addr {addr:#x} past EFBC end {:#x}",
                EFBC_BASE + ESS_SIZE,
            );
            prop_assert_eq!(
                (addr - EFBC_BASE) % SLOT_SIZE,
                0,
                "addr {:#x} is not SLOT_SIZE-aligned (SLOT_SIZE = {})",
                addr,
                SLOT_SIZE,
            );
        }
    }

    /// `allocate(size)` followed by `release(addr, size)` followed by
    /// `allocate(size)` on a freshly-constructed allocator must return
    /// the same address both times. The first-fit walk starts from
    /// slot 0; after `release` zeroes the same slot run, the second
    /// allocate finds them as the first run of free slots again.
    #[test]
    fn allocate_release_roundtrip_returns_same_address(size in 1u32..=ESS_SIZE) {
        let mut ess = EnclaveSwapSpace::new();
        if let Ok(addr) = ess.allocate(size) {
            ess.release(addr, size);
            let addr2 = ess.allocate(size);
            prop_assert_eq!(Ok(addr), addr2);
        }
    }

    /// `allocate(size)` for any size strictly greater than `ESS_SIZE`
    /// must return `Err`. Covers the upper-half `u32` range, including
    /// values where `size + SLOT_SIZE - 1` wraps — large-but-fitting
    /// sizes reject as `EssRegionExhausted`, while sizes that overflow the
    /// slot-count round-up reject as `OffsetOverflow`. Either way the
    /// request must be refused, never satisfied.
    #[test]
    fn allocate_oversized_returns_err(size in (ESS_SIZE + 1)..u32::MAX) {
        let mut ess = EnclaveSwapSpace::new();
        prop_assert!(ess.allocate(size).is_err());
    }

    /// `release(addr, size)` for any `addr` strictly below `EFBC_BASE`
    /// must be a no-op: the early `if address < EFBC_BASE { return; }`
    /// guard prevents the bitmap from being touched. Otherwise an NSC
    /// caller could pass a wild address and corrupt the slot map.
    #[test]
    fn release_below_efbc_base_is_noop(
        bad_addr in 0u32..EFBC_BASE,
        size in 1u32..=ESS_SIZE,
    ) {
        let mut ess = EnclaveSwapSpace::new();
        let bitmap_before = ess.bitmap;
        ess.release(bad_addr, size);
        prop_assert_eq!(ess.bitmap, bitmap_before);
    }

    /// `register_enclave` returns `true` for the first `MAX_ENCLAVES_CTX`
    /// calls on a fresh allocator and `false` thereafter. After the
    /// successful calls, exactly that many slots in `loaded_enclaves`
    /// must be `Some`.
    #[test]
    fn register_enclave_fills_slots_until_full(
        n in 0usize..=MAX_ENCLAVES_CTX * 2,
    ) {
        let mut ess = EnclaveSwapSpace::new();
        let mut successful = 0;
        for i in 0..n {
            let mut desc = EnclaveDescriptor::new();
            desc.id = i as u32;
            let efbs = [EfbDescriptor::default(); MAX_EFBS];
            if ess.register_enclave(desc, EFBC_BASE, efbs, 0) {
                successful += 1;
            }
        }
        let want = n.min(MAX_ENCLAVES_CTX);
        prop_assert_eq!(successful, want);
        let filled = ess.loaded_enclaves.iter().filter(|s| s.is_some()).count();
        prop_assert_eq!(filled, want);
    }

    /// `get_block_address` returns `None` for any `(enclave_id, block_id)`
    /// query against a freshly-constructed allocator with no enclaves
    /// registered. Catches a regression where an unitialised slot would
    /// be matched as `Some`.
    #[test]
    fn get_block_address_empty_ess_returns_none(
        enclave_id in 0u32..u32::MAX,
        block_id in 0u32..u32::MAX,
    ) {
        let ess = EnclaveSwapSpace::new();
        prop_assert_eq!(ess.get_block_address(enclave_id, block_id), None);
    }

    /// `get_block_address(enclave_id, block_id)` for a registered enclave
    /// with a loaded EFB at `block_id` (matching `id`) must return
    /// `Some(start_address + block_id * SLOT_SIZE)`. `block_id` and
    /// `start_address` are bounded to avoid `checked_*` overflow paths
    /// (those are exercised by `allocate_oversized_returns_none`'s
    /// upstream invariant).
    #[test]
    fn get_block_address_loaded_block_returns_start_plus_offset(
        enclave_id in 0u32..1_000,
        block_id in 0u32..(MAX_EFBS as u32),
        start_address in 0u32..(u32::MAX / 2),
    ) {
        let mut ess = EnclaveSwapSpace::new();
        let mut desc = EnclaveDescriptor::new();
        desc.id = enclave_id;
        let mut efbs = [EfbDescriptor::default(); MAX_EFBS];
        efbs[block_id as usize].is_loaded = true;
        efbs[block_id as usize].id = block_id;
        let efb_count = (block_id + 1) as usize;
        prop_assert!(ess.register_enclave(desc, start_address, efbs, efb_count));

        let expected = start_address
            .checked_add(block_id.saturating_mul(SLOT_SIZE));
        prop_assert_eq!(ess.get_block_address(enclave_id, block_id), expected);
    }

    /// `LoadedEnclave::find_eviction_victim` enforces three invariants
    /// that the formal model's "Check Cache" pathway relies on:
    ///   1. index `0` is NEVER returned (the loop starts at `i = 1`),
    ///   2. `exclude_idx` is NEVER returned,
    ///   3. the returned EFB is loaded.
    #[test]
    fn find_eviction_victim_respects_zero_and_excluded_and_loaded(
        loaded_mask in 0u64..(1u64 << 8),
        exclude_idx in 0u32..8,
    ) {
        let mut efbs = [EfbDescriptor::default(); MAX_EFBS];
        for i in 0..8 {
            efbs[i].is_loaded = ((loaded_mask >> i) & 1) == 1;
            // Distinct counters so the lowest-counter winner is stable.
            efbs[i].counter = i as u8;
        }
        let enclave = LoadedEnclave {
            descriptor: EnclaveDescriptor::new(),
            start_address: EFBC_BASE,
            efbs,
            efb_count: 8,
        };

        if let Some(idx) = enclave.find_eviction_victim(exclude_idx) {
            prop_assert_ne!(idx, 0, "index 0 must never be picked");
            prop_assert_ne!(idx, exclude_idx, "exclude_idx must never be picked");
            prop_assert!(
                efbs[idx as usize].is_loaded,
                "returned EFB at idx {} must be loaded",
                idx,
            );
        }
    }

    /// `LoadedEnclave::loaded_count` returns exactly the number of
    /// `is_loaded` EFBs in `efbs[..efb_count]`. EFBs beyond `efb_count`
    /// must be ignored even if their `is_loaded` flag is set —
    /// `efb_count` is the live-cache size, the rest is undefined slot
    /// memory.
    #[test]
    fn loaded_count_matches_set_efbs_in_efb_count_range(
        loaded_mask in 0u64..(1u64 << 16),
        efb_count in 0usize..=16usize,
    ) {
        let mut efbs = [EfbDescriptor::default(); MAX_EFBS];
        for i in 0..16 {
            efbs[i].is_loaded = ((loaded_mask >> i) & 1) == 1;
        }
        let enclave = LoadedEnclave {
            descriptor: EnclaveDescriptor::new(),
            start_address: EFBC_BASE,
            efbs,
            efb_count,
        };

        let expected = (0..efb_count)
            .filter(|i| ((loaded_mask >> i) & 1) == 1)
            .count();
        prop_assert_eq!(enclave.loaded_count(), expected);
    }

    /// `enclave_psp_top(idx)` returns `ENCLAVE_PSP_TOP - idx *
    /// ENCLAVE_PSP_STACK_SIZE`. For valid indices `[0, MAX_ENCLAVES_CTX)`
    /// the result is bounded between `ENCLAVE_PSP_BASE` and
    /// `ENCLAVE_PSP_TOP`, and successive indices land on strictly
    /// decreasing addresses spaced by exactly one stack size.
    #[test]
    fn enclave_psp_top_decreases_by_one_stack_per_index(
        idx in 0usize..MAX_ENCLAVES_CTX,
    ) {
        let top = enclave_psp_top(idx);
        let expected = ENCLAVE_PSP_TOP - (idx as u32) * ENCLAVE_PSP_STACK_SIZE;
        prop_assert_eq!(top, expected);
        prop_assert!(
            top <= ENCLAVE_PSP_TOP,
            "psp_top({idx}) = {top:#x} above ENCLAVE_PSP_TOP",
        );
        prop_assert!(
            top >= ENCLAVE_PSP_BASE,
            "psp_top({idx}) = {top:#x} below ENCLAVE_PSP_BASE — would alias .bss",
        );
    }

    /// Adjacent valid indices produce strictly-decreasing PSP tops:
    /// every enclave gets its own stack region, no aliasing. The
    /// per-index spacing is exactly `ENCLAVE_PSP_STACK_SIZE`.
    #[test]
    fn enclave_psp_top_is_strictly_decreasing(
        idx in 0usize..(MAX_ENCLAVES_CTX - 1),
    ) {
        let a = enclave_psp_top(idx);
        let b = enclave_psp_top(idx + 1);
        prop_assert_eq!(a - b, ENCLAVE_PSP_STACK_SIZE);
    }
}
