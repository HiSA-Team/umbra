//! Chained-measurement blob verification — **re-export shim over the proved leaf
//! crate** `crates/umbra-chain-core` (`#![no_std]`, `#![forbid(unsafe_code)]`).
//!
//! `enclave_update` authenticates an update package's 76-byte core (pkg-tag v2,
//! including the full 48-byte header `blob[0,48)`), which provably does NOT
//! include the blob body
//! (`Umbra_Canonical.blob_body_is_not_covered_by_pkg_tag`, `Qed`). The body is
//! covered by a second, chained HMAC rooted at the authenticated `header.hmac`
//! window `blob[16,48)`. That chain is what this module exposes, and what
//! `formal/rocq/chain-core/` proves about:
//!
//! - **Coverage** — `Chain_Value.preimage_pins_block`: two blobs whose block-`k`
//!   preimages agree agree on all 288 bytes of block `k`.
//! - **The target theorem** — `Chain_Body.chain_accept_pins_the_blob_body`: two
//!   blobs accepted by the gate against the same authenticated `header.hmac`
//!   either agree on every folded byte, or the HMAC seam collided (witness
//!   exhibited). No assumption on the seam.
//! - **Composed** — `Chain_Compose.verified_update_pins_the_blob_body`: the same,
//!   consuming `Update_Crypto.accept_implies_authenticated_fields` (P2).
//! - **The residue** — `Chain_Residual`: exactly which blob bytes the gate cannot
//!   see (`blob[4,10)`, `blob[14,16)`, and everything after the blocks).
//!
//! # Fidelity to the firmware
//!
//! The crate replaces the firmware's `read_volatile` reads of the memory-mapped
//! XSPI2 window with indexing into a caller-owned `&[u8]`; order, bounds and
//! gate are identical. `blob_chain_tests.rs` holds a byte-exact replica of
//! `stm32n657/boot/src/api_impl.rs::fold_block_from_flash` and asserts the two
//! agree, so drift in either direction fails a host test.
//!
//! # Wiring status
//!
//! **Both N657 folds call [`block_preimage_of_block`]**:
//! `api_impl.rs::update_chain` (the real create path, whose measurement decides
//! whether an enclave runs) and `api_impl.rs::fold_block_from_flash` (the
//! side-effect-free probe behind A/B slot selection and post-update
//! re-verification). Each keeps its own `read_volatile` loops — they read MMIO
//! and cannot be pure — materialises the 288-byte block, and hands it to the
//! proved function. "KEEP IN SYNC" between the two folds is now structural:
//! there is one assembly and both call it.
//!
//! # Exactly how much of this module the firmware runs: one entry point of six
//!
//! The N657 calls [`block_preimage_of_block`] and **nothing else here**.
//! [`block_preimage`], [`chain_root`], [`blob_block_count`],
//! [`verify_blob_chain`] and the crate's `ct_eq32_at` have **zero N657 call
//! sites**. So the boundary does NOT simply run at the end of the volatile
//! reads: it closes at the end of `block_preimage_of_block` and re-opens
//! immediately, for three things the firmware still does itself and no theorem
//! touches:
//!
//! | firmware, unproved | the modelled counterpart it transcribes |
//! |---|---|
//! | `header.code_size / TOTAL_BLOCK_SIZE`, then `n == 0 \|\| n > MAX_EFBS` (`api_impl.rs`) | [`blob_block_count`], magic check included |
//! | `while blk < num_blocks { … }` (`api_impl.rs`) | [`chain_root`], accumulator threading included |
//! | `Kernel::finalize_measurement` (`secure_kernel.rs`), or `search_version` under `enclave_version_bind` | [`verify_blob_chain`]'s gate / `ct_eq32_at` |
//!
//! plus the address arithmetic and the volatile reads themselves. The differential
//! test in `blob_chain_tests.rs` is what pins the count and the gate; it exercises
//! the real call path (`block_preimage_of_block`) for the assembly only.

pub use umbra_chain_core::{
    blob_block_count, block_preimage, block_preimage_of_block, chain_root, verify_blob_chain,
    ChainHmac, BLOCK_LEN, BLOCK_PREIMAGE_LEN, CODE_LEN, CODE_SIZE_OFF, HDR_HMAC_OFF, HDR_LEN,
    MAX_BLOCKS, META_LEN, UMBR_MAGIC,
};

#[cfg(test)]
#[path = "blob_chain_tests.rs"]
mod tests;
