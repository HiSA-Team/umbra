//! Verifiable chained-measurement logic — the blob-body half of the secure
//! enclave update (issue #58).
//!
//! `umbra-update-core`'s package tag authenticates a 76-byte core (pkg-tag v2):
//! nonce, `author_id`, `version`, `blob_len` and the full 48-byte UMBR header
//! `blob[0,48)` (which includes `header.hmac` at `blob[16,48)`). It does
//! **not** cover the blob body; that is machine-checked
//! (`Umbra_Canonical.blob_body_is_not_covered_by_pkg_tag`, `Qed`). Body integrity
//! rests on a *second*, chained HMAC rooted at that authenticated `header.hmac`:
//!
//! ```text
//!   M₀    = master_key
//!   Mₖ₊₁  = HMAC(Mₖ,  blk_le32(k) ‖ block[k].code ‖ block[k].meta)
//!   accept  ⟺  M_n == blob[16..48)   (the authenticated header.hmac window)
//! ```
//!
//! # On-flash blob layout this file mirrors
//!
//! ```text
//!   0  48   UMBR header
//!            0   4  magic = "UMBR"
//!            4   1  trust_level
//!            5   1  reserved0
//!            6   2  efbc_size
//!            8   2  ess_blocks
//!           10   4  code_size          <- must be a positive multiple of 288
//!           14   2  reloc_count
//!           16  32  hmac               <- the chain root; authenticated by P2
//!  48  ..   code_size bytes = code_size/288 blocks of 288 bytes each,
//!           each laid out [meta(32) | code(256)]
//!  48+code_size ..  reloc_count u32 entries (NOT folded — see below)
//! ```
//!
//! # Fidelity to the firmware
//!
//! The per-block preimage is `[block_idx_le(4) | code(256) | meta(32)]` — the
//! code half first, then the meta half, which is the order
//! `stm32n657/boot/src/api_impl.rs::fold_block_from_flash` (and its ESS-backed
//! twin `update_chain`) assembles, and the order `tools/protect_enclave.py`
//! stamps offline. The constants below are pinned to the firmware's by
//! [`tests::constants_match_firmware`].
//!
//! `fold_block_from_flash` **calls [`block_preimage_of_block`]**: it keeps its
//! two `read_volatile` loops on the memory-mapped XSPI2 window, materialises the
//! 288-byte block, and delegates the assembly. So there is no transcription of
//! the assembly to be faithful to any more — from the block onwards the firmware
//! runs this code.
//!
//! What is still a substitution is the *other* entry point: [`block_preimage`]
//! indexes a caller-owned `&[u8]`, where the firmware does pointer arithmetic
//! and volatile reads. The address computation and the reads are outside every
//! theorem; everything downstream of them is inside. That is the same modelling
//! step `umbra-update-core` makes for the package buffer, now confined to
//! strictly less code.
//!
//! # What the chain does NOT cover
//!
//! Only `blob[48, 48 + 288·n)` is folded. The header's own metadata
//! (`blob[0,10)` and `blob[14,16)` — `trust_level`, `efbc_size`, `ess_blocks`,
//! `reloc_count`) and the relocation table appended after the blocks are **not**
//! in any chain preimage. Since pkg-tag v2 the full header `blob[0,48)` IS
//! covered by the update package tag (`umbra-update-v2`), so those bytes are
//! authenticated at the tag rather than by this chain; the reloc table is
//! outside both, and what that does and does not buy is below. `code_size` has
//! indirect chain protection: it fixes `n`, so changing it changes the number
//! of folds and therefore the root. See the crate README and
//! `formal/rocq/chain-core/` for the exact residual statement.
//!
//! ## The reloc table: what is actually true (the N657 does not check `reloc_count`)
//!
//! An earlier revision of this docstring labelled this residual **fail-closed**
//! and concluded that "in practice N657 blobs must have `reloc_count == 0`".
//! Its narrow sentence — that a blob *from `protect_enclave.py`* carrying
//! relocations is rejected — was true; the label and the invariant drawn from it
//! were not, because both name the DEVICE for a property of the SIGNER. There is
//! **no `reloc_count` check anywhere in the N657 firmware**: nothing reads the
//! field, and the fold loops
//! (`stm32n657/boot/src/api_impl.rs:173-177` in `authenticated_version_at`,
//! `:472-481` in `umbra_enclave_create_imp`) stop at `num_blocks`, after which
//! the gate compares only that block root
//! (`stm32n657/boot/src/secure_kernel.rs:190-202`, or `search_version` at
//! `api_impl.rs:196-198` / `:515-517` under `enclave_version_bind`). The true
//! statement is narrower and belongs to the **signer**, not to the device:
//!
//! - `tools/protect_enclave.py:856-857` folds the reloc table into the chain
//!   whenever `chained_mode and reloc_count > 0` — no platform guard — and
//!   stamps the result into `header.hmac` (`:893-894`, `:917`). The N657 never
//!   folds it, so such a blob presents a root the device cannot reproduce and is
//!   rejected. That is a statement about *this tool*: it cannot emit an
//!   N657-acceptable blob carrying relocations.
//! - It does **not** make the gate reject `reloc_count > 0`. A blob signed
//!   without that extra fold — anything not produced by that script — is
//!   accepted with `reloc_count` set to any value, and the table is then simply
//!   ignored. Both halves are pinned by
//!   `src/lib_tests.rs::reloc_count_is_not_checked_by_the_gate`.
//! - Today the case is unreachable rather than defended: reloc extraction needs
//!   the ELF to be linked with `--emit-relocs` (`tools/protect_enclave.py:139`),
//!   which only `host/stm32l552/taclebench/Makefile:90` passes. No N657 link
//!   does, so `readelf -W -r` on an N657 enclave ELF reports no relocations at
//!   all and every N657 blob carries `reloc_count == 0`.
//!
//! What bounds the exposure today is therefore (a) no N657 consumer of the field
//! or the table, and (b) pkg-tag v2, which stops the field being flipped after
//! signing on the update path. See the crate README for the fix owed the day the
//! N657 gains reloc support.
//!
//! # Extraction
//!
//! `#![no_std]`, `forbid(unsafe_code)`, no closures, no `dyn`. The HMAC seam is
//! the [`ChainHmac`] trait taking one flat preimage array, exactly as the
//! on-target HW HASH path does. Extract with
//! `formal/rocq/chain-core/extract.sh`.

#![no_std]
#![forbid(unsafe_code)]

/// UMBR header magic, little-endian ("UMBR").
pub const UMBR_MAGIC: u32 = 0x524D_4255;
/// Size of the UMBR header prefixing every blob.
pub const HDR_LEN: usize = 48;
/// Offset of the 32-byte `header.hmac` field — the chain root the gate compares
/// against; a sub-window of the full header `blob[0,48)` that `umbra-update-core`'s
/// package tag authenticates (pkg-tag v2).
pub const HDR_HMAC_OFF: usize = 16;
/// Offset of the `code_size` u32 inside the header.
pub const CODE_SIZE_OFF: usize = 10;
/// Bytes of executable code per block.
pub const CODE_LEN: usize = 256;
/// Bytes of per-block metadata.
pub const META_LEN: usize = 32;
/// On-flash block stride: `[meta(32) | code(256)]`.
pub const BLOCK_LEN: usize = 288;
/// Per-block HMAC preimage: `[blk_idx_le(4) | code(256) | meta(32)]`.
pub const BLOCK_PREIMAGE_LEN: usize = 292;
/// Upper bound on the block count, mirroring the firmware's `MAX_EFBS` guard.
/// It is what makes every offset in this file provably overflow-free.
pub const MAX_BLOCKS: u32 = 64;

/// The chained-HMAC seam. On target this is the HW HASH engine keyed with the
/// running chain state; in tests and extraction it is an injected model. Takes a
/// single flat preimage (not a slice-of-borrows, not a closure) so Aeneas can
/// translate the call.
pub trait ChainHmac {
    fn hmac_chain(&self, key: &[u8; 32], pre: &[u8; BLOCK_PREIMAGE_LEN]) -> [u8; 32];
}

/// **The preimage assembly, and the single source of truth for it.** Given an
/// already-materialised 288-byte block `[meta(32) | code(256)]`, build block
/// `blk`'s HMAC preimage `[blk_le(4) | code(256) | meta(32)]`.
///
/// This is the function the N657 Secure kernel calls
/// (`stm32n657/boot/src/api_impl.rs::fold_block_from_flash`), which is why it
/// takes a block rather than a blob: the firmware materialises the block out of
/// the memory-mapped XSPI2 window with `read_volatile`, and a `&[u8]` over that
/// window is not something it can hand over. Everything downstream of that read
/// — this assembly, the ordering, the fold, the gate — is this crate's, and is
/// what `formal/rocq/chain-core/` proves about.
///
/// Total: there is no failure mode once the block exists. [`block_preimage`]
/// carries the bounds checks and delegates here, so the two cannot drift.
pub fn block_preimage_of_block(blk: u32, block: &[u8; BLOCK_LEN]) -> [u8; BLOCK_PREIMAGE_LEN] {
    let b: &[u8] = block;
    let mut pre = [0u8; BLOCK_PREIMAGE_LEN];
    pre[0..4].copy_from_slice(&blk.to_le_bytes());
    // code half: block[32..288]
    pre[4..260].copy_from_slice(&b[META_LEN..BLOCK_LEN]);
    // meta half: block[0..32]
    pre[260..292].copy_from_slice(&b[0..META_LEN]);
    pre
}

/// Build block `blk`'s HMAC preimage from the blob: `[blk_le(4) | code(256) |
/// meta(32)]`, where the block sits at `48 + 288·blk` and is `[meta | code]`.
/// `None` if `blk` is past the guard or the blob is too short to hold the block.
///
/// The guards are here; the assembly is [`block_preimage_of_block`]'s. This
/// function is the blob-shaped view used by [`chain_root`] and by the offline
/// tooling; the firmware uses the block-shaped one. Both compute the same bytes
/// *by construction*, not by transcription.
pub fn block_preimage(blob: &[u8], blk: u32) -> Option<[u8; BLOCK_PREIMAGE_LEN]> {
    // The guard is what bounds every offset below: base ≤ 48 + 63·288 = 18192,
    // so neither the multiply nor any add can overflow a 32-bit usize.
    if blk >= MAX_BLOCKS {
        return None;
    }
    let base = HDR_LEN + (blk as usize) * BLOCK_LEN;
    if blob.len() < base + BLOCK_LEN {
        return None;
    }
    let mut block = [0u8; BLOCK_LEN];
    block[0..BLOCK_LEN].copy_from_slice(&blob[base..base + BLOCK_LEN]);
    Some(block_preimage_of_block(blk, &block))
}

/// Fold blocks `0..num_blocks` into the chain, starting from `master`.
/// `None` if any block is out of range.
pub fn chain_root<H: ChainHmac>(
    h: &H,
    master: &[u8; 32],
    blob: &[u8],
    num_blocks: u32,
) -> Option<[u8; 32]> {
    let mut chain = *master;
    let mut i: u32 = 0;
    while i < num_blocks {
        match block_preimage(blob, i) {
            Some(pre) => {
                chain = h.hmac_chain(&chain, &pre);
            }
            None => return None,
        }
        i += 1;
    }
    Some(chain)
}

/// Read the block count out of the header. `code_size` must describe complete
/// 288-byte blocks; rejecting a remainder prevents bytes declared as code from
/// falling outside the folded region. The resulting count is subject to the
/// same `0 < n ≤ MAX_BLOCKS` guard the firmware applies.
pub fn blob_block_count(blob: &[u8]) -> Option<u32> {
    if blob.len() < HDR_LEN {
        return None;
    }
    let magic = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
    if magic != UMBR_MAGIC {
        return None;
    }
    let code_size = u32::from_le_bytes([
        blob[CODE_SIZE_OFF],
        blob[CODE_SIZE_OFF + 1],
        blob[CODE_SIZE_OFF + 2],
        blob[CODE_SIZE_OFF + 3],
    ]);
    if code_size % (BLOCK_LEN as u32) != 0 {
        return None;
    }
    let n = code_size / (BLOCK_LEN as u32);
    if n == 0 || n > MAX_BLOCKS {
        return None;
    }
    Some(n)
}

/// **The accept gate.** Recompute the chain over the blob's blocks from `master`
/// and accept iff the root equals the blob's own `header.hmac` window
/// `blob[16..48)` — a sub-window of the full header `blob[0..48)` that
/// `umbra-update-core`'s package tag authenticates (pkg-tag v2).
/// Constant-time in the compared bytes.
pub fn verify_blob_chain<H: ChainHmac>(h: &H, master: &[u8; 32], blob: &[u8]) -> bool {
    let n = match blob_block_count(blob) {
        Some(n) => n,
        None => return false,
    };
    let root = match chain_root(h, master, blob, n) {
        Some(r) => r,
        None => return false,
    };
    ct_eq32_at(&root, blob, HDR_HMAC_OFF)
}

/// Constant-time compare of `a` against `blob[off..off+32)`.
fn ct_eq32_at(a: &[u8; 32], blob: &[u8], off: usize) -> bool {
    if blob.len() < off + 32 {
        return false;
    }
    let mut d: u8 = 0;
    let mut i: usize = 0;
    while i < 32 {
        d |= a[i] ^ blob[off + i];
        i += 1;
    }
    d == 0
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
