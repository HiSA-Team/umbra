//! Host tests for the chained-measurement gate. Sibling-file pattern; the
//! `#[cfg(test)]` build links `std`, but `Vec` is not in a `no_std` prelude.

extern crate std;
use std::vec;
use std::vec::Vec;

use super::*;

/// A deterministic stand-in for HMAC-SHA-256: one independent FNV-1a pass per
/// output byte, each seeded differently and run over `key ‖ pre`. Not
/// cryptographic — it only has to be a function of its input and to change when
/// the input changes, which is what the gate's behaviour depends on. (An earlier
/// revision derived all 32 bytes from one 64-bit digest by shifting; that had
/// ~8 bits of live entropy and collided on single-byte flips.)
struct MockHmac;

fn fnv(seed: u64, bytes: &[u8]) -> u64 {
    let mut h = seed;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

impl ChainHmac for MockHmac {
    fn hmac_chain(&self, key: &[u8; 32], pre: &[u8; BLOCK_PREIMAGE_LEN]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, o) in out.iter_mut().enumerate() {
            let seed = 0xcbf2_9ce4_8422_2325u64 ^ ((i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let h = fnv(fnv(seed, key), pre);
            *o = (h ^ (h >> 19) ^ (h >> 37)) as u8;
        }
        out
    }
}

const MASTER: [u8; 32] = [0x5Au8; 32];

/// Build a well-formed blob of `n` blocks with pseudo-random body bytes, then
/// stamp the correct chain root into `header.hmac`.
fn make_blob(n: u32) -> Vec<u8> {
    let mut blob = vec![0u8; HDR_LEN + (n as usize) * BLOCK_LEN];
    blob[0..4].copy_from_slice(&UMBR_MAGIC.to_le_bytes());
    let code_size = n * (BLOCK_LEN as u32);
    blob[CODE_SIZE_OFF..CODE_SIZE_OFF + 4].copy_from_slice(&code_size.to_le_bytes());
    for (i, b) in blob.iter_mut().enumerate().skip(HDR_LEN) {
        *b = (i as u8).wrapping_mul(31).wrapping_add(7);
    }
    let root = chain_root(&MockHmac, &MASTER, &blob, n).expect("chain must fold");
    blob[HDR_HMAC_OFF..HDR_HMAC_OFF + 32].copy_from_slice(&root);
    blob
}

#[test]
fn constants_match_the_on_flash_layout() {
    assert_eq!(BLOCK_LEN, CODE_LEN + META_LEN);
    assert_eq!(BLOCK_PREIMAGE_LEN, 4 + CODE_LEN + META_LEN);
    // UMBRA_HEADER_SIZE / the `hmac` field offset in `kernel::common::enclave`.
    assert_eq!(HDR_LEN, 48);
    assert_eq!(HDR_HMAC_OFF, 16);
    // magic(4) trust(1) reserved(1) efbc_size(2) ess_blocks(2) -> code_size at 10.
    assert_eq!(CODE_SIZE_OFF, 10);
    // stm32n657: CODE_BLOCK_SIZE + BLOCK_HEADER_SIZE with chained_measurement on.
    assert_eq!(BLOCK_LEN, 256 + 32);
    // umbra_ess_core::MAX_EFBS, the firmware's block-count guard.
    assert_eq!(MAX_BLOCKS, 64);
}

#[test]
fn preimage_is_index_then_code_then_meta() {
    let mut blob = vec![0u8; HDR_LEN + BLOCK_LEN];
    for i in 0..BLOCK_LEN {
        blob[HDR_LEN + i] = i as u8;
    }
    let pre = block_preimage(&blob, 0).expect("in range");
    assert_eq!(&pre[0..4], &0u32.to_le_bytes());
    // code half = block[32..288]
    for i in 0..CODE_LEN {
        assert_eq!(pre[4 + i], blob[HDR_LEN + META_LEN + i]);
    }
    // meta half = block[0..32]
    for i in 0..META_LEN {
        assert_eq!(pre[4 + CODE_LEN + i], blob[HDR_LEN + i]);
    }
}

#[test]
fn preimage_carries_the_block_index() {
    let blob = vec![0u8; HDR_LEN + 3 * BLOCK_LEN];
    for blk in 0..3u32 {
        let pre = block_preimage(&blob, blk).expect("in range");
        assert_eq!(&pre[0..4], &blk.to_le_bytes());
    }
    assert!(block_preimage(&blob, 3).is_none()); // past the blob
    assert!(block_preimage(&blob, MAX_BLOCKS).is_none()); // past the guard
}

#[test]
fn well_formed_blob_verifies() {
    for n in [1u32, 2, 7] {
        let blob = make_blob(n);
        assert_eq!(blob_block_count(&blob), Some(n));
        assert!(verify_blob_chain(&MockHmac, &MASTER, &blob));
    }
}

#[test]
fn any_body_byte_flip_is_rejected() {
    let base = make_blob(3);
    // Every byte of the folded region, sampled at each block boundary and inside
    // both halves.
    for off in [
        HDR_LEN,
        HDR_LEN + 31,
        HDR_LEN + 32,
        HDR_LEN + 287,
        HDR_LEN + BLOCK_LEN,
        HDR_LEN + 2 * BLOCK_LEN + 100,
        HDR_LEN + 3 * BLOCK_LEN - 1,
    ] {
        let mut blob = base.clone();
        blob[off] ^= 0x01;
        assert!(
            !verify_blob_chain(&MockHmac, &MASTER, &blob),
            "flip at {off} must be rejected"
        );
    }
}

#[test]
fn every_single_byte_of_the_folded_region_matters() {
    // Exhaustive over a one-block blob: the chain must reject a flip at EVERY
    // one of the 288 body bytes. This is the executable shadow of the coverage
    // theorem (`Chain_Value.preimage_pins_block`).
    let base = make_blob(1);
    for off in HDR_LEN..HDR_LEN + BLOCK_LEN {
        let mut blob = base.clone();
        blob[off] ^= 0xFF;
        assert!(
            !verify_blob_chain(&MockHmac, &MASTER, &blob),
            "flip at {off} must be rejected"
        );
    }
}

#[test]
fn header_hmac_flip_is_rejected() {
    let mut blob = make_blob(2);
    blob[HDR_HMAC_OFF + 5] ^= 0x80;
    assert!(!verify_blob_chain(&MockHmac, &MASTER, &blob));
}

#[test]
fn wrong_master_key_is_rejected() {
    let blob = make_blob(2);
    assert!(!verify_blob_chain(&MockHmac, &[0u8; 32], &blob));
}

#[test]
fn block_reorder_is_rejected() {
    // The block index in the preimage is what makes a swap detectable even when
    // the multiset of block bytes is unchanged.
    let mut blob = make_blob(2);
    let (a, b) = (HDR_LEN, HDR_LEN + BLOCK_LEN);
    for i in 0..BLOCK_LEN {
        blob.swap(a + i, b + i);
    }
    assert!(!verify_blob_chain(&MockHmac, &MASTER, &blob));
}

#[test]
fn malformed_headers_are_rejected() {
    assert_eq!(blob_block_count(&[0u8; 47]), None); // too short
    let mut blob = make_blob(1);
    let good = blob.clone();
    blob[0] ^= 0xFF;
    assert_eq!(blob_block_count(&blob), None); // bad magic
    assert!(!verify_blob_chain(&MockHmac, &MASTER, &blob));

    let mut blob = good.clone();
    blob[CODE_SIZE_OFF..CODE_SIZE_OFF + 4].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(blob_block_count(&blob), None); // n == 0

    let mut blob = good.clone();
    let partial = (BLOCK_LEN as u32) + 1;
    blob[CODE_SIZE_OFF..CODE_SIZE_OFF + 4].copy_from_slice(&partial.to_le_bytes());
    assert_eq!(blob_block_count(&blob), None); // incomplete block would escape the fold
    assert!(!verify_blob_chain(&MockHmac, &MASTER, &blob));

    let mut blob = good.clone();
    let too_many = (MAX_BLOCKS + 1) * (BLOCK_LEN as u32);
    blob[CODE_SIZE_OFF..CODE_SIZE_OFF + 4].copy_from_slice(&too_many.to_le_bytes());
    assert_eq!(blob_block_count(&blob), None); // n > MAX_BLOCKS
}

#[test]
fn truncated_body_is_rejected_not_panicking() {
    let blob = make_blob(4);
    for cut in [
        HDR_LEN,
        HDR_LEN + 1,
        HDR_LEN + 3 * BLOCK_LEN,
        blob.len() - 1,
    ] {
        assert!(!verify_blob_chain(&MockHmac, &MASTER, &blob[..cut]));
    }
}

#[test]
fn declared_code_size_is_bound_to_the_fold_count() {
    // Shrinking code_size drops blocks from the fold; the root then differs, so
    // the header field is protected indirectly even though it is in no preimage.
    let mut blob = make_blob(3);
    let two = 2 * (BLOCK_LEN as u32);
    blob[CODE_SIZE_OFF..CODE_SIZE_OFF + 4].copy_from_slice(&two.to_le_bytes());
    assert_eq!(blob_block_count(&blob), Some(2));
    assert!(!verify_blob_chain(&MockHmac, &MASTER, &blob));
}

#[test]
fn every_declared_code_byte_belongs_to_a_complete_folded_block() {
    let mut blob = make_blob(2);
    for remainder in [1u32, 31, 287] {
        let malformed = 2 * (BLOCK_LEN as u32) + remainder;
        blob[CODE_SIZE_OFF..CODE_SIZE_OFF + 4].copy_from_slice(&malformed.to_le_bytes());
        assert_eq!(blob_block_count(&blob), None);
        assert!(!verify_blob_chain(&MockHmac, &MASTER, &blob));
    }
}

#[test]
fn bytes_outside_the_folded_region_are_not_covered() {
    // The honest negative: the chain says nothing about the header metadata
    // outside `code_size`, nor about anything appended after the blocks. This
    // test PASSES when the gate still accepts — it documents the residual gap
    // (`Chain_Residual.v`), it does not endorse it.
    let base = make_blob(2);

    let mut blob = base.clone();
    blob[4] ^= 0xFF; // trust_level
    assert!(verify_blob_chain(&MockHmac, &MASTER, &blob));

    let mut blob = base.clone();
    blob[14] ^= 0xFF; // reloc_count
    assert!(verify_blob_chain(&MockHmac, &MASTER, &blob));

    let mut blob = base.clone();
    blob.extend_from_slice(&[0xAA; 16]); // a "reloc table" appended after the blocks
    assert!(verify_blob_chain(&MockHmac, &MASTER, &blob));
}

/// The reloc-table asymmetry, stated as the gate actually behaves.
///
/// `tools/protect_enclave.py:856-857` folds the appended reloc table into the
/// chain whenever `chained_mode and reloc_count > 0`; the N657's fold loops
/// (`stm32n657/boot/src/api_impl.rs:173-177`, `:472-481`) stop at `num_blocks`
/// and never fold it. Both halves of what that does and does not buy are pinned
/// here:
///
/// 1. **Fold-then-sign is rejected.** A blob whose `header.hmac` carries the
///    extra reloc fold does not verify against the block-only chain — which is
///    why `protect_enclave.py` cannot emit an N657-acceptable blob carrying
///    relocations.
/// 2. **Sign-without-fold is ACCEPTED, with any `reloc_count`.** The gate has no
///    `reloc_count` check and no view of anything past `48 + 288·n`. So the
///    property in (1) belongs to the signing tool, not to this gate and not to
///    the device; a blob signed by anything that skips the extra fold sails
///    through. This assertion PASSES on acceptance: like
///    `bytes_outside_the_folded_region_are_not_covered`, it documents the
///    residual, it does not endorse it.
///
/// **If you are here to fix the residual, expect to edit this test.** The fix
/// the crate README proposes — folding the reloc table into the chain on the
/// N657 too — makes assertion (2) false by construction, and a `reloc_count`
/// guard inside `chain_root` would break both (2) and the pre-existing
/// `bytes_outside_the_folded_region_are_not_covered`. That is expected: these
/// two tests describe today's boundary, so moving the boundary must move them.
/// Update them deliberately; do not delete them to make a build go green.
#[test]
fn reloc_count_is_not_checked_by_the_gate() {
    // Stand-in for `hmac.new(chain_state, reloc_table_bytes, sha256)`: the same
    // FNV construction as `MockHmac`, over a variable-length message.
    fn mock_hmac_bytes(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, o) in out.iter_mut().enumerate() {
            let seed = 0xcbf2_9ce4_8422_2325u64 ^ ((i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let h = fnv(fnv(seed, key), msg);
            *o = (h ^ (h >> 19) ^ (h >> 37)) as u8;
        }
        out
    }

    // Two relocation offsets, `[u32 offset]...`, appended after the blocks —
    // the layout `protect_enclave.py:849-850` writes.
    let reloc_table: [u8; 8] = [0x30, 0x00, 0x00, 0x00, 0x70, 0x01, 0x00, 0x00];
    let reloc_count: u16 = 2;

    let mut base = make_blob(2);
    let block_root: [u8; 32] = base[HDR_HMAC_OFF..HDR_HMAC_OFF + 32]
        .try_into()
        .expect("32 bytes");
    base[14..16].copy_from_slice(&reloc_count.to_le_bytes());
    base.extend_from_slice(&reloc_table);

    // (1) offline signing folded the table in: the device's block-only root
    //     cannot reproduce it.
    let mut folded = base.clone();
    let root_with_reloc_fold = mock_hmac_bytes(&block_root, &reloc_table);
    folded[HDR_HMAC_OFF..HDR_HMAC_OFF + 32].copy_from_slice(&root_with_reloc_fold);
    assert!(
        !verify_blob_chain(&MockHmac, &MASTER, &folded),
        "a blob signed WITH the reloc fold must not verify against the block-only chain"
    );

    // (2) the same blob signed WITHOUT the extra fold — the gate accepts it,
    //     reloc_count and table and all, and never looks at either.
    assert!(
        verify_blob_chain(&MockHmac, &MASTER, &base),
        "the gate has no reloc_count check: this is the residual, not a pass"
    );
    let mut other_count = base.clone();
    other_count[14..16].copy_from_slice(&0xBEEFu16.to_le_bytes());
    assert!(verify_blob_chain(&MockHmac, &MASTER, &other_count));
    let mut other_table = base.clone();
    let n = other_table.len();
    other_table[n - 8..].copy_from_slice(&[0xFF; 8]);
    assert!(verify_blob_chain(&MockHmac, &MASTER, &other_table));
}

// --- the factorisation, tested ------------------------------------------
//
// `block_preimage` no longer assembles anything: it checks bounds, materialises
// the block and delegates to `block_preimage_of_block`, which is the function
// the N657 firmware calls. These two tests are what stop that delegation from
// silently changing the bytes.

/// The PRE-REFACTOR body, transcribed literally: index the blob directly, no
/// intermediate block. If the refactor changed one byte of the observable
/// output of `block_preimage`, this fails.
fn preimage_pre_refactor(blob: &[u8], blk: u32) -> Option<[u8; BLOCK_PREIMAGE_LEN]> {
    if blk >= MAX_BLOCKS {
        return None;
    }
    let base = HDR_LEN + (blk as usize) * BLOCK_LEN;
    if blob.len() < base + BLOCK_LEN {
        return None;
    }
    let mut pre = [0u8; BLOCK_PREIMAGE_LEN];
    pre[0..4].copy_from_slice(&blk.to_le_bytes());
    pre[4..260].copy_from_slice(&blob[base + META_LEN..base + BLOCK_LEN]);
    pre[260..292].copy_from_slice(&blob[base..base + META_LEN]);
    Some(pre)
}

#[test]
fn refactor_did_not_change_block_preimage() {
    let blob = make_blob(5);
    // in range, out of range past the body, and past the MAX_BLOCKS guard
    for blk in [0u32, 1, 2, 3, 4, 5, 6, MAX_BLOCKS - 1, MAX_BLOCKS, MAX_BLOCKS + 1] {
        assert_eq!(
            block_preimage(&blob, blk),
            preimage_pre_refactor(&blob, blk),
            "block_preimage drifted at blk={blk}"
        );
    }
    // short blobs: every truncation of a two-block blob, at block 0 and 1
    let full = make_blob(2);
    for cut in 0..=full.len() {
        for blk in [0u32, 1] {
            assert_eq!(
                block_preimage(&full[..cut], blk),
                preimage_pre_refactor(&full[..cut], blk),
                "block_preimage drifted at cut={cut} blk={blk}"
            );
        }
    }
}

#[test]
fn block_preimage_factors_through_block_preimage_of_block() {
    // The Coq-level statement is `Chain_Value.preimage_factors_through_block`;
    // this is its executable shadow.
    let blob = make_blob(4);
    for blk in 0..4u32 {
        let base = HDR_LEN + (blk as usize) * BLOCK_LEN;
        let mut block = [0u8; BLOCK_LEN];
        block.copy_from_slice(&blob[base..base + BLOCK_LEN]);
        assert_eq!(
            block_preimage(&blob, blk).expect("in range"),
            block_preimage_of_block(blk, &block)
        );
    }
}

#[test]
fn preimage_of_block_is_index_then_code_then_meta() {
    let mut block = [0u8; BLOCK_LEN];
    for (i, b) in block.iter_mut().enumerate() {
        *b = i as u8;
    }
    let pre = block_preimage_of_block(9, &block);
    assert_eq!(&pre[0..4], &9u32.to_le_bytes());
    for i in 0..CODE_LEN {
        assert_eq!(pre[4 + i], block[META_LEN + i]);
    }
    for i in 0..META_LEN {
        assert_eq!(pre[4 + CODE_LEN + i], block[i]);
    }
}
