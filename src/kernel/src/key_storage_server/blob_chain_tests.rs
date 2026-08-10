//! DIFFERENTIAL TEST — the proved crate against a replica of the shipping N657
//! fold. **Half of what this file used to compare no longer exists.**
//!
//! `formal/rocq/chain-core/` proves things about `umbra-chain-core`. Those proofs
//! are worth exactly as much as the claim that the crate computes what the
//! firmware computes. That claim used to be underwritten by a transcription:
//! this file held a byte-exact copy of `fold_block_from_flash`'s preimage
//! assembly and asserted the copy agreed with the crate. A copy that agrees is a
//! drift DETECTOR — it fires only after one side has already changed.
//!
//! `fold_block_from_flash` now **calls** `block_preimage_of_block`, so the
//! assembly is not duplicated and cannot drift; there is one of it, and it is
//! the proved one. [`the_firmware_calls_the_proved_assembly`] checks that
//! against the firmware's own source, so it cannot decay into a stale comment.
//!
//! What is still transcribed is exactly what cannot be shared: the address
//! arithmetic and the two `read_volatile` loops that materialise a block out of
//! the memory-mapped XSPI2 window. [`firmware_replica_block`] is that half, with
//! the pointer reads replaced by slice indexing and nothing else changed, and
//! [`the_replica_block_is_the_blobs_block`] pins it against the crate's own
//! `base` arithmetic. That is also, precisely, the residual: the theorems
//! constrain everything downstream of those reads and nothing upstream of them.
//!
//! # THE CONFIGURATION THIS IS TRUE OF, AND ONLY OF
//!
//! The constants below are those of the DEFAULT N657 feature set
//! (`chained_measurement` on, `ess_miss_recovery` off): `BLOCK_META_OFFSET = 0`,
//! `BLOCK_HEADER_SIZE = 32`, so a block is `[meta(32) | code(256)]` of 288
//! bytes. **Under either other `cfg` arm of `secure_kernel.rs:109-128`
//! (`BLOCK_HEADER_SIZE = 64`, `BLOCK_META_OFFSET = 32`, stride 320) the crate,
//! the transcription and every Coq theorem about them are simply WRONG for that
//! build**, because `umbra-chain-core` hardcodes the 288-byte stride.
//!
//! Asserting the transcribed literals against each other would not catch a `cfg`
//! flip in the firmware — both sides are in this file. So
//! [`the_firmware_still_uses_the_configuration_we_transcribed`] reads the
//! firmware's OWN source and its OWN `Cargo.toml` at compile time and fails if
//! either the default feature list or the `chained_measurement` arm of the
//! constant block changes. That is a layering inversion (the kernel is a
//! dependency of the boot crate, not the other way round) and it is confined to
//! `#[cfg(test)]`; it buys the one guarantee the differential test cannot
//! otherwise have.

extern crate std;
use std::vec;
use std::vec::Vec;

use super::*;

// --- the firmware's constants, transcribed ------------------------------
const UMBRA_HEADER_SIZE: usize = 48; // kernel::common::enclave
const CODE_BLOCK_SIZE: usize = 256; // secure_kernel.rs:106
const BLOCK_META_SIZE: usize = 32; // secure_kernel.rs:107
const BLOCK_META_OFFSET: usize = 0; // secure_kernel.rs:110 (chained_measurement)
const BLOCK_HEADER_SIZE: usize = 32; // secure_kernel.rs:112 (chained_measurement)
const TOTAL_BLOCK_SIZE: usize = CODE_BLOCK_SIZE + BLOCK_HEADER_SIZE;
const MAX_EFBS: usize = 64; // umbra_ess_core::MAX_EFBS

/// Transcription of `fold_block_from_flash`'s **MMIO half, and only that**: the
/// address arithmetic and the two read loops, with `read_volatile` replaced by
/// slice indexing. This is now the whole of what is transcribed, and therefore
/// the whole of what can drift.
fn firmware_replica_block(blob: &[u8], blk: u32) -> [u8; TOTAL_BLOCK_SIZE] {
    let blk_off = (blk as usize) * TOTAL_BLOCK_SIZE;
    let block_base = UMBRA_HEADER_SIZE + blk_off;
    let code_src = block_base + BLOCK_HEADER_SIZE;
    let meta_src = block_base + BLOCK_META_OFFSET;

    let mut block = [0u8; TOTAL_BLOCK_SIZE];
    let mut i = 0usize;
    while i < CODE_BLOCK_SIZE {
        block[BLOCK_HEADER_SIZE + i] = blob[code_src + i];
        i += 1;
    }
    let mut j = 0usize;
    while j < BLOCK_META_SIZE {
        block[BLOCK_META_OFFSET + j] = blob[meta_src + j];
        j += 1;
    }
    block
}

/// The replica's preimage — assembled by **the same function the firmware
/// calls**, not by a second copy of it.
///
/// Before the crate was wired in, this body transcribed the firmware's inline
/// assembly and the test compared two independent implementations. That is a
/// drift DETECTOR: it fails only after someone has already changed one side.
/// Now `fold_block_from_flash` and this function both call
/// `block_preimage_of_block`, so the assembly cannot drift — there is one of it.
/// What is still duplicated is the offset arithmetic above, and
/// [`the_replica_block_is_the_blobs_block`] pins that against the crate's own.
fn firmware_replica_preimage(blob: &[u8], blk: u32) -> [u8; BLOCK_PREIMAGE_LEN] {
    block_preimage_of_block(blk, &firmware_replica_block(blob, blk))
}

/// Transcription of `authenticated_version_at`'s accept condition (the
/// `enclave_version_bind`-off arm: `finalize_measurement(&header.hmac)`).
fn firmware_replica_accept<H: ChainHmac>(h: &H, master: &[u8; 32], blob: &[u8]) -> bool {
    if blob.len() < UMBRA_HEADER_SIZE {
        return false;
    }
    let magic = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
    if magic != UMBR_MAGIC {
        return false;
    }
    let code_size = u32::from_le_bytes([blob[10], blob[11], blob[12], blob[13]]);
    let num_blocks = code_size / (TOTAL_BLOCK_SIZE as u32);
    if num_blocks == 0 || (num_blocks as usize) > MAX_EFBS {
        return false;
    }
    if blob.len() < UMBRA_HEADER_SIZE + (num_blocks as usize) * TOTAL_BLOCK_SIZE {
        return false; // the firmware would fault; the crate returns false
    }
    let mut chain = *master; // begin_measurement()
    let mut blk = 0u32;
    while blk < num_blocks {
        let pre = firmware_replica_preimage(blob, blk);
        chain = h.hmac_chain(&chain, &pre);
        blk += 1;
    }
    // finalize_measurement: constant-time compare against header.hmac
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= chain[i] ^ blob[16 + i];
    }
    diff == 0
}

// --- a deterministic stand-in for the HW HMAC ---------------------------

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

fn make_blob(n: u32) -> Vec<u8> {
    let mut blob = vec![0u8; UMBRA_HEADER_SIZE + (n as usize) * TOTAL_BLOCK_SIZE];
    blob[0..4].copy_from_slice(&UMBR_MAGIC.to_le_bytes());
    let code_size = n * (TOTAL_BLOCK_SIZE as u32);
    blob[10..14].copy_from_slice(&code_size.to_le_bytes());
    for (i, b) in blob.iter_mut().enumerate().skip(UMBRA_HEADER_SIZE) {
        *b = (i as u8).wrapping_mul(37).wrapping_add(11);
    }
    let root = chain_root(&MockHmac, &MASTER, &blob, n).expect("fold");
    blob[16..48].copy_from_slice(&root);
    blob
}

// --- the differential ---------------------------------------------------

/// The N657 boot crate's own sources, pulled in at compile time. See the module
/// header for why a `#[cfg(test)]` layering inversion is the right trade here.
const N657_SECURE_KERNEL_RS: &str =
    include_str!("../../../hardware/platform/stm32n657/boot/src/secure_kernel.rs");
const N657_BOOT_CARGO_TOML: &str =
    include_str!("../../../hardware/platform/stm32n657/boot/Cargo.toml");
const N657_API_IMPL_RS: &str =
    include_str!("../../../hardware/platform/stm32n657/boot/src/api_impl.rs");

/// A named function's body, sliced out of the firmware source at compile time.
/// Used to check *structurally* that the shipping folds delegate.
fn firmware_fn_body(sig: &str) -> &'static str {
    let start = N657_API_IMPL_RS
        .find(sig)
        .unwrap_or_else(|| panic!("api_impl.rs must still define `{sig}`"));
    let rest = &N657_API_IMPL_RS[start..];
    // Up to the NEAREST following item boundary at column 0 — the minimum over
    // the candidates, not the first candidate that matches, or a body would run
    // on into the next function and the assertions below would stop being about
    // the function they name.
    let end = ["\n#[no_mangle]", "\nfn ", "\npub ", "\n/// ", "\nconst "]
        .iter()
        .filter_map(|pat| rest[1..].find(pat).map(|i| i + 1))
        .min()
        .unwrap_or(rest.len());
    &rest[..end]
}

/// The claim the rest of this file rests on: the firmware does not have its own
/// copy of the assembly any more, it calls the proved one. Asserted against the
/// firmware's own source, so it cannot rot into a comment.
///
/// **Both** N657 folds are checked. `fold_block_from_flash` is the
/// side-effect-free probe (`authenticated_version_at`, which drives A/B slot
/// selection and post-update re-verification); `update_chain` is the REAL
/// create-path fold, and it is the one whose measurement decides whether an
/// enclave runs. A claim that "the shipping firmware executes the proved
/// function" is worth nothing if only the probe does.
#[test]
fn the_firmware_calls_the_proved_assembly() {
    for (sig, call) in [
        ("fn fold_block_from_flash(", "block_preimage_of_block(blk, &block)"),
        ("fn update_chain(", "block_preimage_of_block(block_idx, &block)"),
    ] {
        let body = firmware_fn_body(sig);
        assert!(
            body.contains(call),
            "`{sig}` no longer calls the proved assembly:\n{body}"
        );
        // and it must not have grown one back: both old inline bodies wrote the
        // block index and the two halves straight into the 292-byte buffer.
        assert!(
            !body.contains("verify_buf[..4].copy_from_slice")
                && !body.contains("verify_buf[0] =")
                && !body.contains("verify_buf[4 + i]")
                && !body.contains("verify_buf[4 + CODE_BLOCK_SIZE"),
            "`{sig}` assembles the preimage inline again:\n{body}"
        );
        // the MMIO half must still be there — that is the part this file
        // transcribes, and the part no theorem reaches
        assert_eq!(
            body.matches("core::ptr::read_volatile").count(),
            2,
            "`{sig}` no longer has exactly the two volatile read loops:\n{body}"
        );
        // AND the two loops must write where the crate expects to read.
        //
        // This is not belt-and-braces. Swapping only the DESTINATION offsets —
        // code into `block[0..256]`, meta into `block[256..288]`, constants
        // untouched, still exactly two volatile reads, still calling the proved
        // function — inverts the two halves of every preimage and would reject
        // every already-signed enclave on hardware. Every other assertion in
        // this file survives that mutation, including
        // `the_replica_block_is_the_blobs_block`, because the replica is a
        // transcription and does not execute the firmware's own arithmetic.
        // A structural check on the firmware source is the only thing here that
        // can see it.
        assert!(
            body.contains("block[BLOCK_HEADER_SIZE as usize + i] = core::ptr::read_volatile"),
            "`{sig}`'s code loop no longer writes to block[BLOCK_HEADER_SIZE + i] \
             — the crate reads the code half from block[32..288]:\n{body}"
        );
        assert!(
            body.contains("block[BLOCK_META_OFFSET as usize + j] = core::ptr::read_volatile"),
            "`{sig}`'s meta loop no longer writes to block[BLOCK_META_OFFSET + j] \
             — the crate reads the meta half from block[0..32]:\n{body}"
        );
    }
}

#[test]
fn the_firmware_still_uses_the_configuration_we_transcribed() {
    // 1. The default feature set is still the one the transcription assumes.
    let default_line = N657_BOOT_CARGO_TOML
        .lines()
        .find(|l| l.trim_start().starts_with("default = ["))
        .expect("umbra-n657-boot must declare a default feature list");
    assert!(
        default_line.contains("chained_measurement"),
        "N657 default features no longer include chained_measurement: {default_line}"
    );
    assert!(
        !default_line.contains("ess_miss_recovery"),
        "N657 default features now include ess_miss_recovery, which moves \
         BLOCK_META_OFFSET to 32 and the stride to 320: {default_line}"
    );

    // 2. The block-layout constants of that arm are still what we transcribed.
    //    `secure_kernel.rs` declares CODE_BLOCK_SIZE/BLOCK_META_SIZE once, and
    //    BLOCK_META_OFFSET/BLOCK_HEADER_SIZE three times behind cfgs; we check
    //    the unconditional two directly and the cfg arm by its guard line.
    let want_unconditional = [
        ("pub const CODE_BLOCK_SIZE: u32 = ", CODE_BLOCK_SIZE),
        ("pub const BLOCK_META_SIZE: u32 = ", BLOCK_META_SIZE),
    ];
    for (decl, expected) in want_unconditional {
        let line = N657_SECURE_KERNEL_RS
            .lines()
            .find(|l| l.trim_start().starts_with(decl))
            .unwrap_or_else(|| panic!("secure_kernel.rs no longer declares `{decl}`"));
        let value: usize = line
            .trim_end_matches(';')
            .rsplit(' ')
            .next()
            .and_then(|v| v.trim_end_matches(';').parse().ok())
            .unwrap_or_else(|| panic!("cannot parse `{line}`"));
        assert_eq!(value, expected, "firmware constant drifted: {line}");
    }

    // The chained_measurement arm: the two constants immediately following its
    // cfg guard must still be 0 and 32.
    let guard =
        "#[cfg(all(feature = \"chained_measurement\", not(feature = \"ess_miss_recovery\")))]";
    let arm: Vec<&str> = N657_SECURE_KERNEL_RS
        .lines()
        .skip_while(|l| l.trim() != guard)
        .take(4)
        .collect();
    assert!(
        !arm.is_empty(),
        "secure_kernel.rs no longer has the chained_measurement cfg arm we transcribed"
    );
    let arm_text = arm.join("\n");
    assert!(
        arm_text.contains("BLOCK_META_OFFSET: u32 = 0"),
        "chained_measurement BLOCK_META_OFFSET is no longer 0:\n{arm_text}"
    );
    assert!(
        arm_text.contains("BLOCK_HEADER_SIZE: u32 = 32"),
        "chained_measurement BLOCK_HEADER_SIZE is no longer 32:\n{arm_text}"
    );

    // 3. And the stride the crate hardcodes follows from those.
    assert_eq!(BLOCK_LEN, CODE_BLOCK_SIZE + BLOCK_HEADER_SIZE);
}

#[test]
fn the_crates_constants_are_the_firmwares() {
    assert_eq!(HDR_LEN, UMBRA_HEADER_SIZE);
    assert_eq!(CODE_LEN, CODE_BLOCK_SIZE);
    assert_eq!(META_LEN, BLOCK_META_SIZE);
    assert_eq!(BLOCK_LEN, TOTAL_BLOCK_SIZE);
    assert_eq!(BLOCK_PREIMAGE_LEN, 4 + CODE_BLOCK_SIZE + BLOCK_META_SIZE);
    assert_eq!(MAX_BLOCKS as usize, MAX_EFBS);
    assert_eq!(HDR_HMAC_OFF, 16);
    assert_eq!(CODE_SIZE_OFF, 10);
}

#[test]
fn crate_preimage_matches_the_firmware_replica() {
    let blob = make_blob(5);
    for blk in 0..5u32 {
        let a = block_preimage(&blob, blk).expect("in range");
        let b = firmware_replica_preimage(&blob, blk);
        assert_eq!(a, b, "preimage drift at block {blk}");
    }
}

#[test]
fn the_replica_block_is_the_blobs_block() {
    // THE REMAINING DIFFERENTIAL. The assembly is shared now, so the only thing
    // that can differ between the firmware and the crate is where the firmware's
    // pointer arithmetic lands. `block_preimage` materialises
    // `blob[48 + 288*blk, +288)`; the replica walks the firmware's `block_base`,
    // `code_src` and `meta_src`. Those two must be the same 288 bytes, in the
    // same order, for every block.
    let blob = make_blob(6);
    for blk in 0..6u32 {
        let replica = firmware_replica_block(&blob, blk);
        let base = HDR_LEN + (blk as usize) * BLOCK_LEN;
        assert_eq!(
            &replica[..],
            &blob[base..base + BLOCK_LEN],
            "the firmware's offsets do not land on blob[{base}, {}) at block {blk}",
            base + BLOCK_LEN
        );
    }
}

#[test]
fn crate_verdict_matches_the_firmware_replica_on_tampering() {
    let base = make_blob(3);
    // the honest blob
    assert!(verify_blob_chain(&MockHmac, &MASTER, &base));
    assert!(firmware_replica_accept(&MockHmac, &MASTER, &base));
    // every single-byte flip in the whole blob: the two must agree, verdict for
    // verdict, whether they accept or reject
    for off in 0..base.len() {
        let mut blob = base.clone();
        blob[off] ^= 0x5A;
        let a = verify_blob_chain(&MockHmac, &MASTER, &blob);
        let b = firmware_replica_accept(&MockHmac, &MASTER, &blob);
        assert_eq!(a, b, "verdict drift at byte {off}");
    }
}

#[test]
fn the_folded_region_is_exactly_the_blocks() {
    // Every byte of blob[48, 48+288*n) matters; the header metadata outside the
    // count and the hmac window does not. This is the executable form of
    // Chain_Residual.chain_root_ignores_everything_outside_the_blocks.
    let base = make_blob(2);
    for off in HDR_LEN..base.len() {
        let mut blob = base.clone();
        blob[off] ^= 0xFF;
        assert!(
            !verify_blob_chain(&MockHmac, &MASTER, &blob),
            "folded byte {off} must matter"
        );
    }
    for off in [4usize, 5, 6, 7, 8, 9, 14, 15] {
        let mut blob = base.clone();
        blob[off] ^= 0xFF;
        assert!(
            verify_blob_chain(&MockHmac, &MASTER, &blob),
            "header byte {off} is outside the gate's view (residual R1)"
        );
    }
    // and anything appended after the blocks is invisible (residual R3 — this is
    // where the relocation table lives)
    let mut blob = base.clone();
    blob.extend_from_slice(&[0xDE; 32]);
    assert!(verify_blob_chain(&MockHmac, &MASTER, &blob));
}
