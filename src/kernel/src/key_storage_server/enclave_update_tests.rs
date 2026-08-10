extern crate std;
use super::*;
use std::vec::Vec;

fn mock_hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut acc: [u8; 32] = [0; 32];
    let mut n: usize = 0;
    for &b in key { acc[n % 32] = acc[n % 32].wrapping_add(b).wrapping_add(1); n += 1; }
    for p in parts { for &b in *p { acc[n % 32] = acc[n % 32].wrapping_add(b).wrapping_add(2); n += 1; } }
    acc
}

// Capture the flattened preimage compute_pkg_tag hands the HMAC, in order.
fn capture_preimage(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let _ = key;
    // Stash the concatenation in a thread-local so the test can assert the byte order.
    let mut flat = Vec::new();
    for p in parts {
        flat.extend_from_slice(p);
    }
    PREIMAGE.with(|c| *c.borrow_mut() = flat);
    [0u8; 32]
}

std::thread_local! {
    static PREIMAGE: core::cell::RefCell<Vec<u8>> = const { core::cell::RefCell::new(Vec::new()) };
}

/// Pin the pkg_tag preimage BYTE ORDER against a hand-built literal — the same order
/// tools/test_attestation_guard.py and tools/attest_update.py build. A field reorder in
/// compute_pkg_tag that kept the length would pass the round-trip tests but silently
/// break Python↔Rust parity; this catches it. Mirror of attestation.rs's golden preimage.
#[test]
fn pkg_tag_preimage_order_matches_python() {
    let nonce = [0x22u8; 16];
    let header: [u8; HDR_LEN] = core::array::from_fn(|i| i as u8); // 0..=47
    let author = 0x0A0B_0C0Du32;
    let version = 0x1112_1314u32;
    let blob_len = 336u32;
    compute_pkg_tag(&nonce, author, version, blob_len, &header, capture_preimage, &[0u8; 32]);

    // Expected: LABEL(15) ‖ nonce(16) ‖ author_le(4) ‖ version_le(4) ‖ blob_len_le(4) ‖ header(48)
    let mut expected = Vec::new();
    expected.extend_from_slice(PKG_TAG_LABEL);
    expected.extend_from_slice(&nonce);
    expected.extend_from_slice(&author.to_le_bytes());
    expected.extend_from_slice(&version.to_le_bytes());
    expected.extend_from_slice(&blob_len.to_le_bytes());
    expected.extend_from_slice(&header);
    assert_eq!(expected.len(), PKG_PREIMAGE_LEN);

    PREIMAGE.with(|c| assert_eq!(*c.borrow(), expected));
}

// Build a well-formed package: the tag covers the full 48-byte header blob[0,48).
fn make_pkg(nonce: [u8; 16], author: u32, version: u32, blob: &[u8], key: &[u8]) -> Vec<u8> {
    let mut header = [0u8; HDR_LEN];
    header.copy_from_slice(&blob[0..HDR_LEN]);
    let tag = compute_pkg_tag(&nonce, author, version, blob.len() as u32, &header,
        mock_hmac, key);
    let mut pkg = Vec::new();
    pkg.extend_from_slice(&UPDATE_MAGIC.to_le_bytes());
    pkg.extend_from_slice(&nonce);
    pkg.extend_from_slice(&author.to_le_bytes());
    pkg.extend_from_slice(&version.to_le_bytes());
    pkg.extend_from_slice(&(blob.len() as u32).to_le_bytes());
    pkg.extend_from_slice(blob);
    pkg.extend_from_slice(&tag);
    pkg
}

fn dummy_blob() -> Vec<u8> {
    // 48-byte UMBR header + one 288-byte block = 336 bytes; header at [0..48).
    let mut b = std::vec![0u8; 336];
    for i in 0..48 { b[i] = i as u8; }
    b
}

#[test]
fn accepts_matching_nonce_and_tag() {
    let key = [0x5A; 32];
    let nonce = [0x22; 16];
    let blob = dummy_blob();
    let pkg = make_pkg(nonce, 1, 3, &blob, &key);
    let r = parse_and_verify(&pkg, &nonce, mock_hmac, &key);
    assert!(matches!(r, Ok(ref u) if u.version == 3 && u.author_id == 1 && u.blob == &blob[..]));
}

#[test]
fn rejects_wrong_nonce() {
    let key = [0x5A; 32];
    let nonce = [0x22; 16];
    let blob = dummy_blob();
    let pkg = make_pkg(nonce, 1, 3, &blob, &key);
    let mut expected = nonce; expected[0] ^= 1;
    let r = parse_and_verify(&pkg, &expected, mock_hmac, &key);
    assert_eq!(r.err(), Some(UpdateError::NonceMismatch));
}

#[test]
fn rejects_tampered_tag() {
    let key = [0x5A; 32];
    let nonce = [0x22; 16];
    let blob = dummy_blob();
    let mut pkg = make_pkg(nonce, 1, 3, &blob, &key);
    let last = pkg.len() - 1;
    pkg[last] ^= 0xFF;
    let r = parse_and_verify(&pkg, &nonce, mock_hmac, &key);
    assert_eq!(r.err(), Some(UpdateError::TagInvalid));
}

#[test]
fn rejects_truncated_package() {
    let key = [0x5A; 32];
    let nonce = [0x22; 16];
    let r = parse_and_verify(&[0u8; 8], &nonce, mock_hmac, &key);
    assert_eq!(r.err(), Some(UpdateError::Malformed));
}

#[test]
fn selects_higher_authenticated_version() {
    // slot A version 2, slot B version 5 -> pick B; tie -> A.
    assert_eq!(select_active_slot(Some(2), Some(5)), Some(1));
    assert_eq!(select_active_slot(Some(5), Some(2)), Some(0));
    assert_eq!(select_active_slot(Some(3), Some(3)), Some(0));
    assert_eq!(select_active_slot(Some(2), None), Some(0));
    assert_eq!(select_active_slot(None, Some(4)), Some(1));
    assert_eq!(select_active_slot(None, None), None);
}

#[test]
fn rejects_bad_magic() {
    let key = [0x5A; 32];
    let nonce = [0x22; 16];
    let blob = dummy_blob();
    let mut pkg = make_pkg(nonce, 1, 3, &blob, &key);
    pkg[0] ^= 0xFF;
    let r = parse_and_verify(&pkg, &nonce, mock_hmac, &key);
    assert_eq!(r.err(), Some(UpdateError::BadMagic));
}

#[test]
fn rejects_swapped_author_version() {
    // Distinct values so a field swap is observable.
    let key = [0x5A; 32];
    let nonce = [0x22; 16];
    let blob = dummy_blob();
    let author = 0x0A0B0C0D_u32;
    let version = 0x1112_1314_u32;
    let mut pkg = make_pkg(nonce, author, version, &blob, &key);
    // author field is at offset 20..24, version at 24..28.
    let mut author_bytes = [0u8; 4];
    author_bytes.copy_from_slice(&pkg[20..24]);
    let mut version_bytes = [0u8; 4];
    version_bytes.copy_from_slice(&pkg[24..28]);
    pkg[20..24].copy_from_slice(&version_bytes);
    pkg[24..28].copy_from_slice(&author_bytes);
    let r = parse_and_verify(&pkg, &nonce, mock_hmac, &key);
    assert_eq!(r.err(), Some(UpdateError::TagInvalid));
}

#[test]
fn rejects_wrong_blob_len_field() {
    let key = [0x5A; 32];
    let nonce = [0x22; 16];
    let blob = dummy_blob();
    let mut pkg = make_pkg(nonce, 0x0A0B0C0D, 0x1112_1314, &blob, &key);
    // blob_len field is at offset 28..32; corrupt it without recomputing the tag.
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&pkg[28..32]);
    let len_val = u32::from_le_bytes(len_bytes) + 1;
    pkg[28..32].copy_from_slice(&len_val.to_le_bytes());
    let r = parse_and_verify(&pkg, &nonce, mock_hmac, &key);
    assert_eq!(r.err(), Some(UpdateError::Malformed));
}

#[test]
fn rejects_blob_below_min() {
    // Fully coherent package (lengths consistent, tag computed normally) whose
    // blob is shorter than a UMBR header — the MIN_BLOB constraint must be the
    // deciding condition (everything else about the package is well-formed).
    let key = [0x5A; 32];
    let nonce = [0x22; 16];
    let mut blob = std::vec![0u8; 40];
    for i in 16..40 { blob[i] = i as u8; }
    // make_pkg reads the header from blob[0..48]; build the package by hand
    // since the blob is too short for that helper.
    let mut header = [0u8; HDR_LEN];
    header[..40].copy_from_slice(&blob[..40]);
    let tag = compute_pkg_tag(&nonce, 0x0A0B0C0D, 0x1112_1314, blob.len() as u32,
        &header, mock_hmac, &key);
    let mut pkg = Vec::new();
    pkg.extend_from_slice(&UPDATE_MAGIC.to_le_bytes());
    pkg.extend_from_slice(&nonce);
    pkg.extend_from_slice(&0x0A0B0C0D_u32.to_le_bytes());
    pkg.extend_from_slice(&0x1112_1314_u32.to_le_bytes());
    pkg.extend_from_slice(&(blob.len() as u32).to_le_bytes());
    pkg.extend_from_slice(&blob);
    pkg.extend_from_slice(&tag);
    let r = parse_and_verify(&pkg, &nonce, mock_hmac, &key);
    assert_eq!(r.err(), Some(UpdateError::Malformed));
}

#[test]
fn huge_blob_len_is_malformed_not_panic() {
    // A near-usize::MAX blob_len must be rejected as Malformed with no
    // arithmetic panic (guards the 32-bit tag_off overflow class).
    let key = [0x5A; 32];
    let nonce = [0x22; 16];
    let blob = dummy_blob();
    let mut pkg = make_pkg(nonce, 0x0A0B0C0D, 0x1112_1314, &blob, &key);
    pkg[28..32].copy_from_slice(&0xFFFF_FFC0_u32.to_le_bytes());
    let r = parse_and_verify(&pkg, &nonce, mock_hmac, &key);
    assert_eq!(r.err(), Some(UpdateError::Malformed));
}

/// DIFFERENTIAL KAT for the closure→`PkgHmac` shim (the wiring that makes the
/// firmware execute the Coq-proved `umbra-update-core` code).
///
/// Three paths must agree byte-for-byte on the same package:
///   (a) LEGACY — the pre-shim kernel semantics: the HMAC closure handed the SIX
///       separate parts `[LABEL, nonce, author_le, version_le, blob_len_le, hdr]`;
///   (b) SHIM — today's `kernel::…::enclave_update`, whose adapter hands the
///       closure ONE flat 91-byte preimage;
///   (c) CRATE — `umbra_update_core` called directly through a `PkgHmac` impl.
///
/// (a) == (b) is the claim that the seam refactor was behavior-preserving on the
/// on-target `hw_hmac_single` path (which concatenates its parts with no
/// separators); (b) == (c) is the claim that the shim adds nothing. The same
/// three-way equality is then checked end-to-end through `parse_and_verify`.
#[test]
fn shim_matches_crate_and_legacy_paths() {
    struct DirectHmac;
    impl umbra_update_core::PkgHmac for DirectHmac {
        fn hmac_pkg(&self, key: &[u8], pre: &[u8; PKG_PREIMAGE_LEN]) -> [u8; 32] {
            mock_hmac(key, &[&pre[..]])
        }
    }

    let key = [0x5A; 32];
    let nonce = [0x22u8; 16];
    let header: [u8; HDR_LEN] = core::array::from_fn(|i| i as u8);
    let author = 0x0A0B_0C0Du32;
    let version = 0x1112_1314u32;
    let blob_len = 336u32;

    // (a) legacy six-part call, spelled out exactly as the old kernel body did.
    let legacy = mock_hmac(
        &key,
        &[
            PKG_TAG_LABEL,
            &nonce,
            &author.to_le_bytes(),
            &version.to_le_bytes(),
            &blob_len.to_le_bytes(),
            &header,
        ],
    );
    // (b) through the shim (closure adapter -> crate).
    let via_shim =
        compute_pkg_tag(&nonce, author, version, blob_len, &header, mock_hmac, &key);
    // (c) straight into the proved crate.
    let via_crate = umbra_update_core::compute_pkg_tag(
        &nonce,
        author,
        version,
        blob_len,
        &header,
        &DirectHmac,
        &key,
    );
    assert_eq!(legacy, via_shim, "shim changed the pkg_tag preimage bytes");
    assert_eq!(via_shim, via_crate, "shim disagrees with the proved crate");

    // End-to-end: same package accepted, same fields, on both paths.
    let blob = dummy_blob();
    let pkg = make_pkg(nonce, author, version, &blob, &key);
    let shim_out = parse_and_verify(&pkg, &nonce, mock_hmac, &key).expect("shim must accept");
    let crate_out = umbra_update_core::parse_and_verify(&pkg, &nonce, &DirectHmac, &key)
        .unwrap_or_else(|_| panic!("crate must accept"));
    assert_eq!(shim_out.author_id, crate_out.author_id);
    assert_eq!(shim_out.version, crate_out.version);
    assert_eq!(shim_out.blob, crate_out.blob);
    assert_eq!(shim_out.blob, &blob[..]);
}

/// REGRESSION — "fail closed with a zero tag" is FAIL-OPEN.
///
/// Two sites in this tree used to return `[0u8; 32]` on an internal seam failure,
/// commented "a zero tag will never match a real HMAC". That reasoning is wrong:
/// `expect` is compared by `ct_eq32(&expect, got)` where `got` is 32 bytes taken
/// verbatim from the ATTACKER-SUPPLIED package. An attacker who writes the same
/// constant into the tag field is therefore ACCEPTED. This test demonstrates the
/// acceptance concretely, so any future reintroduction of a constant-tag fallback
/// arm is visibly unsound rather than plausible-looking.
///
/// It also pins the shape of the fix: the seam must never SYNTHESISE a tag. The
/// adapter in this module is now structurally infallible (closure held by value
/// under an `Fn` bound, no `Option`, no fallback arm), and `hw_hmac_single` on the
/// N657 returns a *keyed* poison rather than a constant.
#[test]
fn constant_tag_seam_accepts_an_attacker_chosen_tag() {
    fn zero_hmac(_key: &[u8], _parts: &[&[u8]]) -> [u8; 32] {
        [0u8; 32]
    }
    let nonce = [0x22u8; 16];
    let blob = dummy_blob();
    // Same framing as make_pkg, but the tag field is the attacker's choice: zeros.
    let mut pkg = Vec::new();
    pkg.extend_from_slice(&UPDATE_MAGIC.to_le_bytes());
    pkg.extend_from_slice(&nonce);
    pkg.extend_from_slice(&1u32.to_le_bytes());
    pkg.extend_from_slice(&3u32.to_le_bytes());
    pkg.extend_from_slice(&(blob.len() as u32).to_le_bytes());
    pkg.extend_from_slice(&blob);
    pkg.extend_from_slice(&[0u8; 32]); // attacker-chosen tag

    let r = parse_and_verify(&pkg, &nonce, zero_hmac, &[0x5A; 32]);
    assert!(
        r.is_ok(),
        "a constant-returning seam MUST be understood as fail-OPEN: the attacker \
         simply echoes the constant in the tag field. If this ever stops being \
         true, the reasoning that justified the old zero-tag arms changed — \
         re-derive it before relying on it."
    );
}

/// The closure adapter must never fabricate a tag: every `PkgHmac::hmac_pkg`
/// invocation has to reach the caller's closure. Counting the invocations pins
/// both halves — exactly one seam call per accepted verification, and no
/// synthetic/duplicate call that a fallback arm would have served.
#[test]
fn adapter_never_fabricates_a_tag() {
    use core::cell::Cell;
    std::thread_local! {
        static CALLS: Cell<u32> = const { Cell::new(0) };
    }
    fn counting_hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        CALLS.with(|c| c.set(c.get() + 1));
        assert_eq!(parts.len(), 1, "the adapter hands exactly one flat preimage");
        assert_eq!(parts[0].len(), PKG_PREIMAGE_LEN);
        mock_hmac(key, parts)
    }

    let key = [0x5A; 32];
    let nonce = [0x22; 16];
    let blob = dummy_blob();
    let pkg = make_pkg(nonce, 1, 3, &blob, &key);

    CALLS.with(|c| c.set(0));
    let r = parse_and_verify(&pkg, &nonce, counting_hmac, &key);
    assert!(r.is_ok());
    assert_eq!(CALLS.with(|c| c.get()), 1, "seam called exactly once, by the real closure");

    // A rejected package must not call the seam more than once either.
    CALLS.with(|c| c.set(0));
    let mut bad = pkg.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0xFF;
    assert_eq!(parse_and_verify(&bad, &nonce, counting_hmac, &key).err(), Some(UpdateError::TagInvalid));
    assert_eq!(CALLS.with(|c| c.get()), 1);
}

#[test]
fn preimage_len_fits_all_parts() {
    // A flattening HMAC sized to PKG_PREIMAGE_LEN must hold EVERY part
    // compute_pkg_tag emits, with no slack. Guards the fixed HW HMAC buffer
    // against preimage drift (cf. state_root::preimage_len_fits_all_parts).
    fn flatten_hmac(_key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        let mut buf = [0u8; PKG_PREIMAGE_LEN];
        let mut n = 0;
        for p in parts {
            buf[n..n + p.len()].copy_from_slice(p); // panics if the buffer is too small
            n += p.len();
        }
        assert_eq!(n, PKG_PREIMAGE_LEN, "preimage bytes must equal PKG_PREIMAGE_LEN");
        [0u8; 32]
    }
    let nonce = [0x22; 16];
    let header = [0x33; HDR_LEN];
    let _ = compute_pkg_tag(&nonce, 0x0A0B0C0D, 0x1112_1314, 336, &header,
        flatten_hmac, &[0x5A; 32]);
}
