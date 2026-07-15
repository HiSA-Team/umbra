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
    let header_hmac: [u8; 32] = core::array::from_fn(|i| (16 + i) as u8); // 16..=47
    let author = 0x0A0B_0C0Du32;
    let version = 0x1112_1314u32;
    let blob_len = 336u32;
    compute_pkg_tag(&nonce, author, version, blob_len, &header_hmac, capture_preimage, &[0u8; 32]);

    // Expected: LABEL(15) ‖ nonce(16) ‖ author_le(4) ‖ version_le(4) ‖ blob_len_le(4) ‖ header_hmac(32)
    let mut expected = Vec::new();
    expected.extend_from_slice(PKG_TAG_LABEL);
    expected.extend_from_slice(&nonce);
    expected.extend_from_slice(&author.to_le_bytes());
    expected.extend_from_slice(&version.to_le_bytes());
    expected.extend_from_slice(&blob_len.to_le_bytes());
    expected.extend_from_slice(&header_hmac);
    assert_eq!(expected.len(), PKG_PREIMAGE_LEN);

    PREIMAGE.with(|c| assert_eq!(*c.borrow(), expected));
}

// Build a well-formed package: header.hmac lives at blob offset 16 (32 bytes).
fn make_pkg(nonce: [u8; 16], author: u32, version: u32, blob: &[u8], key: &[u8]) -> Vec<u8> {
    let mut header_hmac = [0u8; 32];
    header_hmac.copy_from_slice(&blob[16..48]);
    let tag = compute_pkg_tag(&nonce, author, version, blob.len() as u32, &header_hmac,
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
    // 48-byte UMBR header + one 288-byte block = 336 bytes; header.hmac at [16..48].
    let mut b = std::vec![0u8; 336];
    for i in 16..48 { b[i] = i as u8; }
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
    // make_pkg reads header.hmac from blob[16..48]; build the package by hand
    // since the blob is too short for that helper.
    let mut header_hmac = [0u8; 32];
    header_hmac[..24].copy_from_slice(&blob[16..40]);
    let tag = compute_pkg_tag(&nonce, 0x0A0B0C0D, 0x1112_1314, blob.len() as u32,
        &header_hmac, mock_hmac, &key);
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
    let header_hmac = [0x33; 32];
    let _ = compute_pkg_tag(&nonce, 0x0A0B0C0D, 0x1112_1314, 336, &header_hmac,
        flatten_hmac, &[0x5A; 32]);
}
