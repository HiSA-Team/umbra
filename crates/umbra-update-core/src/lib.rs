//! Verifiable secure-enclave-update logic (issue #58), carved from
//! `kernel::key_storage_server::enclave_update` verbatim. Zero unsafe; the HMAC
//! primitive is injected behind the `PkgHmac` trait so the Charon→Aeneas→Coq
//! pipeline can extract this (a closure `impl FnOnce(&[u8], &[&[u8]])` is not
//! Aeneas-extractable — vtable + slice-of-borrows).
//!
//! Package layout (little-endian):
//! ```text
//!   0   4   magic = UPDATE_MAGIC ("UUP1")
//!   4  16   nonce (must equal the last armed quote nonce)
//!  20   4   author_id
//!  24   4   version (declared; authority is the on-flash measurement)
//!  28   4   blob_len
//!  32  ..   blob  (protect_enclave.py output: 48-byte UMBR header + blocks)
//!  32+blob_len  32  pkg_tag
//! ```

#![no_std]
#![forbid(unsafe_code)]

pub const UPDATE_MAGIC: u32 = 0x3150_5555; // "UUP1"
/// Domain-separation label, v2: the preimage grew from 75 to 91 bytes when the
/// tag's blob coverage widened from `blob[16,48)` (header.hmac only) to the full
/// 48-byte UMBR header `blob[0,48)`. v1 tags must not verify under v2 and vice
/// versa, so the label version moves with the preimage layout.
pub const PKG_TAG_LABEL: &[u8] = b"umbra-update-v2"; // 15 bytes
/// pkg_tag preimage: LABEL(15) ‖ nonce(16) ‖ author(4) ‖ version(4) ‖ blob_len(4)
/// ‖ header(48) — the ENTIRE UMBR header, so no header byte is left
/// unauthenticated (trust_level, efbc_size, ess_blocks, reloc_count included).
/// The HW HMAC path flattens the parts into a buffer of exactly this size;
/// `compute_pkg_tag` builds the same buffer.
pub const PKG_PREIMAGE_LEN: usize = 91;
/// Full UMBR header length; also the tag-covered blob prefix `blob[0,HDR_LEN)`.
pub const HDR_LEN: usize = 48;
const FIXED_PREFIX: usize = 32; // magic..blob start
const MIN_BLOB: usize = HDR_LEN; // at least a UMBR header

// The Debug/PartialEq/Eq derives on this fieldless enum emit `@discriminant`
// comparison + fmt code Aeneas cannot translate, and are dead weight for the
// extracted logic (parse_and_verify returns but never compares/formats an
// error). charon-driver sets `cfg(charon)`, so strip them only for extraction —
// firmware and tests keep them. Behavior-preserving.
#[cfg_attr(not(charon), derive(Debug, PartialEq, Eq))]
pub enum UpdateError {
    Malformed,
    BadMagic,
    NonceMismatch,
    TagInvalid,
}

/// A verified update, ready to be written to the inactive slot. `blob` is a
/// byte range into the caller-owned package buffer.
pub struct VerifiedUpdate<'a> {
    pub author_id: u32,
    pub version: u32,
    pub blob: &'a [u8],
}

/// The HMAC seam. On target this is the HW HASH engine; in tests/extraction a
/// mock. Takes a single flat preimage (not a slice-of-borrows) so it extracts.
pub trait PkgHmac {
    fn hmac_pkg(&self, key: &[u8], preimage: &[u8; PKG_PREIMAGE_LEN]) -> [u8; 32];
}

/// pkg_tag preimage = LABEL ‖ nonce ‖ author_le ‖ version_le ‖ blob_len_le ‖ header.
/// `header` is the blob's full 48-byte UMBR header (`blob[0,48)`), not just its
/// hmac field — see PKG_TAG_LABEL for the v1→v2 rationale. Builds the fixed
/// preimage buffer, then HMACs it — byte-for-byte identical to the kernel's
/// `compute_pkg_tag(&[LABEL, nonce, &a, &v, &l, header])`.
pub fn compute_pkg_tag<H: PkgHmac>(
    nonce: &[u8; 16],
    author_id: u32,
    version: u32,
    blob_len: u32,
    header: &[u8; HDR_LEN],
    h: &H,
    key: &[u8],
) -> [u8; 32] {
    let mut pre = [0u8; PKG_PREIMAGE_LEN];
    pre[0..15].copy_from_slice(PKG_TAG_LABEL);
    pre[15..31].copy_from_slice(nonce);
    pre[31..35].copy_from_slice(&author_id.to_le_bytes());
    pre[35..39].copy_from_slice(&version.to_le_bytes());
    pre[39..43].copy_from_slice(&blob_len.to_le_bytes());
    pre[43..91].copy_from_slice(header);
    h.hmac_pkg(key, &pre)
}

/// Parse and authenticate a package against the currently armed `expected_nonce`.
pub fn parse_and_verify<'a, H: PkgHmac>(
    pkg: &'a [u8],
    expected_nonce: &[u8; 16],
    h: &H,
    key: &[u8],
) -> Result<VerifiedUpdate<'a>, UpdateError> {
    if pkg.len() < FIXED_PREFIX + MIN_BLOB + 32 {
        return Err(UpdateError::Malformed);
    }
    let magic = u32::from_le_bytes([pkg[0], pkg[1], pkg[2], pkg[3]]);
    if magic != UPDATE_MAGIC {
        return Err(UpdateError::BadMagic);
    }
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&pkg[4..20]);
    let author_id = u32::from_le_bytes([pkg[20], pkg[21], pkg[22], pkg[23]]);
    let version = u32::from_le_bytes([pkg[24], pkg[25], pkg[26], pkg[27]]);
    let blob_len = u32::from_le_bytes([pkg[28], pkg[29], pkg[30], pkg[31]]) as usize;

    // Bounds: blob + trailing 32-byte tag must fit exactly. Derive tag_off from
    // the trusted pkg.len() rather than the attacker-controlled blob_len, so no
    // arithmetic on adversarial input can wrap on 32-bit targets.
    // pkg.len() >= FIXED_PREFIX + MIN_BLOB + 32 was checked above, so neither
    // subtraction can underflow.
    let tag_off = pkg.len() - 32;
    if blob_len < MIN_BLOB || tag_off - FIXED_PREFIX != blob_len {
        return Err(UpdateError::Malformed);
    }
    let blob = &pkg[FIXED_PREFIX..tag_off];

    // Nonce binding (constant-time).
    if !ct_eq16(&nonce, expected_nonce) {
        return Err(UpdateError::NonceMismatch);
    }

    let mut header = [0u8; HDR_LEN];
    header.copy_from_slice(&blob[0..HDR_LEN]);
    let expect = compute_pkg_tag(&nonce, author_id, version, blob_len as u32, &header, h, key);
    let got = &pkg[tag_off..tag_off + 32];
    if !ct_eq32(&expect, got) {
        return Err(UpdateError::TagInvalid);
    }

    Ok(VerifiedUpdate { author_id, version, blob })
}

/// Pick the active slot (0 = A, 1 = B) by highest authenticated version.
/// `None` = that slot has no valid enclave. Tie → A. Both None → None.
pub fn select_active_slot(ver_a: Option<u32>, ver_b: Option<u32>) -> Option<usize> {
    match (ver_a, ver_b) {
        (None, None) => None,
        (Some(_), None) => Some(0),
        (None, Some(_)) => Some(1),
        (Some(a), Some(b)) => Some(if b > a { 1 } else { 0 }),
    }
}

fn ct_eq16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut d = 0u8;
    let mut i = 0;
    while i < 16 {
        d |= a[i] ^ b[i];
        i += 1;
    }
    d == 0
}
fn ct_eq32(a: &[u8; 32], b: &[u8]) -> bool {
    if b.len() != 32 {
        return false;
    }
    let mut d = 0u8;
    let mut i = 0;
    while i < 32 {
        d |= a[i] ^ b[i];
        i += 1;
    }
    d == 0
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
