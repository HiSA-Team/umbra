//! Secure enclave-update package: parse + authenticate a nonce-bound update, and
//! choose the active enclave slot by authenticated version. Pure logic; the HMAC
//! primitive is injected. The package tag authenticates the BINDING (nonce ‖ ids ‖
//! header.hmac), not the whole blob — the blob's integrity is re-established by the
//! measurement chain when the enclave is created from flash. See the design spec.
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

pub const UPDATE_MAGIC: u32 = 0x3150_5555; // "UUP1"
pub const PKG_TAG_LABEL: &[u8] = b"umbra-update-v1"; // 15 bytes
/// Total pkg_tag preimage length: LABEL(15), nonce(16), author(4), version(4),
/// blob_len(4), header.hmac(32). The on-target HW HMAC path flattens the parts
/// into a fixed buffer of exactly this size (cf. `state_root::ROOT_PREIMAGE_LEN`);
/// keep it in lock-step with `compute_pkg_tag`, guarded by the
/// `preimage_len_fits_all_parts` test.
pub const PKG_PREIMAGE_LEN: usize = 75;
const HDR_HMAC_OFF: usize = 16; // UMBR header.hmac offset within the blob
const HDR_HMAC_LEN: usize = 32;
const FIXED_PREFIX: usize = 32; // magic..blob start
const MIN_BLOB: usize = 48; // at least a UMBR header

#[derive(Debug, PartialEq, Eq)]
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

/// pkg_tag preimage = LABEL ‖ nonce ‖ author_le ‖ version_le ‖ blob_len_le ‖ header.hmac.
pub fn compute_pkg_tag(
    nonce: &[u8; 16],
    author_id: u32,
    version: u32,
    blob_len: u32,
    header_hmac: &[u8; 32],
    hmac: impl FnOnce(&[u8], &[&[u8]]) -> [u8; 32],
    key: &[u8],
) -> [u8; 32] {
    let a = author_id.to_le_bytes();
    let v = version.to_le_bytes();
    let l = blob_len.to_le_bytes();
    hmac(key, &[PKG_TAG_LABEL, nonce, &a, &v, &l, header_hmac])
}

/// Parse and authenticate a package against the currently armed `expected_nonce`.
pub fn parse_and_verify<'a>(
    pkg: &'a [u8],
    expected_nonce: &[u8; 16],
    hmac: impl FnOnce(&[u8], &[&[u8]]) -> [u8; 32],
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

    let mut header_hmac = [0u8; 32];
    header_hmac.copy_from_slice(&blob[HDR_HMAC_OFF..HDR_HMAC_OFF + HDR_HMAC_LEN]);
    let expect = compute_pkg_tag(&nonce, author_id, version, blob_len as u32, &header_hmac, hmac, key);
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
    while i < 16 { d |= a[i] ^ b[i]; i += 1; }
    d == 0
}
fn ct_eq32(a: &[u8; 32], b: &[u8]) -> bool {
    if b.len() != 32 { return false; }
    let mut d = 0u8;
    let mut i = 0;
    while i < 32 { d |= a[i] ^ b[i]; i += 1; }
    d == 0
}

#[cfg(test)]
#[path = "enclave_update_tests.rs"]
mod tests;
