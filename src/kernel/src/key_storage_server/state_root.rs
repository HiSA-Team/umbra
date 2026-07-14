//! Root-based anti-rollback for state continuity (2026-07-02 redesign). The freshness
//! truth lives entirely in the trusted anchor as a KEYED root over ALL sectors, so
//! untrusted flash is never compared version-by-version. Supersedes the version-per-
//! sector model. Pure logic; the HMAC primitive is injected (HW HASH on target,
//! mock in tests). See book/src/decisions/010-...md.

use super::state_continuity::MAX_STATE_SECTORS;

/// Byte length of the normative root preimage: 3 little-endian u32 headers
/// (`enclave_id`, `state_format_version`, `generation`) + `MAX_STATE_SECTORS`
/// 32-byte digests. Any HMAC impl that flattens the parts into ONE contiguous
/// buffer (e.g. the HW HMAC on target, which cannot stream) MUST size that buffer
/// to exactly this. Keep in lock-step with `compute_root`'s part layout and the
/// field order frozen in ADR 010 — grow both together if a field is appended.
pub const ROOT_PREIMAGE_LEN: usize = 3 * 4 + MAX_STATE_SECTORS * 32;

/// The anchor root binds the whole logical state at a generation:
/// `HMAC(K, enclave_id_le(4) ‖ state_format_version_le(4) ‖ generation_le(4) ‖ digest_0(32) ‖ … ‖ digest_{N-1}(32))`,
/// truncated to 128 bits. **The field order is NORMATIVE — it is the on-anchor format and
/// cannot change without a migration (ADR 010).**
///
/// `state_format_version` is an AUTHOR-owned tag for the SNAPSHOT LAYOUT — NOT the code
/// version. Bump it only when the serialized state layout changes, so a snapshot written
/// under an old layout recomputes a DIFFERENT root and is refused by a binary using a new
/// layout. This binds "is this state mine to interpret?" without coupling to the monotonic
/// code version (which would wipe continuity on every routine update — see ADR 010 for the
/// design rationale).
///
/// `sector_digests[i]` = an unkeyed hash (SHA-256) of sector i's committed ciphertext. A
/// replayed old-but-coherent checkpoint recomputes to a DIFFERENT root and is rejected. The
/// 128-bit width keeps the DOUBLE-BUFFERED anchor inside TAMP's backup registers left free
/// by the code-version floor; 2^-128 forgery resistance is ample for anti-rollback (the
/// attacker must forge the keyed MAC, not find a collision).
pub fn compute_root(
    key: &[u8],
    enclave_id: u32,
    state_format_version: u32,
    generation: u32,
    sector_digests: &[[u8; 32]; MAX_STATE_SECTORS],
    hmac: impl FnOnce(&[u8], &[&[u8]]) -> [u8; 32],
) -> [u8; 16] {
    let id_le = enclave_id.to_le_bytes();
    let fmt_le = state_format_version.to_le_bytes();
    let gen_le = generation.to_le_bytes();
    // NORMATIVE order (ADR 010): id ‖ format_version ‖ generation ‖ digests.
    // 3 header parts + MAX_STATE_SECTORS digest parts.
    let mut parts: [&[u8]; MAX_STATE_SECTORS + 3] = [&[]; MAX_STATE_SECTORS + 3];
    parts[0] = &id_le;
    parts[1] = &fmt_le;
    parts[2] = &gen_le;
    let mut i = 0;
    while i < MAX_STATE_SECTORS {
        parts[i + 3] = &sector_digests[i];
        i += 1;
    }
    let full = hmac(key, &parts);
    let mut root = [0u8; 16];
    root.copy_from_slice(&full[..16]);
    root
}

/// Constant-time equality of the recomputed root against the trusted anchor root.
/// (Compares all 16 bytes regardless of where they differ — no early return.)
pub fn root_matches(anchor_root: &[u8; 16], recomputed: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    let mut i = 0;
    while i < 16 {
        diff |= anchor_root[i] ^ recomputed[i];
        i += 1;
    }
    diff == 0
}

#[cfg(test)]
#[path = "state_root_tests.rs"]
mod tests;
