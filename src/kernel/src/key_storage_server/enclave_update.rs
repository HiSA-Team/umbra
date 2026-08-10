//! Secure enclave update — **re-export shim over the proved leaf crate**.
//!
//! The parsing/authentication logic no longer lives here. It lives in
//! `crates/umbra-update-core` (`#![no_std]`, `#![forbid(unsafe_code)]`), which
//! is the crate the Charon→Aeneas→Coq pipeline extracts and the crate the
//! machine-checked theorems are proved about:
//!
//! - **P3 — bounds-safety**: `parse_and_verify_total` in
//!   `formal/rocq/update-core/proofs-coq/Update_Safety.v` — on ANY input bytes the
//!   extracted `parse_and_verify` never takes the Aeneas `Fail` channel (panic /
//!   out-of-bounds / arithmetic overflow).
//! - **P4 — anti-rollback**: `select_both_picks_strictly_greater` +
//!   `stale_update_not_selected` in `Update_Props.v` — slot B is activated **iff**
//!   its version strictly exceeds slot A's.
//!
//! This module exists only so the firmware call sites (`attest_imp.rs`,
//! `api_impl.rs` on the N657) keep their historical
//! `kernel::key_storage_server::enclave_update::…` paths **and** their historical
//! signatures: the kernel injects the HMAC primitive as a closure
//! `impl Fn(&[u8], &[&[u8]]) -> [u8; 32]`, which Aeneas cannot extract
//! (closure + slice-of-borrows). The crate takes a `PkgHmac` trait over a single
//! flat `[u8; PKG_PREIMAGE_LEN]` preimage instead — exactly the buffer the
//! on-target HW HMAC path (`hw_hmac_single`) builds when it flattens its parts.
//! `ClosureHmac` below is the (byte-identical) adapter between the two, pinned by
//! the `shim_matches_crate_and_legacy_paths` differential test.
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

pub use umbra_update_core::{
    select_active_slot, PkgHmac, UpdateError, VerifiedUpdate, HDR_LEN, PKG_PREIMAGE_LEN,
    PKG_TAG_LABEL, UPDATE_MAGIC,
};

/// Presents a kernel-style HMAC closure as the crate's `PkgHmac` trait.
///
/// STRUCTURALLY INFALLIBLE — there is no fallback arm. An earlier revision stored
/// the closure in a `Cell<Option<F>>` (because `PkgHmac::hmac_pkg` takes `&self`
/// and the closure was `FnOnce`) and returned an all-zero tag if the cell was
/// already empty, on the reasoning that "a zero tag never matches a real HMAC".
/// That reasoning is WRONG and the arm was FAIL-OPEN: the returned tag is compared
/// by `ct_eq32(&expect, got)` where `got` is 32 bytes taken verbatim from the
/// ATTACKER-SUPPLIED package, so an attacker who puts 32 zero bytes in the tag
/// field is ACCEPTED. It was unreachable at the time (the crate calls the seam at
/// most once) but invisible to the proofs — P3's seam premise is TOTALITY only,
/// which a zero-returning arm satisfies. The fix is to remove the possibility:
/// the adapter now holds the closure by value under an `Fn` bound, so `hmac_pkg`
/// simply calls it and no synthetic tag can ever be produced. Every call site in
/// the tree passes a plain `fn` item (`hw_hmac_single`, the test mocks), all of
/// which implement `Fn`, so no caller changes.
struct ClosureHmac<F: Fn(&[u8], &[&[u8]]) -> [u8; 32]> {
    f: F,
}

impl<F: Fn(&[u8], &[&[u8]]) -> [u8; 32]> PkgHmac for ClosureHmac<F> {
    fn hmac_pkg(&self, key: &[u8], preimage: &[u8; PKG_PREIMAGE_LEN]) -> [u8; 32] {
        // ONE part, already flat: identical bytes to the historical
        // `[LABEL, nonce, &a, &v, &l, header]` call, since the HW path
        // concatenates its parts with no separators (15+16+4+4+4+48 = 91).
        (self.f)(key, &[&preimage[..]])
    }
}

/// pkg_tag preimage = LABEL ‖ nonce ‖ author_le ‖ version_le ‖ blob_len_le ‖ header.
/// `header` is the blob's FULL 48-byte UMBR header (`blob[0,48)`) — v2 widened
/// the coverage from header.hmac alone, closing the unauthenticated-header-bytes
/// residue (trust_level, efbc_size, ess_blocks, reloc_count).
///
/// Signature-compatible wrapper; the assembly itself is
/// `umbra_update_core::compute_pkg_tag` (see `compute_pkg_tag_total`, `Qed`).
pub fn compute_pkg_tag(
    nonce: &[u8; 16],
    author_id: u32,
    version: u32,
    blob_len: u32,
    header: &[u8; HDR_LEN],
    hmac: impl Fn(&[u8], &[&[u8]]) -> [u8; 32],
    key: &[u8],
) -> [u8; 32] {
    umbra_update_core::compute_pkg_tag(
        nonce,
        author_id,
        version,
        blob_len,
        header,
        &ClosureHmac { f: hmac },
        key,
    )
}

/// Parse and authenticate a package against the currently armed `expected_nonce`.
///
/// Signature-compatible wrapper; the parsing/verification is
/// `umbra_update_core::parse_and_verify` — the function P3 proves total on
/// hostile input.
pub fn parse_and_verify<'a>(
    pkg: &'a [u8],
    expected_nonce: &[u8; 16],
    hmac: impl Fn(&[u8], &[&[u8]]) -> [u8; 32],
    key: &[u8],
) -> Result<VerifiedUpdate<'a>, UpdateError> {
    umbra_update_core::parse_and_verify(pkg, expected_nonce, &ClosureHmac { f: hmac }, key)
}

#[cfg(test)]
#[path = "enclave_update_tests.rs"]
mod tests;
