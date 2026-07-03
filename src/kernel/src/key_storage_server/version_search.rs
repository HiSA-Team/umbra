//! Derive the enclave version from the measurement and enforce anti-rollback in
//! one search. The version is NEVER stored in clear: the kernel tries candidate
//! versions starting at the per-author floor and the one that reproduces
//! `header.hmac` is the authenticated version. A rolled-back version (< floor)
//! is below the search start, so rollback is structurally unrepresentable.
//!
//! Phase 1 backs the floor with TAMP backup registers (persist across reset; NOT
//! durable vs a full power-loss without VBAT). Phase 2 swaps an OTP/BSEC fuse
//! counter behind the same `MonotonicCounter` trait.

/// Max version jump per update once the floor is provisioned.
pub const SEARCH_WINDOW: u32 = 256;
/// Wide scan when the floor is cold (0): genuine first boot OR a VBAT wipe.
pub const COLD_WINDOW: u32 = 1024;

/// Search candidate versions for the one whose tag equals `target`.
/// `tag` computes `version_tag(BM, author, v)` for a candidate `v` (the BM and
/// author are captured by the closure). Returns the authenticated version, or
/// `None` (rollback below floor / tampered / out of window).
pub fn search_version<F: FnMut(u32) -> [u8; 32]>(
    target: &[u8; 32],
    floor: u32,
    mut tag: F,
) -> Option<u32> {
    let (lo, hi) = if floor == 0 {
        (0u32, COLD_WINDOW)
    } else {
        (floor, floor.saturating_add(SEARCH_WINDOW))
    };
    let mut v = lo;
    while v <= hi {
        if ct_eq(&tag(v), target) {
            return Some(v);
        }
        v += 1;
    }
    None
}

/// Constant-time 32-byte compare.
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    let mut i = 0;
    while i < 32 {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    diff == 0
}

/// Per-author monotonic floor backed by platform secure storage.
pub trait MonotonicCounter {
    /// Highest version ever admitted for `author_id` (0 if none / wiped).
    fn floor(&self, author_id: u32) -> u32;
    /// Raise the floor to `version` (no-op if not greater). Call ONLY after the
    /// measurement (and thus the version) has been verified.
    fn bump(&mut self, author_id: u32, version: u32);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    // Fake tag: the "true version" is TRUE; only that candidate matches.
    fn fake_tag(true_v: u32) -> impl Fn(u32) -> [u8; 32] {
        move |v| {
            let mut t = [0u8; 32];
            t[..4].copy_from_slice(&v.to_le_bytes());
            if v == true_v { t[31] = 0xAA } // marker the target also has
            t
        }
    }
    fn target_for(true_v: u32) -> [u8; 32] {
        let mut t = [0u8; 32];
        t[..4].copy_from_slice(&true_v.to_le_bytes());
        t[31] = 0xAA;
        t
    }

    #[test]
    fn derives_version_at_or_above_floor() {
        assert_eq!(search_version(&target_for(5), 2, fake_tag(5)), Some(5));
    }

    #[test]
    fn rejects_rollback_below_floor() {
        assert_eq!(search_version(&target_for(1), 3, fake_tag(1)), None);
    }

    #[test]
    fn cold_floor_scans_wide() {
        assert_eq!(search_version(&target_for(900), 0, fake_tag(900)), Some(900));
    }

    #[test]
    fn out_of_window_not_found() {
        let v = 2 + SEARCH_WINDOW + 1;
        assert_eq!(search_version(&target_for(v), 2, fake_tag(v)), None);
    }
}
