//! Pure orchestration of the root-in-anchor checkpoint/restore (2026-07-02 redesign).
//! Flash is UNTRUSTED; freshness+integrity are a keyed root in the trusted anchor.
//! A checkpoint stages dirty sectors then commits ONE anchor {generation, root, parity};
//! restore recomputes the root over the committed slots and compares. Crash before the
//! anchor commit leaves the old anchor (old parity+root) → last-good. Flash/anchor are
//! injected as traits (real impls wrap drivers::state_flash / state_anchor; mocked in
//! tests). See book/src/decisions/010-...md.

use super::state_continuity::MAX_STATE_SECTORS;
use super::state_root::{compute_root, root_matches};

/// The trusted anchor: monotonic generation, keyed root over the whole logical state,
/// and one committed-slot parity bit per sector.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Anchor {
    pub generation: u32,
    pub root: [u8; 16],
    pub parity: u16,
}

/// A/B flash sector store (untrusted). `stage` writes the pending ciphertext of sector
/// `idx` into `slot`; `read_digest` returns an unkeyed digest of what is in (idx, slot).
pub trait SectorStore {
    fn stage(&mut self, idx: usize, slot: usize) -> Result<(), ()>;
    fn read_digest(&self, idx: usize, slot: usize) -> [u8; 32];
}

/// Trusted anchor store (real impl double-buffers over TAMP for atomic commit).
pub trait AnchorStore {
    fn load(&self) -> Option<Anchor>;
    fn store(&mut self, a: &Anchor);
}

#[derive(Debug, PartialEq, Eq)]
pub enum CheckpointError {
    /// Flash stage failed for sector `idx`; the anchor was NOT advanced (last-good stands).
    FlashWrite(usize),
}

#[derive(Debug, PartialEq, Eq)]
pub enum RestoreDecision {
    /// Recomputed root == anchor root → authentic and current → resume.
    Resume,
    /// No anchor / generation 0 (cold boot / POR) → trust flash as new baseline
    /// (COLD_WINDOW fail-open; warm-reset threat model, ADR 009).
    ColdGenesis,
    /// Recomputed root != anchor root (rollback / replay / tamper) → refuse to resume.
    Reject,
}

/// Gather the digests of the currently-committed slot of every sector (slot = parity bit).
fn committed_digests<S: SectorStore>(store: &S, parity: u16) -> [[u8; 32]; MAX_STATE_SECTORS] {
    let mut d = [[0u8; 32]; MAX_STATE_SECTORS];
    let mut i = 0;
    while i < MAX_STATE_SECTORS {
        let slot = ((parity >> i) & 1) as usize;
        d[i] = store.read_digest(i, slot);
        i += 1;
    }
    d
}

/// Checkpoint: stage each dirty sector into its STAGING slot (opposite its committed
/// parity) and flip that sector's parity bit; then recompute the root over the new
/// committed state and commit a single new anchor. A stage failure aborts WITHOUT
/// advancing the anchor.
pub fn checkpoint<S: SectorStore, A: AnchorStore>(
    store: &mut S,
    anchor: &mut A,
    dirty: u16,
    key: &[u8],
    enclave_id: u32,
    hmac: impl FnOnce(&[u8], &[&[u8]]) -> [u8; 32],
) -> Result<(), CheckpointError> {
    let (gen, parity) = match anchor.load() {
        Some(a) => (a.generation, a.parity),
        None => (0, 0),
    };
    let mut new_parity = parity;
    let mut i = 0;
    while i < MAX_STATE_SECTORS {
        if (dirty >> i) & 1 == 1 {
            let committed = ((parity >> i) & 1) as usize;
            let staging = committed ^ 1;
            store.stage(i, staging).map_err(|_| CheckpointError::FlashWrite(i))?;
            new_parity ^= 1 << i; // sector i's committed slot is now the staging slot
        }
        i += 1;
    }
    let new_gen = gen.wrapping_add(1);
    let digests = committed_digests(store, new_parity);
    let root = compute_root(key, enclave_id, new_gen, &digests, hmac);
    anchor.store(&Anchor { generation: new_gen, root, parity: new_parity });
    Ok(())
}

/// Restore: recompute the root over the anchor's committed slots and compare.
pub fn restore<S: SectorStore, A: AnchorStore>(
    store: &S,
    anchor: &A,
    key: &[u8],
    enclave_id: u32,
    hmac: impl FnOnce(&[u8], &[&[u8]]) -> [u8; 32],
) -> RestoreDecision {
    let a = match anchor.load() {
        Some(a) if a.generation != 0 => a,
        _ => return RestoreDecision::ColdGenesis,
    };
    let digests = committed_digests(store, a.parity);
    let recomputed = compute_root(key, enclave_id, a.generation, &digests, hmac);
    if root_matches(&a.root, &recomputed) {
        RestoreDecision::Resume
    } else {
        RestoreDecision::Reject
    }
}

#[cfg(test)]
#[path = "state_checkpoint_tests.rs"]
mod tests;
