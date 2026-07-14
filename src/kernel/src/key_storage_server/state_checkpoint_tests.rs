use super::*;

const N: usize = MAX_STATE_SECTORS;
const SLOTS: usize = 2;

// mock HMAC (length-framed FNV-1a) — same style as the state_root tests.
fn mock_hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    fn absorb(h: &mut u64, b: &[u8]) { for &x in b { *h = (*h ^ x as u64).wrapping_mul(0x100000001b3); } }
    let mut h = 0xcbf29ce484222325u64;
    absorb(&mut h, &(key.len() as u32).to_le_bytes()); absorb(&mut h, key);
    for p in parts { absorb(&mut h, &(p.len() as u32).to_le_bytes()); absorb(&mut h, p); }
    let mut o = [0u8; 32]; let mut i = 0;
    while i < 32 { h = h.wrapping_mul(0x100000001b3) ^ i as u64; o[i..i+8].copy_from_slice(&h.to_le_bytes()); i += 8; }
    o
}

/// Mock flash: a per-(sector,slot) digest, plus a per-sector "pending" digest that a
/// checkpoint stages. `stage(idx, slot)` copies pending[idx] into stored[idx][slot].
struct MockStore { stored: [[[u8;32]; SLOTS]; N], pending: [[u8;32]; N], fail_at: Option<usize> }
impl MockStore {
    fn new() -> Self { Self { stored: [[[0u8;32]; SLOTS]; N], pending: [[0u8;32]; N], fail_at: None } }
    fn set_pending(&mut self, idx: usize, seed: u8) { self.pending[idx] = [seed; 32]; }
}
impl SectorStore for MockStore {
    fn stage(&mut self, idx: usize, slot: usize) -> Result<(), ()> {
        if self.fail_at == Some(idx) { return Err(()); }
        self.stored[idx][slot] = self.pending[idx];
        Ok(())
    }
    fn read_digest(&self, idx: usize, slot: usize) -> [u8;32] { self.stored[idx][slot] }
}

struct MockAnchor { a: Option<Anchor> }
impl MockAnchor { fn new() -> Self { Self { a: None } } }
impl AnchorStore for MockAnchor {
    fn load(&self) -> Option<Anchor> { self.a }
    fn store(&mut self, x: &Anchor) { self.a = Some(*x); }
}

const KEY: [u8; 32] = [0x11; 32];
const EID: u32 = 7;
const FMT: u32 = 1; // snapshot-layout version (author-owned; NOT the code version)

// commit all N sectors dirty with the given seeds (first checkpoint from cold).
fn commit_all(store: &mut MockStore, anchor: &mut MockAnchor, seeds: &[u8; N]) {
    let mut i = 0; while i < N { store.set_pending(i, seeds[i]); i += 1; }
    let dirty = 0xFFFFu16;
    checkpoint(store, anchor, dirty, &KEY, EID, FMT, mock_hmac).unwrap();
}

#[test]
fn full_checkpoint_then_restore_resumes() {
    let mut s = MockStore::new(); let mut a = MockAnchor::new();
    let seeds = [1u8; N];
    commit_all(&mut s, &mut a, &seeds);
    assert_eq!(a.load().unwrap().generation, 1);
    assert_eq!(restore(&s, &a, &KEY, EID, FMT, mock_hmac), RestoreDecision::Resume);
}

#[test]
fn partial_checkpoint_preserves_nondirty_sectors() {
    // THE X1 test: commit all at gen1, then a checkpoint touching ONLY sector 0.
    // Non-dirty sectors 1..15 must still restore (their committed slot is unchanged,
    // and the root recomputes to the anchor root). The OLD A/B-flip design fails this.
    let mut s = MockStore::new(); let mut a = MockAnchor::new();
    commit_all(&mut s, &mut a, &[1u8; N]);
    s.set_pending(0, 2); // new content for sector 0 only
    checkpoint(&mut s, &mut a, 0b1, &KEY, EID, FMT, mock_hmac).unwrap();
    assert_eq!(a.load().unwrap().generation, 2);
    assert_eq!(restore(&s, &a, &KEY, EID, FMT, mock_hmac), RestoreDecision::Resume);
}

#[test]
fn crash_before_anchor_commit_keeps_last_good() {
    // Commit gen1. Then simulate a crash mid-second-checkpoint: stage sector 0 into its
    // STAGING slot but do NOT commit the anchor. The anchor still points at gen1/old
    // parity → restore reads the OLD committed slots → resumes last-good.
    let mut s = MockStore::new(); let mut a = MockAnchor::new();
    commit_all(&mut s, &mut a, &[1u8; N]);
    let committed_parity = a.load().unwrap().parity;
    let committed0 = (committed_parity & 1) as usize;
    s.set_pending(0, 2);
    let _ = s.stage(0, committed0 ^ 1); // wrote staging, anchor untouched
    assert_eq!(restore(&s, &a, &KEY, EID, FMT, mock_hmac), RestoreDecision::Resume);
}

#[test]
fn replayed_old_coherent_checkpoint_is_rejected() {
    // Commit gen1 (seeds=1), then gen2 (sector 0 → seed 2). Attacker rolls flash back to
    // the gen1 content in the CURRENTLY-committed slots. Restore recomputes root over the
    // rolled-back digests at the anchor's generation → root mismatch → Reject.
    let mut s = MockStore::new(); let mut a = MockAnchor::new();
    commit_all(&mut s, &mut a, &[1u8; N]);
    s.set_pending(0, 2);
    checkpoint(&mut s, &mut a, 0b1, &KEY, EID, FMT, mock_hmac).unwrap();
    let anchor = a.load().unwrap();
    // attacker overwrites every sector's committed slot with the old (seed 1) digest:
    let mut i = 0; while i < N { let slot = ((anchor.parity >> i) & 1) as usize; s.stored[i][slot] = [1u8;32]; i += 1; }
    assert_eq!(restore(&s, &a, &KEY, EID, FMT, mock_hmac), RestoreDecision::Reject);
}

#[test]
fn tampered_sector_is_rejected() {
    let mut s = MockStore::new(); let mut a = MockAnchor::new();
    commit_all(&mut s, &mut a, &[1u8; N]);
    let anchor = a.load().unwrap();
    let slot = ((anchor.parity >> 3) & 1) as usize;
    s.stored[3][slot][0] ^= 0xFF; // flip one sector's content
    assert_eq!(restore(&s, &a, &KEY, EID, FMT, mock_hmac), RestoreDecision::Reject);
}

#[test]
fn resume_under_different_state_format_is_rejected() {
    // Commit under snapshot-layout format 1; a binary using layout format 2 recomputes a
    // DIFFERENT root over the same committed sectors → Reject. Chosen coupling
    // (bind the FORMAT version, not the code version): an incompatible layout fails closed
    // instead of being silently deserialized.
    let mut s = MockStore::new();
    let mut a = MockAnchor::new();
    commit_all(&mut s, &mut a, &[1u8; N]); // commit_all uses FMT (= 1)
    assert_eq!(restore(&s, &a, &KEY, EID, 2, mock_hmac), RestoreDecision::Reject);
}

#[test]
fn cold_anchor_is_genesis() {
    let s = MockStore::new(); let a = MockAnchor::new(); // None
    assert_eq!(restore(&s, &a, &KEY, EID, FMT, mock_hmac), RestoreDecision::ColdGenesis);
}

#[test]
fn flash_write_failure_does_not_advance_anchor() {
    let mut s = MockStore::new(); let mut a = MockAnchor::new();
    commit_all(&mut s, &mut a, &[1u8; N]);
    let gen_before = a.load().unwrap().generation;
    s.set_pending(2, 9); s.fail_at = Some(2);
    assert_eq!(checkpoint(&mut s, &mut a, 0b100, &KEY, EID, FMT, mock_hmac), Err(CheckpointError::FlashWrite(2)));
    assert_eq!(a.load().unwrap().generation, gen_before, "anchor must NOT advance on flash failure");
}
