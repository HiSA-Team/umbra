//! Boot-side adapters wiring the kernel state-continuity traits to the N657
//! drivers — **SKELETON**. The trait plumbing and the checkpoint/restore call
//! sites are complete and host-compilable; the three HW/runtime-specific steps
//! are marked `todo!()`:
//!   1. `serialize_snapshot` — capture + AES-encrypt the enclave's mutable memory.
//!   2. `write_state_sector` (in `state_flash`) — the 1-1-1 XSPI2 write path.
//!   3. the MASTER_KEY-derived state key + `enclave_id`, supplied by the caller.
//!
//! `read_digest` is written against memory-mapped XSPI2 + the HW HASH, so it
//! compiles on host but only runs on the board. See the state-continuity handoff
//! and ADR 010.

use crate::hash::Hash;
use crate::state_anchor::StateAnchor;
use crate::state_flash;
use kernel::key_storage_server::state_checkpoint::{
    checkpoint, restore, CheckpointError, RestoreDecision, SectorStore,
};
use kernel::key_storage_server::state_continuity::{MAX_STATE_SECTORS, STATE_SECTOR_SIZE};

/// Flash-backed [`SectorStore`]. Holds the pending (encrypted) ciphertext for each
/// logical sector; `stage` flushes one to XSPI2, `read_digest` hashes the mapped
/// committed copy.
// ponytail: `pending` is 64 KB on the stack — fine as a skeleton; the real impl
// should stream per-sector or use a static scratch to avoid a deep stack frame.
pub struct FlashSectorStore {
    pending: [[u8; STATE_SECTOR_SIZE]; MAX_STATE_SECTORS],
}

impl Default for FlashSectorStore {
    fn default() -> Self {
        Self::new()
    }
}

impl FlashSectorStore {
    pub fn new() -> Self {
        Self { pending: [[0u8; STATE_SECTOR_SIZE]; MAX_STATE_SECTORS] }
    }

    /// Serialize + AES-encrypt the enclave's mutable state (PSP stack + data +
    /// saved registers) into `pending`; return the dirty-sector bitmap. Depends on
    /// the enclave memory map + the AES engine — fill in on the board.
    pub fn serialize_snapshot(&mut self) -> u16 {
        let _ = &mut self.pending;
        todo!("serialize + AES-encrypt the enclave snapshot into self.pending; return dirty mask")
    }
}

impl SectorStore for FlashSectorStore {
    fn stage(&mut self, idx: usize, slot: usize) -> Result<(), ()> {
        // Root model stores raw ciphertext only — no version/tag trailer. Once
        // `write_state_sector` is simplified to (idx, slot, &[u8; 4096]) drop the
        // two placeholder trailer arguments below.
        state_flash::write_state_sector(idx, slot, &self.pending[idx], 0, &[0u8; 32])
            .map_err(|_| ())
    }

    fn read_digest(&self, idx: usize, slot: usize) -> [u8; 32] {
        let addr = state_flash::state_sector_addr(idx, slot).expect("idx/slot bounds-checked");
        // SAFETY: `state_sector_addr` bounds-checks (idx, slot) into the 1 MB state
        // region inside the memory-mapped XSPI2 window; this reads STATE_SECTOR_SIZE
        // bytes and never writes.
        let bytes: &[u8] =
            unsafe { core::slice::from_raw_parts(addr as *const u8, STATE_SECTOR_SIZE) };
        let mut out = [0u8; 32];
        Hash::new().sha256(bytes, &mut out); // unkeyed SHA-256 of the committed ciphertext
        out
    }
}

/// Keyed HMAC-SHA256 root primitive matching `compute_root`'s
/// `FnOnce(&[u8], &[&[u8]]) -> [u8; 32]`. The HW HMAC takes one contiguous buffer,
/// so flatten the fixed parts first: enclave_id(4) ‖ generation(4) ‖ 16×digest(32).
fn hw_hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut buf = [0u8; 8 + MAX_STATE_SECTORS * 32];
    let mut n = 0;
    for p in parts {
        buf[n..n + p.len()].copy_from_slice(p);
        n += p.len();
    }
    let mut out = [0u8; 32];
    Hash::new().hmac_sha256(key, &buf[..n], &mut out);
    out
}

/// Commit the current enclave state — call at yield/suspend. `key` is the
/// MASTER_KEY-derived state key; `enclave_id` identifies the enclave.
pub fn commit_state(key: &[u8], enclave_id: u32) -> Result<(), CheckpointError> {
    let mut store = FlashSectorStore::new();
    let dirty = store.serialize_snapshot();
    let mut anchor = StateAnchor::new();
    checkpoint(&mut store, &mut anchor, dirty, key, enclave_id, hw_hmac)
}

/// Decide whether to resume the enclave — call at resume. On `Resume` the caller
/// deserializes the committed sectors back into enclave memory.
pub fn resume_state(key: &[u8], enclave_id: u32) -> RestoreDecision {
    let store = FlashSectorStore::new();
    let anchor = StateAnchor::new();
    restore(&store, &anchor, key, enclave_id, hw_hmac)
}
