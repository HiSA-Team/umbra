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
    checkpoint, restore, AnchorStore, CheckpointError, RestoreDecision, SectorStore,
};
use kernel::key_storage_server::state_continuity::{MAX_STATE_SECTORS, STATE_SECTOR_SIZE};
use kernel::key_storage_server::state_root::{compute_root, root_matches, ROOT_PREIMAGE_LEN};

/// Author-owned snapshot-layout version — bump ONLY when the serialized state layout
/// changes (NOT the code version). Bound into the anchor root so a binary using a new
/// layout fails closed (Reject) on an old-layout snapshot instead of deserializing it.
/// See ADR 010.
pub const STATE_FORMAT_VERSION: u32 = 1;

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
        // Root model stores raw ciphertext only — no version/tag trailer.
        state_flash::write_state_sector(idx, slot, &self.pending[idx]).map_err(|_| ())
    }

    fn read_digest(&self, idx: usize, slot: usize) -> [u8; 32] {
        let addr = state_flash::state_sector_addr(idx, slot).expect("idx/slot bounds-checked");
        // Invalidate the D-cache first so the SW SHA reads FRESH flash (read-after-write
        // coherency — the digest at checkpoint and at restore must match).
        state_flash::invalidate_dcache_region(addr, STATE_SECTOR_SIZE as u32);
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
/// so flatten the fixed parts first: enclave_id(4) ‖ state_format_version(4) ‖
/// generation(4) ‖ 16×digest(32). The buffer is sized by `ROOT_PREIMAGE_LEN` (the
/// single source of truth) so it can never drift from the preimage layout.
fn hw_hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut buf = [0u8; ROOT_PREIMAGE_LEN];
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
    checkpoint(&mut store, &mut anchor, dirty, key, enclave_id, STATE_FORMAT_VERSION, hw_hmac)
}

/// Decide whether to resume the enclave — call at resume. On `Resume` the caller
/// deserializes the committed sectors back into enclave memory.
pub fn resume_state(key: &[u8], enclave_id: u32) -> RestoreDecision {
    let store = FlashSectorStore::new();
    let anchor = StateAnchor::new();
    restore(&store, &anchor, key, enclave_id, STATE_FORMAT_VERSION, hw_hmac)
}

// ── On-chip proof-slice probe ────────────────────────────────────────────────
// Runs the WHOLE state-continuity control loop on real silicon — HW HASH for the
// keyed root and the sector digests, real TAMP for the double-buffered anchor —
// WITHOUT the XSPI2 write path: the sectors live in a small RAM stand-in. It proves
// the logic (checkpoint → resume → reject) and TAMP anchor durability across a warm
// reset; only flash persistence is deferred. Feature-gated out of production boot.

/// RAM stand-in bytes per sector slot (the real ciphertext is `STATE_SECTOR_SIZE`).
/// Kept small so the whole store is a shallow stack frame — the N657 FSBL stack is
/// tight. It only feeds the HW HASH; its size does not change what the probe proves.
const PROBE_SECTOR_BYTES: usize = 32;

/// RAM-backed [`SectorStore`] for the probe: two A/B slots per sector, each a small
/// buffer hashed by the real HW HASH engine.
pub struct RamSectorStore {
    stored: [[[u8; PROBE_SECTOR_BYTES]; 2]; MAX_STATE_SECTORS],
    pending: [[u8; PROBE_SECTOR_BYTES]; MAX_STATE_SECTORS],
}

impl Default for RamSectorStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RamSectorStore {
    pub fn new() -> Self {
        Self {
            stored: [[[0u8; PROBE_SECTOR_BYTES]; 2]; MAX_STATE_SECTORS],
            pending: [[0u8; PROBE_SECTOR_BYTES]; MAX_STATE_SECTORS],
        }
    }
    /// Load a deterministic "snapshot" into pending (content varies per sector).
    fn set_pending(&mut self, seed: u8) {
        let mut i = 0;
        while i < MAX_STATE_SECTORS {
            self.pending[i] = [seed.wrapping_add(i as u8); PROBE_SECTOR_BYTES];
            i += 1;
        }
    }
    fn tamper(&mut self, idx: usize, slot: usize) {
        self.stored[idx][slot][0] ^= 0xFF;
    }
}

impl SectorStore for RamSectorStore {
    fn stage(&mut self, idx: usize, slot: usize) -> Result<(), ()> {
        self.stored[idx][slot] = self.pending[idx];
        Ok(())
    }
    fn read_digest(&self, idx: usize, slot: usize) -> [u8; 32] {
        let mut out = [0u8; 32];
        Hash::new().sha256(&self.stored[idx][slot], &mut out); // real HW SHA-256
        out
    }
}

/// Outcome of the on-chip probe, printed by the boot crate over UART.
pub struct ProbeReport {
    /// `Some(gen)` if a prior anchor SURVIVED a reset (warm boot) → proves TAMP
    /// durability + `load()` read-back; `None` on a cold anchor (first boot).
    pub anchor_survived_gen: Option<u32>,
    /// anchor generation after the probe's checkpoint (monotone across warm boots).
    pub committed_gen: u32,
    /// `restore()` after commit == `Resume` (root recomputed over the RAM sectors
    /// via the real HASH engine matches the TAMP anchor root).
    pub resumed_ok: bool,
    /// `restore()` after tampering one committed sector == `Reject`.
    pub tamper_rejected: bool,
}

/// Run the full checkpoint → resume → reject loop on real HW. `key` is the
/// MASTER_KEY-derived state key; `enclave_id` identifies the enclave. Requires
/// `tamp_store::init_backup_domain` and the HASH clock to be up.
pub fn run_state_continuity_probe(key: &[u8], enclave_id: u32) -> ProbeReport {
    // A prior anchor still in TAMP proves cross-reset durability (BKP12–25).
    let anchor_survived_gen = StateAnchor::new().load().map(|a| a.generation);

    let mut store = RamSectorStore::new();
    let mut anchor = StateAnchor::new();

    // Checkpoint a deterministic snapshot over the real TAMP anchor + real HASH.
    store.set_pending(0xA5);
    let _ = checkpoint(
        &mut store, &mut anchor, 0xFFFF, key, enclave_id, STATE_FORMAT_VERSION, hw_hmac,
    );
    let committed = anchor.load();
    let committed_gen = committed.map(|a| a.generation).unwrap_or(0);
    let parity = committed.map(|a| a.parity).unwrap_or(0);

    // restore → Resume (root over the committed RAM sectors matches the anchor).
    let resumed_ok = matches!(
        restore(&store, &anchor, key, enclave_id, STATE_FORMAT_VERSION, hw_hmac),
        RestoreDecision::Resume
    );

    // Tamper the committed slot of one sector → Reject.
    let slot3 = ((parity >> 3) & 1) as usize;
    store.tamper(3, slot3);
    let tamper_rejected = matches!(
        restore(&store, &anchor, key, enclave_id, STATE_FORMAT_VERSION, hw_hmac),
        RestoreDecision::Reject
    );

    ProbeReport { anchor_survived_gen, committed_gen, resumed_ok, tamper_rejected }
}

// ── Flash-continuity probe: checkpoint → reset → restore over PERSISTED flash ──
// Unifies the two proven halves — the double-buffered TAMP anchor AND real flash
// sectors — into one loop that survives a reset. Boot 1 (cold anchor) checkpoints a
// couple of sectors to flash and commits the anchor; after a reset boot 2 restores
// the root over the persisted flash + anchor → Resume. Feature-gated dev probe.

/// Flash-backed `SectorStore` for the probe. `stage` writes a deterministic 4 KB
/// pattern (byte 0 = sector index, rest 0) to flash; `read_digest` hashes the mapped
/// committed slot. One reused static scratch — no 64 KB pending array.
pub struct FlashProbeStore;

static mut FLASH_PROBE_SCRATCH: [u8; STATE_SECTOR_SIZE] = [0u8; STATE_SECTOR_SIZE];

impl SectorStore for FlashProbeStore {
    fn stage(&mut self, idx: usize, slot: usize) -> Result<(), ()> {
        // SAFETY: single-threaded boot; exclusive access to the scratch here.
        unsafe {
            let p = core::ptr::addr_of_mut!(FLASH_PROBE_SCRATCH) as *mut u8;
            core::ptr::write_volatile(p, idx as u8); // distinct per sector; rest stays 0
            state_flash::write_state_sector(idx, slot, &*core::ptr::addr_of!(FLASH_PROBE_SCRATCH))
                .map_err(|_| ())
        }
    }
    fn read_digest(&self, idx: usize, slot: usize) -> [u8; 32] {
        let addr = state_flash::state_sector_addr(idx, slot).unwrap_or(STATE_SECTOR_SIZE as u32);
        // Invalidate the D-cache first so the SW SHA reads FRESH flash — otherwise the
        // digest at checkpoint (just after a write) and at restore (cold) can diverge.
        state_flash::invalidate_dcache_region(addr, STATE_SECTOR_SIZE as u32);
        // SAFETY: bounds-checked address inside the mapped XSPI2 window; read-only.
        let bytes: &[u8] =
            unsafe { core::slice::from_raw_parts(addr as *const u8, STATE_SECTOR_SIZE) };
        let mut out = [0u8; 32];
        Hash::new().sha256(bytes, &mut out);
        out
    }
}

/// Outcome of the flash-continuity probe.
pub struct FlashContinuityReport {
    /// restore over persisted flash matched the anchor → Resume (success).
    pub resumed: bool,
    /// resumed: anchor gen; else: the new checkpoint's gen (press RST to verify).
    pub gen: u32,
    /// restore-attempt diagnostics (low 4 bytes): anchor stored root, recomputed root
    /// over persisted flash, sector-0's committed word.
    pub stored_root: u32,
    pub recomp_root: u32,
    /// recomputed AGAIN over the identical digests — if != recomp_root, the HW HMAC
    /// primitive is non-deterministic (residual HASH-engine state).
    pub recomp_root2: u32,
    pub sec0_raw: u32,
}

/// Restore first; if the anchor matches → Resume. Otherwise (cold, or a stale anchor
/// left by a prior boot's key) checkpoint fresh. `key` MUST be stable across boots
/// (the root is keyed by it) — the caller passes a fixed probe key, NOT the ephemeral
/// enc_key. The real integration keys this with the device MASTER_KEY.
pub fn run_flash_continuity_probe(key: &[u8], enclave_id: u32) -> FlashContinuityReport {
    let lo = |b: &[u8; 16]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    if let Some(a) = StateAnchor::new().load() {
        if a.generation != 0 {
            let store = FlashProbeStore;
            let mut digs = [[0u8; 32]; MAX_STATE_SECTORS];
            let mut i = 0;
            while i < MAX_STATE_SECTORS {
                digs[i] = store.read_digest(i, ((a.parity >> i) & 1) as usize);
                i += 1;
            }
            let rec = compute_root(key, enclave_id, STATE_FORMAT_VERSION, a.generation, &digs, hw_hmac);
            // Re-READ the digests and recompute — if rec2 != rec the flash READ (not the
            // HMAC) is non-deterministic (XSPI prefetch / mem-map read cache).
            let mut digs2 = [[0u8; 32]; MAX_STATE_SECTORS];
            let mut j = 0;
            while j < MAX_STATE_SECTORS {
                digs2[j] = store.read_digest(j, ((a.parity >> j) & 1) as usize);
                j += 1;
            }
            let rec2 = compute_root(key, enclave_id, STATE_FORMAT_VERSION, a.generation, &digs2, hw_hmac);
            let a0 = state_flash::state_sector_addr(0, (a.parity & 1) as usize).unwrap_or(0);
            // SAFETY: mapped XSPI2 window.
            let sec0_raw = unsafe { core::ptr::read_volatile(a0 as *const u32) };
            if root_matches(&a.root, &rec) {
                return FlashContinuityReport {
                    resumed: true,
                    gen: a.generation,
                    stored_root: lo(&a.root),
                    recomp_root: lo(&rec),
                    recomp_root2: lo(&rec2),
                    sec0_raw,
                };
            }
            // Stale/foreign anchor — re-checkpoint with the (stable) key, keep the diag.
            let mut store2 = FlashProbeStore;
            let mut anchor2 = StateAnchor::new();
            let _ = checkpoint(&mut store2, &mut anchor2, 0xFFFF, key, enclave_id, STATE_FORMAT_VERSION, hw_hmac);
            let gen = anchor2.load().map(|x| x.generation).unwrap_or(0);
            return FlashContinuityReport {
                resumed: false,
                gen,
                stored_root: lo(&a.root),
                recomp_root: lo(&rec),
                recomp_root2: lo(&rec2),
                sec0_raw,
            };
        }
    }
    // Cold: first checkpoint.
    let mut store = FlashProbeStore;
    let mut anchor = StateAnchor::new();
    let _ = checkpoint(&mut store, &mut anchor, 0xFFFF, key, enclave_id, STATE_FORMAT_VERSION, hw_hmac);
    let gen = anchor.load().map(|x| x.generation).unwrap_or(0);
    FlashContinuityReport { resumed: false, gen, stored_root: 0, recomp_root: 0, recomp_root2: 0, sec0_raw: 0 }
}
