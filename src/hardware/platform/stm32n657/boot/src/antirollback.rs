//! N6 MonotonicCounter backed by TAMP backup registers. The floor lives in TAMP
//! (ST's blessed anti-rollback substrate) rather than BKPSRAM because TAMP writes
//! are durable across an immediate reset (Device memory) and TAMP exposes
//! per-register secure zones (`TAMP_SECCFGR`) that block Non-Secure overwrites.
//! Both TAMP and BKPSRAM retain across a warm/software reset (PIN/SFT) and are
//! wiped by a POR (measured 2026-07-01); an earlier "BKPSRAM does not retain"
//! note was POR/reset-type confusion.
//!
//! Still NOT durable vs a true power-loss / VBAT-pull attacker (the kernel's
//! COLD_WINDOW scan fails open and logs it). Phase 2 would close that with the
//! OTP/BSEC monotonic fuse counter. Gated by `enclave_version_bind`.

use drivers::tamp_store::{init_backup_domain, TampStore};
use kernel::key_storage_server::version_search::MonotonicCounter;

pub struct BackupFloorCounter {
    bk: TampStore,
}

impl BackupFloorCounter {
    pub fn new() -> Self {
        init_backup_domain();
        Self { bk: TampStore::new() }
    }
}

impl MonotonicCounter for BackupFloorCounter {
    fn floor(&self, author_id: u32) -> u32 {
        self.bk.rb_floor(author_id)
    }
    fn bump(&mut self, author_id: u32, version: u32) {
        self.bk.rb_bump(author_id, version)
    }
}

/// Consecutive failed boots of one A/B slot before `create(0)` excludes it and falls
/// back to the other authenticated slot. Sized so the LED-blink boot-loop recovers in
/// a few seconds: an authentic-but-crashing image faults → `handle_fault` →
/// `SYSRESETREQ` (warm reset, TAMP survives), re-selects the same slot, faults again;
/// after this many consecutive crashes the slot is excluded and the previous good slot
/// is booted — no human power-cycle needed. See ADR 013 / the availability finding.
pub const BOOT_FAIL_THRESHOLD: u32 = 3;

/// Liveness-fallback counter over TAMP BKP30/BKP31 (the failed-boot count per A/B slot).
/// Mirror of [`BackupFloorCounter`]: `new()` brings up the backup domain, then the
/// three ops are thin passthroughs to [`TampStore`]. Distinct from the anti-rollback
/// floor — this tracks *did the slot boot healthy*, not *what version*.
pub struct BootFailCounter {
    bk: TampStore,
}

impl BootFailCounter {
    pub fn new() -> Self {
        init_backup_domain();
        Self { bk: TampStore::new() }
    }
    /// Consecutive failed-boot count for `slot` (0 = A, 1 = B).
    pub fn get(&self, slot: usize) -> u32 {
        self.bk.boot_fail(slot)
    }
    /// Record a boot attempt for `slot` (before the enclave runs).
    pub fn inc(&mut self, slot: usize) {
        self.bk.boot_fail_inc(slot)
    }
    /// Mark `slot` healthy (clean termination, or a fresh image written to it).
    pub fn clear(&mut self, slot: usize) {
        self.bk.boot_fail_clear(slot)
    }
}
