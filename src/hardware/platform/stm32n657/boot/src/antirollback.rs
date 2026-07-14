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
