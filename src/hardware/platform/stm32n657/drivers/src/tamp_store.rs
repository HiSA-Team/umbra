//! Per-author anti-rollback floor store in TAMP backup registers (STM32N657).
//!
//! The floor lives in the TAMP backup registers (`TAMP_BKP0R..BKP31R`) — ST's
//! blessed anti-rollback substrate. Retention, measured on this open Nucleo:
//! TAMP AND the 8 KB BKPSRAM both SURVIVE a warm/software reset (PIN/SFT,
//! RCC_RSR bit 22/24) and are wiped only by a cold power-off / POR (RCC_RSR
//! bit 23). An earlier note here claiming "BKPSRAM does NOT retain across reset"
//! was reset-type confusion (a POR/reflash misread as a warm reset). TAMP is
//! chosen over BKPSRAM regardless: its writes are durable across an immediate
//! reset (Device memory, no D-cache flush needed — unlike cacheable BKPSRAM),
//! and it exposes per-register secure zones (`TAMP_SECCFGR`) that block
//! Non-Secure overwrites of the floor.
//!
//! Bring-up (`init_backup_domain`): enable the RTC/TAMP APB clock
//! (RCC_APB4ENR1.RTCEN + RTCAPBEN) and unlock backup-domain writes
//! (PWR_DBPCR.DBP). TAMP registers do NOT use the RTC_WPR write-protect (that
//! is RTC-only); DBP is the gate. Addresses from CMSIS `stm32n657xx.h`:
//!   - RCC_APB4ENR1 (0x5602_8274) bit 16 RTCEN, bit 17 RTCAPBEN
//!   - PWR_DBPCR    (0x5602_482C) bit 0  DBP
//!   - TAMP_BKP0R   (0x5600_4500) = TAMP_BASE_S (0x5600_4400) + 0x100
//!
//! `TampStore` is generic over the MMIO backend so host tests inject
//! `umbra_pal_test::mmio::MmioHandle`; firmware uses `RealMmio`.

use peripheral_regs::{MmioAccess, RealMmio};

/// TAMP backup-register file base (Secure alias): TAMP_BKP0R.
pub const TAMP_BKP_BASE: u32 = 0x5600_4500;

/// Marks a provisioned floor entry (vs cold-boot zero). Bump if the layout changes.
pub const RB_MAGIC: u32 = 0x0DC0_5A02;
/// Number of per-author floor entries (capped table; no eviction).
/// Each entry is 3 backup registers (magic, author_id, hwm); 4 entries = 12 of 32.
pub const RB_N_AUTHORS: usize = 4;
/// One entry: magic(4) author_id(4) hwm(4) — three consecutive TAMP_BKPxR.
const RB_ENTRY_STRIDE: u32 = 12;

// Bring-up registers (CMSIS stm32n657xx.h, HW-confirmed 2026-06-30).
const RCC_APB4ENR1: u32 = 0x5602_8274;
const RCC_APB4ENR1_RTCEN: u32 = 1 << 16;
const RCC_APB4ENR1_RTCAPBEN: u32 = 1 << 17;
const PWR_DBPCR: u32 = 0x5602_482C;
const PWR_DBPCR_DBP: u32 = 1 << 0;
// TAMP_SECCFGR (TAMP_BASE_S 0x5600_4400 + 0x20). BKPWSEC[23:16] = count of
// leading backup registers writable ONLY with Secure access; 32 = all, so
// Non-Secure cannot overwrite the anti-rollback floor (BKP0..11) or the
// state-continuity anchor (BKP12..29) and replay an old version. HW-confirmed
// necessary 2026-07-01: at reset SECCFGR=0 left EVERY backup register
// NS-writable (measured on the open Nucleo), so NS could plant a rolled-back
// version. The Secure FSBL still writes freely; not sticky-locked (re-set each boot).
const TAMP_SECCFGR: u32 = 0x5600_4420;
const TAMP_SECCFGR_BKPWSEC_ALL: u32 = 32 << 16;
// PWR_SECCFGR (PWR_BASE_S 0x5602_4800 + 0x70). SEC5 = "Backup domain
// secure/privilege protection" (HAL `stm32n6xx_hal_pwr.h` PWR_ITEM_5). Setting it
// makes the WHOLE backup domain — including `RCC_BDCR.VSWRST` — Secure-only, so NS
// cannot reset the backup domain to wipe floor+anchor (→ COLD_WINDOW → rollback).
// HW-confirmed necessary 2026-07-01: at reset SEC5=0 + DBP=1 left VSWRST reachable
// from NS (measured on the open Nucleo, then re-verified PROTECTED after this fix).
const PWR_SECCFGR: u32 = 0x5602_4870;
const PWR_SECCFGR_SEC5: u32 = 1 << 5;

/// One-time bring-up: enable the RTC/TAMP APB clock, unlock backup-domain writes
/// (DBP), and lock all backup registers to Secure-only writes (SECCFGR). Call
/// once at boot before any floor/anchor access. Firmware-only raw MMIO (host
/// tests never call this; validated on-target).
pub fn init_backup_domain() {
    unsafe {
        // Enable RTC + RTCAPB clock so TAMP registers are accessible.
        let en = core::ptr::read_volatile(RCC_APB4ENR1 as *const u32);
        core::ptr::write_volatile(
            RCC_APB4ENR1 as *mut u32,
            en | RCC_APB4ENR1_RTCEN | RCC_APB4ENR1_RTCAPBEN,
        );
        #[cfg(target_arch = "arm")]
        core::arch::asm!("dsb");
        // Unlock backup-domain writes (gates TAMP backup-register writes).
        let dbpcr = core::ptr::read_volatile(PWR_DBPCR as *const u32);
        core::ptr::write_volatile(PWR_DBPCR as *mut u32, dbpcr | PWR_DBPCR_DBP);
        #[cfg(target_arch = "arm")]
        core::arch::asm!("dsb");
        // Block Non-Secure writes to ALL backup registers (floor + anchor), so a
        // rolled-back version cannot be planted from NS. Secure writes unaffected.
        core::ptr::write_volatile(TAMP_SECCFGR as *mut u32, TAMP_SECCFGR_BKPWSEC_ALL);
        #[cfg(target_arch = "arm")]
        core::arch::asm!("dsb");
        // Make the whole backup domain Secure-only (incl. RCC_BDCR.VSWRST) so NS
        // cannot reset it to wipe floor+anchor. Read-modify-write to preserve any
        // other SECx bits. Secure FSBL accesses are unaffected.
        let pwr_sec = core::ptr::read_volatile(PWR_SECCFGR as *const u32);
        core::ptr::write_volatile(PWR_SECCFGR as *mut u32, pwr_sec | PWR_SECCFGR_SEC5);
        #[cfg(target_arch = "arm")]
        core::arch::asm!("dsb");
    }
}

/// Per-author anti-rollback floor accessor over TAMP backup registers. Generic
/// over the MMIO backend; default `RealMmio` keeps the firmware call site.
pub struct TampStore<M: MmioAccess = RealMmio> {
    mmio: M,
}

impl TampStore<RealMmio> {
    pub fn new() -> Self {
        TampStore {
            mmio: RealMmio::new(TAMP_BKP_BASE),
        }
    }
}

impl<M: MmioAccess> TampStore<M> {
    /// Host-test constructor — inject any `MmioAccess` backend.
    #[allow(dead_code)]
    pub fn new_with_mmio(mmio: M) -> Self {
        TampStore { mmio }
    }

    fn entry_off(slot: usize) -> u32 {
        (slot as u32) * RB_ENTRY_STRIDE
    }

    /// Floor for `author_id`; 0 if no provisioned entry (cold/never-seen).
    pub fn rb_floor(&self, author_id: u32) -> u32 {
        let mut s = 0;
        while s < RB_N_AUTHORS {
            let b = Self::entry_off(s);
            if self.mmio.read(b) == RB_MAGIC && self.mmio.read(b + 4) == author_id {
                return self.mmio.read(b + 8);
            }
            s += 1;
        }
        0
    }

    /// Raise `author_id`'s floor to `version` (in-place if present, else a free
    /// entry). Magic written LAST so a torn write reads cold (fail-open, never a
    /// forged-higher floor). Caller MUST have verified the version first.
    pub fn rb_bump(&mut self, author_id: u32, version: u32) {
        let mut s = 0;
        while s < RB_N_AUTHORS {
            let b = Self::entry_off(s);
            if self.mmio.read(b) == RB_MAGIC && self.mmio.read(b + 4) == author_id {
                if version > self.mmio.read(b + 8) {
                    self.mmio.write(b + 8, version);
                }
                return;
            }
            s += 1;
        }
        let mut s = 0;
        while s < RB_N_AUTHORS {
            let b = Self::entry_off(s);
            if self.mmio.read(b) != RB_MAGIC {
                self.mmio.write(b + 4, author_id);
                self.mmio.write(b + 8, version);
                self.mmio.write(b, RB_MAGIC); // magic LAST
                return;
            }
            s += 1;
        }
        // Table full (capped at RB_N_AUTHORS): no eviction — a hostile author
        // cannot drop another's floor. Exhaustion is a documented DoS bound.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umbra_pal_test::mmio::MmioMem;

    #[test]
    fn floor_zero_until_bumped_then_monotonic() {
        let mem = MmioMem::new(TAMP_BKP_BASE);
        let mut bk = TampStore::new_with_mmio(mem.handle());
        assert_eq!(bk.rb_floor(7), 0); // cold
        bk.rb_bump(7, 2);
        assert_eq!(bk.rb_floor(7), 2);
        bk.rb_bump(7, 1); // lower: ignored
        assert_eq!(bk.rb_floor(7), 2);
        bk.rb_bump(7, 5); // higher: raised
        assert_eq!(bk.rb_floor(7), 5);
        assert_eq!(bk.rb_floor(8), 0); // other author independent
    }

    #[test]
    fn second_author_uses_separate_entry() {
        let mem = MmioMem::new(TAMP_BKP_BASE);
        let mut bk = TampStore::new_with_mmio(mem.handle());
        bk.rb_bump(1, 3);
        bk.rb_bump(2, 9);
        assert_eq!(bk.rb_floor(1), 3);
        assert_eq!(bk.rb_floor(2), 9);
    }
}
