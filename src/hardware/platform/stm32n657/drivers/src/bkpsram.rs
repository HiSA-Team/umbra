//! BKPSRAM slot storage for the DHUK-wrapped enc_key (issue #45). 8 KB
//! VBAT-retained backup SRAM: survives a warm reset, lost on cold power-off.
//!
//! Writing the backup domain requires a one-time bring-up — enable the BKPSRAM
//! clock, unlock backup-domain writes (DBP), enable retention — done by
//! [`init_backup_domain`]. Confirmed on hardware 2026-06-25: without that
//! sequence the Secure alias `0x3C00_0000` is read-only (writes silently drop).
//! Register addresses/bits are from the on-disk CMSIS header `stm32n657xx.h`:
//! - BKPSRAM clock: `RCC_MEMENR` (0x5602_824C) bit 6 `BKPSRAMEN`
//! - backup-write unlock: `PWR_DBPCR` (0x5602_482C) bit 0 `DBP` (NOT PWR_CR1)
//! - retention: `PWR_BDCR2` (0x5602_4828) bit 0 `BKPRBSEN`
//!
//! Slot layout (24 bytes): `magic`@0x00, `tag`@0x04, `blob`@0x08..0x18.
//!
//! The [`Bkpsram`] data accessor is generic over the MMIO backend so host
//! tests inject [`umbra_pal_test::mmio::MmioHandle`]; firmware uses `RealMmio`.

use peripheral_regs::{MmioAccess, RealMmio};

/// BKPSRAM Secure alias (NS base 0x2C00_0000 + 0x1000_0000 IDAU offset).
pub const BKPSRAM_SECURE_BASE: u32 = 0x3C00_0000;
/// Wrapped-blob length in bytes (DHUK-wrapped AES-128 key; see V3 in plan).
pub const WRAP_BLOB_LEN: usize = 16;
/// Marks a provisioned slot (vs cold-boot garbage). Any fixed 32-bit constant.
/// Bump this whenever the wrapped-blob format changes (e.g. key byte order), so
/// a stale blob from a previous format is re-provisioned instead of reused.
pub const SLOT_MAGIC: u32 = 0x0DC0_0002;

const MAGIC_OFFSET: u32 = 0x00;
const TAG_OFFSET: u32 = 0x04;
const BLOB_OFFSET: u32 = 0x08;

// Backup-domain bring-up registers (CMSIS stm32n657xx.h, HW-confirmed).
const RCC_MEMENR: u32 = 0x5602_824C;
const RCC_MEMENR_BKPSRAMEN: u32 = 1 << 6;
const PWR_DBPCR: u32 = 0x5602_482C;
const PWR_DBPCR_DBP: u32 = 1 << 0;
const PWR_BDCR2: u32 = 0x5602_4828;
const PWR_BDCR2_BKPRBSEN: u32 = 1 << 0;

/// One-time backup-domain bring-up: enable the BKPSRAM clock, unlock
/// backup-domain writes (DBP), enable VBAT retention. Call once at boot before
/// any slot write. Firmware-only raw MMIO (host tests never call this; the
/// sequence is validated on-target, see `w0-verified-values.md`).
pub fn init_backup_domain() {
    unsafe {
        // Enable BKPSRAM clock (read-modify-write: other AXISRAM enables live here).
        let memenr = core::ptr::read_volatile(RCC_MEMENR as *const u32);
        core::ptr::write_volatile(RCC_MEMENR as *mut u32, memenr | RCC_MEMENR_BKPSRAMEN);
        // Barrier so the clock is up before the PWR/BKPSRAM accesses.
        #[cfg(target_arch = "arm")]
        core::arch::asm!("dsb");
        // Unlock backup-domain writes.
        let dbpcr = core::ptr::read_volatile(PWR_DBPCR as *const u32);
        core::ptr::write_volatile(PWR_DBPCR as *mut u32, dbpcr | PWR_DBPCR_DBP);
        // Enable VBAT/Standby retention of BKPSRAM content.
        let bdcr2 = core::ptr::read_volatile(PWR_BDCR2 as *const u32);
        core::ptr::write_volatile(PWR_BDCR2 as *mut u32, bdcr2 | PWR_BDCR2_BKPRBSEN);
    }
}

/// One provisioning slot: provisioned marker, rotated-key tag, wrapped blob.
pub struct Slot {
    pub magic: u32,
    pub tag: u32,
    pub blob: [u8; WRAP_BLOB_LEN],
}

/// BKPSRAM slot accessor. Generic over the MMIO backend; default `RealMmio`
/// keeps the firmware call site (`Bkpsram::new()`) unchanged.
pub struct Bkpsram<M: MmioAccess = RealMmio> {
    mmio: M,
}

impl Bkpsram<RealMmio> {
    pub fn new() -> Self {
        Bkpsram {
            mmio: RealMmio::new(BKPSRAM_SECURE_BASE),
        }
    }
}

impl<M: MmioAccess> Bkpsram<M> {
    /// Host-test constructor — inject any `MmioAccess` backend.
    #[allow(dead_code)]
    pub fn new_with_mmio(mmio: M) -> Self {
        Bkpsram { mmio }
    }

    /// Write the slot: magic, tag, then the blob words (little-endian).
    /// Requires [`init_backup_domain`] to have run, else the writes drop.
    pub fn write_slot(&mut self, slot: &Slot) {
        self.mmio.write(MAGIC_OFFSET, slot.magic);
        self.mmio.write(TAG_OFFSET, slot.tag);
        let mut i = 0;
        while i < WRAP_BLOB_LEN {
            let w = u32::from_le_bytes(slot.blob[i..i + 4].try_into().unwrap());
            self.mmio.write(BLOB_OFFSET + i as u32, w);
            i += 4;
        }
    }

    /// Read the slot back (magic, tag, blob words).
    pub fn read_slot(&self) -> Slot {
        let magic = self.mmio.read(MAGIC_OFFSET);
        let tag = self.mmio.read(TAG_OFFSET);
        let mut blob = [0u8; WRAP_BLOB_LEN];
        let mut i = 0;
        while i < WRAP_BLOB_LEN {
            let w = self.mmio.read(BLOB_OFFSET + i as u32);
            blob[i..i + 4].copy_from_slice(&w.to_le_bytes());
            i += 4;
        }
        Slot { magic, tag, blob }
    }
}

#[cfg(test)]
mod tests {
    //! Host tests for the slot data path. `init_backup_domain` (raw MMIO to
    //! RCC/PWR) is firmware-only and validated on-target, not here.
    use super::*;
    use umbra_pal_test::mmio::MmioMem;

    /// A written slot must read back byte-for-byte (magic, tag, full blob) at
    /// the documented offsets (magic@0, tag@4, blob@8).
    #[test]
    fn slot_round_trips_magic_tag_blob() {
        let mem = MmioMem::new(BKPSRAM_SECURE_BASE);
        let mut bk = Bkpsram::new_with_mmio(mem.handle());
        let mut blob = [0u8; WRAP_BLOB_LEN];
        let mut i = 0;
        while i < WRAP_BLOB_LEN {
            blob[i] = (0xA0 + i) as u8;
            i += 1;
        }
        bk.write_slot(&Slot {
            magic: SLOT_MAGIC,
            tag: 0x1122_3344,
            blob,
        });

        let r = bk.read_slot();
        assert_eq!(r.magic, SLOT_MAGIC);
        assert_eq!(r.tag, 0x1122_3344);
        assert_eq!(r.blob, blob);
    }

    /// An unprovisioned (zeroed) slot reads magic 0 — distinguishable from
    /// `SLOT_MAGIC`, so provision-if-absent re-provisions after a cold boot.
    #[test]
    fn empty_slot_reads_zero_magic() {
        let mem = MmioMem::new(BKPSRAM_SECURE_BASE);
        let bk = Bkpsram::new_with_mmio(mem.handle());
        assert_eq!(bk.read_slot().magic, 0);
        assert_ne!(SLOT_MAGIC, 0);
    }
}
