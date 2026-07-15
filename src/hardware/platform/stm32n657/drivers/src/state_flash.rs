//! XSPI2 write-back driver for enclave state-continuity sectors. The state region
//! sits at the top 1 MB of the 64 MB XSPI2 part (0x73F0_0000), OUTSIDE the MCE2
//! enclave region, so bytes are raw ciphertext (freshness+integrity are the keyed
//! root in the trusted TAMP anchor, not MCE2). Reads are memory-mapped; writes use
//! the 1-1-1 (single-SPI) command path — the chip stays in 1-1-1 SPI the whole time
//! (the boot never enters OPI), so there is no mode dance. Root model: one 4 KB
//! subsector per A/B slot, no version/tag trailer. HW-verified 2026-07-03.

use crate::xspi::Xspi2;
use kernel::key_storage_server::state_continuity::MAX_STATE_SECTORS;

pub const STATE_REGION_BASE: u32 = 0x73F0_0000;
pub const PHYS_SECTOR_SIZE: usize = 0x1000; // 4 KB = one NOR subsector = one A/B slot
pub const SLOT_COUNT: usize = 2; // A/B double-buffer

/// WIP-poll budget (~150k loops per ms at -O0; a 4 KB subsector erase is <~100 ms).
const POLL_MAX: u32 = 3_000_000;

/// Enclave-update A/B slots (secure remote update). Two 64 KB windows below the
/// state-continuity region, each holding one enclave blob. `umbra_enclave_create(0)`
/// authenticates both and runs the highest version; `umbra_enclave_update` writes the
/// inactive one. Works alongside `interenclave_overlay` (the DMA-free version probe
/// reads flash directly, so it needs neither the ESS allocator nor the overlay window).
/// The update path's anti-rollback (`version > active`) is meaningful only with
/// `enclave_version_bind` ON — see ADR 013.
pub const ENCLAVE_SLOT_A: u32 = 0x73D0_0000;
pub const ENCLAVE_SLOT_B: u32 = 0x73D8_0000;
pub const ENCLAVE_SLOT_SIZE: u32 = 0x1_0000; // 64 KB

/// Flash base of enclave slot `slot` (0 = A, 1 = B).
pub fn enclave_slot_base(slot: usize) -> Result<u32, StateFlashError> {
    match slot {
        0 => Ok(ENCLAVE_SLOT_A),
        1 => Ok(ENCLAVE_SLOT_B),
        _ => Err(StateFlashError::SlotOutOfRange),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum StateFlashError {
    IndexOutOfRange,
    SlotOutOfRange,
    WriteEnableFailed,
    EraseTimeout,
    ProgramTimeout,
}

/// Flash address of the ciphertext subsector for logical sector `idx`, slot `slot`.
pub fn state_sector_addr(idx: usize, slot: usize) -> Result<u32, StateFlashError> {
    if idx >= MAX_STATE_SECTORS {
        return Err(StateFlashError::IndexOutOfRange);
    }
    if slot >= SLOT_COUNT {
        return Err(StateFlashError::SlotOutOfRange);
    }
    Ok(STATE_REGION_BASE + ((idx * SLOT_COUNT + slot) * PHYS_SECTOR_SIZE) as u32)
}

/// Erase + program one 4 KB ciphertext subsector into slot `slot` at logical index
/// `idx`, via the 1-1-1 SPI command path. Assumes XSPI2 is memory-mapped on entry
/// (the boot's `init_external_flash` config); restores memory-mapped reads on every
/// exit path so enclave loads from `0x7000_0000` keep working. HW-verified.
pub fn write_state_sector(idx: usize, slot: usize, bytes: &[u8; 4096]) -> Result<(), StateFlashError> {
    let base = state_sector_addr(idx, slot)?;
    let x = Xspi2::new();
    let _saved = x.enter_indirect_mode(); // mem-map -> indirect-write
    let r = write_sector_inner(&x, base, bytes);
    x.restore_memory_mapped_1_1_1(); // ALWAYS restore, even on error, or loads fault
    invalidate_dcache_region(base, 4096); // read-after-write coherency (see below)
    r
}

/// Invalidate the D-cache over `[base, base+len)` so a memory-mapped read AFTER an
/// indirect flash write sees fresh content. The M55 D-cache is enabled at boot and
/// the indirect write bypasses it, so a stale line would otherwise be returned (a
/// real hazard for `checkpoint`, which writes sectors then re-reads them for the
/// root). `DCIMVAC` = invalidate-by-VA to PoC (0xE000_EF5C); the state region is
/// CPU-read-only, so there are no dirty lines to lose.
pub fn invalidate_dcache_region(base: u32, len: u32) {
    const DCIMVAC: *mut u32 = 0xE000_EF5C as *mut u32;
    const LINE: u32 = 32; // Cortex-M55 D-cache line size
    cortex_m::asm::dsb();
    let mut a = base & !(LINE - 1);
    let end = base + len;
    while a < end {
        // SAFETY: DCIMVAC is the fixed system-control D-cache maintenance register.
        unsafe { core::ptr::write_volatile(DCIMVAC, a) };
        a += LINE;
    }
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
}

fn write_sector_inner(x: &Xspi2, base: u32, bytes: &[u8; 4096]) -> Result<(), StateFlashError> {
    // Erase the 4 KB subsector.
    write_enable_verified(x)?;
    x.subsector_erase_4k_spi(base).map_err(|_| StateFlashError::EraseTimeout)?;
    x.poll_wip_spi(POLL_MAX).map_err(|_| StateFlashError::EraseTimeout)?;
    // Program 256 B at a time (16 pages per 4 KB subsector).
    let mut off: usize = 0;
    while off < 4096 {
        write_enable_verified(x)?;
        x.page_program_spi(base + off as u32, &bytes[off..off + 256])
            .map_err(|_| StateFlashError::ProgramTimeout)?;
        x.poll_wip_spi(POLL_MAX).map_err(|_| StateFlashError::ProgramTimeout)?;
        off += 256;
    }
    Ok(())
}

/// Load-bearing write-enable: WREN, then RDSR to CONFIRM WEL, leaving FMODE in
/// indirect-write for the following erase/program. HW-verified 2026-07-03 that the
/// RDSR (with its FMODE write→read→write toggle) between WREN and the operation is
/// REQUIRED — without it the program returns ok but silently writes 0xFF.
fn write_enable_verified(x: &Xspi2) -> Result<(), StateFlashError> {
    x.switch_fmode_minimal(false); // indirect-write
    x.write_enable_spi_minimal().map_err(|_| StateFlashError::WriteEnableFailed)?;
    x.switch_fmode_minimal(true); // indirect-read
    let sr = x
        .read_status_register_spi_minimal()
        .map_err(|_| StateFlashError::WriteEnableFailed)?;
    if sr & 0x02 == 0 {
        return Err(StateFlashError::WriteEnableFailed); // WEL not latched
    }
    x.switch_fmode_minimal(false); // back to indirect-write for the operation
    Ok(())
}

/// Erase + program `bytes` into enclave slot `slot`, starting at its base. `bytes`
/// length must be non-zero, a multiple of 4096, and ≤ ENCLAVE_SLOT_SIZE. Uses the
/// same 1-1-1 SPI indirect path as `write_state_sector`; restores memory-mapped
/// reads on every exit so enclave loads from 0x7000_0000 keep working. Un-erased NOR
/// reads non-deterministically, so callers MUST pad the blob to a whole-sector,
/// zero-filled buffer (the digest/measurement over the slot must be stable).
pub fn write_enclave_slot(slot: usize, bytes: &[u8]) -> Result<(), StateFlashError> {
    let base = enclave_slot_base(slot)?;
    if bytes.is_empty() || bytes.len() % 4096 != 0 || bytes.len() as u32 > ENCLAVE_SLOT_SIZE {
        return Err(StateFlashError::IndexOutOfRange);
    }
    // The XSPI2 write path (indirect mode, WREN, erase/program, D-cache barriers) is
    // arm-only. On host we compile it out — the address math + input guards above are
    // the only host-testable surface. Mirrors `hash_sector` in state_store.rs.
    #[cfg(not(target_arch = "arm"))]
    {
        let _ = base;
        Ok(())
    }
    #[cfg(target_arch = "arm")]
    {
        let x = Xspi2::new();
        let _saved = x.enter_indirect_mode();
        let mut r = Ok(());
        let mut off = 0usize;
        while off < bytes.len() {
            let mut page = [0u8; 4096];
            page.copy_from_slice(&bytes[off..off + 4096]);
            if let Err(e) = write_sector_inner(&x, base + off as u32, &page) {
                r = Err(e);
                break;
            }
            off += 4096;
        }
        x.restore_memory_mapped_1_1_1();
        invalidate_dcache_region(base, bytes.len() as u32);
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sector_addr_is_erase_aligned_and_in_region() {
        let a = state_sector_addr(0, 0).unwrap();
        assert_eq!(a, STATE_REGION_BASE);
        assert_eq!(a % 0x1000, 0, "must be 4 KB erase-aligned");
        // last valid sector still inside the 1 MB region
        let last = state_sector_addr(MAX_STATE_SECTORS - 1, SLOT_COUNT - 1).unwrap();
        assert!(last + PHYS_SECTOR_SIZE as u32 <= STATE_REGION_BASE + 0x10_0000);
    }

    #[test]
    fn ab_slots_and_indices_never_overlap() {
        let a0 = state_sector_addr(3, 0).unwrap();
        let a1 = state_sector_addr(3, 1).unwrap();
        let b0 = state_sector_addr(4, 0).unwrap();
        assert_eq!(a1 - a0, PHYS_SECTOR_SIZE as u32);
        assert_eq!(b0 - a0, (SLOT_COUNT as u32) * PHYS_SECTOR_SIZE as u32);
        // every slot address is its own 4 KB subsector (erasable independently)
        assert_eq!(a0 % 0x1000, 0);
        assert_eq!(a1 % 0x1000, 0);
    }

    #[test]
    fn out_of_range_is_rejected() {
        assert!(matches!(state_sector_addr(MAX_STATE_SECTORS, 0), Err(StateFlashError::IndexOutOfRange)));
        assert!(matches!(state_sector_addr(0, SLOT_COUNT), Err(StateFlashError::SlotOutOfRange)));
    }

    #[test]
    fn enclave_slots_are_distinct_and_erase_aligned() {
        assert_eq!(enclave_slot_base(0).unwrap(), ENCLAVE_SLOT_A);
        assert_eq!(enclave_slot_base(1).unwrap(), ENCLAVE_SLOT_B);
        assert_eq!(ENCLAVE_SLOT_A % 0x1000, 0);
        assert_eq!(ENCLAVE_SLOT_B % 0x1000, 0);
        assert!(ENCLAVE_SLOT_A + ENCLAVE_SLOT_SIZE <= ENCLAVE_SLOT_B, "slots overlap");
        assert!(ENCLAVE_SLOT_B + ENCLAVE_SLOT_SIZE <= STATE_REGION_BASE, "slot collides state region");
        assert!(matches!(enclave_slot_base(2), Err(StateFlashError::SlotOutOfRange)));
    }

    #[test]
    fn write_enclave_slot_rejects_bad_lengths() {
        // NOTE: these inputs are rejected by the length guard BEFORE any Xspi2 access,
        // so they are safe to run on host (they return Err without touching hardware).
        assert!(matches!(write_enclave_slot(0, &[]), Err(StateFlashError::IndexOutOfRange)));
        assert!(matches!(write_enclave_slot(0, &[0u8; 100]), Err(StateFlashError::IndexOutOfRange)));
        assert!(matches!(write_enclave_slot(2, &[0u8; 4096]), Err(StateFlashError::SlotOutOfRange)));
    }
}
