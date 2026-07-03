//! XSPI2 write-back driver for enclave state-continuity sectors. The state region
//! sits at the top 1 MB of the 64 MB XSPI2 part (0x73F0_0000), OUTSIDE the MCE2
//! enclave region, so bytes are raw (integrity is the per-sector keyed MAC, not MCE2).
//! Reads are memory-mapped; writes/erases use the 1-1-1 (single-SPI) command path —
//! the one that latches WEL on this Nucleo (OPI WREN does not). HW sequence to be
//! brought up from the dropped `xspi.rs` at commit `ed48915^` (write_enable_spi_minimal
//! + subsector erase 0x21 + page program 0x12, 4-byte address, bounded polling).

use kernel::key_storage_server::state_continuity::MAX_STATE_SECTORS;

pub const STATE_REGION_BASE: u32 = 0x73F0_0000;
pub const PHYS_SECTOR_SIZE: usize = 0x2000; // 8 KB = two 4 KB subsectors
pub const SLOT_COUNT: usize = 2; // A/B double-buffer

#[derive(Debug, PartialEq, Eq)]
pub enum StateFlashError {
    IndexOutOfRange,
    SlotOutOfRange,
    /// HW write path not yet brought up on hardware.
    NotImplemented,
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

/// Address of the stored version word (trailer, second subsector).
pub fn state_version_addr(idx: usize, slot: usize) -> Result<u32, StateFlashError> {
    Ok(state_sector_addr(idx, slot)? + 4096)
}

/// Address of the stored 32-byte tag (trailer, right after the version word).
pub fn state_tag_addr(idx: usize, slot: usize) -> Result<u32, StateFlashError> {
    Ok(state_sector_addr(idx, slot)? + 4100)
}

/// Read back a committed sector's `(tag, version)` via memory-mapped access.
/// Memory-mapped reads need no XSPI command setup.
pub fn read_state_tag(idx: usize, slot: usize) -> Result<([u8; 32], u32), StateFlashError> {
    let vaddr = state_version_addr(idx, slot)?;
    let taddr = state_tag_addr(idx, slot)?;
    // SAFETY: address is bounds-checked and inside the mapped XSPI2 window.
    unsafe {
        let version = core::ptr::read_volatile(vaddr as *const u32);
        let mut tag = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            tag[i] = core::ptr::read_volatile((taddr + i as u32) as *const u8);
            i += 1;
        }
        Ok((tag, version))
    }
}

/// Erase + program one 4 KB ciphertext subsector and its trailer (version+tag) into
/// slot `slot` at logical index `idx`, via the 1-1-1 (single-SPI) command path.
///
/// NOT IMPLEMENTED — HW bring-up only (no host validation possible). The recipe
/// below is recovered from the dropped driver `drivers/src/xspi.rs` at commit
/// `ed48915^` (the 1-1-1 path that latches WEL on this Nucleo; OPI WREN does not).
///
/// Registers (XSPI2_BASE = 0x5802_A000): CR=0x000 (EN, ABORT, FMODE[29:28]),
/// SR=0x020 (TCF b1, BUSY b5), FCR=0x024 (clear-TCF b1), DLR=0x040 (len-1),
/// AR=0x048 (flash OFFSET = addr & 0x07FF_FFFF), DR=0x050, CCR=0x100, TCR=0x108,
/// IR=0x110. CCR modes: IMODE_1L=0b001, ADMODE_1L=0b001<<8, ADSIZE_4B=0b11<<12,
/// DMODE_1L=0b001<<24. Opcodes (1-1-1): WREN 0x06, RDSR 0x05 (WEL=b1, WIP=b0),
/// subsector-erase(4 KB) 0x21 (4-byte addr), page-program 0x12 (4-byte addr, 256 B).
///
/// Sequence:
///  1. Abort memory-mapped: CR |= ABORT; wait ABORT clear; CR = 0;
///     CR = FMODE_INDIRECT_WRITE (0<<28) | EN; settle.
///  2. For the ciphertext subsector, then the trailer subsector:
///     a. WREN (minimal): TCR=0; CCR=IMODE_1L; IR=0x06; wait BUSY=0.
///     b. Verify WEL: RDSR (0x05) → bit1==1, else Err(WriteEnableFailed).
///     c. Subsector erase: CCR=IMODE_1L|ADMODE_1L|ADSIZE_4B; IR=0x21;
///        AR=(sector_addr & 0x07FF_FFFF); wait BUSY=0; then poll WIP (RDSR b0)==0
///        (bounded, ~tens–hundreds of ms) else Err(EraseTimeout).
///     d. Page-program 256 B at a time (16 pages per 4 KB): per page WREN, then
///        CCR=IMODE_1L|ADMODE_1L|ADSIZE_4B|DMODE_1L; DLR=255; IR=0x12;
///        AR=page_addr; write 256 bytes to DR; wait TCF; poll WIP==0
///        else Err(ProgramTimeout).
///     Ciphertext subsector = `bytes` (4096 = 16 pages). Trailer subsector holds
///     `version` (LE u32) at +4096 and `tag` (32 B) at +4100 — one 36-byte program
///     into the second subsector's first page.
///  3. Re-enter memory-mapped read — THE RISKY STEP: restore the EXACT OPI read
///     config the FSBL/BootROM set up (WCCR/CCR/TCR + CR.FMODE=0b11), or subsequent
///     enclave loads from 0x7000_0000 fault. Capture that config once before the
///     first write and replay it here.
///
/// Recovered helpers to reuse verbatim from `ed48915^:xspi.rs`:
/// `write_enable_spi_minimal`, `read_status_register_in_spi`, `poll_wip`,
/// `wait_not_busy`/`wait_tcf` (all bounded — never infinite waits).
pub fn write_state_sector(
    _idx: usize,
    _slot: usize,
    _bytes: &[u8; 4096],
    _version: u32,
    _tag: &[u8; 32],
) -> Result<(), StateFlashError> {
    Err(StateFlashError::NotImplemented)
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
    }

    #[test]
    fn trailer_sits_in_the_second_subsector() {
        let s = state_sector_addr(2, 1).unwrap();
        assert_eq!(state_version_addr(2, 1).unwrap(), s + 4096);
        assert_eq!(state_tag_addr(2, 1).unwrap(), s + 4100);
    }

    #[test]
    fn out_of_range_is_rejected() {
        assert!(matches!(state_sector_addr(MAX_STATE_SECTORS, 0), Err(StateFlashError::IndexOutOfRange)));
        assert!(matches!(state_sector_addr(0, SLOT_COUNT), Err(StateFlashError::SlotOutOfRange)));
    }
}
