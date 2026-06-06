#![cfg(feature = "stm32l562")]
#![allow(dead_code, unused_imports)]

use peripheral_regs::MmioAccess;

use super::{
    OspiDriver, CMD_PAGE_PROGRAM, CMD_READ_STATUS, CMD_SECTOR_ERASE, CMD_WRITE_ENABLE,
    OCTOSPI_AR_OFFSET, OCTOSPI_CCR_OFFSET, OCTOSPI_CR_OFFSET, OCTOSPI_DLR_OFFSET,
    OCTOSPI_DR_OFFSET, OCTOSPI_FCR_OFFSET, OCTOSPI_IR_OFFSET, OCTOSPI_SR_OFFSET, STATUS_WIP_MASK,
};

impl<M: MmioAccess> OspiDriver<M> {
    // -----------------------------------------------------------------------
    // Indirect-mode primitives for MX25LM51245G in reset-state SPI
    // -----------------------------------------------------------------------

    /// Issue a no-data command (e.g. WREN, WRDI).
    /// FMODE=00 (indirect-write), IMODE=1 (1-line), no address, no data.
    /// Triggers by writing IR, then busy-waits and clears TCF.
    pub fn issue_command_no_data(&self, cmd: u8) -> Result<(), &'static str> {
        // 1. Disable OCTOSPI before reconfiguring.
        let cr = self.mmio.read(OCTOSPI_CR_OFFSET);
        self.mmio.write(OCTOSPI_CR_OFFSET, cr & !(1 << 0));

        // 2. FMODE = 00 (indirect-write): clear bits [29:28], keep EN=0.
        let mut cr2 = self.mmio.read(OCTOSPI_CR_OFFSET);
        cr2 &= !(0b11 << 28);
        self.mmio.write(OCTOSPI_CR_OFFSET, cr2);

        // 3. CCR: IMODE=1 (instruction on 1 line, bits [1:0]=01), no address, no data.
        self.mmio.write(OCTOSPI_CCR_OFFSET, 0b01u32);

        // 4. EN=1 — must be set before writing the trigger register (IR).
        // Per RM0438 §5.7: in indirect mode the transfer starts when the
        // trigger register (IR when ADMODE=0) is written, so EN must
        // already be 1 at that point.
        let cr3 = self.mmio.read(OCTOSPI_CR_OFFSET);
        self.mmio.write(OCTOSPI_CR_OFFSET, cr3 | (1 << 0));

        // 5. Write IR — triggers the transfer (ADMODE=0, so IR is the trigger).
        self.mmio.write(OCTOSPI_IR_OFFSET, cmd as u32);

        // Wait for BUSY (SR bit 5) to clear.
        for _ in 0..1_000_000 {
            let sr = self.mmio.read(OCTOSPI_SR_OFFSET);
            if (sr & (1 << 5)) == 0 {
                // Clear Transfer Complete Flag (FCR bit 1 = CTCF).
                self.mmio.write(OCTOSPI_FCR_OFFSET, 1 << 1);
                // SAFETY: barrier — completion ordering for the indirect
                // transfer before the caller observes Ok(()).
                unsafe {
                    core::arch::asm!("dsb sy", options(nostack, preserves_flags));
                }
                return Ok(());
            }
        }
        Err("OSPI BUSY timeout (no-data cmd)")
    }

    /// Read the MX25LM51245G Status Register 1 (READ STATUS, 0x05).
    /// FMODE=01 (indirect-read), IMODE=1, DMODE=1, DLR=0 (1 byte).
    pub fn read_status_register(&self) -> u8 {
        // 0. Clear stale flags (TEF|TCF|SMF|TOF) in FCR so a prior
        // transfer error doesn't prevent the new transfer from
        // asserting TCF. Write-1-to-clear.
        self.mmio.write(OCTOSPI_FCR_OFFSET, 0x1B);

        // 1. Disable OCTOSPI.
        let cr = self.mmio.read(OCTOSPI_CR_OFFSET);
        self.mmio.write(OCTOSPI_CR_OFFSET, cr & !(1 << 0));

        // 2. FMODE = 01 (indirect-read): bits [29:28] = 01, keep EN=0.
        let mut cr2 = self.mmio.read(OCTOSPI_CR_OFFSET);
        cr2 &= !(0b11 << 28);
        cr2 |= 0b01 << 28;
        self.mmio.write(OCTOSPI_CR_OFFSET, cr2);

        // 3. DLR = 0 (transfer 1 byte; DLR holds length-1).
        self.mmio.write(OCTOSPI_DLR_OFFSET, 0);

        // 3. CCR: IMODE=1 (bits [1:0]=01), DMODE=1 (bits [26:24]=001).
        // Note: ADMODE=0 (no address) since READ STATUS has no address phase.
        let ccr = (0b01u32 << 0)          // IMODE = 1-line
                | (0b001u32 << 24); // DMODE = 1-line
        self.mmio.write(OCTOSPI_CCR_OFFSET, ccr);

        // 4. EN=1 — must be set before writing IR (the trigger register).
        // Per RM0438 §5.7: ADMODE=0 so IR is the trigger; EN must
        // already be 1 when IR is written.
        let cr3 = self.mmio.read(OCTOSPI_CR_OFFSET);
        self.mmio.write(OCTOSPI_CR_OFFSET, cr3 | (1 << 0));

        // 5. Write IR = 0x05 (READ STATUS) — triggers the transfer.
        self.mmio.write(OCTOSPI_IR_OFFSET, CMD_READ_STATUS as u32);

        // Wait for TCF (Transfer Complete Flag, SR bit 1).
        for _ in 0..1_000_000 {
            let sr = self.mmio.read(OCTOSPI_SR_OFFSET);
            if (sr & (1 << 1)) != 0 {
                // Read DR as a byte (volatile u8 read from DR base address).
                // SAFETY: DR is a byte-addressable data port in indirect-read
                // mode. `MmioAccess` only exposes 32-bit access, so the byte
                // read stays as a raw volatile against `base + DR_OFFSET`.
                let val = unsafe {
                    let dr_ptr = (self.base + OCTOSPI_DR_OFFSET) as *const u8;
                    core::ptr::read_volatile(dr_ptr)
                };
                // Clear TCF via FCR.CTCF (bit 1).
                self.mmio.write(OCTOSPI_FCR_OFFSET, 1 << 1);
                // SAFETY: barrier — DR byte read must retire before caller.
                unsafe {
                    core::arch::asm!("dsb sy", options(nostack, preserves_flags));
                }
                return val;
            }
        }
        // Timeout: return 0xFF (WIP=1 in all 1s is a safe pessimistic value).
        0xFF
    }

    /// Poll WIP (Write-In-Progress, bit 0 of Status Register 1) until clear.
    pub fn wait_wip(&self, timeout_loops: u32) -> Result<(), &'static str> {
        for _ in 0..timeout_loops {
            if (self.read_status_register() & STATUS_WIP_MASK) == 0 {
                return Ok(());
            }
        }
        Err("OSPI WIP timeout")
    }

    /// Erase a 4 KB sector at `flash_addr` (3-byte address, SE command 0x20).
    /// Sends WREN first, then the erase command, then waits for WIP clear.
    pub fn sector_erase_4k(&self, flash_addr: u32) -> Result<(), &'static str> {
        // Write-enable.
        self.issue_command_no_data(CMD_WRITE_ENABLE)?;

        // 1. Disable OCTOSPI.
        let cr = self.mmio.read(OCTOSPI_CR_OFFSET);
        self.mmio.write(OCTOSPI_CR_OFFSET, cr & !(1 << 0));

        // 2. FMODE = 00 (indirect-write), keep EN=0.
        let mut cr2 = self.mmio.read(OCTOSPI_CR_OFFSET);
        cr2 &= !(0b11 << 28);
        self.mmio.write(OCTOSPI_CR_OFFSET, cr2);

        // 3. CCR: IMODE=1, ADMODE=1 (bits [12:8]=001), ADSIZE=2 (bits [13:12]=10 → 24-bit).
        // ADMODE bits [12:8]? No — per RM0438 / SVD for OCTOSPI CCR:
        // IMODE = bits [2:0] (001 = 1 line)
        // ADMODE = bits [10:8] (001 = 1 line)
        // ADSIZE = bits [13:12](10 = 24-bit / 3-byte)
        // DMODE = bits [26:24](000 = none)
        let ccr = (0b001u32 << 0)   // IMODE = 1-line  [2:0]
                | (0b001u32 << 8)   // ADMODE = 1-line [10:8]
                | (0b10u32  << 12); // ADSIZE = 24-bit [13:12]
        self.mmio.write(OCTOSPI_CCR_OFFSET, ccr);

        // 4. EN=1 — must be set before writing IR and AR.
        // Per RM0438 §5.7: ADMODE≠0 so AR is the trigger; EN must
        // already be 1 when AR is written.
        let cr3 = self.mmio.read(OCTOSPI_CR_OFFSET);
        self.mmio.write(OCTOSPI_CR_OFFSET, cr3 | (1 << 0));

        // 5. Write IR = 0x20 (Sector Erase 4K).
        self.mmio.write(OCTOSPI_IR_OFFSET, CMD_SECTOR_ERASE as u32);

        // 6. Write AR = lower 24 bits of flash_addr — triggers the transfer
        // (ADMODE≠0, so AR write is the trigger per RM0438 §5.7).
        self.mmio.write(OCTOSPI_AR_OFFSET, flash_addr & 0x00FF_FFFF);

        // Wait for BUSY clear, tracking whether we succeeded.
        let mut busy_ok = false;
        for _ in 0..1_000_000 {
            let sr = self.mmio.read(OCTOSPI_SR_OFFSET);
            if (sr & (1 << 5)) == 0 {
                self.mmio.write(OCTOSPI_FCR_OFFSET, 1 << 1);
                // SAFETY: barrier — erase trigger must retire before WIP poll.
                unsafe {
                    core::arch::asm!("dsb sy", options(nostack, preserves_flags));
                }
                busy_ok = true;
                break;
            }
        }

        if !busy_ok {
            return Err("OSPI BUSY timeout (erase cmd)");
        }

        // Wait for the erase to complete (flash WIP clear).
        self.wait_wip(100_000_000)
    }

    /// Program up to 256 bytes into a single flash page at `flash_addr`
    /// (must be page-aligned; `data` must be 1..=256 bytes). Sends WREN,
    /// then PAGE PROGRAM (0x02) with 3-byte address and data, then waits
    /// for WIP clear.
    pub fn page_program(&self, flash_addr: u32, data: &[u8]) -> Result<(), &'static str> {
        if data.is_empty() || data.len() > 256 {
            return Err("page_program: data length must be 1..=256");
        }

        // Write-enable.
        self.issue_command_no_data(CMD_WRITE_ENABLE)?;

        // 1. Disable OCTOSPI.
        let cr = self.mmio.read(OCTOSPI_CR_OFFSET);
        self.mmio.write(OCTOSPI_CR_OFFSET, cr & !(1 << 0));

        // 2. FMODE = 00 (indirect-write), keep EN=0.
        let mut cr2 = self.mmio.read(OCTOSPI_CR_OFFSET);
        cr2 &= !(0b11 << 28);
        self.mmio.write(OCTOSPI_CR_OFFSET, cr2);

        // 3. DLR = len - 1.
        self.mmio.write(OCTOSPI_DLR_OFFSET, (data.len() as u32) - 1);

        // 3. CCR: IMODE=1, ADMODE=1, ADSIZE=2 (24-bit), DMODE=1.
        let ccr = (0b001u32 << 0)    // IMODE  = 1-line
                | (0b001u32 << 8)    // ADMODE = 1-line
                | (0b10u32  << 12)   // ADSIZE = 24-bit
                | (0b001u32 << 24); // DMODE  = 1-line
        self.mmio.write(OCTOSPI_CCR_OFFSET, ccr);

        // 4. EN=1 — must be set before writing IR and AR.
        // Per RM0438 §5.7: ADMODE≠0 so AR is the trigger; EN must
        // already be 1 when AR is written.
        let cr3 = self.mmio.read(OCTOSPI_CR_OFFSET);
        self.mmio.write(OCTOSPI_CR_OFFSET, cr3 | (1 << 0));

        // 5. Write IR = 0x02 (Page Program).
        self.mmio.write(OCTOSPI_IR_OFFSET, CMD_PAGE_PROGRAM as u32);

        // 6. Write AR = lower 24 bits of flash_addr — triggers the data phase
        // (ADMODE≠0 and DMODE≠0: AR write arms the transfer; data is driven
        // by the DR pump below).
        self.mmio.write(OCTOSPI_AR_OFFSET, flash_addr & 0x00FF_FFFF);

        // 7. Push each byte through the DR byte port, gated on FTF (SR bit 2).
        // The OCTOSPI FIFO is 32 bytes deep; without waiting for FTF the
        // FIFO fills after byte 32 and subsequent writes are silently
        // discarded, corrupting bytes 33..256 of a 256-byte page program.
        // SAFETY: DR is a byte-addressable data port. `MmioAccess` only
        // exposes 32-bit access; the byte writes stay as raw volatile
        // against `base + DR_OFFSET` to preserve FIFO byte semantics.
        let dr_ptr = (self.base + OCTOSPI_DR_OFFSET) as *mut u8;
        for &byte in data {
            for _ in 0..1_000_000 {
                if (self.mmio.read(OCTOSPI_SR_OFFSET) & (1 << 2)) != 0 {
                    break; // FTF set: FIFO has space
                }
            }
            unsafe {
                core::ptr::write_volatile(dr_ptr, byte);
            }
        }

        // Wait for BUSY clear, tracking whether we succeeded.
        let mut busy_ok = false;
        for _ in 0..1_000_000 {
            let sr = self.mmio.read(OCTOSPI_SR_OFFSET);
            if (sr & (1 << 5)) == 0 {
                self.mmio.write(OCTOSPI_FCR_OFFSET, 1 << 1);
                // SAFETY: barrier — page-program trigger must retire before WIP poll.
                unsafe {
                    core::arch::asm!("dsb sy", options(nostack, preserves_flags));
                }
                busy_ok = true;
                break;
            }
        }

        if !busy_ok {
            return Err("OSPI BUSY timeout (page program)");
        }

        // Wait for flash write to complete.
        self.wait_wip(10_000_000)
    }

    /// Issue a WRITE ENABLE (WREN, opcode 0x06) command in indirect mode.
    /// Convenience wrapper around `issue_command_no_data` for the MX25LM51245G
    /// WREN requirement. Must be called before every page-program boundary
    /// in the OTFDEC cipher pass because OCTOSPI on STM32L5 has no automatic
    /// WREN re-issue in memory-mapped write mode.
    pub fn write_enable(&self) -> Result<(), &'static str> {
        self.issue_command_no_data(CMD_WRITE_ENABLE)
    }
}

// L562 transfer-layer tests live in a sibling file. The whole file is
// already `#![cfg(feature = "stm32l562")]`, so a plain `#[cfg(test)]`
// gate is sufficient — the test module disappears entirely when the
// feature is off because the parent module is not compiled at all.
#[cfg(test)]
#[path = "transfer_l562_tests.rs"]
mod l562_tests;
