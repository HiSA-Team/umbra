#![cfg(feature = "stm32l562")]
#![allow(dead_code, unused_imports)]

use peripheral_regs::MmioAccess;

use super::{
    OspiDriver, CMD_PAGE_PROGRAM, OCTOSPI_CCR_OFFSET, OCTOSPI_CR_OFFSET, OCTOSPI_IR_OFFSET,
    OCTOSPI_SR_OFFSET, OCTOSPI_TCR_OFFSET, OCTOSPI_WCCR_OFFSET, OCTOSPI_WIR_OFFSET,
    OCTOSPI_WTCR_OFFSET,
};

impl<M: MmioAccess> OspiDriver<M> {
    /// Enable memory-mapped reads using legacy 1-1-1 FAST_READ (0x0B) with
    /// 8 dummy cycles and 3-byte addressing. This is the reset-default MX25LM51245G
    /// mode — no flash config register writes needed, which keeps Stage 1 a
    /// minimal gate over "OCTOSPI registers are reachable + memory-mapped path
    /// returns real flash bytes". Stage 2+ (OTFDEC integration) is the correct
    /// place to add the OPI DTR entry sequence
    /// (WRITE_CFG_REG_2 → CR2_DTR_OPI_ENABLE → OCTAL_IO_DTR_READ_CMD 0xEE11)
    /// that the STMicro STM32CubeL5 OTFDEC example uses.
    /// After this returns `Ok(())`, reads from `OCTOSPI_MEMMAP_BASE` issue
    /// real flash fetches at 1-1-1 FAST_READ speed.
    pub fn enable_memory_mapped_octa(&self) -> Result<(), &'static str> {
        // --- 1. Disable OCTOSPI while reconfiguring CCR/TCR/IR ---
        let cr = self.mmio.read(OCTOSPI_CR_OFFSET);
        self.mmio.write(OCTOSPI_CR_OFFSET, cr & !(1 << 0));

        // --- 2. CCR: 1-1-1 FAST_READ command shape ---
        // IMODE = 1 (instruction 1-line) [bits 1:0] = 01
        // ADMODE = 1 (address 1-line) [bits 10:8] = 001
        // ADSIZE = 2 (24-bit address) [bits 13:12] = 10
        // DMODE = 1 (data 1-line) [bits 26:24] = 001
        let ccr = (0b01u32 << 0) | (0b001u32 << 8) | (0b10u32 << 12) | (0b001u32 << 24);
        self.mmio.write(OCTOSPI_CCR_OFFSET, ccr);

        // --- 3. TCR: 8 dummy cycles (MX25LM51245G FAST_READ default) ---
        self.mmio.write(OCTOSPI_TCR_OFFSET, 8);

        // --- 4. IR: FAST_READ opcode 0x0B (3-byte address variant) ---
        self.mmio.write(OCTOSPI_IR_OFFSET, 0x0B);

        // --- 5. CR.FMODE = 11 (memory-mapped), EN=1 ---
        let mut cr2 = self.mmio.read(OCTOSPI_CR_OFFSET);
        cr2 &= !(0b11 << 28); // clear FMODE
        cr2 |= 0b11 << 28; // FMODE = memory-mapped
        cr2 |= 1 << 0; // EN
        self.mmio.write(OCTOSPI_CR_OFFSET, cr2);

        // --- 6. BUSY wait with bounded timeout ---
        for _ in 0..1_000_000 {
            let sr = self.mmio.read(OCTOSPI_SR_OFFSET);
            if (sr & (1 << 5)) == 0 {
                // BUSY bit cleared
                // SAFETY: barrier instructions — required by the OCTOSPI
                // state machine before memory-mapped reads can be issued.
                unsafe {
                    core::arch::asm!("dsb sy", options(nostack, preserves_flags));
                    core::arch::asm!("isb sy", options(nostack, preserves_flags));
                }
                return Ok(());
            }
        }
        Err("OSPI BUSY timeout")
    }

    // -----------------------------------------------------------------------
    // Memory-mapped write-read mode (OTFDEC integration path)
    // -----------------------------------------------------------------------

    /// Configure OCTOSPI for memory-mapped mode with BOTH a read command
    /// (FAST_READ 0x0B, 3-byte address, 8 dummy cycles via CCR/TCR/IR) and a
    /// write command (Page Program 0x02, 3-byte address, 0 dummy cycles via
    /// WCCR/WTCR/WIR). CR.FMODE is set to 11 (memory-mapped) on return.
    /// After this returns `Ok(())`, reads from `OCTOSPI_MEMMAP_BASE` issue
    /// FAST_READ sequences; writes to `OCTOSPI_MEMMAP_BASE` issue Page Program
    /// sequences. This is the mode required by `HAL_OTFDEC_Cipher`, which
    /// drives enciphered data into flash via `*extMem_ptr = *in_ptr`.
    /// # WREN / write-enable responsibility
    /// The OCTOSPI peripheral on STM32L5 has NO automatic write-enable
    /// mechanism (no WREN, AUTOPOLL, or WPOL auto-issue feature — confirmed
    /// by exhaustive SVD search of CR fields: FMODE, PMM, APMS, TOIE, SMIE,
    /// FTIE, TCIE, TEIE, FTHRES, FSEL, DQM, TCEN, DMAEN, ABORT, EN — none
    /// auto-issue WREN). The flash MX25LM51245G requires a WREN (0x06)
    /// command before EACH page-program boundary. Therefore:
    /// * This helper configures the mode only — it does NOT issue WREN.
    /// * Task 2c (the OTFDEC encipherment loop) MUST call
    /// `disable_memory_mapped()` → `issue_command_no_data(CMD_WRITE_ENABLE)`
    /// → re-enable memory-mapped mode before each 256-byte page boundary
    /// write if writes actually touch flash (not just OTFDEC key loading).
    /// # SVD verification (all offsets against STM32L562.svd OCTOSPI1 block)
    /// | Register | Offset | Key fields verified |
    /// |----------|----------|------------------------------------------------|
    /// | CCR | 0x100 | IMODE[2:0], ADMODE[10:8], ADSIZE[13:12], DMODE[26:24] |
    /// | TCR | 0x108 | DCYC[4:0] |
    /// | IR | 0x110 | INSTRUCTION[31:0] |
    /// | WCCR | 0x180 | same field positions as CCR (verified) |
    /// | WTCR | 0x188 | DCYC[4:0] (same as TCR; explicitly zeroed here)|
    /// | WIR | 0x190 | INSTRUCTION[31:0] |
    /// The draft used `OCTOSPI_WCCR_OFFSET + 0x10` for WIR; this resolves to
    /// 0x190, which matches the SVD — corrected to use the named constant
    /// `OCTOSPI_WIR_OFFSET`. WCCR bit positions match CCR — no correction
    /// needed. WTCR exists and is explicitly zeroed (Page Program: 0 dummy
    /// cycles).
    pub fn enable_memory_mapped_write_read(&self) -> Result<(), &'static str> {
        // 1. Disable OCTOSPI while reconfiguring CCR/TCR/IR/WCCR/WTCR/WIR.
        let cr = self.mmio.read(OCTOSPI_CR_OFFSET);
        self.mmio.write(OCTOSPI_CR_OFFSET, cr & !(1 << 0));

        // 2. READ shape — CCR: 1-1-1 FAST_READ command
        // IMODE = 001 (instruction on 1 line) [bits 2:0]
        // ADMODE = 001 (address on 1 line) [bits 10:8]
        // ADSIZE = 10 (24-bit / 3-byte addr) [bits 13:12]
        // DMODE = 001 (data on 1 line) [bits 26:24]
        let rccr = (0b001u32 << 0) | (0b001u32 << 8) | (0b10u32 << 12) | (0b001u32 << 24);
        self.mmio.write(OCTOSPI_CCR_OFFSET, rccr);

        // 3. TCR: 8 dummy cycles for FAST_READ (MX25LM51245G requirement).
        self.mmio.write(OCTOSPI_TCR_OFFSET, 8);

        // 4. IR: FAST_READ opcode 0x0B.
        self.mmio.write(OCTOSPI_IR_OFFSET, 0x0B);

        // 5. WRITE shape — WCCR: 1-1-1 Page Program command
        // Bit positions are identical to CCR (SVD-verified).
        // IMODE = 001 [bits 2:0]
        // ADMODE = 001 [bits 10:8]
        // ADSIZE = 10 [bits 13:12]
        // DMODE = 001 [bits 26:24]
        let wccr = (0b001u32 << 0) | (0b001u32 << 8) | (0b10u32 << 12) | (0b001u32 << 24);
        self.mmio.write(OCTOSPI_WCCR_OFFSET, wccr);

        // 6. WTCR: 0 dummy cycles for Page Program (explicitly zeroed;
        // WTCR exists at 0x188 per SVD, DCYC field [4:0]).
        self.mmio.write(OCTOSPI_WTCR_OFFSET, 0);

        // 7. WIR: Page Program opcode 0x02
        // (SVD: WIR at 0x190; draft's +0x10 arithmetic was correct).
        self.mmio.write(OCTOSPI_WIR_OFFSET, CMD_PAGE_PROGRAM as u32);

        // 8. CR.FMODE = 11 (memory-mapped), EN=1.
        let mut cr2 = self.mmio.read(OCTOSPI_CR_OFFSET);
        cr2 &= !(0b11 << 28); // clear FMODE
        cr2 |= 0b11 << 28; // FMODE = 11 (memory-mapped)
        cr2 |= 1 << 0; // EN=1
        self.mmio.write(OCTOSPI_CR_OFFSET, cr2);

        // 9. Wait for BUSY (SR bit 5) to clear, then issue barriers so
        // subsequent memory-mapped accesses see the new configuration.
        for _ in 0..1_000_000 {
            let sr = self.mmio.read(OCTOSPI_SR_OFFSET);
            if (sr & (1 << 5)) == 0 {
                // SAFETY: barriers — required by the OCTOSPI state machine.
                unsafe {
                    core::arch::asm!("dsb sy", options(nostack, preserves_flags));
                    core::arch::asm!("isb sy", options(nostack, preserves_flags));
                }
                return Ok(());
            }
        }
        Err("OSPI BUSY timeout (mm write-read)")
    }

    /// Safely exit memory-mapped mode.
    /// Per RM0438 §5, the ABORT bit (CR bit 1) must be asserted and BUSY
    /// polled to idle before CR.EN can be safely cleared from FMODE=11.
    /// Clearing EN directly while a memory-mapped prefetch is in flight can
    /// leave the peripheral stuck BUSY.
    /// Used by Task 2c between page-program boundary writes to issue a
    /// WREN in indirect mode (memory-mapped cannot auto-issue WREN on L5).
    pub fn disable_memory_mapped(&self) -> Result<(), &'static str> {
        // Per RM0438: CR.ABORT self-clears only on a BUSY 1→0 edge.
        // If BUSY=1 (mm prefetch in flight) we must abort first; if
        // BUSY=0 we must NOT set ABORT (it would latch forever).
        if (self.mmio.read(OCTOSPI_SR_OFFSET) & (1 << 5)) != 0 {
            let cr = self.mmio.read(OCTOSPI_CR_OFFSET);
            self.mmio.write(OCTOSPI_CR_OFFSET, cr | (1 << 1));
            for _ in 0..1_000_000 {
                if (self.mmio.read(OCTOSPI_SR_OFFSET) & (1 << 5)) == 0 {
                    break;
                }
            }
        }
        let cr = self.mmio.read(OCTOSPI_CR_OFFSET);
        self.mmio.write(OCTOSPI_CR_OFFSET, cr & !(1 << 0));
        // SAFETY: barrier — ensure the CR.EN clear retires before any
        // subsequent indirect-mode reconfiguration.
        unsafe {
            core::arch::asm!("dsb sy", options(nostack, preserves_flags));
        }
        Ok(())
    }
}

// L562 memory-mapped tests live in a sibling file. The whole file is
// already `#![cfg(feature = "stm32l562")]`, so a plain `#[cfg(test)]`
// gate is sufficient.
#[cfg(test)]
#[path = "memory_mapped_l562_tests.rs"]
mod l562_tests;
