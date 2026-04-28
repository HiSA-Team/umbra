// STM32L562 OCTOSPI1 driver
//
// Memory-mapped 1-8-8 bringup for the MX25LM51245G Octa-SPI flash on the
// STM32L562E-DK. Pin assignment (per the L562E-DK schematic / UM2617):
//
//   NCS  = PA2  AF10
//   CLK  = PA3  AF10
//   IO3  = PA6  AF10
//   IO2  = PA7  AF10
//   IO1  = PB0  AF10
//   IO0  = PB1  AF10
//   DQS  = PB2  AF10
//   IO4  = PC0  AF10
//   IO5  = PC1  AF10
//   IO6  = PC2  AF10
//   IO7  = PC3  AF10

#![cfg(feature = "stm32l562")]
#![allow(dead_code, unused_imports)]

use peripheral_regs::*;

use crate::rcc::{self, Rcc};
use crate::gpio::{self, Gpio, PinMode, Port};

// OCTOSPI1 register base. On STM32L5 the OCTOSPI1 control registers live
// in the extended AHB3 peripheral range (AHB3PERIPH_BASE + 0x1000), not the
// normal 0x5002_xxxx APB/AHB area. Per STM32L562xx CMSIS header:
//   AHB3PERIPH_BASE_S = PERIPH_BASE_S(0x5000_0000) + 0x0402_0000 = 0x5402_0000
//   OCTOSPI1_R_BASE_S = AHB3PERIPH_BASE_S + 0x1000                = 0x5402_1000
pub const OCTOSPI1_BASE_ADDR: u32 = 0x5402_1000; // Secure alias
pub const OCTOSPI_MEMMAP_BASE: u32 = 0x9000_0000;

// Register offsets (subset used during bringup)
const OCTOSPI_CR_OFFSET:   u32 = 0x000;
const OCTOSPI_DCR1_OFFSET: u32 = 0x008;
const OCTOSPI_DCR2_OFFSET: u32 = 0x00C;
const OCTOSPI_SR_OFFSET:   u32 = 0x020;
const OCTOSPI_FCR_OFFSET:  u32 = 0x024;
const OCTOSPI_DLR_OFFSET:  u32 = 0x040; // Data length register (SVD-verified)
const OCTOSPI_AR_OFFSET:   u32 = 0x048; // Address register     (SVD-verified; draft had 0x120 which is ABR — corrected)
const OCTOSPI_DR_OFFSET:   u32 = 0x050; // Data register        (SVD-verified)
const OCTOSPI_CCR_OFFSET:  u32 = 0x100;
const OCTOSPI_TCR_OFFSET:  u32 = 0x108;
const OCTOSPI_IR_OFFSET:   u32 = 0x110;
const OCTOSPI_WCCR_OFFSET: u32 = 0x180; // Write comm config reg   (SVD-verified; offset 0x180)
const OCTOSPI_WTCR_OFFSET: u32 = 0x188; // Write timing config reg  (SVD-verified; offset 0x188; DCYC bits [4:0])
const OCTOSPI_WIR_OFFSET:  u32 = 0x190; // Write instruction reg    (SVD-verified; offset 0x190; draft +0x10 was correct)

pub struct OspiDriver {
    regs: *const u32,
}

impl OspiDriver {
    pub fn new() -> Self {
        let rcc = Rcc::new();
        rcc.enable_clock(rcc::peripherals::OSPI1);
        rcc.select_ospi_clock_source_sysclk();
        rcc.reset_ospi();
        Self { regs: OCTOSPI1_BASE_ADDR as *const u32 }
    }

    /// Initialize GPIOs + OCTOSPI1 to a quiescent state ready for
    /// `enable_memory_mapped_octa()`. Configures the 11 L562E-DK OCTOSPI1
    /// pins (see file header) to AF10 with the GPIO defaults that are
    /// already set by the existing `gpio` driver (push-pull, no pull, and
    /// reset-state max speed
    pub fn init(&self) {
        // --- 1. GPIO AF10 configuration for OCTOSPI1 on L562E-DK ---
        let rcc = Rcc::new();
        rcc.enable_clock(rcc::peripherals::GPIOA);
        rcc.enable_clock(rcc::peripherals::GPIOB);
        rcc.enable_clock(rcc::peripherals::GPIOC);

        let gpioa = Gpio::new(Port::GpioA);
        let gpiob = Gpio::new(Port::GpioB);
        let gpioc = Gpio::new(Port::GpioC);

        // PA2 (NCS), PA3 (CLK), PA6 (IO3), PA7 (IO2) — AF10.
        for pin in [2u8, 3, 6, 7] {
            gpioa.set_mode(pin, PinMode::AlternateFunction);
            gpioa.set_alternate_function(pin, 10);
        }

        // PB0 (IO1), PB1 (IO0), PB2 (DQS) — AF10.
        for pin in [0u8, 1, 2] {
            gpiob.set_mode(pin, PinMode::AlternateFunction);
            gpiob.set_alternate_function(pin, 10);
        }

        // PC0 (IO4) uses AF3 on the L562E-DK muxing; PC1..PC3 (IO5..IO7) are
        // AF10. Confirmed against STMicro's STM32CubeL5
        // Projects/STM32L562E-DK/Examples/OTFDEC/OTFDEC_ExecutingCryptedInstruction
        // stm32l5xx_hal_msp.c HAL_OSPI_MspInit.
        gpioc.set_mode(0, PinMode::AlternateFunction);
        gpioc.set_alternate_function(0, 3);
        for pin in [1u8, 2, 3] {
            gpioc.set_mode(pin, PinMode::AlternateFunction);
            gpioc.set_alternate_function(pin, 10);
        }

        unsafe {
            // --- 2. Disable OCTOSPI before configuring ---
            let cr = read_register(self.regs, OCTOSPI_CR_OFFSET);
            write_register(self.regs, OCTOSPI_CR_OFFSET, cr & !(1 << 0)); // EN=0

            // --- 3. DCR1: MTYP=Standard(0), DEVSIZE=25 (64 MB), CSHT=3 ---
            //     MTYP    bits [26:24] = 000 (Standard SPI / Micron-compatible —
            //                               suits 1-1-1 FAST_READ, no DQS)
            //     DEVSIZE bits [20:16] = 25  (2^(25+1) = 64 MB, MX25LM51245G)
            //     CSHT    bits [13:8]  = 3   (4 cycles between CS toggles)
            let dcr1 = (0b000u32 << 24) | (25u32 << 16) | (3u32 << 8);
            write_register(self.regs, OCTOSPI_DCR1_OFFSET, dcr1);

            // --- 4. DCR2: prescaler = 2 (SYSCLK/3 ≈ 36.7 MHz at 110 MHz SYSCLK, within AN5050 table 21 8READ limits) ---
            write_register(self.regs, OCTOSPI_DCR2_OFFSET, 0x0000_0002);

            // --- 5. Re-enable OCTOSPI ---
            let cr2 = read_register(self.regs, OCTOSPI_CR_OFFSET);
            write_register(self.regs, OCTOSPI_CR_OFFSET, cr2 | (1 << 0)); // EN=1
        }
    }

    /// Enable memory-mapped reads using legacy 1-1-1 FAST_READ (0x0B) with
    /// 8 dummy cycles and 3-byte addressing. This is the reset-default MX25LM51245G
    /// mode — no flash config register writes needed, which keeps Stage 1 a
    /// minimal gate over "OCTOSPI registers are reachable + memory-mapped path
    /// returns real flash bytes". Stage 2+ (OTFDEC integration) is the correct
    /// place to add the OPI DTR entry sequence
    /// (WRITE_CFG_REG_2 → CR2_DTR_OPI_ENABLE → OCTAL_IO_DTR_READ_CMD 0xEE11)
    /// that the STMicro STM32CubeL5 OTFDEC example uses.
    ///
    /// After this returns `Ok(())`, reads from `OCTOSPI_MEMMAP_BASE` issue
    /// real flash fetches at 1-1-1 FAST_READ speed.
    pub fn enable_memory_mapped_octa(&self) -> Result<(), &'static str> {
        unsafe {
            // --- 1. Disable OCTOSPI while reconfiguring CCR/TCR/IR ---
            let cr = read_register(self.regs, OCTOSPI_CR_OFFSET);
            write_register(self.regs, OCTOSPI_CR_OFFSET, cr & !(1 << 0));

            // --- 2. CCR: 1-1-1 FAST_READ command shape ---
            //     IMODE  = 1 (instruction 1-line) [bits 1:0]   = 01
            //     ADMODE = 1 (address 1-line)     [bits 10:8]  = 001
            //     ADSIZE = 2 (24-bit address)     [bits 13:12] = 10
            //     DMODE  = 1 (data 1-line)        [bits 26:24] = 001
            let ccr = (0b01u32 << 0)
                    | (0b001u32 << 8)
                    | (0b10u32  << 12)
                    | (0b001u32 << 24);
            write_register(self.regs, OCTOSPI_CCR_OFFSET, ccr);

            // --- 3. TCR: 8 dummy cycles (MX25LM51245G FAST_READ default) ---
            write_register(self.regs, OCTOSPI_TCR_OFFSET, 8);

            // --- 4. IR: FAST_READ opcode 0x0B (3-byte address variant) ---
            write_register(self.regs, OCTOSPI_IR_OFFSET, 0x0B);

            // --- 5. CR.FMODE = 11 (memory-mapped), EN=1 ---
            let mut cr2 = read_register(self.regs, OCTOSPI_CR_OFFSET);
            cr2 &= !(0b11 << 28);       // clear FMODE
            cr2 |=   0b11 << 28;        // FMODE = memory-mapped
            cr2 |=   1 << 0;            // EN
            write_register(self.regs, OCTOSPI_CR_OFFSET, cr2);

            // --- 6. BUSY wait with bounded timeout ---
            for _ in 0..1_000_000 {
                let sr = read_register(self.regs, OCTOSPI_SR_OFFSET);
                if (sr & (1 << 5)) == 0 { // BUSY bit cleared
                    core::arch::asm!("dsb sy", options(nostack, preserves_flags));
                    core::arch::asm!("isb sy", options(nostack, preserves_flags));
                    return Ok(());
                }
            }
            Err("OSPI BUSY timeout")
        }
    }

    /// Bringup trace char — emits a single byte over UART via the kernel's
    /// `serial.write_byte` path (wired in Task 1.1). Placeholder here.
    pub fn bringup_trace(&self, _c: u8) {
        // Intentionally empty
    }

    // -----------------------------------------------------------------------
    // Indirect-mode primitives for MX25LM51245G in reset-state SPI
    // -----------------------------------------------------------------------

    /// Issue a no-data command (e.g. WREN, WRDI).
    /// FMODE=00 (indirect-write), IMODE=1 (1-line), no address, no data.
    /// Triggers by writing IR, then busy-waits and clears TCF.
    pub fn issue_command_no_data(&self, cmd: u8) -> Result<(), &'static str> {
        unsafe {
            // 1. Disable OCTOSPI before reconfiguring.
            let cr = read_register(self.regs, OCTOSPI_CR_OFFSET);
            write_register(self.regs, OCTOSPI_CR_OFFSET, cr & !(1 << 0));

            // 2. FMODE = 00 (indirect-write): clear bits [29:28], keep EN=0.
            let mut cr2 = read_register(self.regs, OCTOSPI_CR_OFFSET);
            cr2 &= !(0b11 << 28);
            write_register(self.regs, OCTOSPI_CR_OFFSET, cr2);

            // 3. CCR: IMODE=1 (instruction on 1 line, bits [1:0]=01), no address, no data.
            write_register(self.regs, OCTOSPI_CCR_OFFSET, 0b01u32);

            // 4. EN=1 — must be set before writing the trigger register (IR).
            //    Per RM0438 §5.7: in indirect mode the transfer starts when the
            //    trigger register (IR when ADMODE=0) is written, so EN must
            //    already be 1 at that point.
            let cr3 = read_register(self.regs, OCTOSPI_CR_OFFSET);
            write_register(self.regs, OCTOSPI_CR_OFFSET, cr3 | (1 << 0));

            // 5. Write IR — triggers the transfer (ADMODE=0, so IR is the trigger).
            write_register(self.regs, OCTOSPI_IR_OFFSET, cmd as u32);

            // Wait for BUSY (SR bit 5) to clear.
            for _ in 0..1_000_000 {
                let sr = read_register(self.regs, OCTOSPI_SR_OFFSET);
                if (sr & (1 << 5)) == 0 {
                    // Clear Transfer Complete Flag (FCR bit 1 = CTCF).
                    write_register(self.regs, OCTOSPI_FCR_OFFSET, 1 << 1);
                    core::arch::asm!("dsb sy", options(nostack, preserves_flags));
                    return Ok(());
                }
            }
            Err("OSPI BUSY timeout (no-data cmd)")
        }
    }

    /// Read the MX25LM51245G Status Register 1 (READ STATUS, 0x05).
    /// FMODE=01 (indirect-read), IMODE=1, DMODE=1, DLR=0 (1 byte).
    pub fn read_status_register(&self) -> u8 {
        unsafe {
            // 0. Clear stale flags (TEF|TCF|SMF|TOF) in FCR so a prior
            //    transfer error doesn't prevent the new transfer from
            //    asserting TCF. Write-1-to-clear.
            write_register(self.regs, OCTOSPI_FCR_OFFSET, 0x1B);

            // 1. Disable OCTOSPI.
            let cr = read_register(self.regs, OCTOSPI_CR_OFFSET);
            write_register(self.regs, OCTOSPI_CR_OFFSET, cr & !(1 << 0));

            // 2. FMODE = 01 (indirect-read): bits [29:28] = 01, keep EN=0.
            let mut cr2 = read_register(self.regs, OCTOSPI_CR_OFFSET);
            cr2 &= !(0b11 << 28);
            cr2 |= 0b01 << 28;
            write_register(self.regs, OCTOSPI_CR_OFFSET, cr2);

            // 3. DLR = 0 (transfer 1 byte; DLR holds length-1).
            write_register(self.regs, OCTOSPI_DLR_OFFSET, 0);

            // 3. CCR: IMODE=1 (bits [1:0]=01), DMODE=1 (bits [26:24]=001).
            // Note: ADMODE=0 (no address) since READ STATUS has no address phase.
            let ccr = (0b01u32 << 0)          // IMODE = 1-line
                    | (0b001u32 << 24);        // DMODE = 1-line
            write_register(self.regs, OCTOSPI_CCR_OFFSET, ccr);

            // 4. EN=1 — must be set before writing IR (the trigger register).
            //    Per RM0438 §5.7: ADMODE=0 so IR is the trigger; EN must
            //    already be 1 when IR is written.
            let cr3 = read_register(self.regs, OCTOSPI_CR_OFFSET);
            write_register(self.regs, OCTOSPI_CR_OFFSET, cr3 | (1 << 0));

            // 5. Write IR = 0x05 (READ STATUS) — triggers the transfer.
            write_register(self.regs, OCTOSPI_IR_OFFSET, CMD_READ_STATUS as u32);

            // Wait for TCF (Transfer Complete Flag, SR bit 1).
            for _ in 0..1_000_000 {
                let sr = read_register(self.regs, OCTOSPI_SR_OFFSET);
                if (sr & (1 << 1)) != 0 {
                    // Read DR as a byte (volatile u8 read from DR base address).
                    let dr_ptr = (self.regs as u32 + OCTOSPI_DR_OFFSET) as *const u8;
                    let val = core::ptr::read_volatile(dr_ptr);
                    // Clear TCF via FCR.CTCF (bit 1).
                    write_register(self.regs, OCTOSPI_FCR_OFFSET, 1 << 1);
                    core::arch::asm!("dsb sy", options(nostack, preserves_flags));
                    return val;
                }
            }
            // Timeout: return 0xFF (WIP=1 in all 1s is a safe pessimistic value).
            0xFF
        }
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

        let busy_ok;
        unsafe {
            // 1. Disable OCTOSPI.
            let cr = read_register(self.regs, OCTOSPI_CR_OFFSET);
            write_register(self.regs, OCTOSPI_CR_OFFSET, cr & !(1 << 0));

            // 2. FMODE = 00 (indirect-write), keep EN=0.
            let mut cr2 = read_register(self.regs, OCTOSPI_CR_OFFSET);
            cr2 &= !(0b11 << 28);
            write_register(self.regs, OCTOSPI_CR_OFFSET, cr2);

            // 3. CCR: IMODE=1, ADMODE=1 (bits [12:8]=001), ADSIZE=2 (bits [13:12]=10 → 24-bit).
            // ADMODE bits [12:8]? No — per RM0438 / SVD for OCTOSPI CCR:
            //   IMODE  = bits [2:0]  (001 = 1 line)
            //   ADMODE = bits [10:8] (001 = 1 line)
            //   ADSIZE = bits [13:12](10  = 24-bit / 3-byte)
            //   DMODE  = bits [26:24](000 = none)
            let ccr = (0b001u32 << 0)   // IMODE = 1-line  [2:0]
                    | (0b001u32 << 8)   // ADMODE = 1-line [10:8]
                    | (0b10u32  << 12); // ADSIZE = 24-bit [13:12]
            write_register(self.regs, OCTOSPI_CCR_OFFSET, ccr);

            // 4. EN=1 — must be set before writing IR and AR.
            //    Per RM0438 §5.7: ADMODE≠0 so AR is the trigger; EN must
            //    already be 1 when AR is written.
            let cr3 = read_register(self.regs, OCTOSPI_CR_OFFSET);
            write_register(self.regs, OCTOSPI_CR_OFFSET, cr3 | (1 << 0));

            // 5. Write IR = 0x20 (Sector Erase 4K).
            write_register(self.regs, OCTOSPI_IR_OFFSET, CMD_SECTOR_ERASE as u32);

            // 6. Write AR = lower 24 bits of flash_addr — triggers the transfer
            //    (ADMODE≠0, so AR write is the trigger per RM0438 §5.7).
            write_register(self.regs, OCTOSPI_AR_OFFSET, flash_addr & 0x00FF_FFFF);

            // Wait for BUSY clear, tracking whether we succeeded.
            let mut ok = false;
            for _ in 0..1_000_000 {
                let sr = read_register(self.regs, OCTOSPI_SR_OFFSET);
                if (sr & (1 << 5)) == 0 {
                    write_register(self.regs, OCTOSPI_FCR_OFFSET, 1 << 1);
                    core::arch::asm!("dsb sy", options(nostack, preserves_flags));
                    ok = true;
                    break;
                }
            }
            busy_ok = ok;
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

        let busy_ok;
        unsafe {
            // 1. Disable OCTOSPI.
            let cr = read_register(self.regs, OCTOSPI_CR_OFFSET);
            write_register(self.regs, OCTOSPI_CR_OFFSET, cr & !(1 << 0));

            // 2. FMODE = 00 (indirect-write), keep EN=0.
            let mut cr2 = read_register(self.regs, OCTOSPI_CR_OFFSET);
            cr2 &= !(0b11 << 28);
            write_register(self.regs, OCTOSPI_CR_OFFSET, cr2);

            // 3. DLR = len - 1.
            write_register(self.regs, OCTOSPI_DLR_OFFSET, (data.len() as u32) - 1);

            // 3. CCR: IMODE=1, ADMODE=1, ADSIZE=2 (24-bit), DMODE=1.
            let ccr = (0b001u32 << 0)    // IMODE  = 1-line
                    | (0b001u32 << 8)    // ADMODE = 1-line
                    | (0b10u32  << 12)   // ADSIZE = 24-bit
                    | (0b001u32 << 24);  // DMODE  = 1-line
            write_register(self.regs, OCTOSPI_CCR_OFFSET, ccr);

            // 4. EN=1 — must be set before writing IR and AR.
            //    Per RM0438 §5.7: ADMODE≠0 so AR is the trigger; EN must
            //    already be 1 when AR is written.
            let cr3 = read_register(self.regs, OCTOSPI_CR_OFFSET);
            write_register(self.regs, OCTOSPI_CR_OFFSET, cr3 | (1 << 0));

            // 5. Write IR = 0x02 (Page Program).
            write_register(self.regs, OCTOSPI_IR_OFFSET, CMD_PAGE_PROGRAM as u32);

            // 6. Write AR = lower 24 bits of flash_addr — triggers the data phase
            //    (ADMODE≠0 and DMODE≠0: AR write arms the transfer; data is driven
            //    by the DR pump below).
            write_register(self.regs, OCTOSPI_AR_OFFSET, flash_addr & 0x00FF_FFFF);

            // 7. Push each byte through the DR byte port, gated on FTF (SR bit 2).
            //    The OCTOSPI FIFO is 32 bytes deep; without waiting for FTF the
            //    FIFO fills after byte 32 and subsequent writes are silently
            //    discarded, corrupting bytes 33..256 of a 256-byte page program.
            let dr_ptr = (self.regs as u32 + OCTOSPI_DR_OFFSET) as *mut u8;
            for &byte in data {
                for _ in 0..1_000_000 {
                    if (read_register(self.regs, OCTOSPI_SR_OFFSET) & (1 << 2)) != 0 {
                        break; // FTF set: FIFO has space
                    }
                }
                core::ptr::write_volatile(dr_ptr, byte);
            }

            // Wait for BUSY clear, tracking whether we succeeded.
            let mut ok = false;
            for _ in 0..1_000_000 {
                let sr = read_register(self.regs, OCTOSPI_SR_OFFSET);
                if (sr & (1 << 5)) == 0 {
                    write_register(self.regs, OCTOSPI_FCR_OFFSET, 1 << 1);
                    core::arch::asm!("dsb sy", options(nostack, preserves_flags));
                    ok = true;
                    break;
                }
            }
            busy_ok = ok;
        }

        if !busy_ok {
            return Err("OSPI BUSY timeout (page program)");
        }

        // Wait for flash write to complete.
        self.wait_wip(10_000_000)
    }

    // -----------------------------------------------------------------------
    // Memory-mapped write-read mode (OTFDEC integration path)
    // -----------------------------------------------------------------------

    /// Configure OCTOSPI for memory-mapped mode with BOTH a read command
    /// (FAST_READ 0x0B, 3-byte address, 8 dummy cycles via CCR/TCR/IR) and a
    /// write command (Page Program 0x02, 3-byte address, 0 dummy cycles via
    /// WCCR/WTCR/WIR).  CR.FMODE is set to 11 (memory-mapped) on return.
    ///
    /// After this returns `Ok(())`, reads from `OCTOSPI_MEMMAP_BASE` issue
    /// FAST_READ sequences; writes to `OCTOSPI_MEMMAP_BASE` issue Page Program
    /// sequences.  This is the mode required by `HAL_OTFDEC_Cipher`, which
    /// drives enciphered data into flash via `*extMem_ptr = *in_ptr`.
    ///
    /// # WREN / write-enable responsibility
    ///
    /// The OCTOSPI peripheral on STM32L5 has NO automatic write-enable
    /// mechanism (no WREN, AUTOPOLL, or WPOL auto-issue feature — confirmed
    /// by exhaustive SVD search of CR fields: FMODE, PMM, APMS, TOIE, SMIE,
    /// FTIE, TCIE, TEIE, FTHRES, FSEL, DQM, TCEN, DMAEN, ABORT, EN — none
    /// auto-issue WREN).  The flash MX25LM51245G requires a WREN (0x06)
    /// command before EACH page-program boundary.  Therefore:
    ///
    ///   * This helper configures the mode only — it does NOT issue WREN.
    ///   * Task 2c (the OTFDEC encipherment loop) MUST call
    ///     `disable_memory_mapped()` → `issue_command_no_data(CMD_WRITE_ENABLE)`
    ///     → re-enable memory-mapped mode before each 256-byte page boundary
    ///     write if writes actually touch flash (not just OTFDEC key loading).
    ///
    /// # SVD verification (all offsets against STM32L562.svd OCTOSPI1 block)
    ///
    /// | Register | Offset   | Key fields verified                            |
    /// |----------|----------|------------------------------------------------|
    /// | CCR      | 0x100    | IMODE[2:0], ADMODE[10:8], ADSIZE[13:12], DMODE[26:24] |
    /// | TCR      | 0x108    | DCYC[4:0]                                      |
    /// | IR       | 0x110    | INSTRUCTION[31:0]                              |
    /// | WCCR     | 0x180    | same field positions as CCR (verified)         |
    /// | WTCR     | 0x188    | DCYC[4:0] (same as TCR; explicitly zeroed here)|
    /// | WIR      | 0x190    | INSTRUCTION[31:0]                              |
    ///
    /// The draft used `OCTOSPI_WCCR_OFFSET + 0x10` for WIR; this resolves to
    /// 0x190, which matches the SVD — corrected to use the named constant
    /// `OCTOSPI_WIR_OFFSET`.  WCCR bit positions match CCR — no correction
    /// needed.  WTCR exists and is explicitly zeroed (Page Program: 0 dummy
    /// cycles).
    pub fn enable_memory_mapped_write_read(&self) -> Result<(), &'static str> {
        unsafe {
            // 1. Disable OCTOSPI while reconfiguring CCR/TCR/IR/WCCR/WTCR/WIR.
            let cr = read_register(self.regs, OCTOSPI_CR_OFFSET);
            write_register(self.regs, OCTOSPI_CR_OFFSET, cr & !(1 << 0));

            // 2. READ shape — CCR: 1-1-1 FAST_READ command
            //    IMODE  = 001 (instruction on 1 line) [bits  2:0]
            //    ADMODE = 001 (address on 1 line)     [bits 10:8]
            //    ADSIZE = 10  (24-bit / 3-byte addr)  [bits 13:12]
            //    DMODE  = 001 (data on 1 line)        [bits 26:24]
            let rccr = (0b001u32 << 0)
                     | (0b001u32 << 8)
                     | (0b10u32  << 12)
                     | (0b001u32 << 24);
            write_register(self.regs, OCTOSPI_CCR_OFFSET, rccr);

            // 3. TCR: 8 dummy cycles for FAST_READ (MX25LM51245G requirement).
            write_register(self.regs, OCTOSPI_TCR_OFFSET, 8);

            // 4. IR: FAST_READ opcode 0x0B.
            write_register(self.regs, OCTOSPI_IR_OFFSET, 0x0B);

            // 5. WRITE shape — WCCR: 1-1-1 Page Program command
            //    Bit positions are identical to CCR (SVD-verified).
            //    IMODE  = 001 [bits  2:0]
            //    ADMODE = 001 [bits 10:8]
            //    ADSIZE = 10  [bits 13:12]
            //    DMODE  = 001 [bits 26:24]
            let wccr = (0b001u32 << 0)
                     | (0b001u32 << 8)
                     | (0b10u32  << 12)
                     | (0b001u32 << 24);
            write_register(self.regs, OCTOSPI_WCCR_OFFSET, wccr);

            // 6. WTCR: 0 dummy cycles for Page Program (explicitly zeroed;
            //    WTCR exists at 0x188 per SVD, DCYC field [4:0]).
            write_register(self.regs, OCTOSPI_WTCR_OFFSET, 0);

            // 7. WIR: Page Program opcode 0x02
            //    (SVD: WIR at 0x190; draft's +0x10 arithmetic was correct).
            write_register(self.regs, OCTOSPI_WIR_OFFSET, CMD_PAGE_PROGRAM as u32);

            // 8. CR.FMODE = 11 (memory-mapped), EN=1.
            let mut cr2 = read_register(self.regs, OCTOSPI_CR_OFFSET);
            cr2 &= !(0b11 << 28);  // clear FMODE
            cr2 |=   0b11 << 28;   // FMODE = 11 (memory-mapped)
            cr2 |=   1    << 0;    // EN=1
            write_register(self.regs, OCTOSPI_CR_OFFSET, cr2);

            // 9. Wait for BUSY (SR bit 5) to clear, then issue barriers so
            //    subsequent memory-mapped accesses see the new configuration.
            for _ in 0..1_000_000 {
                let sr = read_register(self.regs, OCTOSPI_SR_OFFSET);
                if (sr & (1 << 5)) == 0 {
                    core::arch::asm!("dsb sy", options(nostack, preserves_flags));
                    core::arch::asm!("isb sy", options(nostack, preserves_flags));
                    return Ok(());
                }
            }
            Err("OSPI BUSY timeout (mm write-read)")
        }
    }

    /// Issue a WRITE ENABLE (WREN, opcode 0x06) command in indirect mode.
    ///
    /// Convenience wrapper around `issue_command_no_data` for the MX25LM51245G
    /// WREN requirement.  Must be called before every page-program boundary
    /// in the OTFDEC cipher pass because OCTOSPI on STM32L5 has no automatic
    /// WREN re-issue in memory-mapped write mode.
    pub fn write_enable(&self) -> Result<(), &'static str> {
        self.issue_command_no_data(CMD_WRITE_ENABLE)
    }

    /// Safely exit memory-mapped mode.
    ///
    /// Per RM0438 §5, the ABORT bit (CR bit 1) must be asserted and BUSY
    /// polled to idle before CR.EN can be safely cleared from FMODE=11.
    /// Clearing EN directly while a memory-mapped prefetch is in flight can
    /// leave the peripheral stuck BUSY.
    ///
    /// Used by Task 2c between page-program boundary writes to issue a
    /// WREN in indirect mode (memory-mapped cannot auto-issue WREN on L5).
    pub fn disable_memory_mapped(&self) -> Result<(), &'static str> {
        unsafe {
            // Per RM0438: CR.ABORT self-clears only on a BUSY 1→0 edge.
            // If BUSY=1 (mm prefetch in flight) we must abort first; if
            // BUSY=0 we must NOT set ABORT (it would latch forever).
            if (read_register(self.regs, OCTOSPI_SR_OFFSET) & (1 << 5)) != 0 {
                let cr = read_register(self.regs, OCTOSPI_CR_OFFSET);
                write_register(self.regs, OCTOSPI_CR_OFFSET, cr | (1 << 1));
                for _ in 0..1_000_000 {
                    if (read_register(self.regs, OCTOSPI_SR_OFFSET) & (1 << 5)) == 0 {
                        break;
                    }
                }
            }
            let cr = read_register(self.regs, OCTOSPI_CR_OFFSET);
            write_register(self.regs, OCTOSPI_CR_OFFSET, cr & !(1 << 0));
            core::arch::asm!("dsb sy", options(nostack, preserves_flags));
            Ok(())
        }
    }
}

// MX25LM51245G SPI command opcodes (reset-state 1-1-1 SPI mode).
const CMD_READ_STATUS:  u8 = 0x05;
const CMD_WRITE_ENABLE: u8 = 0x06;
const CMD_PAGE_PROGRAM: u8 = 0x02; // 3-byte address, 256-byte page
const CMD_SECTOR_ERASE: u8 = 0x20; // 4 KB sector erase; 0xD8 = 64 KB block erase
const STATUS_WIP_MASK:  u8 = 0x01;
