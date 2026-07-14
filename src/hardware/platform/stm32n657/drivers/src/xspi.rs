//! XSPI2 indirect-mode driver for STM32N657 + Macronix MX25UM51245G.
//!
//! Used by the E.4c oracle to erase 64-KB blocks of flash. The chip is
//! in 1-1-1 SPI mode after FSBL bringup (configured in
//! `platform_impl.rs::init_external_flash`); this driver only switches
//! the FMODE between memory-map (default) and indirect-write /
//! indirect-read for erase + status polling.
//!
//! Register layout extracted from working `platform_impl::init_external_flash`
//! (Phase D — verified working). Notable offset deltas vs L552 OSPI:
//! SR @ 0x024 (not 0x020), FCR @ 0x028 (not 0x024).
//!
//! Macronix MX25UM51245G SPI commands (datasheet rev 2.6 §7):
//!   - WREN = 0x06 (1 byte, no address, no data)
//!   - BE64 in 4-byte mode = 0xDC (1 byte + 4-byte address, no data)
//!   - RDSR = 0x05 (1 byte, no address, returns 1 byte status)

const XSPI2_BASE: usize = 0x5802_A000;

const CR_OFFSET: usize  = 0x000;
// SR @ 0x020 / FCR @ 0x024 per RM0486 §28.7.6/§28.7.7. NOTE: platform_impl.rs
// has a long-standing bug using 0x024 for SR and 0x028 for FCR — its TCF poll
// always times out silently. We need correct offsets here for E.4c BE64 erase.
const SR_OFFSET: usize  = 0x020;
const FCR_OFFSET: usize = 0x024;
const DLR_OFFSET: usize = 0x040;
const AR_OFFSET: usize  = 0x048;
const DR_OFFSET: usize  = 0x050;
const CCR_OFFSET: usize = 0x100;
const TCR_OFFSET: usize = 0x108;
const IR_OFFSET: usize  = 0x110;
// Memory-mapped WRITE-side config (RM0486 §28.7.23-25). Used to configure
// PP4B for E.4c oracle DMA writes through MCE2.
const WCCR_OFFSET: usize = 0x180;
const WTCR_OFFSET: usize = 0x188;
const WIR_OFFSET: usize  = 0x190;

// CR bits
const CR_EN:                   u32 = 1 << 0;
const CR_ABORT:                u32 = 1 << 1;
const CR_FMODE_INDIRECT_WRITE: u32 = 0b00 << 28;
const CR_FMODE_INDIRECT_READ:  u32 = 0b01 << 28;
const CR_FMODE_MASK:           u32 = 0b11 << 28;

// SR bits (verified at platform_impl.rs:350,367)
const SR_TCF: u32  = 1 << 1;
const SR_BUSY: u32 = 1 << 5;

// FCR bits (write-1-to-clear)
const FCR_CTCF: u32 = 1 << 1;

// TCR bit 30 = DHQC (Delay Hold Quarter Cycle). Shifts MISO sampling by half a
// SCK period to compensate for chip-side propagation delay. `init_external_flash`
// uses DHQC=1 for RDID and FAST_READ_4B; bringing it up here for read commands
// is consistent with that established working pattern.
const TCR_DHQC: u32 = 1 << 30;

// CCR bitfield encoding for 1-1-1 SPI mode (no DDR, 8-bit instruction).
const CCR_IMODE_1L: u32   = 0b001 << 0;
const CCR_ADMODE_1L: u32  = 0b001 << 8;
const CCR_ADSIZE_4B: u32  = 0b11  << 12;
const CCR_DMODE_1L: u32   = 0b001 << 24;

// CCR bitfield for 8-8-8 Octa-SPI STR (no DDR) mode (Macronix MX25UM51245G).
// All phases on 8 lines, 16-bit instruction. DQS not strictly required in STR.
// Easier to bring up than DTR (no double-rate timing ambiguity).
const CCR_IMODE_8L:  u32 = 0b100 << 0;
const CCR_ISIZE_16B: u32 = 0b01  << 4;
const CCR_ADMODE_8L: u32 = 0b100 << 8;
const CCR_DMODE_8L:  u32 = 0b100 << 24;
// DTR / DQS placeholders — kept for the OPI 8D-8D-8D revival path. We use
// STR exclusively today, so these resolve to 0 and are unused. Marked
// `#[allow(dead_code)]` instead of deleted so the OPI mode field encoding
// stays documented for whoever wires DTR mode (Phase E.4c revival).
#[allow(dead_code)]
const CCR_IDTR:      u32 = 0;        // STR: no IDTR
#[allow(dead_code)]
const CCR_ADDTR:     u32 = 0;        // STR: no ADDTR
#[allow(dead_code)]
const CCR_DDTR:      u32 = 0;        // STR: no DDTR
#[allow(dead_code)]
const CCR_DQSE:      u32 = 0;        // STR: DQS not used

// Macronix MX25UM51245G 1-1-1 SPI opcodes (8-bit).
const OP_WREN_SPI:  u32 = 0x06;
const OP_RDSR_SPI:  u32 = 0x05;  // Read Status Register in 1-1-1 SPI
const OP_WRCR2:     u32 = 0x72;  // Write Configuration Register 2 (in 1-1-1 SPI)
const OP_RDCR2_SPI: u32 = 0x71;  // Read  Configuration Register 2 (in 1-1-1 SPI)
const OP_RDID:      u32 = 0x9F;  // Read identification (mfg ID + type + density)
const OP_RSTEN:     u32 = 0x66;  // Reset enable
const OP_RST:       u32 = 0x99;  // Reset
const OP_RDP:       u32 = 0xAB;  // Release from Deep Power Down
const OP_SSE_4B:    u32 = 0x21;  // 4KB subsector erase (4-byte address)
const OP_PP_4B:     u32 = 0x12;  // Page program (4-byte address)
const OP_RDCR:      u32 = 0x15;  // Read Configuration Register 1 (1-1-1 SPI)
const OP_RDSCUR:    u32 = 0x2B;  // Read Security Register (Macronix-specific):
                                 //   bit 0 SOI    — Secure OTP Indicator
                                 //   bit 1 LDSO   — Lock-Down Secured OTP (irreversible)
                                 //   bit 2 PSB    — Program Suspend Bit
                                 //   bit 3 ESB    — Erase Suspend Bit
                                 //   bit 5 P_FAIL — Last Program failed
                                 //   bit 6 E_FAIL — Last Erase failed
                                 //   bit 7 WPSEL  — Solid Block Protection mode active

// Macronix MX25UM51245G OPI 8D-8D-8D DTR opcodes (16-bit).
// XSPI controller with ISIZE=01 (16-bit instruction) sends IR[7:0] FIRST
// on the bus, then IR[15:8]. So opcode goes in LOW byte, complement in HIGH.
//   WREN = 0x06, complement 0xF9 → IR = 0xF9 << 8 | 0x06 = 0xF906
const OP_WREN: u32         = 0xF906;
// WREN_VOLATILE (0x50) — Macronix-specific. Required by some chip variants
// for VOLATILE register writes (WRSR for SR volatile bits, WRCR2). Some
// MX25UM datasheets list WRCR2 as needing 0x50 specifically; others list
// 0x06 sufficient. Try as fallback if regular WREN doesn't latch WEL.
//   WREN_VOL = 0x50, complement 0xAF → IR = 0xAF50
const OP_WREN_VOL_OPI: u32 = 0xAF50;
const OP_WREN_VOL_SPI: u32 = 0x50;
const OP_BE64: u32         = 0x23DC;
const OP_RDSR: u32         = 0xFA05;
const OP_FAST_READ_4B: u32 = 0x13EC;  // Octa Read 4-byte addressing
const OP_PP4B: u32         = 0xED12;  // Page Program 4-byte addressing
const OP_RDCR2_OPI: u32    = 0x8E71;  // Read CR2 in OPI 16-bit (low byte 0x71)

const SR_WIP: u8 = 1 << 0;

#[derive(Debug)]
pub enum XspiError {
    EraseTimeout,
    BusyTimeout,
    TransferIncomplete,
}

pub struct Xspi2;
pub struct SavedCr(u32);

// ── WP# active-drive helper (Phase E.4c diagnostic) ─────────────────
// On the Nucleo-N657X0-Q, PN5 is multiplexed as XSPI2 IO2 / Macronix WP#
// and PN6 as IO3 / HOLD#. In 1-1-1 SPI mode the XSPI2 controller does not
// drive IO2/IO3 (only IO0/IO1 are used), and the Macronix MX25UM51245G
// silently rejects WREN if WP# is not actively high. Earlier sessions
// configured these pins as AF9 with PUPDR=01 (weak pull-up ~10 kΩ),
// which was insufficient against any PCB-side pull-down — and that's
// the prevailing hypothesis for why WEL never latched.
//
// `wp_drive_high_via_gpio` switches PN5 + PN6 from AF9 to GPIO output
// push-pull driving HIGH, which is a much stronger source than a pull-up.
// `wp_back_to_xspi_af` restores AF9 so XSPI2 can drive IO2/IO3 in OPI mode.

const GPION_S_BASE: usize = 0x5602_3400;
const GPION_MODER:  usize = 0x000;
const GPION_PUPDR:  usize = 0x00C;
const GPION_ODR:    usize = 0x014;

/// Force PN5 (WP#) and PN6 (HOLD#) into GPIO output push-pull driving high,
/// overriding the AF9 mapping set up by `init_external_flash` Step 5.
/// Use only while XSPI2 is in 1-1-1 SPI indirect mode (IO2/IO3 unused).
pub unsafe fn wp_drive_high_via_gpio() {
    let gpion = GPION_S_BASE;

    // Set ODR.5 = ODR.6 = 1 BEFORE switching MODER, so the high level is
    // present the moment the pin becomes output (avoids a glitch low).
    let odr = core::ptr::read_volatile((gpion + GPION_ODR) as *const u32);
    core::ptr::write_volatile(
        (gpion + GPION_ODR) as *mut u32,
        odr | (1 << 5) | (1 << 6),
    );

    // Clear PUPDR for these pins (push-pull output is the active driver).
    let pupdr = core::ptr::read_volatile((gpion + GPION_PUPDR) as *const u32);
    let new_pupdr = pupdr & !((0b11 << 10) | (0b11 << 12));
    core::ptr::write_volatile((gpion + GPION_PUPDR) as *mut u32, new_pupdr);

    // Switch MODER from 10 (AF) to 01 (output) for pins 5 and 6.
    let moder = core::ptr::read_volatile((gpion + GPION_MODER) as *const u32);
    let new_moder = (moder & !((0b11 << 10) | (0b11 << 12)))
        | (0b01 << 10)
        | (0b01 << 12);
    core::ptr::write_volatile((gpion + GPION_MODER) as *mut u32, new_moder);

    cortex_m::asm::dsb(); cortex_m::asm::isb();
    let mut d: u32 = 0;
    while d < 1_000 { core::hint::spin_loop(); d = d.wrapping_add(1); }
}

/// Restore PN5 + PN6 to AF9 so XSPI2 controls IO2/IO3 (required for OPI ops).
pub unsafe fn wp_back_to_xspi_af() {
    let gpion = GPION_S_BASE;
    let moder = core::ptr::read_volatile((gpion + GPION_MODER) as *const u32);
    let new_moder = (moder & !((0b11 << 10) | (0b11 << 12)))
        | (0b10 << 10)
        | (0b10 << 12);
    core::ptr::write_volatile((gpion + GPION_MODER) as *mut u32, new_moder);
    cortex_m::asm::dsb(); cortex_m::asm::isb();
}

/// Wait for CR.ABORT bit to self-clear (controller acknowledged abort).
/// Bounded loop — the controller takes <100 cycles in normal cases.
#[inline]
unsafe fn wait_abort_clear(cr: *mut u32) {
    let mut i: u32 = 0;
    while i < 100_000 {
        if core::ptr::read_volatile(cr) & CR_ABORT == 0 {
            return;
        }
        i += 1;
    }
}

/// Settle delay after CR.EN=1 — controller needs ~5000 cycles to come up.
/// Pattern from init_external_flash STEP 8 / STEP 11.
#[inline]
fn settle_after_enable() {
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
    let mut d: u32 = 0;
    while d < 5_000 {
        core::hint::spin_loop();
        d = d.wrapping_add(1);
    }
}

impl Xspi2 {
    pub fn new() -> Self {
        Xspi2
    }

    /// Enter indirect-write mode (FMODE=00), returning the previous CR for restore.
    /// Matches ST HAL_XSPI_Command pattern: FMODE=00 is the default for ALL
    /// command types. For data reads, callers temporarily switch to FMODE=01.
    /// For no-data commands, IR write triggers and BUSY=0 indicates completion
    /// (TCF is NOT set for no-data commands per ST HAL behavior).
    pub fn enter_indirect_mode(&self) -> SavedCr {
        let saved = unsafe {
            let cr = (XSPI2_BASE + CR_OFFSET) as *mut u32;
            let prev = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, prev | CR_ABORT);
            wait_abort_clear(cr);
            core::ptr::write_volatile(cr, 0);
            core::ptr::write_volatile(cr, CR_FMODE_INDIRECT_WRITE | CR_EN);
            prev
        };
        settle_after_enable();
        SavedCr(saved)
    }

    /// Restore CR to memory-mapped mode, also re-issuing the FAST_READ_4B
    /// command setup (CCR/TCR/IR) since indirect-mode commands trampled them.
    /// Mirrors init_external_flash STEP 11.
    pub fn exit_indirect_mode(&self, saved: SavedCr) {
        unsafe {
            let cr = (XSPI2_BASE + CR_OFFSET) as *mut u32;
            let cur = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, cur | CR_ABORT);
            wait_abort_clear(cr);
            core::ptr::write_volatile(cr, 0);
            // Restore mem-map mode in OPI 8-8-8 STR (chip is now in OPI).
            let opi_format = CCR_IMODE_8L | CCR_ISIZE_16B
                | CCR_ADMODE_8L | CCR_ADSIZE_4B
                | CCR_DMODE_8L;
            core::ptr::write_volatile((XSPI2_BASE + CCR_OFFSET) as *mut u32,
                opi_format);
            core::ptr::write_volatile((XSPI2_BASE + TCR_OFFSET) as *mut u32, 20);
            core::ptr::write_volatile((XSPI2_BASE + IR_OFFSET) as *mut u32,
                OP_FAST_READ_4B);
            core::ptr::write_volatile((XSPI2_BASE + WCCR_OFFSET) as *mut u32,
                opi_format);
            core::ptr::write_volatile((XSPI2_BASE + WTCR_OFFSET) as *mut u32, 0);
            core::ptr::write_volatile((XSPI2_BASE + WIR_OFFSET) as *mut u32,
                OP_PP4B);
            core::ptr::write_volatile(cr, saved.0);
        }
        settle_after_enable();
    }

    /// Restore 1-1-1 SPI memory-mapped FAST_READ_4B (opcode 0x0C, DCYC=8) — the
    /// EXACT config the current boot installs (`platform_impl/dma.rs::init_external_
    /// flash`, mem-map block). Call after an indirect-mode write excursion so enclave
    /// loads from `0x7000_0000` resume. The chip stays in 1-1-1 SPI throughout (the
    /// boot never enters OPI), so NO chip-mode change is needed — this is the whole
    /// reason the write path is simple and wedge-free on this board.
    pub fn restore_memory_mapped_1_1_1(&self) {
        unsafe {
            let cr = (XSPI2_BASE + CR_OFFSET) as *mut u32;
            let cur = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, cur | CR_ABORT);
            wait_abort_clear(cr);
            core::ptr::write_volatile(cr, 0); // disable before FMODE change
            core::ptr::write_volatile(
                (XSPI2_BASE + CCR_OFFSET) as *mut u32,
                CCR_DMODE_1L | CCR_ADSIZE_4B | CCR_ADMODE_1L | CCR_IMODE_1L,
            );
            core::ptr::write_volatile((XSPI2_BASE + TCR_OFFSET) as *mut u32, 8 | TCR_DHQC);
            core::ptr::write_volatile((XSPI2_BASE + IR_OFFSET) as *mut u32, 0x0C); // FAST_READ_4B 1-1-1
            core::ptr::write_volatile(cr, CR_FMODE_MASK | CR_EN); // FMODE=11 (mem-map), EN
        }
        settle_after_enable();
    }

    /// Erase one 4 KB subsector (opcode 0x21, 4-byte address) in 1-1-1 SPI. Requires
    /// a prior WREN (WEL=1) and FMODE=indirect-write. Does not poll WIP — caller polls.
    pub fn subsector_erase_4k_spi(&self, flash_addr: u32) -> Result<(), XspiError> {
        self.wait_not_busy()?;
        self.clear_tcf();
        unsafe {
            core::ptr::write_volatile((XSPI2_BASE + TCR_OFFSET) as *mut u32, 0);
            core::ptr::write_volatile(
                (XSPI2_BASE + CCR_OFFSET) as *mut u32,
                CCR_IMODE_1L | CCR_ADMODE_1L | CCR_ADSIZE_4B,
            );
            core::ptr::write_volatile((XSPI2_BASE + IR_OFFSET) as *mut u32, OP_SSE_4B);
            cortex_m::asm::dsb();
            core::ptr::write_volatile((XSPI2_BASE + AR_OFFSET) as *mut u32, flash_addr & 0x07FF_FFFF);
        }
        self.wait_not_busy()?;
        self.clear_tcf();
        Ok(())
    }

    /// Page-program up to 256 bytes (opcode 0x12, 4-byte address) in 1-1-1 SPI.
    /// Requires a prior WREN and FMODE=indirect-write. "DR last" trigger: IR + AR are
    /// pre-set, then the DR byte writes push the data and start the transaction.
    pub fn page_program_spi(&self, flash_addr: u32, data: &[u8]) -> Result<(), XspiError> {
        self.wait_not_busy()?;
        self.clear_tcf();
        unsafe {
            core::ptr::write_volatile((XSPI2_BASE + TCR_OFFSET) as *mut u32, 0);
            core::ptr::write_volatile(
                (XSPI2_BASE + DLR_OFFSET) as *mut u32,
                (data.len() as u32).wrapping_sub(1),
            );
            core::ptr::write_volatile(
                (XSPI2_BASE + CCR_OFFSET) as *mut u32,
                CCR_IMODE_1L | CCR_ADMODE_1L | CCR_ADSIZE_4B | CCR_DMODE_1L,
            );
            core::ptr::write_volatile((XSPI2_BASE + IR_OFFSET) as *mut u32, OP_PP_4B);
            core::ptr::write_volatile((XSPI2_BASE + AR_OFFSET) as *mut u32, flash_addr & 0x07FF_FFFF);
            cortex_m::asm::dsb();
            // DR-last = trigger. Write full 32-bit words (matches the working
            // write_cr2_mode_spi_minimal); a byte-wise *mut u8 push underran the FIFO
            // and programmed 0xFF. The controller consumes only DLR+1 bytes, so a
            // tail shorter than 4 bytes is padded with 0xFF (a no-op for NOR program).
            let dr = (XSPI2_BASE + DR_OFFSET) as *mut u32;
            let mut i = 0;
            while i < data.len() {
                let mut w = [0xFFu8; 4];
                let mut j = 0;
                while j < 4 && i + j < data.len() {
                    w[j] = data[i + j];
                    j += 1;
                }
                core::ptr::write_volatile(dr, u32::from_le_bytes(w));
                i += 4;
            }
        }
        self.wait_tcf()?;
        self.clear_tcf();
        self.wait_not_busy()?;
        Ok(())
    }

    /// Poll WIP (SR bit 0) until clear or timeout, in 1-1-1 SPI. Switches FMODE to
    /// indirect-read; requires CR.EN=1 (a prior `enter_indirect_mode`).
    pub fn poll_wip_spi(&self, max_loops: u32) -> Result<(), XspiError> {
        self.switch_fmode_minimal(true);
        let mut i: u32 = 0;
        while i < max_loops {
            let sr = self.read_status_register_spi_minimal()?;
            if sr & SR_WIP == 0 {
                return Ok(());
            }
            i += 1;
        }
        Err(XspiError::EraseTimeout)
    }

    /// FMODE-neutral 1-1-1 SPI RDID. Returns mfg / type / density bytes packed
    /// into a u32 as 0x00DDTTMM (DD=density, TT=type, MM=mfg). Diagnostic
    /// only — used to confirm chip identity (Macronix expected, mfg ID 0xC2).
    pub fn read_id(&self) -> Result<u32, XspiError> {
        self.wait_not_busy()?;
        self.clear_tcf();
        let saved_cr = unsafe {
            let cr = (XSPI2_BASE + CR_OFFSET) as *mut u32;
            let prev = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, prev | CR_ABORT);
            wait_abort_clear(cr);
            core::ptr::write_volatile(cr, 0);
            core::ptr::write_volatile(cr, CR_FMODE_INDIRECT_READ | CR_EN);
            prev
        };
        settle_after_enable();
        unsafe {
            let tcr = (XSPI2_BASE + TCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(tcr, TCR_DHQC); // DHQC=1, no dummy cycles
            let dlr = (XSPI2_BASE + DLR_OFFSET) as *mut u32;
            core::ptr::write_volatile(dlr, 2); // 3 bytes - 1
            let ccr = (XSPI2_BASE + CCR_OFFSET) as *mut u32;
            // 1-1-1 SPI, 8-bit opcode, no address, 1-line data.
            core::ptr::write_volatile(ccr, CCR_IMODE_1L | CCR_DMODE_1L);
            cortex_m::asm::dsb();
            let ir = (XSPI2_BASE + IR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ir, OP_RDID);
        }
        let tcf_result = self.wait_tcf();
        let id_val = if tcf_result.is_ok() {
            unsafe {
                let dr = (XSPI2_BASE + DR_OFFSET) as *const u32;
                core::ptr::read_volatile(dr) & 0x00FF_FFFF
            }
        } else {
            0xFFFF_FFFF
        };
        self.clear_tcf();
        unsafe {
            let cr = (XSPI2_BASE + CR_OFFSET) as *mut u32;
            let cur = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, cur | CR_ABORT);
            wait_abort_clear(cr);
            core::ptr::write_volatile(cr, 0);
            core::ptr::write_volatile(cr, saved_cr);
        }
        settle_after_enable();
        tcf_result?;
        Ok(id_val)
    }

    /// FMODE-neutral 1-1-1 SPI software reset: RSTEN (0x66) + RST (0x99) +
    /// recovery delay (~200 us). Forces the chip back to a known clean state
    /// (1-1-1 SPI, all volatile config cleared). Useful when chip seems stuck
    /// after init's mem-mapped probe sequence.
    pub fn chip_reset_spi(&self) -> Result<(), XspiError> {
        self.wait_not_busy()?;
        self.clear_tcf();
        // FMODE=00 (indirect-write) — ST HAL default for all commands.
        // Instruction-only commands trigger on IR write; BUSY indicates done.
        let saved_cr = unsafe {
            let cr = (XSPI2_BASE + CR_OFFSET) as *mut u32;
            let prev = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, prev | CR_ABORT);
            wait_abort_clear(cr);
            core::ptr::write_volatile(cr, 0);
            core::ptr::write_volatile(cr, CR_FMODE_INDIRECT_WRITE | CR_EN);
            prev
        };
        settle_after_enable();
        // Step 1: RSTEN (0x66) — instruction-only, FMODE=00, IR write triggers,
        // wait BUSY=0 to confirm completion (matches ST HAL_XSPI_Command for
        // DataMode=NONE).
        unsafe {
            let tcr = (XSPI2_BASE + TCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(tcr, 0);
            let ccr = (XSPI2_BASE + CCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ccr, CCR_IMODE_1L);
            cortex_m::asm::dsb();
            let ir = (XSPI2_BASE + IR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ir, OP_RSTEN);
        }
        let r1 = self.wait_not_busy();
        self.clear_tcf();
        // Step 2: RST (0x99). RSTEN must be immediately followed by RST.
        unsafe {
            let ir = (XSPI2_BASE + IR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ir, OP_RST);
        }
        let r2 = self.wait_not_busy();
        self.clear_tcf();
        // Recovery delay (~200 us at 150 MHz = 30K cycles; pad to 50K).
        let mut d: u32 = 0;
        while d < 50_000 {
            core::hint::spin_loop();
            d = d.wrapping_add(1);
        }
        unsafe {
            let cr = (XSPI2_BASE + CR_OFFSET) as *mut u32;
            let cur = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, cur | CR_ABORT);
            wait_abort_clear(cr);
            core::ptr::write_volatile(cr, 0);
            core::ptr::write_volatile(cr, saved_cr);
        }
        settle_after_enable();
        r1?;
        r2?;
        Ok(())
    }

    /// FMODE-neutral 1-1-1 SPI RDCR (Read Configuration Register 1, opcode 0x15).
    /// CR1 default for MX25UM51245G has ODS bits set (typically 0x07 or 0x30).
    /// Diagnostic — used to disambiguate "sampling broken" vs "chip rejects writes".
    /// CR1 != 0x00 confirms full read-direction integrity.
    pub fn read_cr1_in_spi(&self) -> Result<u8, XspiError> {
        self.wait_not_busy()?;
        self.clear_tcf();
        let saved_cr = unsafe {
            let cr = (XSPI2_BASE + CR_OFFSET) as *mut u32;
            let prev = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, prev | CR_ABORT);
            wait_abort_clear(cr);
            core::ptr::write_volatile(cr, 0);
            core::ptr::write_volatile(cr, CR_FMODE_INDIRECT_READ | CR_EN);
            prev
        };
        settle_after_enable();
        unsafe {
            let tcr = (XSPI2_BASE + TCR_OFFSET) as *mut u32;
            // 1-1-1 RDCR: no dummy cycles, DHQC=1 for sample timing.
            core::ptr::write_volatile(tcr, TCR_DHQC);
            let dlr = (XSPI2_BASE + DLR_OFFSET) as *mut u32;
            core::ptr::write_volatile(dlr, 0); // 1 byte - 1
            let ccr = (XSPI2_BASE + CCR_OFFSET) as *mut u32;
            // 1-1-1 SPI, 8-bit opcode, no address, 1-line data.
            core::ptr::write_volatile(ccr, CCR_IMODE_1L | CCR_DMODE_1L);
            cortex_m::asm::dsb();
            let ir = (XSPI2_BASE + IR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ir, OP_RDCR);
        }
        let tcf_result = self.wait_tcf();
        let cr1_byte = if tcf_result.is_ok() {
            unsafe {
                let dr = (XSPI2_BASE + DR_OFFSET) as *const u32;
                (core::ptr::read_volatile(dr) & 0xFF) as u8
            }
        } else {
            0xFF
        };
        self.clear_tcf();
        unsafe {
            let cr = (XSPI2_BASE + CR_OFFSET) as *mut u32;
            let cur = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, cur | CR_ABORT);
            wait_abort_clear(cr);
            core::ptr::write_volatile(cr, 0);
            core::ptr::write_volatile(cr, saved_cr);
        }
        settle_after_enable();
        tcf_result?;
        Ok(cr1_byte)
    }

    /// FMODE-neutral 1-1-1 SPI Release from Deep Power Down (RDP, opcode 0xAB).
    /// Wakes the chip if boot ROM left it in DP. tRES1 datasheet ~30us;
    /// 50K cycle recovery (~333us at 150MHz) for safety margin.
    pub fn release_dp_spi(&self) -> Result<(), XspiError> {
        self.wait_not_busy()?;
        self.clear_tcf();
        // FMODE=00 + instruction-only — ST HAL pattern.
        let saved_cr = unsafe {
            let cr = (XSPI2_BASE + CR_OFFSET) as *mut u32;
            let prev = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, prev | CR_ABORT);
            wait_abort_clear(cr);
            core::ptr::write_volatile(cr, 0);
            core::ptr::write_volatile(cr, CR_FMODE_INDIRECT_WRITE | CR_EN);
            prev
        };
        settle_after_enable();
        unsafe {
            let tcr = (XSPI2_BASE + TCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(tcr, 0);
            let ccr = (XSPI2_BASE + CCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ccr, CCR_IMODE_1L);
            cortex_m::asm::dsb();
            let ir = (XSPI2_BASE + IR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ir, OP_RDP);
        }
        let r = self.wait_not_busy();
        self.clear_tcf();
        // tRES1 wakeup recovery delay before any other command.
        let mut d: u32 = 0;
        while d < 50_000 {
            core::hint::spin_loop();
            d = d.wrapping_add(1);
        }
        unsafe {
            let cr = (XSPI2_BASE + CR_OFFSET) as *mut u32;
            let cur = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, cur | CR_ABORT);
            wait_abort_clear(cr);
            core::ptr::write_volatile(cr, 0);
            core::ptr::write_volatile(cr, saved_cr);
        }
        settle_after_enable();
        r
    }

    /// FMODE-neutral 1-1-1 SPI WREN. Used by oracle.rs as a primitive so it
    /// can read SR between WREN and WRCR2 (verify WEL=1) for diagnostics.
    pub fn write_enable_spi(&self) -> Result<(), XspiError> {
        self.wait_not_busy()?;
        self.clear_tcf();
        // ST HAL pattern: FMODE=00 + DataMode=NONE for instruction-only WREN.
        // IR write triggers, BUSY=0 indicates done. TCF is NOT used for no-data.
        let saved_cr = unsafe {
            let cr = (XSPI2_BASE + CR_OFFSET) as *mut u32;
            let prev = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, prev | CR_ABORT);
            wait_abort_clear(cr);
            core::ptr::write_volatile(cr, 0);
            core::ptr::write_volatile(cr, CR_FMODE_INDIRECT_WRITE | CR_EN);
            prev
        };
        settle_after_enable();
        unsafe {
            let tcr = (XSPI2_BASE + TCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(tcr, 0);
            let ccr = (XSPI2_BASE + CCR_OFFSET) as *mut u32;
            // 1-1-1 SPI, 8-bit opcode, no address, no data — DataMode=NONE.
            core::ptr::write_volatile(ccr, CCR_IMODE_1L);
            cortex_m::asm::dsb();
            let ir = (XSPI2_BASE + IR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ir, OP_WREN_SPI);
        }
        // Wait BUSY=0 (transfer complete for no-data commands per ST HAL).
        let tcf_result = self.wait_not_busy();
        self.clear_tcf();
        unsafe {
            let cr = (XSPI2_BASE + CR_OFFSET) as *mut u32;
            let cur = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, cur | CR_ABORT);
            wait_abort_clear(cr);
            core::ptr::write_volatile(cr, 0);
            core::ptr::write_volatile(cr, saved_cr);
        }
        settle_after_enable();
        tcf_result
    }

    /// FMODE-neutral 1-1-1 SPI RDSR. Returns the chip's status register byte.
    /// Bit 0 = WIP (Write In Progress), bit 1 = WEL (Write Enable Latch).
    /// DHQC=1 for sample-timing margin (matches init_external_flash RDID).
    pub fn read_status_register_in_spi(&self) -> Result<u8, XspiError> {
        self.wait_not_busy()?;
        self.clear_tcf();
        let saved_cr = unsafe {
            let cr = (XSPI2_BASE + CR_OFFSET) as *mut u32;
            let prev = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, prev | CR_ABORT);
            wait_abort_clear(cr);
            core::ptr::write_volatile(cr, 0);
            core::ptr::write_volatile(cr, CR_FMODE_INDIRECT_READ | CR_EN);
            prev
        };
        settle_after_enable();
        unsafe {
            let tcr = (XSPI2_BASE + TCR_OFFSET) as *mut u32;
            // 1-1-1 RDSR: no dummy cycles, DHQC=1 for sample timing.
            core::ptr::write_volatile(tcr, TCR_DHQC);
            let dlr = (XSPI2_BASE + DLR_OFFSET) as *mut u32;
            core::ptr::write_volatile(dlr, 0); // 1 byte - 1
            let ccr = (XSPI2_BASE + CCR_OFFSET) as *mut u32;
            // 1-1-1 SPI: 8-bit opcode, no address, 1-line data.
            core::ptr::write_volatile(ccr, CCR_IMODE_1L | CCR_DMODE_1L);
            cortex_m::asm::dsb();
            let ir = (XSPI2_BASE + IR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ir, OP_RDSR_SPI);
        }
        let tcf_result = self.wait_tcf();
        let sr_byte = if tcf_result.is_ok() {
            unsafe {
                let dr = (XSPI2_BASE + DR_OFFSET) as *const u32;
                (core::ptr::read_volatile(dr) & 0xFF) as u8
            }
        } else {
            0xFF
        };
        self.clear_tcf();
        unsafe {
            let cr = (XSPI2_BASE + CR_OFFSET) as *mut u32;
            let cur = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, cur | CR_ABORT);
            wait_abort_clear(cr);
            core::ptr::write_volatile(cr, 0);
            core::ptr::write_volatile(cr, saved_cr);
        }
        settle_after_enable();
        tcf_result?;
        Ok(sr_byte)
    }

    // ─────────────────────────────────────────────────────────────────
    // Phase E.4c Opt ζ: "minimal disturb" WREN + RDSR primitives
    //
    // Hypothesis: our standard `write_enable_spi` does ABORT + CR=0 +
    // CR=EN|FMODE_INDIRECT_WRITE + settle on every call. This generates a
    // CS# disturbance + 5000-cycle gap that may corrupt WREN at the chip
    // side. The ST loader (per disassembly) leaves XSPI2 EN=1 stable
    // and just writes CCR/TCR/IR per command, switching FMODE without
    // ABORT.
    //
    // These primitives assume the caller has set CR.EN=1 and the
    // appropriate FMODE before invocation. They do NOT touch CR. To
    // mode-switch between WREN (FMODE=00) and RDSR (FMODE=01) the
    // caller writes CR directly with the new FMODE — this works while
    // EN=1 per RM0486 §28 (FMODE may be changed at any time provided
    // ongoing transactions complete first).
    // ─────────────────────────────────────────────────────────────────

    /// 1-1-1 SPI WREN with no CR mutation. Caller must have CR.EN=1 and
    /// CR.FMODE = 00 (indirect-write) already configured. Returns Ok if
    /// the controller signals BUSY=0 within timeout.
    pub fn write_enable_spi_minimal(&self) -> Result<(), XspiError> {
        self.wait_not_busy()?;
        self.clear_tcf();
        unsafe {
            let tcr = (XSPI2_BASE + TCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(tcr, 0);
            let ccr = (XSPI2_BASE + CCR_OFFSET) as *mut u32;
            // 1-1-1 SPI, opcode only — DataMode=NONE, no address.
            core::ptr::write_volatile(ccr, CCR_IMODE_1L);
            cortex_m::asm::dsb();
            let ir = (XSPI2_BASE + IR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ir, OP_WREN_SPI);
        }
        let r = self.wait_not_busy();
        self.clear_tcf();
        r
    }

    /// 1-1-1 SPI RDSR with no CR mutation. Caller must have CR.EN=1 and
    /// CR.FMODE = 01 (indirect-read) already configured. Returns the SR byte
    /// or XspiError on timeout.
    pub fn read_status_register_spi_minimal(&self) -> Result<u8, XspiError> {
        self.wait_not_busy()?;
        self.clear_tcf();
        unsafe {
            let tcr = (XSPI2_BASE + TCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(tcr, TCR_DHQC);
            let dlr = (XSPI2_BASE + DLR_OFFSET) as *mut u32;
            core::ptr::write_volatile(dlr, 0); // 1 byte - 1
            let ccr = (XSPI2_BASE + CCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ccr, CCR_IMODE_1L | CCR_DMODE_1L);
            cortex_m::asm::dsb();
            let ir = (XSPI2_BASE + IR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ir, OP_RDSR_SPI);
        }
        let tcf = self.wait_tcf();
        let sr = if tcf.is_ok() {
            unsafe {
                let dr = (XSPI2_BASE + DR_OFFSET) as *const u32;
                (core::ptr::read_volatile(dr) & 0xFF) as u8
            }
        } else {
            0xFF
        };
        self.clear_tcf();
        tcf?;
        Ok(sr)
    }

    /// 1-1-1 SPI WRCR2 (write CR2 location addressable) with no CR mutation.
    /// Caller must have CR.EN=1 and CR.FMODE=00 (indirect-write) configured,
    /// AND must have issued WREN within the same WEL-active window. Returns
    /// Ok if the controller signals BUSY=0 within timeout. Pattern "DR last":
    /// IR + AR pre-set BEFORE DR (DR write triggers per RM0486 §28.4.10 since
    /// FMODE=00 + DMODE!=000).
    pub fn write_cr2_mode_spi_minimal(&self, data: u8) -> Result<(), XspiError> {
        self.wait_not_busy()?;
        self.clear_tcf();
        unsafe {
            let tcr = (XSPI2_BASE + TCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(tcr, 0);
            let dlr = (XSPI2_BASE + DLR_OFFSET) as *mut u32;
            core::ptr::write_volatile(dlr, 0); // 1 byte - 1
            let ccr = (XSPI2_BASE + CCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ccr,
                CCR_IMODE_1L | CCR_ADMODE_1L | CCR_ADSIZE_4B | CCR_DMODE_1L);
            let ir = (XSPI2_BASE + IR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ir, OP_WRCR2);
            let ar = (XSPI2_BASE + AR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ar, 0); // CR2 location 0 = Mode Select
            cortex_m::asm::dsb();
            // DR LAST = trigger.
            let dr = (XSPI2_BASE + DR_OFFSET) as *mut u32;
            core::ptr::write_volatile(dr, data as u32);
        }
        let r = self.wait_tcf();
        self.clear_tcf();
        r
    }

    /// OPI 8-8-8 STR chip reset sequence (RSTEN 0x9966 + RST 0x6699) using the
    /// minimal pattern with explicit delays (don't trust BUSY polling for OPI
    /// reset edge cases). Used to recover the chip if a WRCR2(0x01) successfully
    /// switched it to OPI mode and we want to bring it back to 1-1-1 SPI
    /// default (chip RST clears all volatile registers including CR2.0).
    /// Caller must have CR.EN=1 and CR.FMODE=00.
    pub fn chip_reset_opi_minimal(&self) -> Result<(), XspiError> {
        self.wait_not_busy()?;
        self.clear_tcf();

        // Configure CCR ONCE for OPI 8-8-8 STR instruction-only (used for both
        // RSTEN and RST — the controller keeps CCR config across IR writes).
        unsafe {
            let tcr = (XSPI2_BASE + TCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(tcr, 0);
            let ccr = (XSPI2_BASE + CCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ccr, CCR_IMODE_8L | CCR_ISIZE_16B);
            cortex_m::asm::dsb(); cortex_m::asm::isb();
        }

        // ── RSTEN (OPI 16-bit opcode 0x9966) ──
        unsafe {
            let ir = (XSPI2_BASE + IR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ir, 0x9966);
            cortex_m::asm::dsb(); cortex_m::asm::isb();
        }
        // Generous transaction-complete wait (~100 µs at 100 MHz). Don't poll
        // BUSY — it can be unreliable across OPI command boundaries on N657.
        let mut d: u32 = 0;
        while d < 10_000 { core::hint::spin_loop(); d = d.wrapping_add(1); }
        self.clear_tcf();

        // tRSTHL inter-command delay (Macronix datasheet: minimum 1 µs between
        // RSTEN and RST). Spin ~100 µs to be safe.
        let mut d: u32 = 0;
        while d < 10_000 { core::hint::spin_loop(); d = d.wrapping_add(1); }

        // ── RST (OPI 16-bit opcode 0x6699) — same CCR ──
        unsafe {
            let ir = (XSPI2_BASE + IR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ir, 0x6699);
            cortex_m::asm::dsb(); cortex_m::asm::isb();
        }
        // Transaction-complete wait
        let mut d: u32 = 0;
        while d < 10_000 { core::hint::spin_loop(); d = d.wrapping_add(1); }
        self.clear_tcf();

        // tRPH chip recovery (Macronix max 30 µs; we wait ~5 ms for safety —
        // chip needs to clear all volatile registers including CR2.0).
        let mut d: u32 = 0;
        while d < 500_000 { core::hint::spin_loop(); d = d.wrapping_add(1); }
        Ok(())
    }

    /// OPI 8-8-8 STR WREN_VOLATILE (opcode 0xAF50) — alternative WREN for
    /// volatile-register writes. Some Macronix variants accept 0x06 (regular
    /// WREN) for WRCR2; others require 0x50 (WREN_VOLATILE). Try this if
    /// regular OPI WREN doesn't latch WEL chip-side.
    /// Caller must have CR.EN=1 and CR.FMODE=00.
    pub fn write_enable_volatile_opi(&self) -> Result<(), XspiError> {
        self.wait_not_busy()?;
        self.clear_tcf();
        unsafe {
            let tcr = (XSPI2_BASE + TCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(tcr, 0);
            let ccr = (XSPI2_BASE + CCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ccr, CCR_IMODE_8L | CCR_ISIZE_16B);
            cortex_m::asm::dsb();
            let ir = (XSPI2_BASE + IR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ir, OP_WREN_VOL_OPI);
        }
        let r = self.wait_not_busy();
        self.clear_tcf();
        r
    }

    /// 1-1-1 SPI WREN_VOLATILE (opcode 0x50) — alternative WREN for volatile
    /// register writes. Caller must have CR.EN=1 and CR.FMODE=00.
    pub fn write_enable_volatile_spi_minimal(&self) -> Result<(), XspiError> {
        self.wait_not_busy()?;
        self.clear_tcf();
        unsafe {
            let tcr = (XSPI2_BASE + TCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(tcr, 0);
            let ccr = (XSPI2_BASE + CCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ccr, CCR_IMODE_1L);
            cortex_m::asm::dsb();
            let ir = (XSPI2_BASE + IR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ir, OP_WREN_VOL_SPI);
        }
        let r = self.wait_not_busy();
        self.clear_tcf();
        r
    }

    /// OPI 8-8-8 STR RDSR with no CR mutation. Caller must have CR.EN=1 and
    /// CR.FMODE=01 (indirect-read). Returns chip's status register byte.
    /// Pattern: 16-bit opcode 0xFA05 + 4 dummy cycles + 1 byte data in 8-line.
    /// Used to verify WEL=1 chip-side after OPI WREN.
    pub fn read_status_register_opi_minimal(&self) -> Result<u8, XspiError> {
        self.wait_not_busy()?;
        self.clear_tcf();
        unsafe {
            let tcr = (XSPI2_BASE + TCR_OFFSET) as *mut u32;
            // OPI STR RDSR: 4 dummy cycles + DHQC=1 for sample-timing margin.
            core::ptr::write_volatile(tcr, 4 | TCR_DHQC);
            let dlr = (XSPI2_BASE + DLR_OFFSET) as *mut u32;
            core::ptr::write_volatile(dlr, 0); // 1 byte - 1
            let ccr = (XSPI2_BASE + CCR_OFFSET) as *mut u32;
            // OPI 8-8-8 STR: 16-bit opcode, no address, 8-line data.
            core::ptr::write_volatile(ccr,
                CCR_IMODE_8L | CCR_ISIZE_16B | CCR_DMODE_8L);
            cortex_m::asm::dsb();
            let ir = (XSPI2_BASE + IR_OFFSET) as *mut u32;
            // FMODE=01 + DMODE!=000 + ADMODE=000 → IR write triggers.
            core::ptr::write_volatile(ir, OP_RDSR); // 0xFA05
        }
        let tcf = self.wait_tcf();
        let sr = if tcf.is_ok() {
            unsafe {
                let dr = (XSPI2_BASE + DR_OFFSET) as *const u32;
                (core::ptr::read_volatile(dr) & 0xFF) as u8
            }
        } else {
            0xFF
        };
        self.clear_tcf();
        tcf?;
        Ok(sr)
    }

    /// OPI 8-8-8 STR WRCR2 with no CR mutation. Caller must have CR.EN=1 and
    /// CR.FMODE=00 (indirect-write), AND must have issued OPI WREN within the
    /// same WEL-active window. Returns Ok if the controller signals TCF within
    /// timeout. Pattern "DR last": IR + AR pre-set BEFORE DR (DR write triggers).
    ///
    /// Primary use: recovery from OPI back to 1-1-1 SPI default by writing
    /// CR2 location 0 = 0x00. This is more reliable than RSTEN+RST because
    /// it follows the same minimal-disturb pattern proven to work for WRCR2
    /// in 1-1-1 SPI.
    pub fn write_cr2_in_opi_minimal(&self, data: u8) -> Result<(), XspiError> {
        self.wait_not_busy()?;
        self.clear_tcf();
        unsafe {
            let tcr = (XSPI2_BASE + TCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(tcr, 0);
            let dlr = (XSPI2_BASE + DLR_OFFSET) as *mut u32;
            core::ptr::write_volatile(dlr, 0); // 1 byte - 1
            let ccr = (XSPI2_BASE + CCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ccr,
                CCR_IMODE_8L | CCR_ISIZE_16B
                | CCR_ADMODE_8L | CCR_ADSIZE_4B
                | CCR_DMODE_8L);
            // OPI WRCR2 16-bit: opcode 0x72 first, complement 0x8D second.
            // ST controller with ISIZE=01 sends IR[7:0] first → IR = 0x8D72.
            let ir = (XSPI2_BASE + IR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ir, 0x8D72);
            let ar = (XSPI2_BASE + AR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ar, 0); // CR2 location 0 = Mode Select
            cortex_m::asm::dsb();
            // DR LAST = trigger.
            let dr = (XSPI2_BASE + DR_OFFSET) as *mut u32;
            core::ptr::write_volatile(dr, data as u32);
        }
        let r = self.wait_tcf();
        self.clear_tcf();
        r
    }

    /// Switch CR.FMODE in-place between indirect-write (00) and
    /// indirect-read (01) without doing the ABORT + disable dance.
    /// Assumes a prior `enter_indirect_mode()` already brought us into
    /// the indirect-* domain (mem-map → indirect-* direct switch is
    /// known broken on N657 per prior session diagnosis).
    pub fn switch_fmode_minimal(&self, indirect_read: bool) {
        unsafe {
            let cr = (XSPI2_BASE + CR_OFFSET) as *mut u32;
            let cur = core::ptr::read_volatile(cr);
            let new_fmode = if indirect_read {
                CR_FMODE_INDIRECT_READ
            } else {
                CR_FMODE_INDIRECT_WRITE
            };
            let new_cr = (cur & !CR_FMODE_MASK) | new_fmode;
            core::ptr::write_volatile(cr, new_cr);
            cortex_m::asm::dsb(); cortex_m::asm::isb();
        }
    }

    /// FMODE-neutral 1-1-1 SPI RDSCUR (Read Security Register, Macronix-specific).
    /// Same wire pattern as RDSR but opcode 0x2B. Returns the 8-bit security
    /// register: SOI/LDSO/PSB/ESB/P_FAIL/E_FAIL/WPSEL — diagnoses chip-internal
    /// protection state (Solid Block, Secure OTP lockdown, prior write/erase fail).
    pub fn read_security_register_spi(&self) -> Result<u8, XspiError> {
        self.wait_not_busy()?;
        self.clear_tcf();
        let saved_cr = unsafe {
            let cr = (XSPI2_BASE + CR_OFFSET) as *mut u32;
            let prev = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, prev | CR_ABORT);
            wait_abort_clear(cr);
            core::ptr::write_volatile(cr, 0);
            core::ptr::write_volatile(cr, CR_FMODE_INDIRECT_READ | CR_EN);
            prev
        };
        settle_after_enable();
        unsafe {
            let tcr = (XSPI2_BASE + TCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(tcr, TCR_DHQC);
            let dlr = (XSPI2_BASE + DLR_OFFSET) as *mut u32;
            core::ptr::write_volatile(dlr, 0); // 1 byte - 1
            let ccr = (XSPI2_BASE + CCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ccr, CCR_IMODE_1L | CCR_DMODE_1L);
            cortex_m::asm::dsb();
            let ir = (XSPI2_BASE + IR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ir, OP_RDSCUR);
        }
        let tcf_result = self.wait_tcf();
        let scur_byte = if tcf_result.is_ok() {
            unsafe {
                let dr = (XSPI2_BASE + DR_OFFSET) as *const u32;
                (core::ptr::read_volatile(dr) & 0xFF) as u8
            }
        } else {
            0xFF
        };
        self.clear_tcf();
        unsafe {
            let cr = (XSPI2_BASE + CR_OFFSET) as *mut u32;
            let cur = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, cur | CR_ABORT);
            wait_abort_clear(cr);
            core::ptr::write_volatile(cr, 0);
            core::ptr::write_volatile(cr, saved_cr);
        }
        settle_after_enable();
        tcf_result?;
        Ok(scur_byte)
    }

    /// FMODE-neutral 1-1-1 SPI WRCR2 (write CR2 location 0 with `data`).
    /// Caller must have issued WREN within the same WEL-active window
    /// (no intervening write commands that auto-clear WEL).
    /// Pattern "IR last": AR + DR pre-set BEFORE IR (the trigger).
    pub fn write_cr2_mode_spi(&self, data: u8) -> Result<(), XspiError> {
        self.wait_not_busy()?;
        self.clear_tcf();
        let saved_cr = unsafe {
            let cr = (XSPI2_BASE + CR_OFFSET) as *mut u32;
            let prev = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, prev | CR_ABORT);
            wait_abort_clear(cr);
            core::ptr::write_volatile(cr, 0);
            core::ptr::write_volatile(cr, CR_FMODE_INDIRECT_WRITE | CR_EN);
            prev
        };
        settle_after_enable();
        unsafe {
            let tcr = (XSPI2_BASE + TCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(tcr, 0);
            let dlr = (XSPI2_BASE + DLR_OFFSET) as *mut u32;
            core::ptr::write_volatile(dlr, 0); // 1 byte - 1
            let ccr = (XSPI2_BASE + CCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ccr,
                CCR_IMODE_1L | CCR_ADMODE_1L | CCR_ADSIZE_4B | CCR_DMODE_1L);
            // FMODE=00 + DMODE!=000 → DR write is the trigger (RM0486 §28.4.10).
            // Order: IR + AR pre-set, DR LAST so chip sees correct opcode +
            // address when DR triggers the bus transaction.
            let ir = (XSPI2_BASE + IR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ir, OP_WRCR2);
            let ar = (XSPI2_BASE + AR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ar, 0); // CR2 location 0 = "Mode Select"
            cortex_m::asm::dsb();
            // DR LAST = trigger.
            let dr = (XSPI2_BASE + DR_OFFSET) as *mut u32;
            core::ptr::write_volatile(dr, data as u32);
        }
        let tcf_result = self.wait_tcf();
        self.clear_tcf();
        unsafe {
            let cr = (XSPI2_BASE + CR_OFFSET) as *mut u32;
            let cur = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, cur | CR_ABORT);
            wait_abort_clear(cr);
            core::ptr::write_volatile(cr, 0);
            core::ptr::write_volatile(cr, saved_cr);
        }
        settle_after_enable();
        tcf_result
    }

    /// Switch the Macronix MX25UM51245G chip from 1-1-1 SPI default to
    /// 8-8-8 Octa-SPI STR (OPI without DDR) mode.
    ///
    /// CR2 location 0:
    ///   0x00 = standard 1-1-1 SPI (default)
    ///   0x01 = 8-8-8 OPI Single Transfer Rate ← we use this
    ///   0x02 = 8D-8D-8D OPI Double Transfer Rate
    pub fn switch_chip_to_opi_dtr(&self) -> Result<(), XspiError> {
        // Step 1: WREN in 1-1-1 SPI (8-bit opcode).
        self.wait_not_busy()?;
        self.clear_tcf();
        unsafe {
            let tcr = (XSPI2_BASE + TCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(tcr, 0);
            let ccr = (XSPI2_BASE + CCR_OFFSET) as *mut u32;
            // 1-1-1 SPI, 8-bit instruction (default ISIZE=00), no address, no data.
            core::ptr::write_volatile(ccr, CCR_IMODE_1L);
            cortex_m::asm::dsb();
            let ir = (XSPI2_BASE + IR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ir, OP_WREN_SPI);
        }
        self.wait_tcf()?;
        self.clear_tcf();

        // Step 2: WRCR2 0x72 + 4-byte address 0x00000000 + 1 byte data 0x01.
        // Pattern "IR last": AR + DR pre-set BEFORE writing IR (which triggers
        // the bus transaction). The previous "IR-then-AR-then-DR" ordering
        // produced silent failures: chip stayed in 1-1-1 SPI even though TCF
        // signalled completion at the controller level.
        self.wait_not_busy()?;
        self.clear_tcf();
        unsafe {
            let tcr = (XSPI2_BASE + TCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(tcr, 0);
            let dlr = (XSPI2_BASE + DLR_OFFSET) as *mut u32;
            core::ptr::write_volatile(dlr, 0); // 1 byte - 1
            let ccr = (XSPI2_BASE + CCR_OFFSET) as *mut u32;
            // 1-1-1 SPI for command, 4-byte address, 1-line data.
            core::ptr::write_volatile(ccr,
                CCR_IMODE_1L | CCR_ADMODE_1L | CCR_ADSIZE_4B | CCR_DMODE_1L);
            // Pre-set address (CR2 location 0 = "Mode Select").
            let ar = (XSPI2_BASE + AR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ar, 0);
            // Pre-fill TX FIFO with data byte 0x01 = 8-8-8 Octa-SPI STR mode.
            let dr = (XSPI2_BASE + DR_OFFSET) as *mut u32;
            core::ptr::write_volatile(dr, 0x01);
            cortex_m::asm::dsb();
            // IR last = trigger.
            let ir = (XSPI2_BASE + IR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ir, OP_WRCR2);
        }
        self.wait_tcf()?;
        self.clear_tcf();
        // Step 3: chip needs ~50 us internal time to actually transition mode
        // after WRCR2. Use ~200_000 cycles ≈ 1.3 ms at 150 MHz as safety margin.
        // Cannot poll WIP via RDSR here (RDSR opcode format depends on mode —
        // we don't yet know whether chip switched).
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        let mut d: u32 = 0;
        while d < 200_000 {
            core::hint::spin_loop();
            d = d.wrapping_add(1);
        }
        // Chip is now in OPI 8D-8D-8D mode. All subsequent commands must
        // use 16-bit OPI opcodes.
        Ok(())
    }

    /// Diagnostic: read Configuration Register 2 location 0 in 1-1-1 SPI.
    /// CR2[0] meaning per Macronix MX25UM51245G:
    ///   0x00 = standard 1-1-1 SPI (factory default / WRCR2 never landed)
    ///   0x01 = 8-8-8 OPI Single Transfer Rate
    ///   0x02 = 8D-8D-8D OPI Double Transfer Rate
    /// If chip already in OPI mode, this 1-1-1 command is not recognized →
    /// returns garbage (typically 0xFF, idle MISO) or TCF timeout.
    /// FMODE-neutral; mirrors read_status_register's CR save/restore pattern.
    pub fn read_cr2_in_spi(&self) -> Result<u8, XspiError> {
        self.wait_not_busy()?;
        self.clear_tcf();
        let saved_cr = unsafe {
            let cr = (XSPI2_BASE + CR_OFFSET) as *mut u32;
            let prev = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, prev | CR_ABORT);
            wait_abort_clear(cr);
            core::ptr::write_volatile(cr, 0);
            core::ptr::write_volatile(cr, CR_FMODE_INDIRECT_READ | CR_EN);
            prev
        };
        settle_after_enable();
        unsafe {
            let tcr = (XSPI2_BASE + TCR_OFFSET) as *mut u32;
            // 1-1-1 RDCR2: no dummy cycles, but DHQC=1 for sample-timing margin.
            core::ptr::write_volatile(tcr, TCR_DHQC);
            let dlr = (XSPI2_BASE + DLR_OFFSET) as *mut u32;
            core::ptr::write_volatile(dlr, 0); // 1 byte - 1
            let ccr = (XSPI2_BASE + CCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ccr,
                CCR_IMODE_1L | CCR_ADMODE_1L | CCR_ADSIZE_4B | CCR_DMODE_1L);
            // FMODE=01 + ADMODE!=000 → AR write is the trigger (RM0486 §28.4.10).
            // Order: IR pre-set, AR LAST.
            let ir = (XSPI2_BASE + IR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ir, OP_RDCR2_SPI);
            cortex_m::asm::dsb();
            let ar = (XSPI2_BASE + AR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ar, 0); // CR2 location 0 — AR write triggers
        }
        let tcf_result = self.wait_tcf();
        let cr2_byte = if tcf_result.is_ok() {
            unsafe {
                let dr = (XSPI2_BASE + DR_OFFSET) as *const u32;
                (core::ptr::read_volatile(dr) & 0xFF) as u8
            }
        } else {
            0xFF
        };
        self.clear_tcf();
        unsafe {
            let cr = (XSPI2_BASE + CR_OFFSET) as *mut u32;
            let cur = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, cur | CR_ABORT);
            wait_abort_clear(cr);
            core::ptr::write_volatile(cr, 0);
            core::ptr::write_volatile(cr, saved_cr);
        }
        settle_after_enable();
        tcf_result?;
        Ok(cr2_byte)
    }

    /// Diagnostic: read Configuration Register 2 location 0 in 8-8-8 OPI STR.
    /// Should return 0x01 if `switch_chip_to_opi_dtr` succeeded. Uses 4 dummy
    /// cycles (Macronix default for read commands in OPI STR after WRCR2).
    pub fn read_cr2_in_opi(&self) -> Result<u8, XspiError> {
        self.wait_not_busy()?;
        self.clear_tcf();
        let saved_cr = unsafe {
            let cr = (XSPI2_BASE + CR_OFFSET) as *mut u32;
            let prev = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, prev | CR_ABORT);
            wait_abort_clear(cr);
            core::ptr::write_volatile(cr, 0);
            core::ptr::write_volatile(cr, CR_FMODE_INDIRECT_READ | CR_EN);
            prev
        };
        settle_after_enable();
        unsafe {
            let tcr = (XSPI2_BASE + TCR_OFFSET) as *mut u32;
            // OPI STR RDCR2: 4 dummy cycles + DHQC=1 for sample-timing margin.
            core::ptr::write_volatile(tcr, 4 | TCR_DHQC);
            let dlr = (XSPI2_BASE + DLR_OFFSET) as *mut u32;
            core::ptr::write_volatile(dlr, 0); // 1 byte - 1
            let ccr = (XSPI2_BASE + CCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ccr,
                CCR_IMODE_8L | CCR_ISIZE_16B
                | CCR_ADMODE_8L | CCR_ADSIZE_4B
                | CCR_DMODE_8L);
            // FMODE=01 + ADMODE!=000 → AR write is the trigger.
            // Order: IR pre-set, AR LAST.
            let ir = (XSPI2_BASE + IR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ir, OP_RDCR2_OPI);
            cortex_m::asm::dsb();
            let ar = (XSPI2_BASE + AR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ar, 0); // CR2 location 0 — AR write triggers
        }
        let tcf_result = self.wait_tcf();
        let cr2_byte = if tcf_result.is_ok() {
            unsafe {
                let dr = (XSPI2_BASE + DR_OFFSET) as *const u32;
                (core::ptr::read_volatile(dr) & 0xFF) as u8
            }
        } else {
            0xFF
        };
        self.clear_tcf();
        unsafe {
            let cr = (XSPI2_BASE + CR_OFFSET) as *mut u32;
            let cur = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, cur | CR_ABORT);
            wait_abort_clear(cr);
            core::ptr::write_volatile(cr, 0);
            core::ptr::write_volatile(cr, saved_cr);
        }
        settle_after_enable();
        tcf_result?;
        Ok(cr2_byte)
    }

    /// Switch from indirect-write to memory-mapped mode with BOTH read
    /// (FAST_READ_4B) AND write (PP4B) configured. AXI writes to the
    /// XSPI2 mem-map region during this state translate into PP4B
    /// commands at the chip side (MCE2 inline encrypts on the AXI path).
    /// Caller must have already issued WREN before entering this mode.
    pub fn enter_program_mem_map(&self) {
        unsafe {
            let cr = (XSPI2_BASE + CR_OFFSET) as *mut u32;
            let cur = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, cur | CR_ABORT);
            wait_abort_clear(cr);
            core::ptr::write_volatile(cr, 0);
            // OPI 8-8-8 STR format: 8-line everything, no DDR, 16-bit instruction.
            let opi_format = CCR_IMODE_8L | CCR_ISIZE_16B
                | CCR_ADMODE_8L | CCR_ADSIZE_4B
                | CCR_DMODE_8L;
            core::ptr::write_volatile((XSPI2_BASE + CCR_OFFSET) as *mut u32,
                opi_format);
            // OPI STR Octa Read DCYC: Macronix default after WRCR2 switch is
            // 20 dummy cycles (CR1.DC[2:0]=000). Don't change without first
            // re-programming chip's CR1.DC.
            core::ptr::write_volatile((XSPI2_BASE + TCR_OFFSET) as *mut u32, 20);
            core::ptr::write_volatile((XSPI2_BASE + IR_OFFSET) as *mut u32,
                OP_FAST_READ_4B);
            core::ptr::write_volatile((XSPI2_BASE + WCCR_OFFSET) as *mut u32,
                opi_format);
            core::ptr::write_volatile((XSPI2_BASE + WTCR_OFFSET) as *mut u32, 0);
            core::ptr::write_volatile((XSPI2_BASE + WIR_OFFSET) as *mut u32,
                OP_PP4B);
            core::ptr::write_volatile(cr, (0b11u32 << 28) | CR_EN);
        }
        settle_after_enable();
    }

    /// Switch back from memory-mapped program mode to indirect-write mode.
    /// Per RM0486 §28.4.16, the abort sequence triggers the start of the
    /// page programming. We must:
    ///   1. dsb sy — flush any pending AXI writes from preceding DMA
    ///   2. ABORT bit set + wait abort clear (this triggers PP at chip)
    ///   3. Wait BUSY=0 — controller drains FIFO and finishes mem-map work
    ///   4. Disable + re-enable indirect-write mode (for next WREN/RDSR)
    pub fn exit_program_mem_map(&self) {
        unsafe {
            // (1) Drain AXI writes from DMA into XSPI FIFO.
            cortex_m::asm::dsb(); cortex_m::asm::isb();
            let cr = (XSPI2_BASE + CR_OFFSET) as *mut u32;
            // (2) ABORT — this triggers PP at chip side.
            let cur = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, cur | CR_ABORT);
            wait_abort_clear(cr);
            // (3) Wait BUSY=0. Per §28.4.16, BUSY stays high in mem-map mode
            // until abort or disable; after abort_clear, BUSY drops.
            let sr = (XSPI2_BASE + SR_OFFSET) as *const u32;
            let mut i: u32 = 0;
            while i < 100_000 {
                if core::ptr::read_volatile(sr) & SR_BUSY == 0 { break; }
                i += 1;
            }
            // (4) Disable + re-enable indirect-write (FMODE=00, ST HAL default).
            core::ptr::write_volatile(cr, 0);
            core::ptr::write_volatile(cr, CR_FMODE_INDIRECT_WRITE | CR_EN);
        }
        settle_after_enable();
    }

    /// Issue Write Enable (sets WEL bit in flash status reg).
    /// OPI 8-8-8 STR instruction-only (no DMODE) — FMODE=00 from caller's
    /// `enter_indirect_mode`, IR write triggers, BUSY=0 indicates done.
    /// Matches ST HAL_XSPI_Command pattern for DataMode=NONE.
    pub fn write_enable(&self) -> Result<(), XspiError> {
        self.wait_not_busy()?;
        self.clear_tcf();
        unsafe {
            let tcr = (XSPI2_BASE + TCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(tcr, 0);
            // OPI 8-8-8 STR instruction-only command: 8-line, 16-bit opcode.
            let ccr = (XSPI2_BASE + CCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ccr,
                CCR_IMODE_8L | CCR_ISIZE_16B);
            cortex_m::asm::dsb();
            let ir = (XSPI2_BASE + IR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ir, OP_WREN);
        }
        // Wait BUSY=0 — no data phase per ST HAL DataMode=NONE pattern.
        self.wait_not_busy()?;
        self.clear_tcf();
        Ok(())
    }

    /// Block-erase 64 KB at flash_addr (must be 64KB-aligned).
    /// OPI 8-8-8 STR with instruction + 4-byte address, no data.
    /// FMODE=00 from caller's enter_indirect_mode. Per ST HAL pattern: write
    /// IR then AR (AR last triggers the address phase), wait BUSY=0 for done.
    pub fn block_erase_64k(&self, flash_addr: u32) -> Result<(), XspiError> {
        debug_assert!(flash_addr & 0xFFFF == 0, "BE64 requires 64KB-aligned address");
        self.wait_not_busy()?;
        self.clear_tcf();
        unsafe {
            let tcr = (XSPI2_BASE + TCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(tcr, 0);
            let ccr = (XSPI2_BASE + CCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ccr,
                CCR_IMODE_8L | CCR_ISIZE_16B
                | CCR_ADMODE_8L | CCR_ADSIZE_4B);
            // ST HAL pattern: IR then AR (no specific trigger ordering rule,
            // any complete config triggers the controller).
            let ir = (XSPI2_BASE + IR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ir, OP_BE64);
            cortex_m::asm::dsb();
            let ar = (XSPI2_BASE + AR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ar, flash_addr & 0x07FF_FFFF);
        }
        // Wait BUSY=0 (no data phase = no TCF, just controller idle).
        self.wait_not_busy()?;
        self.clear_tcf();
        Ok(())
    }

    /// Read flash status register byte (RDSR) in 1-1-1 SPI mode.
    /// FMODE-neutral: saves and restores the caller's CR around the read.
    /// Uses ABORT + disable + reconfig + re-enable for FMODE switching
    /// (canonical N657 sequence — direct CR write while EN=1 is silently ignored).
    pub fn read_status_register(&self) -> Result<u8, XspiError> {
        self.wait_not_busy()?;
        self.clear_tcf();
        let saved_cr = unsafe {
            let cr = (XSPI2_BASE + CR_OFFSET) as *mut u32;
            let prev = core::ptr::read_volatile(cr);
            // Switch to indirect-read: ABORT + disable + new CR
            core::ptr::write_volatile(cr, prev | CR_ABORT);
            wait_abort_clear(cr);
            core::ptr::write_volatile(cr, 0);
            core::ptr::write_volatile(cr, CR_FMODE_INDIRECT_READ | CR_EN);
            prev
        };
        settle_after_enable();
        unsafe {
            // OPI 8-8-8 STR RDSR: 4 dummy cycles + DHQC=1 for sample-timing margin.
            let tcr = (XSPI2_BASE + TCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(tcr, 4 | TCR_DHQC);
            let dlr = (XSPI2_BASE + DLR_OFFSET) as *mut u32;
            core::ptr::write_volatile(dlr, 0); // 1 byte - 1
            let ccr = (XSPI2_BASE + CCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ccr,
                CCR_IMODE_8L | CCR_ISIZE_16B | CCR_DMODE_8L);
            cortex_m::asm::dsb();
            let ir = (XSPI2_BASE + IR_OFFSET) as *mut u32;
            core::ptr::write_volatile(ir, OP_RDSR);
        }
        let tcf_result = self.wait_tcf();
        let sr_byte = if tcf_result.is_ok() {
            unsafe {
                let dr = (XSPI2_BASE + DR_OFFSET) as *const u32;
                (core::ptr::read_volatile(dr) & 0xFF) as u8
            }
        } else {
            0
        };
        self.clear_tcf();
        // Always restore caller's CR via ABORT + disable + write saved.
        unsafe {
            let cr = (XSPI2_BASE + CR_OFFSET) as *mut u32;
            let cur = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, cur | CR_ABORT);
            wait_abort_clear(cr);
            core::ptr::write_volatile(cr, 0);
            core::ptr::write_volatile(cr, saved_cr);
        }
        settle_after_enable();
        tcf_result?;
        Ok(sr_byte)
    }

    /// Poll WIP bit until clear or timeout. `max_loops` proxies time at -O0:
    /// pass ~150_000 per ms of budget (~1.5 M for a 1500 ms BE64 budget).
    pub fn poll_wip(&self, max_loops: u32) -> Result<(), XspiError> {
        let mut i: u32 = 0;
        while i < max_loops {
            let sr = self.read_status_register()?;
            if sr & SR_WIP == 0 {
                return Ok(());
            }
            i += 1;
        }
        Err(XspiError::EraseTimeout)
    }

    fn wait_not_busy(&self) -> Result<(), XspiError> {
        let mut i: u32 = 0;
        while i < 1_000_000 {
            unsafe {
                let sr = (XSPI2_BASE + SR_OFFSET) as *const u32;
                if core::ptr::read_volatile(sr) & SR_BUSY == 0 {
                    return Ok(());
                }
            }
            i += 1;
        }
        Err(XspiError::BusyTimeout)
    }

    fn wait_tcf(&self) -> Result<(), XspiError> {
        let mut i: u32 = 0;
        while i < 1_000_000 {
            unsafe {
                let sr = (XSPI2_BASE + SR_OFFSET) as *const u32;
                if core::ptr::read_volatile(sr) & SR_TCF != 0 {
                    return Ok(());
                }
            }
            i += 1;
        }
        Err(XspiError::TransferIncomplete)
    }

    fn clear_tcf(&self) {
        unsafe {
            let fcr = (XSPI2_BASE + FCR_OFFSET) as *mut u32;
            core::ptr::write_volatile(fcr, FCR_CTCF);
        }
    }
}
