//! HPDMA1 driver for STM32N657 — minimal channel driver for feeding a peripheral
//! FIFO (here: HASH_DIN for DMA-fed SHA-256). Recovered from the reverted issue-#44
//! Phase B.X CRYP attempt (commit 476e060, RM0486 §18-verified register map) and
//! adapted: `wait_complete` returns the status word instead of panicking so a failed
//! transfer can be diagnosed over UART/GDB rather than halting.
//!
//! - **Base**: 0x5802_0000 (Secure alias). N657 has one HPDMA (no HPDMA2).
//! - **Channels**: 16. Ch 0–11: 16-byte FIFO + plain linked-list (we use these).
//! - **Per-channel block**: base + 0x50 + 0x80*ch.
//! - **Clock**: RCC AHB5ENR bit 0 = HPDMA1EN (enable before use).

use peripheral_regs::{read_register, write_register};

/// HPDMA1 secure base address (RM0486 §2.3 memory map).
pub const HPDMA1_BASE: u32 = 0x5802_0000;

const CHANNEL_BLOCK_BASE: u32 = 0x50;
const CHANNEL_BLOCK_STRIDE: u32 = 0x80;

// Per-channel register offsets (relative to the channel block base, §18.8.22).
const CCR_OFFSET: u32 = 0x14;
const CFCR_OFFSET: u32 = 0x0C;
const CSR_OFFSET: u32 = 0x10;
const CTR1_OFFSET: u32 = 0x40;
const CTR2_OFFSET: u32 = 0x44;
const CBR1_OFFSET: u32 = 0x48;
const CSAR_OFFSET: u32 = 0x4C;
const CDAR_OFFSET: u32 = 0x50;
const CLLR_OFFSET: u32 = 0x7C;

const CR_EN: u32 = 1 << 0;
const CR_RESET: u32 = 1 << 1;
const CR_TCIE: u32 = 1 << 8; // transfer-complete interrupt enable (CxCR, RM0486 §18.8.22)

// CxSR flags
pub const SR_IDLEF: u32 = 1 << 0;
const SR_TCF: u32 = 1 << 8;
const SR_DTEF: u32 = 1 << 10; // data-transfer error
const SR_ULEF: u32 = 1 << 11; // update-link error
const SR_USEF: u32 = 1 << 12; // user-setting error
const SR_ERR_MASK: u32 = SR_DTEF | SR_ULEF | SR_USEF;

// CxFCR — write 1 to clear (mirror of CxSR)
const FCR_CTCF: u32 = 1 << 8;
const FCR_CDTEF: u32 = 1 << 10;
const FCR_CULEF: u32 = 1 << 11;
const FCR_CUSEF: u32 = 1 << 12;
const FCR_CLEAR_ALL: u32 = FCR_CTCF | FCR_CDTEF | FCR_CULEF | FCR_CUSEF;

// CxTR1 fields — bit positions VERIFIED against CMSIS stm32n657xx.h DMA_CTR1_*.
// (The reverted 476e060 file had SAP at bit 11 = PAM padding, and DAP at bit 27 —
// both wrong; plus it never set SSEC/DSEC. Those, together with the missing channel
// SECCFGR bit, are the prime suspects for why DMA→CRYP silently failed.)
const TR1_SDW_WORD: u32 = 0b10 << 0; // SDW_LOG2 @0: source data width = word
const TR1_SINC: u32 = 1 << 3; // SINC @3: source address increment
const TR1_SBL4: u32 = 3 << 4; // SBL_1 @4: source burst = 4 (N-1)
const TR1_SSEC: u32 = 1 << 15; // SSEC @15: secure source access
const TR1_DDW_WORD: u32 = 0b10 << 16; // DDW_LOG2 @16: dest data width = word
const TR1_DINC: u32 = 1 << 19; // DINC @19: dest address increment
const TR1_DBL4: u32 = 3 << 20; // DBL_1 @20: dest burst = 4 (N-1)
const TR1_DSEC: u32 = 1 << 31; // DSEC @31: secure dest access
// SAP @14 / DAP @30 select the master port (0 or 1); leave 0 (port 0) — port 0
// reaches both the AXISRAM/flash source and the AHB3 HASH. Flip to port 1 if the
// transfer errors with a bus fault on one endpoint.

// CxTR2
const TR2_SWREQ: u32 = 1 << 9; // SWREQ @9: 1 = software-triggered (mem-to-mem)
const TR2_DREQ: u32 = 1 << 10; // DREQ @10: 1 = destination is the peripheral

// DMA global secure/privileged config (DMA_TypeDef @ HPDMA1_BASE): SECCFGR @0x00,
// PRIVCFGR @0x04, one bit per channel. A channel must be Secure to drive the Secure
// HASH/CRYP — without this the RIFSC/RISAF silently drops its writes.
const SECCFGR_OFFSET: u32 = 0x00;
const PRIVCFGR_OFFSET: u32 = 0x04;

// Per-channel CID config (channel_base + 0x04, CMSIS DMA_CCIDCFGR). CFEN enables the
// channel's CID filtering; SCID (bits 4:6) is the static CID the channel presents on
// its bus transactions. The AXISRAM RISAF default region admits only CID 1 (the CPU
// master), so the channel must present CID 1 or the RISAF silently drops its accesses.
const CCIDCFGR_OFFSET: u32 = 0x04;
const CCIDCFGR_CID1: u32 = (1 << 0) | (1 << 4); // CFEN | SCID=1

// RCC AHB5ENR bit 0 = HPDMA1EN — the HPDMA1 kernel clock (RM0486 §11 / §18.3).
const RCC_AHB5ENR: u32 = 0x5602_8260;
const AHB5ENR_HPDMA1EN: u32 = 1 << 0;

/// Enable the HPDMA1 kernel clock (idempotent — a no-op if already on). The DMA
/// drivers call this before first use so the DMA path is self-sufficient and doesn't
/// depend on where in the boot sequence the clock was brought up.
pub fn enable_clock() {
    let rcc = RCC_AHB5ENR as *const u32;
    // SAFETY: RCC AHB5ENR read-modify-write; setting an already-set enable bit is a no-op.
    unsafe {
        let v = read_register(rcc, 0);
        write_register(rcc, 0, v | AHB5ENR_HPDMA1EN);
    }
}

/// Transfer-complete flag for a channel (public so callers can poll if desired).
#[allow(dead_code)]
pub const CH_TCF: u32 = SR_TCF;

pub struct Hpdma1;

impl Default for Hpdma1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Hpdma1 {
    pub fn new() -> Self {
        Hpdma1
    }

    fn channel_base(ch: u8) -> u32 {
        HPDMA1_BASE + CHANNEL_BLOCK_BASE + CHANNEL_BLOCK_STRIDE * (ch as u32)
    }

    /// Read a channel's status register (for diagnostics).
    pub fn status(&self, ch: u8) -> u32 {
        let base = Self::channel_base(ch) as *const u32;
        // SAFETY: HPDMA1 channel MMIO read.
        unsafe { read_register(base, CSR_OFFSET) }
    }

    /// Mark a channel Secure + privileged in the DMA global config, so its accesses
    /// to the Secure HASH/CRYP are not dropped by the RIFSC/RISAF. MUST be called
    /// before configuring a channel that touches a Secure peripheral.
    pub fn set_channel_secure(&self, ch: u8) {
        let g = HPDMA1_BASE as *const u32;
        let base = Self::channel_base(ch) as *const u32;
        // SAFETY: DMA global SECCFGR/PRIVCFGR + per-channel CCIDCFGR — device registers.
        unsafe {
            let sec = read_register(g, SECCFGR_OFFSET);
            write_register(g, SECCFGR_OFFSET, sec | (1 << ch));
            let priv_ = read_register(g, PRIVCFGR_OFFSET);
            write_register(g, PRIVCFGR_OFFSET, priv_ | (1 << ch));
            // Present CID 1 on the channel's transfers so the AXISRAM RISAF admits them.
            write_register(base, CCIDCFGR_OFFSET, CCIDCFGR_CID1);
        }
    }

    /// Reset a channel and clear pending flags. Idempotent (CxCR.RESET self-clears).
    pub fn reset_channel(&self, ch: u8) {
        let base = Self::channel_base(ch) as *const u32;
        // SAFETY: HPDMA1 channel MMIO writes, single-word bus-acknowledged accesses.
        unsafe {
            write_register(base, CCR_OFFSET, CR_RESET);
            while (read_register(base, CCR_OFFSET) & CR_RESET) != 0 {}
            write_register(base, CFCR_OFFSET, FCR_CLEAR_ALL);
        }
    }

    /// Configure **memory → peripheral** (AXISRAM/flash-mapped src → fixed periph FIFO).
    /// Word-width burst-of-4, incrementing AXI source, fixed AHB destination, paced by
    /// the peripheral's DMA request line (`reqsel`, DREQ=1). `byte_count` must be a
    /// multiple of the data width (4).
    pub fn configure_mem_to_periph(
        &self,
        ch: u8,
        src: u32,
        periph_dst: u32,
        byte_count: u32,
        reqsel: u8,
    ) {
        let base = Self::channel_base(ch) as *const u32;
        // SAFETY: HPDMA1 channel block MMIO; one channel per concurrent use.
        unsafe {
            // Source: word, incrementing, burst-4, Secure. Dest: word, FIXED (no
            // DINC — a peripheral FIFO), burst-4, Secure. Ports left at 0.
            let tr1 = TR1_SDW_WORD | TR1_SINC | TR1_SBL4 | TR1_SSEC | TR1_DDW_WORD | TR1_DBL4 | TR1_DSEC;
            write_register(base, CTR1_OFFSET, tr1);
            write_register(base, CTR2_OFFSET, (reqsel as u32) | TR2_DREQ);
            write_register(base, CBR1_OFFSET, byte_count);
            write_register(base, CSAR_OFFSET, src);
            write_register(base, CDAR_OFFSET, periph_dst);
            write_register(base, CLLR_OFFSET, 0);
        }
    }

    /// Configure **peripheral → memory** (fixed periph FIFO src → incrementing AXI dst).
    /// Word-width burst-of-4, FIXED AHB source (no SINC), incrementing destination, paced
    /// by the peripheral's DMA request line (`reqsel`, DREQ=0 → the peripheral is the
    /// SOURCE). Mirror of `configure_mem_to_periph` for draining e.g. CRYP_DOUT.
    pub fn configure_periph_to_mem(
        &self,
        ch: u8,
        periph_src: u32,
        dst: u32,
        byte_count: u32,
        reqsel: u8,
    ) {
        let base = Self::channel_base(ch) as *const u32;
        // SAFETY: HPDMA1 channel block MMIO; one channel per concurrent use.
        unsafe {
            // Source: word, FIXED (no SINC — a peripheral FIFO), burst-4, Secure. Dest:
            // word, incrementing, burst-4, Secure. Ports left at 0.
            let tr1 = TR1_SDW_WORD | TR1_SBL4 | TR1_SSEC | TR1_DDW_WORD | TR1_DINC | TR1_DBL4 | TR1_DSEC;
            write_register(base, CTR1_OFFSET, tr1);
            // DREQ=0 (bit 10 clear) → the hardware request drives the SOURCE (peripheral).
            write_register(base, CTR2_OFFSET, reqsel as u32);
            write_register(base, CBR1_OFFSET, byte_count);
            write_register(base, CSAR_OFFSET, periph_src);
            write_register(base, CDAR_OFFSET, dst);
            write_register(base, CLLR_OFFSET, 0);
        }
    }

    /// Configure **memory → memory** (both endpoints incrementing, software-triggered).
    /// Used to isolate the DMA data path from a peripheral FIFO. Word burst-4, Secure.
    pub fn configure_mem_to_mem(&self, ch: u8, src: u32, dst: u32, byte_count: u32) {
        let base = Self::channel_base(ch) as *const u32;
        // SAFETY: HPDMA1 channel block MMIO.
        unsafe {
            let tr1 = TR1_SDW_WORD
                | TR1_SINC
                | TR1_SBL4
                | TR1_SSEC
                | TR1_DDW_WORD
                | TR1_DINC
                | TR1_DBL4
                | TR1_DSEC;
            write_register(base, CTR1_OFFSET, tr1);
            write_register(base, CTR2_OFFSET, TR2_SWREQ); // no peripheral handshake
            write_register(base, CBR1_OFFSET, byte_count);
            write_register(base, CSAR_OFFSET, src);
            write_register(base, CDAR_OFFSET, dst);
            write_register(base, CLLR_OFFSET, 0);
        }
    }

    /// Configure a **mem-to-mem** transfer and START it with the transfer-complete
    /// interrupt enabled — does NOT wait. The channel's TC IRQ fires on completion; the
    /// CPU keeps running while the DMA loads in the background (the async prefetch path).
    /// The caller must have called `set_channel_secure` + `reset_channel` first.
    pub fn start_mem_to_mem_irq(&self, ch: u8, src: u32, dst: u32, byte_count: u32) {
        self.configure_mem_to_mem(ch, src, dst, byte_count);
        let base = Self::channel_base(ch) as *const u32;
        // SAFETY: arm TCIE and start (EN) in one CCR write.
        unsafe {
            let cr = read_register(base, CCR_OFFSET);
            write_register(base, CCR_OFFSET, cr | CR_TCIE | CR_EN);
        }
    }

    /// Enable a configured channel; it then arms its handshake and transfers on the
    /// next peripheral request.
    pub fn enable_channel(&self, ch: u8) {
        let base = Self::channel_base(ch) as *const u32;
        // SAFETY: HPDMA1 channel CR write.
        unsafe {
            let cr = read_register(base, CCR_OFFSET);
            write_register(base, CCR_OFFSET, cr | CR_EN);
        }
    }

    /// Poll until transfer-complete (`TCF`) or an error flag surfaces, or the budget
    /// elapses. Returns the final status word — the caller inspects `SR_ERR_MASK` /
    /// `SR_TCF` and prints it (no panic, so a broken transfer is diagnosable).
    pub fn wait_complete(&self, ch: u8, mut budget: u32) -> u32 {
        let base = Self::channel_base(ch) as *const u32;
        // SAFETY: HPDMA1 channel SR polling read.
        loop {
            let sr = unsafe { read_register(base, CSR_OFFSET) };
            if (sr & (SR_TCF | SR_ERR_MASK)) != 0 {
                return sr;
            }
            if budget == 0 {
                return sr;
            }
            budget -= 1;
        }
    }

    /// Clear a channel's status flags so it can be reused.
    pub fn clear_flags(&self, ch: u8) {
        let base = Self::channel_base(ch) as *const u32;
        // SAFETY: write-1-to-clear on CxFCR.
        unsafe {
            write_register(base, CFCR_OFFSET, FCR_CLEAR_ALL);
        }
    }
}

// ── Cortex-M55 D-cache maintenance (DMA coherency) ──────────────────────────
// The M55 D-cache is enabled at boot; DMA to/from cacheable memory needs the CPU
// view flushed. DCCMVAC @ SCB+0x268 (clean by VA), DCIMVAC @ SCB+0x25C (invalidate
// by VA). Line size 32 B; round the range to line boundaries.

const SCB_DCIMVAC: *mut u32 = 0xE000_EF5C as *mut u32;
const SCB_DCCMVAC: *mut u32 = 0xE000_EF68 as *mut u32;
const DCACHE_LINE: usize = 32;

#[inline]
fn dcache_op_range(reg: *mut u32, addr: usize, len: usize) {
    let mut a = addr & !(DCACHE_LINE - 1);
    let end = (addr + len + DCACHE_LINE - 1) & !(DCACHE_LINE - 1);
    // SAFETY: SCB maintenance-register writes, one per cache line in range.
    unsafe {
        while a < end {
            core::ptr::write_volatile(reg, a as u32);
            a += DCACHE_LINE;
        }
        core::arch::asm!("dsb");
        core::arch::asm!("isb");
    }
}

/// Clean (write back) the D-cache lines covering `[addr, addr+len)`. Call before a
/// DMA that READS this buffer so the DMA sees the latest CPU writes.
pub fn dcache_clean_range(addr: usize, len: usize) {
    dcache_op_range(SCB_DCCMVAC, addr, len);
}

/// Invalidate the D-cache lines covering `[addr, addr+len)`. Call after a DMA has
/// WRITTEN this buffer so CPU reads pull the DMA bytes from RAM.
#[allow(dead_code)]
pub fn dcache_invalidate_range(addr: usize, len: usize) {
    dcache_op_range(SCB_DCIMVAC, addr, len);
}
