//! RISAF driver — Resource Isolation Slave unit for Address space protection
//! (full version), STM32N657. RM0486 chapter 7.
//!
//! Each RISAF instance protects one memory target and exposes up to 7 base
//! regions (4 KB granularity on AXI). Region START/END registers store
//! byte-offsets RELATIVE to the protected memory base, but the hardware masks
//! out address bits outside the protected space (RM0486 §7.5.7-8). This means
//! the caller can pass absolute addresses (Secure or NS alias) and the
//! correct relative offset always lands in the register.
//!
//! ## Default behaviour
//! When BREN = 0, the primary region 0 applies: secure, privileged, CID = 1
//! only. The Cortex-M55 CPU master uses CID = 1 on the AXI bus. That is why
//! every NS access to AXISRAM1 (host code/data, BLXNS instruction fetch)
//! faults until at least one base region is configured with SEC = 0 and
//! RDENC1/WRENC1 set.
//!
//! ## Programming order (RM0486 §7.4.5)
//! 1. STARTR / ENDR (writes ignored when BREN = 1, so do them while disabled)
//! 2. CIDCFGR (RDENCy / WRENCy per CID)
//! 3. CFGR (SEC + PRIVCy + BREN = 1) — single write enables the region.
//!
//! ## RM0486 references
//! - Table 24 (RISAF resource assignment): RISAF2 = AXISRAM1, RISAF3 = AXISRAM2,
//!   RISAF12 = XSPI2, etc.
//! - Section 2.3.2 (memory map): MMIO base addresses (RISAF2 @ 0x54027000, …).
//! - Sections 7.5.6–7.5.9: per-region register layout.

#![allow(dead_code)]

/// Cortex-M55 master compartment ID on the AXI bus (RM0486 §7.4.5 note).
pub const CPU_CID: u8 = 1;

/// Convenience: bitmask matching the CPU CID, suitable for the
/// RDENCy / WRENCy / PRIVCy fields.
pub const CPU_CID_MASK: u8 = 1 << CPU_CID;

/// RISAF instances we currently program. The variant carries the MMIO base
/// of the per-instance register block (Secure alias).
///
/// IMPORTANT: the AXISRAM1 view (0x24000000 / 0x34000000) is NOT a single
/// memory bank. RM0486 §2.3.2 Table 1 splits it as:
/// - 0x34000000 - 0x34063FFF: FLEXRAM (400 KB, FLEXMEM extension) → RISAF7
/// - 0x34064000 - 0x340FFFFF: AXISRAM1 proper (~624 KB) → RISAF2
///
/// Software using the full 1 MB range as one buffer must program BOTH
/// RISAF7 and RISAF2.
#[derive(Clone, Copy)]
pub enum RisafInstance {
    /// RISAF2 — protects AXISRAM1 proper (~624 KB starting at 0x34064000),
    /// 7 regions, 4 KB granularity.
    Risaf2,
    /// RISAF3 — protects AXISRAM2 (1 MB), 7 regions, 4 KB granularity.
    Risaf3,
    /// RISAF7 — protects FLEXRAM (400 KB at 0x34000000), 11 regions,
    /// 4 KB granularity.
    Risaf7,
    /// RISAF12 — protects XSPI2 memory-mapped window (256 MB).
    Risaf12,
}

impl RisafInstance {
    fn mmio_base(self) -> usize {
        match self {
            // RM0486 §2.3.2 memory map.
            RisafInstance::Risaf2  => 0x5402_7000,
            RisafInstance::Risaf3  => 0x5402_8000,
            RisafInstance::Risaf7  => 0x5402_C000,
            RisafInstance::Risaf12 => 0x5403_1000,
        }
    }
}

// Top-level RISAF registers
const REG_CR:    usize = 0x000; // bit 0 = GLOCK
const REG_IASR:  usize = 0x008;
const REG_IACR:  usize = 0x00C;
const REG_IAESR: usize = 0x020;
const REG_IADDR: usize = 0x024;

// Per-region offsets: address = base + 0x040 + 0x40 * (x - 1), x = 1..=7
const REG_BLOCK_BASE:   usize = 0x040;
const REG_BLOCK_STRIDE: usize = 0x040;
const OFF_CFGR:    usize = 0x000; // RISAF_REGx_CFGR
const OFF_STARTR:  usize = 0x004; // RISAF_REGx_STARTR
const OFF_ENDR:    usize = 0x008; // RISAF_REGx_ENDR
const OFF_CIDCFGR: usize = 0x00C; // RISAF_REGx_CIDCFGR

// CFGR bit fields (RM0486 §7.5.6)
const CFGR_BREN: u32 = 1 << 0; // base region enable
const CFGR_SEC:  u32 = 1 << 8; // 1 = secure-only, 0 = NS-only
// Bits 16..23 = PRIVC0..PRIVC7 (1 = priv-only for that compartment)

pub struct Risaf {
    base: usize,
}

impl Risaf {
    pub fn new(instance: RisafInstance) -> Self {
        Risaf { base: instance.mmio_base() }
    }

    /// Configure a base region with absolute start/end addresses.
    ///
    /// * `region` is 1-indexed (1..=7).
    /// * `abs_start` / `abs_end` are absolute addresses (either Secure or NS
    ///   alias works). The hardware ignores the high bits beyond the protected
    ///   address space size and the low bits below the granularity (RM0486
    ///   §7.5.7-8), so the result is always the correct relative offset
    ///   irrespective of which alias the caller used.
    /// * `secure` selects which security state can access the region:
    ///   `true`  → only Secure requests, `false` → only NS requests.
    /// * `read_cid_mask` / `write_cid_mask` are 8-bit masks of compartments
    ///   allowed to read / write (bit y = CID y). Bit `CPU_CID` (1) is the
    ///   Cortex-M55.
    /// * `priv_cid_mask` bit y = CID y is restricted to privileged accesses.
    ///   Use 0 to allow unprivileged.
    ///
    /// Programming order follows RM0486 §7.4.5: START/END first (writes
    /// ignored if BREN = 1), then CIDCFGR, then CFGR with BREN = 1.
    pub fn configure_region(
        &self,
        region: u8,
        abs_start: u32,
        abs_end: u32,
        secure: bool,
        read_cid_mask: u8,
        write_cid_mask: u8,
        priv_cid_mask: u8,
    ) {
        let off = REG_BLOCK_BASE + REG_BLOCK_STRIDE * (region as usize - 1);

        let sec_bits  = if secure { CFGR_SEC } else { 0 };
        let priv_bits = (priv_cid_mask as u32) << 16;

        unsafe {
            // 1. Disable region so START/END accept writes (BREN must be 0).
            core::ptr::write_volatile((self.base + off + OFF_CFGR) as *mut u32, 0);
            cortex_m::asm::dsb();

            // 2. Boundaries — HW masks bits outside the protected address
            //    space and below granularity, so the absolute address (Secure
            //    or NS alias) collapses to the correct relative offset.
            core::ptr::write_volatile((self.base + off + OFF_STARTR) as *mut u32, abs_start);
            core::ptr::write_volatile((self.base + off + OFF_ENDR)   as *mut u32, abs_end);

            // 3. Per-CID read/write enables. RDENCy = bits 0..7,
            //    WRENCy = bits 16..23 (RM0486 §7.5.9).
            let cidcfg = (read_cid_mask as u32)
                | ((write_cid_mask as u32) << 16);
            core::ptr::write_volatile((self.base + off + OFF_CIDCFGR) as *mut u32, cidcfg);
            cortex_m::asm::dsb();

            // 4a. Program SEC + PRIVCy WITHOUT BREN (RM0486 §7.4.5 step 3).
            core::ptr::write_volatile(
                (self.base + off + OFF_CFGR) as *mut u32,
                sec_bits | priv_bits,
            );
            cortex_m::asm::dsb();

            // 4b. Enable the region (RM0486 §7.4.5 step 4).
            core::ptr::write_volatile(
                (self.base + off + OFF_CFGR) as *mut u32,
                sec_bits | priv_bits | CFGR_BREN,
            );
            cortex_m::asm::dsb();
            cortex_m::asm::isb();
        }
    }

    /// Disable a base region (BREN = 0). Default region 0 (Secure, privileged,
    /// CID = 1 only) re-applies between START and END.
    pub fn disable_region(&self, region: u8) {
        let off = REG_BLOCK_BASE + REG_BLOCK_STRIDE * (region as usize - 1);
        unsafe {
            core::ptr::write_volatile((self.base + off + OFF_CFGR) as *mut u32, 0);
        }
    }

    /// Lock the entire RISAF configuration until next reset (sets GLOCK).
    /// After this only subregion registers stay writable (RM0486 §7.5.1).
    pub fn lock(&self) {
        unsafe {
            core::ptr::write_volatile((self.base + REG_CR) as *mut u32, 1);
        }
    }

    /// Read CR — bit 0 = GLOCK. Useful for diagnostics.
    pub fn read_cr(&self) -> u32 {
        unsafe { core::ptr::read_volatile((self.base + REG_CR) as *const u32) }
    }

    /// Read CFGR for a region (diagnostic).
    pub fn read_cfgr(&self, region: u8) -> u32 {
        let off = REG_BLOCK_BASE + REG_BLOCK_STRIDE * (region as usize - 1);
        unsafe { core::ptr::read_volatile((self.base + off + OFF_CFGR) as *const u32) }
    }

    /// Read STARTR for a region (diagnostic). Value is the offset from the
    /// protected memory base, granularity-aligned.
    pub fn read_startr(&self, region: u8) -> u32 {
        let off = REG_BLOCK_BASE + REG_BLOCK_STRIDE * (region as usize - 1);
        unsafe { core::ptr::read_volatile((self.base + off + OFF_STARTR) as *const u32) }
    }

    /// Read ENDR for a region (diagnostic).
    pub fn read_endr(&self, region: u8) -> u32 {
        let off = REG_BLOCK_BASE + REG_BLOCK_STRIDE * (region as usize - 1);
        unsafe { core::ptr::read_volatile((self.base + off + OFF_ENDR) as *const u32) }
    }

    /// Read CIDCFGR for a region (diagnostic). RDENCy = bits 0..7,
    /// WRENCy = bits 16..23.
    pub fn read_cidcfgr(&self, region: u8) -> u32 {
        let off = REG_BLOCK_BASE + REG_BLOCK_STRIDE * (region as usize - 1);
        unsafe { core::ptr::read_volatile((self.base + off + OFF_CIDCFGR) as *const u32) }
    }

    /// Read the illegal-access status flags (IAEF/CAEF) — non-zero indicates
    /// at least one denied access since last clear.
    pub fn read_iasr(&self) -> u32 {
        unsafe { core::ptr::read_volatile((self.base + REG_IASR) as *const u32) }
    }

    /// Read the address that triggered the latest illegal access. The captured
    /// value is the byte-offset from the base of the protected address space.
    pub fn read_iaddr(&self) -> u32 {
        unsafe { core::ptr::read_volatile((self.base + REG_IADDR) as *const u32) }
    }
}
