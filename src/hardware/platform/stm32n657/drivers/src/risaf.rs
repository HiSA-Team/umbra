//! RISAF driver — Resource Isolation Slave unit for Address space protection
//! (full version), STM32N657. RM0486 chapter 7.
//! Each RISAF instance protects one memory target and exposes up to 7 base
//! regions (4 KB granularity on AXI). Region START/END registers store
//! byte-offsets RELATIVE to the protected memory base, but the hardware masks
//! out address bits outside the protected space (RM0486 §7.5.7-8). This means
//! the caller can pass absolute addresses (Secure or NS alias) and the
//! correct relative offset always lands in the register.
//! ## Default behaviour
//! When BREN = 0, the primary region 0 applies: secure, privileged, CID = 1
//! only. The Cortex-M55 CPU master uses CID = 1 on the AXI bus. That is why
//! every NS access to AXISRAM1 (host code/data, BLXNS instruction fetch)
//! faults until at least one base region is configured with SEC = 0 and
//! RDENC1/WRENC1 set.
//! ## Programming order (RM0486 §7.4.5) — **CJ3 load-bearing**
//! 1. STARTR / ENDR (writes ignored when BREN = 1, so do them while disabled)
//! 2. CIDCFGR (RDENCy / WRENCy per CID)
//! 3. CFGR (SEC + PRIVCy + BREN = 1) — single write enables the region.
//! The full sequence executed by `configure_region` (per RM0486 §7.4.5):
//! (a) CFGR:= 0 (disable so START/END accept writes)
//! (b) DSB
//! (c) STARTR:= abs_start
//! (d) ENDR:= abs_end
//! (e) CIDCFGR:= RDENC | WRENC
//! (f) DSB
//! (g) CFGR:= SEC | PRIVC (program attributes, BREN still 0)
//! (h) DSB
//! (i) CFGR:= SEC | PRIVC | BREN (atomic enable)
//! (j) DSB; ISB
//! Reordering ANY step in this list re-introduces a window where AXISRAM1
//! /XSPI2 sees stale attribution and CJ3 (EFB confidentiality) breaks.
//! ## RM0486 references
//! - Table 24 (RISAF resource assignment): RISAF2 = AXISRAM1, RISAF3 = AXISRAM2,
//! RISAF12 = XSPI2, etc.
//! - Section 2.3.2 (memory map): MMIO base addresses (RISAF2 @ 0x54027000, …).
//! - Sections 7.5.6–7.5.9: per-region register layout.

#![allow(dead_code)]

use peripheral_regs::{MmioAccess, RealMmio};

/// Cortex-M55 master compartment ID on the AXI bus (RM0486 §7.4.5 note).
pub const CPU_CID: u8 = 1;

/// Convenience: bitmask matching the CPU CID, suitable for the
/// RDENCy / WRENCy / PRIVCy fields.
pub const CPU_CID_MASK: u8 = 1 << CPU_CID;

/// RISAF instances we currently program. The variant carries the MMIO base
/// of the per-instance register block (Secure alias).
/// IMPORTANT: the AXISRAM1 view (0x24000000 / 0x34000000) is NOT a single
/// memory bank. RM0486 §2.3.2 Table 1 splits it as:
/// - 0x34000000 - 0x34063FFF: FLEXRAM (400 KB, FLEXMEM extension) → RISAF7
/// - 0x34064000 - 0x340FFFFF: AXISRAM1 proper (~624 KB) → RISAF2
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
    pub fn mmio_base(self) -> u32 {
        match self {
            // RM0486 §2.3.2 memory map.
            RisafInstance::Risaf2 => 0x5402_7000,
            RisafInstance::Risaf3 => 0x5402_8000,
            RisafInstance::Risaf7 => 0x5402_C000,
            RisafInstance::Risaf12 => 0x5403_1000,
        }
    }
}

// Top-level RISAF registers
const REG_CR: u32 = 0x000; // bit 0 = GLOCK
const REG_IASR: u32 = 0x008;
const REG_IACR: u32 = 0x00C;
const REG_IAESR: u32 = 0x020;
const REG_IADDR: u32 = 0x024;

// Per-region offsets: address = base + 0x040 + 0x40 * (x - 1), x = 1..=7
const REG_BLOCK_BASE: u32 = 0x040;
const REG_BLOCK_STRIDE: u32 = 0x040;
const OFF_CFGR: u32 = 0x000; // RISAF_REGx_CFGR
const OFF_STARTR: u32 = 0x004; // RISAF_REGx_STARTR
const OFF_ENDR: u32 = 0x008; // RISAF_REGx_ENDR
const OFF_CIDCFGR: u32 = 0x00C; // RISAF_REGx_CIDCFGR

// CFGR bit fields (RM0486 §7.5.6)
const CFGR_BREN: u32 = 1 << 0; // base region enable
const CFGR_SEC: u32 = 1 << 8; // 1 = secure-only, 0 = NS-only
                              // Bits 16..23 = PRIVC0..PRIVC7 (1 = priv-only for that compartment)

/// Generic over the MMIO backend so host
/// tests can inject [`umbra_pal_test::mmio::MmioHandle`]. Default
/// `M = RealMmio` keeps every existing `Risaf::new(instance)` call site
/// unchanged at the source level — the firmware build monomorphises to
/// `Risaf<RealMmio>` and inlines the volatile accesses exactly as before.
/// The CJ3 register-write order in `configure_region` (CFGR→0, STARTR, ENDR,
/// CIDCFGR, CFGR with SEC|PRIVC but no BREN, CFGR with BREN) is preserved
/// byte-for-byte — see the module doc above for the load-bearing sequence.
pub struct Risaf<M: MmioAccess = RealMmio> {
    mmio: M,
}

impl Risaf<RealMmio> {
    pub fn new(instance: RisafInstance) -> Self {
        Self {
            mmio: RealMmio::new(instance.mmio_base()),
        }
    }
}

impl<M: MmioAccess> Risaf<M> {
    /// Constructor for host-side tests — accepts any `MmioAccess` backend.
    /// On firmware build, callers use `Risaf::new(instance)` which
    /// monomorphises to `Risaf<RealMmio>` and inlines the volatile accesses.
    #[allow(dead_code)]
    pub fn new_with_mmio(mmio: M) -> Self {
        Self { mmio }
    }

    /// Configure a base region with absolute start/end addresses.
    /// * `region` is 1-indexed (1..=7).
    /// * `abs_start` / `abs_end` are absolute addresses (either Secure or NS
    /// alias works). The hardware ignores the high bits beyond the protected
    /// address space size and the low bits below the granularity (RM0486
    /// §7.5.7-8), so the result is always the correct relative offset
    /// irrespective of which alias the caller used.
    /// * `secure` selects which security state can access the region:
    /// `true` → only Secure requests, `false` → only NS requests.
    /// * `read_cid_mask` / `write_cid_mask` are 8-bit masks of compartments
    /// allowed to read / write (bit y = CID y). Bit `CPU_CID` (1) is the
    /// Cortex-M55.
    /// * `priv_cid_mask` bit y = CID y is restricted to privileged accesses.
    /// Use 0 to allow unprivileged.
    /// Programming order follows RM0486 §7.4.5: START/END first (writes
    /// ignored if BREN = 1), then CIDCFGR, then CFGR with BREN = 1. This
    /// sequence is **CJ3 load-bearing** — do not reorder. See module doc.
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
        let off = REG_BLOCK_BASE + REG_BLOCK_STRIDE * (region as u32 - 1);

        let sec_bits = if secure { CFGR_SEC } else { 0 };
        let priv_bits = (priv_cid_mask as u32) << 16;

        // 1. Disable region so START/END accept writes (BREN must be 0).
        self.mmio.write(off + OFF_CFGR, 0);
        // dsb/isb are ARM intrinsics — gated for host-test builds.
        #[cfg(target_arch = "arm")]
        cortex_m::asm::dsb();

        // 2. Boundaries — HW masks bits outside the protected address
        // space and below granularity, so the absolute address (Secure
        // or NS alias) collapses to the correct relative offset.
        self.mmio.write(off + OFF_STARTR, abs_start);
        self.mmio.write(off + OFF_ENDR, abs_end);

        // 3. Per-CID read/write enables. RDENCy = bits 0..7,
        // WRENCy = bits 16..23 (RM0486 §7.5.9).
        let cidcfg = (read_cid_mask as u32) | ((write_cid_mask as u32) << 16);
        self.mmio.write(off + OFF_CIDCFGR, cidcfg);
        // dsb/isb are ARM intrinsics — gated for host-test builds.
        #[cfg(target_arch = "arm")]
        cortex_m::asm::dsb();

        // 4a. Program SEC + PRIVCy WITHOUT BREN (RM0486 §7.4.5 step 3).
        self.mmio.write(off + OFF_CFGR, sec_bits | priv_bits);
        // dsb/isb are ARM intrinsics — gated for host-test builds.
        #[cfg(target_arch = "arm")]
        cortex_m::asm::dsb();

        // 4b. Enable the region (RM0486 §7.4.5 step 4).
        self.mmio
            .write(off + OFF_CFGR, sec_bits | priv_bits | CFGR_BREN);
        // dsb/isb are ARM intrinsics — gated for host-test builds.
        #[cfg(target_arch = "arm")]
        cortex_m::asm::dsb();
        #[cfg(target_arch = "arm")]
        cortex_m::asm::isb();
    }

    /// Disable a base region (BREN = 0). Default region 0 (Secure, privileged,
    /// CID = 1 only) re-applies between START and END.
    pub fn disable_region(&self, region: u8) {
        let off = REG_BLOCK_BASE + REG_BLOCK_STRIDE * (region as u32 - 1);
        self.mmio.write(off + OFF_CFGR, 0);
    }

    /// Lock the entire RISAF configuration until next reset (sets GLOCK).
    /// After this only subregion registers stay writable (RM0486 §7.5.1).
    pub fn lock(&self) {
        self.mmio.write(REG_CR, 1);
    }

    /// Read CR — bit 0 = GLOCK. Useful for diagnostics.
    pub fn read_cr(&self) -> u32 {
        self.mmio.read(REG_CR)
    }

    /// Read CFGR for a region (diagnostic).
    pub fn read_cfgr(&self, region: u8) -> u32 {
        let off = REG_BLOCK_BASE + REG_BLOCK_STRIDE * (region as u32 - 1);
        self.mmio.read(off + OFF_CFGR)
    }

    /// Read STARTR for a region (diagnostic). Value is the offset from the
    /// protected memory base, granularity-aligned.
    pub fn read_startr(&self, region: u8) -> u32 {
        let off = REG_BLOCK_BASE + REG_BLOCK_STRIDE * (region as u32 - 1);
        self.mmio.read(off + OFF_STARTR)
    }

    /// Read ENDR for a region (diagnostic).
    pub fn read_endr(&self, region: u8) -> u32 {
        let off = REG_BLOCK_BASE + REG_BLOCK_STRIDE * (region as u32 - 1);
        self.mmio.read(off + OFF_ENDR)
    }

    /// Read CIDCFGR for a region (diagnostic). RDENCy = bits 0..7,
    /// WRENCy = bits 16..23.
    pub fn read_cidcfgr(&self, region: u8) -> u32 {
        let off = REG_BLOCK_BASE + REG_BLOCK_STRIDE * (region as u32 - 1);
        self.mmio.read(off + OFF_CIDCFGR)
    }

    /// Read the illegal-access status flags (IAEF/CAEF) — non-zero indicates
    /// at least one denied access since last clear.
    pub fn read_iasr(&self) -> u32 {
        self.mmio.read(REG_IASR)
    }

    /// Read the address that triggered the latest illegal access. The captured
    /// value is the byte-offset from the base of the protected address space.
    pub fn read_iaddr(&self) -> u32 {
        self.mmio.read(REG_IADDR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umbra_pal_test::mmio::{MmioMem, MmioOp};

    /// Verifies `configure_region(region=1, abs_start, abs_end, secure=true,
    /// read=CPU_CID_MASK, write=CPU_CID_MASK, priv=0)` issues the documented
    /// CJ3 register-write order verbatim:
    /// (a) CFGR:= 0
    /// (b) STARTR:= abs_start
    /// (c) ENDR:= abs_end
    /// (d) CIDCFGR:= RDENC | (WRENC << 16)
    /// (e) CFGR:= SEC | PRIVC (BREN still 0)
    /// (f) CFGR:= SEC | PRIVC | BREN (enable)
    /// Region 1 → offset block = REG_BLOCK_BASE = 0x040.
    /// SEC = 1 << 8 = 0x100, BREN = 1, PRIVC mask = 0 → SEC|PRIVC = 0x100.
    /// CIDCFGR with RDENC = WRENC = CPU_CID_MASK (=0x02) → 0x0002_0002.
    /// This test pins the CJ3 (EFB confidentiality) sequence — any reorder,
    /// added/dropped write, or changed bit-field would break enclave region
    /// attribution at runtime.
    #[test]
    fn configure_region_writes_cj3_sequence_verbatim() {
        // Use RISAF2 base (matches production AXISRAM1 attribution).
        let base = RisafInstance::Risaf2.mmio_base();
        let mem = MmioMem::new(base);
        let risaf = Risaf::<_>::new_with_mmio(mem.handle());

        let abs_start = 0x3406_4000;
        let abs_end = 0x340F_FFFF;

        risaf.configure_region(
            1, // region
            abs_start,
            abs_end,
            true,         // secure
            CPU_CID_MASK, // read_cid_mask  = 0x02
            CPU_CID_MASK, // write_cid_mask = 0x02
            0,            // priv_cid_mask  = 0 (unprivileged OK)
        );

        let log = mem.write_log();
        // 6 writes: CFGR=0, STARTR, ENDR, CIDCFGR, CFGR(no BREN), CFGR(BREN).
        // Filter to writes only — DSB/ISB are CPU barriers, not MMIO.
        // no_std crate: no alloc::Vec — use fixed-size array + counter,
        // same hand-rolled pattern as cryp.rs / dma.rs tests.
        let mut writes: [(u32, u32); 6] = [(0, 0); 6];
        let mut n: usize = 0;
        for op in log.iter() {
            if let MmioOp::Write { addr, value } = *op {
                assert!(n < 6, "more than 6 writes: {:?}", op);
                writes[n] = (addr, value);
                n += 1;
            }
        }
        assert_eq!(n, 6, "writes count");

        let region_off = REG_BLOCK_BASE; // region 1 → 0x040

        // (a) CFGR:= 0 — disable so STARTR/ENDR accept writes.
        assert_eq!(writes[0], (base + region_off + OFF_CFGR, 0));

        // (b) STARTR:= abs_start.
        assert_eq!(writes[1], (base + region_off + OFF_STARTR, abs_start));

        // (c) ENDR:= abs_end.
        assert_eq!(writes[2], (base + region_off + OFF_ENDR, abs_end));

        // (d) CIDCFGR:= RDENC[7:0] | (WRENC[7:0] << 16). With CPU_CID_MASK
        // = 0x02 on both lanes → 0x0002_0002.
        let expected_cidcfg = (CPU_CID_MASK as u32) | ((CPU_CID_MASK as u32) << 16);
        assert_eq!(expected_cidcfg, 0x0002_0002);
        assert_eq!(
            writes[3],
            (base + region_off + OFF_CIDCFGR, expected_cidcfg)
        );

        // (e) CFGR:= SEC | PRIVC, BREN still 0. priv_cid_mask=0 → PRIVC=0,
        // SEC=1<<8=0x100. BREN bit (0) must be CLEAR at this stage.
        assert_eq!(writes[4], (base + region_off + OFF_CFGR, CFGR_SEC));
        assert_eq!(
            writes[4].1 & CFGR_BREN,
            0,
            "BREN must still be 0 at step 4a"
        );

        // (f) CFGR:= SEC | PRIVC | BREN — atomic enable.
        assert_eq!(
            writes[5],
            (base + region_off + OFF_CFGR, CFGR_SEC | CFGR_BREN),
        );
        assert_eq!(writes[5].1 & CFGR_BREN, CFGR_BREN, "BREN must be set at 4b");
    }

    /// Verifies the read-back path. `read_cfgr(region)` should issue a single
    /// read from `base + REG_BLOCK_BASE + STRIDE*(region-1) + OFF_CFGR` and
    /// return whatever the mem seeded there. Pins the per-region offset
    /// arithmetic (region indexing is 1-based, stride = 0x40).
    #[test]
    fn read_cfgr_uses_correct_per_region_offset() {
        let base = RisafInstance::Risaf3.mmio_base();
        let mem = MmioMem::new(base);

        // Region 3 → offset = 0x040 + 0x40 * (3 - 1) = 0x0C0.
        let region_off = REG_BLOCK_BASE + REG_BLOCK_STRIDE * (3 - 1);
        assert_eq!(region_off, 0x0C0);
        // Seed a recognisable CFGR value: SEC=1, BREN=1, PRIVC1=1.
        let seeded = CFGR_SEC | CFGR_BREN | (1 << 17);
        mem.preload_register(region_off + OFF_CFGR, seeded);

        let risaf = Risaf::<_>::new_with_mmio(mem.handle());
        let observed = risaf.read_cfgr(3);

        assert_eq!(observed, seeded);

        // Exactly one MMIO op — a single read at the computed address.
        let log = mem.write_log();
        assert_eq!(log.len(), 1, "log = {:?}", log);
        match log[0] {
            MmioOp::Read { addr, value } => {
                assert_eq!(addr, base + region_off + OFF_CFGR);
                assert_eq!(value, seeded);
            }
            _ => panic!("expected Read at position 0, got {:?}", log[0]),
        }
    }
}
