//! MCE (Memory Cipher Engine) driver for STM32N657.
//! MCE2 sits in front of XSPI2 (memory-mapped at 0x70000000) and is the only
//! instance touched by the active boot path. This driver only exposes the
//! passthrough surface needed today: region 1 must be disabled at boot so
//! that AXI reads from 0x70080000+ return raw flash bytes (the host bin
//! already carries an encrypted enclave produced by
//! `protect_enclave.py --hmac-over-plaintext`).
//! Encryption-at-rest via MCE2 is not implemented — see the design notes for
//! the OPI WREN write-path and proprietary KDF blockers.
//! # Why MCE2 encryption-at-rest is not implemented (the two blockers)
//! 1. **OPI WREN does not latch WEL on the Nucleo-N657X0-Q.** Tested
//! in.4c with both OPI STR (WRCR2=0x01) and OPI DTR (WRCR2=0x02);
//! regular OPI WREN (0xF906), OPI WREN_VOLATILE (0xAF50), and 5×-burst
//! WREN. The 1-1-1 SPI WREN path works once the "minimal pattern" is
//! used (CR.EN stays at 1, single CCR/TCR/IR write per command — do NOT
//! do ABORT + disable + re-enable + settle around every command, that
//! CS# glitch is exactly what prevents WEL latching). The OPI residual
//! is most likely an HW-level latched protection at OPI entry on this
//! specific board. Whoever revives the write path should preserve the
//! minimal-pattern primitives and continue investigation on a board
//! with WP# / oscilloscope-class HW debug.//! 2. **MCE2 block-cipher KDF is proprietary** (memory
//!). Offline pre-encryption (Path C)
//! is therefore blocked; chip-as-oracle (Path B-full) was viable but
//! blocked by the WREN issue above. Current shipping mode is Path B-lite
//! (raw bytes in flash, integrity via chained HMAC) — this driver
//! matches that mode by disabling region 1.

use peripheral_regs::{MmioAccess, RealMmio};

const MCE2_BASE: u32 = 0x5802_BC00;

// Region x: offset = 0x040 + 0x10 * (x - 1), x = 1..4
const REGCR1_OFFSET: u32 = 0x040;

// MCE_REGCR1 bits
const REGCR_BREN: u32 = 1 << 0;

/// Generic over the MMIO backend so host
/// tests can inject [`umbra_pal_test::mmio::MmioHandle`]. Default
/// `M = RealMmio` keeps every existing `Mce2::new()` call site unchanged at
/// the source level — the firmware build monomorphises to `Mce2<RealMmio>`
/// and inlines the volatile accesses exactly as before.
/// MCE2 ships in passthrough plaintext mode (Path B-lite). The only method
/// surfaced today is `disable_region1`, which the boot path must call once
/// to override any Boot-ROM-left Fast Block mode and let AXI reads from
/// 0x70080000+ return raw flash bytes.
pub struct Mce2<M: MmioAccess = RealMmio> {
    mmio: M,
}

impl Mce2<RealMmio> {
    pub fn new() -> Self {
        Self {
            mmio: RealMmio::new(MCE2_BASE),
        }
    }
}

impl<M: MmioAccess> Mce2<M> {
    /// Constructor for host-side tests — accepts any `MmioAccess` backend.
    /// On firmware build, callers use `Mce2::new()` which monomorphises to
    /// `Mce2<RealMmio>` and inlines the volatile accesses.
    #[allow(dead_code)]
    pub fn new_with_mmio(mmio: M) -> Self {
        Self { mmio }
    }

    /// Disable region 1 (BREN=0) so AXI reads bypass MCE2 decryption.
    /// Path B-lite invariant: must be called once during boot — Boot ROM
    /// may leave the region enabled in Fast Block mode, which would garble
    /// every read from 0x70080000+ and break the host bin handoff.
    pub fn disable_region1(&self) {
        let v = self.mmio.read(REGCR1_OFFSET);
        self.mmio.write(REGCR1_OFFSET, v & !REGCR_BREN);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umbra_pal_test::mmio::{MmioMem, MmioOp};

    /// Verifies `disable_region1` issues a read-modify-write to REGCR1 at
    /// offset 0x040 that clears bit 0 (BREN) while preserving the other
    /// bits. Path B-lite invariant — Boot ROM may leave Fast Block mode
    /// enabled and the only way to guarantee plaintext AXI reads from
    /// 0x70080000+ is to clear BREN explicitly.
    #[test]
    fn disable_region1_clears_bren_bit_at_0x040() {
        let mem = MmioMem::new(MCE2_BASE);
        // Preload REGCR1 with BREN=1 plus an unrelated upper bit — the RMW
        // must clear BREN but leave the upper bit intact.
        mem.preload_register(REGCR1_OFFSET, REGCR_BREN | (1 << 16));

        let mce = Mce2::<_>::new_with_mmio(mem.handle());
        mce.disable_region1();

        let log = mem.write_log();
        // RMW = 1 Read + 1 Write.
        assert_eq!(log.len(), 2, "log = {:?}", log);
        match log[0] {
            MmioOp::Read { addr, .. } => {
                assert_eq!(addr, MCE2_BASE + REGCR1_OFFSET);
            }
            _ => panic!("expected Read REGCR1 at position 0, got {:?}", log[0]),
        }
        match log[1] {
            MmioOp::Write { addr, value } => {
                assert_eq!(addr, MCE2_BASE + REGCR1_OFFSET);
                // BREN (bit 0) cleared; upper bit preserved.
                assert_eq!(value & REGCR_BREN, 0, "BREN must be cleared");
                assert_eq!(value & (1 << 16), 1 << 16, "upper bit must be preserved");
            }
            _ => panic!("expected Write REGCR1 at position 1, got {:?}", log[1]),
        }
    }

    /// Verifies `disable_region1` is idempotent — when BREN is already 0,
    /// the RMW writes back the same value. Important because the boot
    /// sequence may invoke it after a warm reset where the previous boot
    /// already cleared the bit.
    #[test]
    fn disable_region1_is_idempotent_when_bren_already_zero() {
        let mem = MmioMem::new(MCE2_BASE);
        // BREN already cleared, but other bits set.
        mem.preload_register(REGCR1_OFFSET, 0xFFFF_FFFE);

        let mce = Mce2::<_>::new_with_mmio(mem.handle());
        mce.disable_region1();

        let log = mem.write_log();
        assert_eq!(log.len(), 2, "log = {:?}", log);
        match log[1] {
            MmioOp::Write { addr, value } => {
                assert_eq!(addr, MCE2_BASE + REGCR1_OFFSET);
                // Value unchanged — BREN stays 0, other bits preserved.
                assert_eq!(value, 0xFFFF_FFFE);
            }
            _ => panic!("expected Write REGCR1 at position 1, got {:?}", log[1]),
        }
    }
}
