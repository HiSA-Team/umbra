//! Typed PMP configuration-byte builder (RV32, M-mode).
//!
//! A `pmpcfgN` CSR packs four 8-bit entries. This builder produces one such
//! byte from a fluent description, so the bit layout (`L | A | X | W | R`) lives
//! in one tested place instead of being open-coded at every call site. The raw
//! CSR writes (`csrw pmpaddrN, …`) live in [`crate::pmp`], where the index must
//! be a compile-time literal.

/// PMP address-matching mode (the `A` field, bits 4:3 of the cfg byte).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PmpMode {
    /// Entry disabled.
    Off = 0,
    /// Top-of-range: this entry's `pmpaddr` is the exclusive top, paired with
    /// the previous entry as the base.
    Tor = 1,
    /// Naturally-aligned 4-byte region.
    Na4 = 2,
    /// Naturally-aligned power-of-two region.
    Napot = 3,
}

/// One `pmpcfgN` entry byte. Build with the fluent helpers, read with [`bits`].
///
/// [`bits`]: PmpCfg::bits
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct PmpCfg(u8);

impl PmpCfg {
    /// An empty (mode `Off`, no permissions, unlocked) entry.
    pub const fn new() -> Self {
        PmpCfg(0)
    }
    /// Grant read.
    pub const fn r(self) -> Self {
        PmpCfg(self.0 | 0b001)
    }
    /// Grant write.
    pub const fn w(self) -> Self {
        PmpCfg(self.0 | 0b010)
    }
    /// Grant execute.
    pub const fn x(self) -> Self {
        PmpCfg(self.0 | 0b100)
    }
    /// Grant read + write + execute.
    pub const fn rwx(self) -> Self {
        PmpCfg(self.0 | 0b111)
    }
    /// Set the address-matching mode (`A` field).
    pub const fn mode(self, m: PmpMode) -> Self {
        PmpCfg((self.0 & !0b1_1000) | ((m as u8) << 3))
    }
    /// Lock the entry (`L` bit) — once set, it applies to M-mode too and stays
    /// locked until reset. Used for the monitor's ePMP self-lock.
    pub const fn lock(self) -> Self {
        PmpCfg(self.0 | 0x80)
    }
    /// The packed config byte.
    pub const fn bits(self) -> u8 {
        self.0
    }
}

/// Force `satp = 0` (MODE = Bare): no address translation. Umbra's RISC-V
/// isolation is purely physical (PMP + SPMP), so the MMU stays off by design.
/// `satp` is already 0 at reset; this makes the intent explicit and guards
/// against any residual state left by a boot ROM.
#[cfg(target_arch = "riscv32")]
pub fn disable_mmu() {
    // SAFETY: writes the architectural satp CSR to Bare mode.
    unsafe { core::arch::asm!("csrw satp, zero") };
}

#[cfg(not(target_arch = "riscv32"))]
#[allow(missing_docs)]
pub fn disable_mmu() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_entry_is_zero() {
        assert_eq!(PmpCfg::new().bits(), 0x00);
    }

    #[test]
    fn tor_rwx_locked_encodes_to_0x8f() {
        // L(0x80) | A=TOR(01)<<3=0x08 | RWX(0x07)
        let c = PmpCfg::new().rwx().mode(PmpMode::Tor).lock();
        assert_eq!(c.bits(), 0x8F);
    }

    #[test]
    fn napot_rwx_locked_encodes_to_0x9f() {
        // L(0x80) | A=NAPOT(11)<<3=0x18 | RWX(0x07)
        let c = PmpCfg::new().rwx().mode(PmpMode::Napot).lock();
        assert_eq!(c.bits(), 0x9F);
    }

    #[test]
    fn napot_ro_unlocked_encodes_to_0x19() {
        // A=NAPOT(0x18) | R(0x01)
        let c = PmpCfg::new().r().mode(PmpMode::Napot);
        assert_eq!(c.bits(), 0x19);
    }

    #[test]
    fn mode_field_is_replaced_not_ored() {
        // Setting NAPOT then TOR must leave A=TOR, not A=(TOR|NAPOT).
        let c = PmpCfg::new().mode(PmpMode::Napot).mode(PmpMode::Tor);
        assert_eq!((c.bits() >> 3) & 0b11, PmpMode::Tor as u8);
    }
}
