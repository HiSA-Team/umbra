// STM32L5xxxx PWR Driver
// This driver implements the Power control (PWR) peripheral present on STM32L5xxxx.
// Implements a minimal subset of PWR features needed by the other drivers.
#![allow(dead_code)]

// Crates
use crate::rcc::*;
use peripheral_regs::{MmioAccess, RealMmio};

const PWR_BASE_ADDR: u32 = 0x50007000; // Secure
type PwrRegisters = u32;

// _____ _ _
// | __ \ (_) | |
// | |__) |___ __ _ _ ___| |_ ___ _ __ ___
// | _ // _ \/ _` | / __| __/ _ \ '__/ __|
// | | \ \ __/ (_| | \__ \ || __/ | \__ \
// |_| \_\___|\__, |_|___/\__\___|_| |___/
// __/ |
// |___/
// TODO: Implement all registers
const PWR_CR1_BASE_OFFSET: PwrRegisters = 0x00;
const PWR_CR2_BASE_OFFSET: PwrRegisters = 0x04;
const PWR_CR3_BASE_OFFSET: PwrRegisters = 0x08;
const PWR_CR4_BASE_OFFSET: PwrRegisters = 0x0C;
const PWR_SR1_BASE_OFFSET: PwrRegisters = 0x10;
const PWR_SR2_BASE_OFFSET: PwrRegisters = 0x14;
const PWR_SCR_BASE_OFFSET: PwrRegisters = 0x18;
const PWR_PUCRA_BASE_OFFSET: PwrRegisters = 0x20;
const PWR_PDCRA_BASE_OFFSET: PwrRegisters = 0x24;
const PWR_PUCRB_BASE_OFFSET: PwrRegisters = 0x28;
const PWR_PDCRB_BASE_OFFSET: PwrRegisters = 0x2C;
const PWR_PUCRC_BASE_OFFSET: PwrRegisters = 0x30;
const PWR_PDCRC_BASE_OFFSET: PwrRegisters = 0x34;

/// Generic over the MMIO backend so host
/// tests can inject [`umbra_pal_test::mmio::MmioHandle`]. Default
/// `M = RealMmio` keeps every existing `Pwr::new()` call site unchanged at
/// the source level — the firmware build monomorphises to `Pwr<RealMmio>`
/// and inlines the `volatile_register` accesses just like before.
pub struct Pwr<M: MmioAccess = RealMmio> {
    mmio: M,
}

impl Pwr<RealMmio> {
    pub fn new() -> Self {
        Self {
            mmio: RealMmio::new(PWR_BASE_ADDR),
        }
    }
}

impl<M: MmioAccess> Pwr<M> {
    /// Constructor for host-side tests — accepts any `MmioAccess` backend.
    /// On firmware build, callers use `Pwr::new()` which monomorphises to
    /// `Pwr<RealMmio>` and inlines the volatile accesses.
    #[allow(dead_code)]
    pub fn new_with_mmio(mmio: M) -> Self {
        Self { mmio }
    }

    pub fn enable_clock(&self) {
        // enable_clock constructs an Rcc HW singleton — only meaningful on
        // the firmware path. Host tests should not invoke this; rcc.rs is
        // not yet migrated to the MmioAccess pattern.
        let rcc = Rcc::new();
        rcc.enable_clock(peripherals::PWR);
    }

    pub fn enable_to_backup_domain(&self) {
        // DBP: Disable backup domain write protection,
        // Enable access to RTC and Backup Registers
        self.mmio.set_bit(PWR_CR1_BASE_OFFSET, 8);

        // IOSB: Indicate that VDDIO2 is valid, needed for GPIOG[15:2]
        self.mmio.set_bit(PWR_CR2_BASE_OFFSET, 9);
    }

    /// Set VOS = range 0 (Boost) in PWR_CR1.
    /// Required for SYSCLK > 80 MHz on STM32L5 (RM0438 §6.1.5).
    /// VOS field is bits [10:9] of PWR_CR1:
    /// 00 = reserved
    /// 01 = Range 1 (max 80 MHz) ← reset default
    /// 10 = Range 2 (max 26 MHz)
    /// 00 with VOS field cleared = Range 0 boost (max 110 MHz)
    /// (RM0438 §6.4.1 — bit pattern is encoded as 00 = Range 0 / Boost.)
    /// After writing, polls PWR_SR2.VOSF (bit 10) until 0 (regulator
    /// settled at the new range). This must be called BEFORE raising
    /// SYSCLK above the previous VOS limit, otherwise the chip
    /// undervolts and hangs.
    pub fn set_vos_range_boost(&self) {
        // PWR_CR1.VOS bits [10:9]: clear to 00 = Range 0.
        let cr1 = self.mmio.read(PWR_CR1_BASE_OFFSET);
        let new = cr1 & !(0b11 << 9);
        self.mmio.write(PWR_CR1_BASE_OFFSET, new);

        // Poll VOSF (PWR_SR2 bit 10) until 0 = regulator ready at new range.
        loop {
            let sr2 = self.mmio.read(PWR_SR2_BASE_OFFSET);
            if (sr2 & (1 << 10)) == 0 {
                break;
            }
        }
    }

    pub fn set_bit(&self, reg_offset: PwrRegisters, bit: u8) {
        self.mmio.set_bit(reg_offset, bit);
    }
    pub fn clear_bit(&self, reg_offset: PwrRegisters, bit: u8) {
        self.mmio.clear_bit(reg_offset, bit);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umbra_pal_test::mmio::{MmioMem, MmioOp};

    /// Verifies `set_vos_range_boost` performs a read-modify-write to
    /// PWR_CR1 that clears bits [10:9] (VOS field → Range 0 / Boost), then
    /// polls PWR_SR2 until bit 10 (VOSF) is 0.
    #[test]
    fn set_vos_range_boost_clears_cr1_vos_then_polls_sr2() {
        let mem = MmioMem::new(PWR_BASE_ADDR);
        // Preload CR1 with VOS = 0b01 (Range 1, reset default) + some
        // unrelated upper bits so the clear step is observable AND the
        // unrelated bits must survive.
        mem.preload_register(PWR_CR1_BASE_OFFSET, (0b01 << 9) | 0xF000_0000);
        // PWR_SR2 default = 0 → VOSF already clear → poll exits after one read.

        let pwr = Pwr::<_>::new_with_mmio(mem.handle());
        pwr.set_vos_range_boost();

        let log = mem.write_log();
        // Expected ops:
        // 0: Read CR1
        // 1: Write CR1 with VOS field cleared, upper bits preserved
        // 2: Read SR2 (poll exits immediately because VOSF=0)
        assert_eq!(log.len(), 3, "log = {:?}", log);

        match log[0] {
            MmioOp::Read { addr, .. } => assert_eq!(addr, PWR_BASE_ADDR + PWR_CR1_BASE_OFFSET),
            _ => panic!("expected Read CR1 at position 0, got {:?}", log[0]),
        }
        match log[1] {
            MmioOp::Write { addr, value } => {
                assert_eq!(addr, PWR_BASE_ADDR + PWR_CR1_BASE_OFFSET);
                // VOS field bits [10:9] must be 0 = Range 0 (Boost).
                assert_eq!((value >> 9) & 0b11, 0b00);
                // Unrelated upper bits must be preserved.
                assert_eq!(value & 0xF000_0000, 0xF000_0000);
            }
            _ => panic!("expected Write CR1 at position 1, got {:?}", log[1]),
        }
        match log[2] {
            MmioOp::Read { addr, value } => {
                assert_eq!(addr, PWR_BASE_ADDR + PWR_SR2_BASE_OFFSET);
                assert_eq!(value & (1 << 10), 0, "VOSF must be 0 to break poll");
            }
            _ => panic!("expected Read SR2 at position 2, got {:?}", log[2]),
        }
    }

    /// Verifies `set_bit` and `clear_bit` perform correct read-modify-write
    /// sequences. We chain a set then a clear on bit 8 of CR1 and inspect
    /// the operation log + the final register state.
    #[test]
    fn set_bit_then_clear_bit_round_trip() {
        let mem = MmioMem::new(PWR_BASE_ADDR);
        // Preload CR1 with bit 0 set so we can verify other bits survive
        // the read-modify-write.
        mem.preload_register(PWR_CR1_BASE_OFFSET, 0x0000_0001);

        let pwr = Pwr::<_>::new_with_mmio(mem.handle());
        pwr.set_bit(PWR_CR1_BASE_OFFSET, 8);
        pwr.clear_bit(PWR_CR1_BASE_OFFSET, 8);

        let log = mem.write_log();
        // set_bit = 1 Read + 1 Write
        // clear_bit = 1 Read + 1 Write
        assert_eq!(log.len(), 4, "log = {:?}", log);

        // After set_bit: value must have bit 8 set and bit 0 preserved.
        match log[1] {
            MmioOp::Write { addr, value } => {
                assert_eq!(addr, PWR_BASE_ADDR + PWR_CR1_BASE_OFFSET);
                assert_eq!(value, 0x0000_0001 | (1 << 8));
            }
            _ => panic!("expected Write at position 1, got {:?}", log[1]),
        }
        // After clear_bit: value must have bit 8 cleared and bit 0 preserved.
        match log[3] {
            MmioOp::Write { addr, value } => {
                assert_eq!(addr, PWR_BASE_ADDR + PWR_CR1_BASE_OFFSET);
                assert_eq!(value, 0x0000_0001);
            }
            _ => panic!("expected Write at position 3, got {:?}", log[3]),
        }
    }
}
