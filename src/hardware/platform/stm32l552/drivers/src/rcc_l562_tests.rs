//! L562-only RCC driver tests.
//!
//! Wired into `rcc.rs` via
//! `#[cfg(all(test, feature = "stm32l562"))] #[path = "rcc_l562_tests.rs"] mod l562_tests;`.
//! Lives in a sibling file (rather than inline in `rcc.rs`) so the
//! parent module stays under the 600-LOC hard cap. Has the same
//! `super::*` access as an inline `mod tests` would.
//!
//! Exercises the silicon-specific peripherals that are absent on L552
//! and therefore behind `#[cfg(feature = "stm32l562")]` both in the
//! driver implementation and in this test gate: USART1 clock
//! selection, OCTOSPI clock routing, and the OCTOSPI / OTFDEC reset
//! pulses.

use super::*;
use umbra_pal_test::mmio::{MmioMem, MmioOp};

/// L562: verifies `select_usart1_hsi16` writes CCIPR1.USART1SEL = 0b10
/// (HSI16) while preserving the upper bits of CCIPR1.
#[test]
fn l562_select_usart1_hsi16_writes_ccipr1_usart1sel_to_10() {
    let mem = MmioMem::new(RCC_BASE_ADDR);
    // Preload CCIPR1 with USART1SEL = 0b00 (PCLK) + an unrelated upper
    // bit. The upper bit must survive the read-modify-write.
    mem.preload_register(RCC_CCIPR1_BASE_OFFSET, 0x8000_0000);

    let rcc = Rcc::<_>::new_with_mmio(mem.handle());
    rcc.select_usart1_hsi16();

    let log = mem.write_log();
    // 1 Read + 1 Write.
    assert_eq!(log.len(), 2, "log = {:?}", log);
    match log[0] {
        MmioOp::Read { addr, .. } => {
            assert_eq!(addr, RCC_BASE_ADDR + RCC_CCIPR1_BASE_OFFSET);
        }
        _ => panic!("expected Read CCIPR1 at position 0, got {:?}", log[0]),
    }
    match log[1] {
        MmioOp::Write { addr, value } => {
            assert_eq!(addr, RCC_BASE_ADDR + RCC_CCIPR1_BASE_OFFSET);
            // USART1SEL bits [1:0] must be 0b10 = HSI16.
            assert_eq!(value & 0b11, 0b10);
            // Unrelated upper bit must be preserved.
            assert_eq!(value & 0x8000_0000, 0x8000_0000);
        }
        _ => panic!("expected Write CCIPR1 at position 1, got {:?}", log[1]),
    }
}

/// L562: verifies `select_ospi_clock_source_sysclk` writes CCIPR2.OSPISEL = 0b00
/// (SYSCLK) while preserving the upper bits of CCIPR2.
#[test]
fn l562_select_ospi_clock_source_sysclk_clears_ccipr2_ospisel() {
    let mem = MmioMem::new(RCC_BASE_ADDR);
    // Preload CCIPR2 with OSPISEL = 0b11 (a non-default value) + an
    // unrelated bit so we can verify the field is cleared and the
    // unrelated bit survives.
    mem.preload_register(RCC_CCIPR2_BASE_OFFSET, (0b11 << 20) | 0x0000_0001);

    let rcc = Rcc::<_>::new_with_mmio(mem.handle());
    rcc.select_ospi_clock_source_sysclk();

    let log = mem.write_log();
    // 1 Read + 1 Write.
    assert_eq!(log.len(), 2, "log = {:?}", log);
    match log[1] {
        MmioOp::Write { addr, value } => {
            assert_eq!(addr, RCC_BASE_ADDR + RCC_CCIPR2_BASE_OFFSET);
            // OSPISEL bits [21:20] must be 0b00 = SYSCLK.
            assert_eq!((value >> 20) & 0b11, 0b00);
            // Unrelated lower bit must be preserved.
            assert_eq!(value & 0x0000_0001, 0x0000_0001);
        }
        _ => panic!("expected Write CCIPR2 at position 1, got {:?}", log[1]),
    }
}

/// L562: verifies `reset_ospi` pulses AHB3RSTR.OSPI1RST (bit 8): one
/// Write sets the bit, then a clearing Write zeroes it again. Two
/// register reads sit between the writes (the OPS-mandated settling
/// pause); the host test cannot observe wall time, but it must see
/// the bit transition and the unrelated bits surviving both writes.
#[test]
fn l562_reset_ospi_pulses_ahb3rstr_bit8() {
    let mem = MmioMem::new(RCC_BASE_ADDR);
    // Preload AHB3RSTR with an unrelated upper bit set so both writes
    // must preserve it.
    mem.preload_register(RCC_AHB3RST_BASE_OFFSET, 0x8000_0000);

    let rcc = Rcc::<_>::new_with_mmio(mem.handle());
    rcc.reset_ospi();

    let log = mem.write_log();
    // 1 Read + 1 Write (set) + 2 dummy Reads + 1 Write (clear) = 5 ops.
    assert_eq!(log.len(), 5, "log = {:?}", log);
    match log[1] {
        MmioOp::Write { addr, value } => {
            assert_eq!(addr, RCC_BASE_ADDR + RCC_AHB3RST_BASE_OFFSET);
            // OSPI1RST (bit 8) must be set on the first write.
            assert_eq!(value & (1 << 8), 1 << 8);
            // Unrelated upper bit must be preserved.
            assert_eq!(value & 0x8000_0000, 0x8000_0000);
        }
        _ => panic!(
            "expected Write AHB3RSTR (set) at position 1, got {:?}",
            log[1]
        ),
    }
    match log[4] {
        MmioOp::Write { addr, value } => {
            assert_eq!(addr, RCC_BASE_ADDR + RCC_AHB3RST_BASE_OFFSET);
            // OSPI1RST (bit 8) must be cleared on the final write.
            assert_eq!(value & (1 << 8), 0);
            // Unrelated upper bit must be preserved across the clear.
            assert_eq!(value & 0x8000_0000, 0x8000_0000);
        }
        _ => panic!(
            "expected Write AHB3RSTR (clear) at position 4, got {:?}",
            log[4]
        ),
    }
}

/// L562: verifies `reset_otfdec` pulses AHB2RSTR.OTFDEC1RST (bit 21):
/// same shape as `reset_ospi`, different bus + bit position.
#[test]
fn l562_reset_otfdec_pulses_ahb2rstr_bit21() {
    let mem = MmioMem::new(RCC_BASE_ADDR);
    // Preload AHB2RSTR with bit 0 set (an unrelated peripheral reset)
    // so both writes must preserve it.
    mem.preload_register(RCC_AHB2RST_BASE_OFFSET, 0x0000_0001);

    let rcc = Rcc::<_>::new_with_mmio(mem.handle());
    rcc.reset_otfdec();

    let log = mem.write_log();
    // 1 Read + 1 Write (set) + 2 dummy Reads + 1 Write (clear) = 5 ops.
    assert_eq!(log.len(), 5, "log = {:?}", log);
    match log[1] {
        MmioOp::Write { addr, value } => {
            assert_eq!(addr, RCC_BASE_ADDR + RCC_AHB2RST_BASE_OFFSET);
            // OTFDEC1RST (bit 21) must be set on the first write.
            assert_eq!(value & (1 << 21), 1 << 21);
            // Unrelated low bit must be preserved.
            assert_eq!(value & 0x0000_0001, 0x0000_0001);
        }
        _ => panic!(
            "expected Write AHB2RSTR (set) at position 1, got {:?}",
            log[1]
        ),
    }
    match log[4] {
        MmioOp::Write { addr, value } => {
            assert_eq!(addr, RCC_BASE_ADDR + RCC_AHB2RST_BASE_OFFSET);
            // OTFDEC1RST (bit 21) must be cleared on the final write.
            assert_eq!(value & (1 << 21), 0);
            // Unrelated low bit must be preserved across the clear.
            assert_eq!(value & 0x0000_0001, 0x0000_0001);
        }
        _ => panic!(
            "expected Write AHB2RSTR (clear) at position 4, got {:?}",
            log[4]
        ),
    }
}
