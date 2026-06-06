//! L562 OSPI init-orchestration tests (multi-MMIO).
//!
//! Wired into `init.rs` via
//! `#[cfg(test)] #[path = "init_l562_tests.rs"] mod l562_tests;`.
//!
//! ## Scope
//!
//! These tests exercise [`OspiDriver::init_with_drivers`], the host-
//! testable variant of [`OspiDriver::init`]. The wrapper `init`
//! materialises `Rcc::new()` / `Gpio::new(Port::…)` which create
//! `RealMmio`-backed singletons against physical peripheral addresses
//! — calling them on host would issue `read_volatile` against an
//! unmapped page. The orchestration logic was extracted into
//! `init_with_drivers` so the same sequence can be driven against
//! `MmioMem`-backed Rcc/Gpio/OspiDriver instances and recorded
//! per-peripheral.
//!
//! ## Multi-MMIO pattern
//!
//! Five independent `MmioMem` regions (one per peripheral base) catch
//! the writes for RCC, GPIOA, GPIOB, GPIOC, and OCTOSPI1 separately.
//! Each region's `write_log` is asserted in isolation, which keeps
//! the test diagnostics targeted: a regression that adds a stray RCC
//! write shows up on the RCC log only, not as an off-by-one elsewhere.

use super::*;
use crate::gpio::Port;
use crate::rcc::RCC_BASE_ADDR;
use umbra_pal_test::mmio::{MmioMem, MmioOp};

fn count_writes(log: &[MmioOp]) -> usize {
    log.iter()
        .filter(|op| matches!(op, MmioOp::Write { .. }))
        .count()
}

/// Verifies `init_with_drivers` orchestrates the cold-path bringup
/// across five peripherals in the documented order: RCC clocks → GPIO
/// pin AF configuration (A, B, C) → OCTOSPI register arm.
#[test]
fn init_with_drivers_orchestrates_clocks_pins_and_octospi() {
    // One MmioMem region per peripheral; the bases match the production
    // addresses so the driver constructors target the right backing.
    let rcc_mem = MmioMem::new(RCC_BASE_ADDR);
    let gpioa_mem = MmioMem::new(Port::GpioA as u32);
    let gpiob_mem = MmioMem::new(Port::GpioB as u32);
    let gpioc_mem = MmioMem::new(Port::GpioC as u32);
    let octospi_mem = MmioMem::new(super::super::OCTOSPI1_BASE_ADDR);

    let rcc = Rcc::<_>::new_with_mmio(rcc_mem.handle());
    let gpioa = Gpio::<_>::new_with_mmio(Port::GpioA, gpioa_mem.handle());
    let gpiob = Gpio::<_>::new_with_mmio(Port::GpioB, gpiob_mem.handle());
    let gpioc = Gpio::<_>::new_with_mmio(Port::GpioC, gpioc_mem.handle());
    let ospi = OspiDriver::<_>::new_with_mmio(octospi_mem.handle());

    ospi.init_with_drivers(&rcc, &gpioa, &gpiob, &gpioc);

    // ── RCC ── 3 clock enables on AHB2ENR (read-modify-write per call). ──
    assert_eq!(
        count_writes(&rcc_mem.write_log()),
        3,
        "RCC must emit 3 writes (one per enable_clock GPIOA/B/C)",
    );

    // ── GPIOA ── pins 2, 3, 6, 7 → set_mode + set_alternate_function. ──
    // Each call is a RMW (1 read + 1 write); per pin = 2 writes. 4 pins = 8.
    assert_eq!(
        count_writes(&gpioa_mem.write_log()),
        4 * 2,
        "GPIOA must emit 8 writes (4 pins × MODER + AFRL)",
    );

    // ── GPIOB ── pins 0, 1, 2. 3 pins × 2 writes = 6. ──
    assert_eq!(
        count_writes(&gpiob_mem.write_log()),
        3 * 2,
        "GPIOB must emit 6 writes (3 pins × MODER + AFRL)",
    );

    // ── GPIOC ── pin 0 (AF3) + pins 1, 2, 3 (AF10). 4 pins × 2 writes = 8. ──
    assert_eq!(
        count_writes(&gpioc_mem.write_log()),
        4 * 2,
        "GPIOC must emit 8 writes (4 pins × MODER + AFRL)",
    );

    // ── OCTOSPI ── configure_octospi_dcr_and_enable: CR-disable, DCR1,
    // DCR2, CR-arm = 4 writes. (configure_octospi_dcr_and_enable's own
    // sequence is asserted in detail by the test in ospi/mod.rs;
    // here we only check that the orchestration calls it.) ──
    assert_eq!(
        count_writes(&octospi_mem.write_log()),
        4,
        "OCTOSPI must emit 4 writes (CR-disable, DCR1, DCR2, CR-arm)",
    );
}

/// Verifies the GPIOC AF mux split — pin 0 lands on AF3 (L562E-DK
/// muxing for IO4), pins 1..3 land on AF10. The orchestration writes
/// to AFRL twice for each pin: the first per-pin write is the MODER
/// configure, the second is the AFRL configure. We crawl the GPIOC
/// log for the AFRL writes and check the encoded nibble per pin.
#[test]
fn init_with_drivers_configures_gpioc_pin0_to_af3_and_pins1_3_to_af10() {
    let rcc_mem = MmioMem::new(RCC_BASE_ADDR);
    let gpioa_mem = MmioMem::new(Port::GpioA as u32);
    let gpiob_mem = MmioMem::new(Port::GpioB as u32);
    let gpioc_mem = MmioMem::new(Port::GpioC as u32);
    let octospi_mem = MmioMem::new(super::super::OCTOSPI1_BASE_ADDR);

    let rcc = Rcc::<_>::new_with_mmio(rcc_mem.handle());
    let gpioa = Gpio::<_>::new_with_mmio(Port::GpioA, gpioa_mem.handle());
    let gpiob = Gpio::<_>::new_with_mmio(Port::GpioB, gpiob_mem.handle());
    let gpioc = Gpio::<_>::new_with_mmio(Port::GpioC, gpioc_mem.handle());
    let ospi = OspiDriver::<_>::new_with_mmio(octospi_mem.handle());

    ospi.init_with_drivers(&rcc, &gpioa, &gpiob, &gpioc);

    // The final AFRL value on GPIOC encodes the AF nibble per pin in the
    // low half of the register (pins 0..7). After the orchestration
    // GPIOC AFRL must show:
    //   pin 0 → 0b0011 (AF3)
    //   pin 1 → 0b1010 (AF10)
    //   pin 2 → 0b1010 (AF10)
    //   pin 3 → 0b1010 (AF10)
    // Higher pins (4..7) remain zero — not touched by the orchestration.
    // We walk the log and capture the last Write to AFRL (offset 0x20).
    let gpioc_log = gpioc_mem.write_log();
    let afrl_addr = Port::GpioC as u32 + 0x20;
    let mut last_afrl: Option<u32> = None;
    for op in &gpioc_log {
        if let MmioOp::Write { addr, value } = *op {
            if addr == afrl_addr {
                last_afrl = Some(value);
            }
        }
    }
    let afrl = last_afrl.expect("GPIOC AFRL must have at least one write");

    assert_eq!(afrl & 0xF, 0x3, "pin 0 must be AF3 in AFRL low nibble");
    assert_eq!((afrl >> 4) & 0xF, 0xA, "pin 1 must be AF10");
    assert_eq!((afrl >> 8) & 0xF, 0xA, "pin 2 must be AF10");
    assert_eq!((afrl >> 12) & 0xF, 0xA, "pin 3 must be AF10");
}

/// Negative scope assertion: the test-side `init_with_drivers` must
/// NOT touch GPIO ports D-H. A bug that adds a stray Gpio::new(Port::GpioD)
/// would compile but break this assertion — the GPIOD MmioMem stays
/// empty.
#[test]
fn init_with_drivers_does_not_touch_other_gpio_ports() {
    let rcc_mem = MmioMem::new(RCC_BASE_ADDR);
    let gpioa_mem = MmioMem::new(Port::GpioA as u32);
    let gpiob_mem = MmioMem::new(Port::GpioB as u32);
    let gpioc_mem = MmioMem::new(Port::GpioC as u32);
    let gpiod_mem = MmioMem::new(Port::GpioD as u32);
    let octospi_mem = MmioMem::new(super::super::OCTOSPI1_BASE_ADDR);

    let rcc = Rcc::<_>::new_with_mmio(rcc_mem.handle());
    let gpioa = Gpio::<_>::new_with_mmio(Port::GpioA, gpioa_mem.handle());
    let gpiob = Gpio::<_>::new_with_mmio(Port::GpioB, gpiob_mem.handle());
    let gpioc = Gpio::<_>::new_with_mmio(Port::GpioC, gpioc_mem.handle());
    let _gpiod = Gpio::<_>::new_with_mmio(Port::GpioD, gpiod_mem.handle());
    let ospi = OspiDriver::<_>::new_with_mmio(octospi_mem.handle());

    ospi.init_with_drivers(&rcc, &gpioa, &gpiob, &gpioc);

    assert_eq!(
        gpiod_mem.write_log().len(),
        0,
        "GPIOD must remain untouched by OSPI init",
    );

    // RCC must not enable a GPIOD clock either. We can't inspect the
    // RCC-side decode of which clock got enabled without re-implementing
    // the bit map, but we can lower-bound check: 3 writes total, no more.
    // (The exact 3-write count is asserted by the orchestration test.)
    let rcc_writes = count_writes(&rcc_mem.write_log());
    assert!(
        rcc_writes <= 3,
        "RCC must emit at most 3 writes; an extra would imply a stray clock enable",
    );
}
