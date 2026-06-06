//! L562-only OCTOSPI memory-mapped driver tests.
//!
//! Wired into `memory_mapped.rs` via
//! `#[cfg(test)] #[path = "memory_mapped_l562_tests.rs"] mod l562_tests;`.
//! Sibling file pattern keeps the parent module clear of test code and
//! mirrors the layout used in `transfer_l562_tests.rs`.
//!
//! Coverage scope: all three public entry points (`enable_memory_mapped_octa`,
//! `enable_memory_mapped_write_read`, `disable_memory_mapped`) go entirely
//! through `MmioAccess` — there is no raw pointer read of the OCTOSPI
//! data port on the memory-mapped path, so every step is observable
//! from the [`MmioMem`] write log.

use super::*;
use umbra_pal_test::mmio::{MmioMem, MmioOp};

fn count_writes(log: &[MmioOp]) -> usize {
    log.iter()
        .filter(|op| matches!(op, MmioOp::Write { .. }))
        .count()
}

fn nth_write(log: &[MmioOp], n: usize) -> (u32, u32) {
    let mut seen = 0;
    for op in log {
        if let MmioOp::Write { addr, value } = *op {
            if seen == n {
                return (addr, value);
            }
            seen += 1;
        }
    }
    panic!("log only contains {seen} writes, wanted index {n}");
}

/// L562: verifies `enable_memory_mapped_octa` emits the legacy 1-1-1
/// FAST_READ bringup sequence:
///   1. CR disable (EN ← 0)
///   2. CCR ← FAST_READ shape (IMODE=1 ADMODE=1 ADSIZE=2 DMODE=1)
///   3. TCR ← 8 dummy cycles
///   4. IR ← 0x0B (FAST_READ)
///   5. CR ← FMODE=11 (memory-mapped) | EN=1
/// followed by a BUSY poll exit. Pins the cold-boot register-write
/// ordering so a future refactor cannot inadvertently reorder
/// CCR/TCR/IR vs the CR rearm.
#[test]
fn enable_memory_mapped_octa_emits_fast_read_bringup_sequence() {
    let mem = MmioMem::new(super::super::OCTOSPI1_BASE_ADDR);
    // Preload CR with an unrelated upper bit so RMW preservation is
    // observable on the final CR write.
    mem.preload_register(OCTOSPI_CR_OFFSET, 0x8000_0000);
    // Preload SR with BUSY=0 so the post-EN poll exits on first read.
    mem.preload_register(OCTOSPI_SR_OFFSET, 0);

    let ospi = OspiDriver::<_>::new_with_mmio(mem.handle());
    let result = ospi.enable_memory_mapped_octa();

    assert!(
        result.is_ok(),
        "must succeed when BUSY is clear, got {result:?}"
    );

    let log = mem.write_log();
    // 5 writes: CR-disable, CCR, TCR, IR, CR-arm.
    assert_eq!(
        count_writes(&log),
        5,
        "expected 5 writes (CR-disable, CCR, TCR, IR, CR-arm), log = {log:?}",
    );

    let cr_addr = super::super::OCTOSPI1_BASE_ADDR + OCTOSPI_CR_OFFSET;
    let ccr_addr = super::super::OCTOSPI1_BASE_ADDR + OCTOSPI_CCR_OFFSET;
    let tcr_addr = super::super::OCTOSPI1_BASE_ADDR + OCTOSPI_TCR_OFFSET;
    let ir_addr = super::super::OCTOSPI1_BASE_ADDR + OCTOSPI_IR_OFFSET;

    // [0] CR ← preload & !1 (EN cleared, upper bit preserved).
    let (a0, v0) = nth_write(&log, 0);
    assert_eq!(a0, cr_addr);
    assert_eq!(v0 & 1, 0, "first CR write must clear EN");
    assert_eq!(
        v0 & 0x8000_0000,
        0x8000_0000,
        "upper bit must survive disable"
    );

    // [1] CCR ← FAST_READ shape.
    let (a1, v1) = nth_write(&log, 1);
    assert_eq!(a1, ccr_addr);
    let expected_ccr = (0b01u32 << 0) | (0b001u32 << 8) | (0b10u32 << 12) | (0b001u32 << 24);
    assert_eq!(v1, expected_ccr, "CCR must encode 1-1-1 FAST_READ");

    // [2] TCR ← 8 dummy cycles.
    let (a2, v2) = nth_write(&log, 2);
    assert_eq!(a2, tcr_addr);
    assert_eq!(v2, 8, "TCR must hold 8 dummy cycles");

    // [3] IR ← 0x0B (FAST_READ opcode).
    let (a3, v3) = nth_write(&log, 3);
    assert_eq!(a3, ir_addr);
    assert_eq!(v3, 0x0B, "IR must hold FAST_READ opcode");

    // [4] CR ← FMODE=11 | EN=1, upper bit preserved.
    let (a4, v4) = nth_write(&log, 4);
    assert_eq!(a4, cr_addr);
    assert_eq!((v4 >> 28) & 0b11, 0b11, "FMODE must be 11 (memory-mapped)");
    assert_eq!(v4 & 1, 1, "EN must be set");
    assert_eq!(v4 & 0x8000_0000, 0x8000_0000, "upper bit must survive arm");
}

/// L562: verifies `enable_memory_mapped_write_read` emits the dual
/// read+write bringup sequence — adds WCCR/WTCR/WIR after the read
/// triple before arming CR.FMODE=11.
#[test]
fn enable_memory_mapped_write_read_emits_dual_read_write_bringup_sequence() {
    let mem = MmioMem::new(super::super::OCTOSPI1_BASE_ADDR);
    mem.preload_register(OCTOSPI_CR_OFFSET, 0x8000_0000);
    mem.preload_register(OCTOSPI_SR_OFFSET, 0);

    let ospi = OspiDriver::<_>::new_with_mmio(mem.handle());
    let result = ospi.enable_memory_mapped_write_read();

    assert!(
        result.is_ok(),
        "must succeed when BUSY is clear, got {result:?}"
    );

    let log = mem.write_log();
    // 8 writes: CR-disable, CCR, TCR, IR, WCCR, WTCR, WIR, CR-arm.
    assert_eq!(
        count_writes(&log),
        8,
        "expected 8 writes (CR-disable, CCR, TCR, IR, WCCR, WTCR, WIR, CR-arm), log = {log:?}",
    );

    let cr_addr = super::super::OCTOSPI1_BASE_ADDR + OCTOSPI_CR_OFFSET;
    let wccr_addr = super::super::OCTOSPI1_BASE_ADDR + OCTOSPI_WCCR_OFFSET;
    let wtcr_addr = super::super::OCTOSPI1_BASE_ADDR + OCTOSPI_WTCR_OFFSET;
    let wir_addr = super::super::OCTOSPI1_BASE_ADDR + OCTOSPI_WIR_OFFSET;

    // [4] WCCR ← Page Program shape (same field layout as CCR).
    let (a4, v4) = nth_write(&log, 4);
    assert_eq!(a4, wccr_addr);
    let expected_wccr = (0b001u32 << 0) | (0b001u32 << 8) | (0b10u32 << 12) | (0b001u32 << 24);
    assert_eq!(
        v4, expected_wccr,
        "WCCR must encode 1-1-1 Page Program shape"
    );

    // [5] WTCR ← 0 dummy cycles (Page Program needs none).
    let (a5, v5) = nth_write(&log, 5);
    assert_eq!(a5, wtcr_addr);
    assert_eq!(v5, 0, "WTCR must hold 0 dummy cycles");

    // [6] WIR ← Page Program opcode (0x02).
    let (a6, v6) = nth_write(&log, 6);
    assert_eq!(a6, wir_addr);
    assert_eq!(v6, 0x02, "WIR must hold the Page Program opcode");

    // [7] CR arm — FMODE=11 (memory-mapped) | EN=1, upper bit preserved.
    let (a7, v7) = nth_write(&log, 7);
    assert_eq!(a7, cr_addr);
    assert_eq!((v7 >> 28) & 0b11, 0b11, "FMODE must be 11 (memory-mapped)");
    assert_eq!(v7 & 1, 1, "EN must be set");
    assert_eq!(v7 & 0x8000_0000, 0x8000_0000, "upper bit must survive arm");
}

/// L562: verifies `disable_memory_mapped` skips the ABORT branch when
/// BUSY is clear and emits exactly one CR write (EN cleared) with
/// upper bits preserved. The ABORT branch is intentionally **not**
/// exercised here because the polling loop would not terminate against
/// an [`MmioMem`] preload that keeps returning BUSY=1; documenting it
/// as a HW-only path is the right granularity for the host suite.
#[test]
fn disable_memory_mapped_skips_abort_when_busy_clear() {
    let mem = MmioMem::new(super::super::OCTOSPI1_BASE_ADDR);
    // Preload CR with an unrelated upper bit + EN=1 to verify both:
    // - the EN bit gets cleared,
    // - the unrelated upper bit survives the write.
    mem.preload_register(OCTOSPI_CR_OFFSET, 0x8000_0001);
    // BUSY=0 in SR → the initial check at the head of `disable_memory_mapped`
    // sees no in-flight prefetch and skips the ABORT branch entirely.
    mem.preload_register(OCTOSPI_SR_OFFSET, 0);

    let ospi = OspiDriver::<_>::new_with_mmio(mem.handle());
    let result = ospi.disable_memory_mapped();

    assert!(result.is_ok(), "must always return Ok when BUSY is clear");

    let log = mem.write_log();
    // Exactly 1 write: CR ← preload & !1.
    assert_eq!(
        count_writes(&log),
        1,
        "no ABORT path expected when BUSY=0, log = {log:?}",
    );

    let cr_addr = super::super::OCTOSPI1_BASE_ADDR + OCTOSPI_CR_OFFSET;
    let (addr, value) = nth_write(&log, 0);
    assert_eq!(addr, cr_addr, "the only write must target CR");
    assert_eq!(value & 1, 0, "EN must be cleared on the disable write");
    assert_eq!(
        value & 0x8000_0000,
        0x8000_0000,
        "unrelated upper bit must survive the disable write",
    );
}
