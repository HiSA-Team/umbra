//! L562-only OCTOSPI indirect-transfer driver tests.
//!
//! Wired into `transfer.rs` via
//! `#[cfg(test)] #[path = "transfer_l562_tests.rs"] mod l562_tests;`.
//! Lives in a sibling file so `transfer.rs` stays clear of test code
//! and the file-size cap is easier to honour as the transfer surface
//! grows.
//!
//! ## Coverage scope
//!
//! Only the functions that go **exclusively** through `MmioAccess` are
//! exercised here: `issue_command_no_data` and the thin
//! `write_enable` wrapper. The `read_status_register` /
//! `read_status_register`-driven helpers (`wait_wip`,
//! `sector_erase_4k`, `page_program`) read the OCTOSPI data port via a
//! raw `core::ptr::read_volatile((base + DR_OFFSET) as *const u8)`,
//! which bypasses the [`MmioMem`] backing store and dereferences an
//! unmapped host virtual address — a host-side test that hit that line
//! would segfault. The byte-port path is exercised on HW; the host
//! test surface stops at the indirect-write path.

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

/// L562: verifies `issue_command_no_data` performs the canonical
/// indirect-write sequence:
/// * Read CR
/// * Write CR with EN=0 (disable while reconfiguring)
/// * Read CR
/// * Write CR with FMODE bits [29:28] cleared (00 = indirect-write)
/// * Write CCR with IMODE=1 (instruction on 1 line, no address, no data)
/// * Read CR
/// * Write CR with EN=1 (re-enable before IR write)
/// * Write IR with the command opcode (triggers the transfer)
/// * Read SR (poll exits because BUSY=0 in the preloaded state)
/// * Write FCR to clear TCF (W1C bit 1)
///
/// Uses the WREN opcode (0x06) as the canonical no-data command.
/// Pre-load CR with an unrelated upper bit so the three RMW steps must
/// preserve it across each write.
#[test]
fn issue_command_no_data_emits_full_indirect_write_sequence_for_wren() {
    let mem = MmioMem::new(super::super::OCTOSPI1_BASE_ADDR);
    // Preload CR with an unrelated upper bit so RMW preservation is observable.
    mem.preload_register(OCTOSPI_CR_OFFSET, 0x8000_0000);
    // Preload SR with BUSY=0 so the poll exits on the first read.
    // (Default is 0 anyway, but make the intent explicit.)
    mem.preload_register(OCTOSPI_SR_OFFSET, 0);

    let ospi = OspiDriver::<_>::new_with_mmio(mem.handle());
    let result = ospi.issue_command_no_data(0x06);

    assert!(
        result.is_ok(),
        "WREN must succeed when BUSY is clear, got {result:?}"
    );

    let log = mem.write_log();

    // 6 writes total: CR(EN=0), CR(FMODE=00), CCR, CR(EN=1), IR, FCR.
    assert_eq!(
        count_writes(&log),
        6,
        "expected 6 writes (CR-disable, CR-FMODE, CCR, CR-enable, IR, FCR), log = {log:?}",
    );

    // [0] CR ← preload & !1 (EN cleared, upper bit preserved).
    let (a0, v0) = nth_write(&log, 0);
    assert_eq!(a0, super::super::OCTOSPI1_BASE_ADDR + OCTOSPI_CR_OFFSET);
    assert_eq!(v0 & 1, 0, "first CR write must clear EN");
    assert_eq!(
        v0 & 0x8000_0000,
        0x8000_0000,
        "upper bit must survive CR-disable"
    );

    // [1] CR ← FMODE bits [29:28] cleared to 0b00 (indirect-write).
    let (a1, v1) = nth_write(&log, 1);
    assert_eq!(a1, super::super::OCTOSPI1_BASE_ADDR + OCTOSPI_CR_OFFSET);
    assert_eq!((v1 >> 28) & 0b11, 0b00, "FMODE must be 00 = indirect-write");
    assert_eq!(v1 & 1, 0, "EN must still be cleared at this step");

    // [2] CCR ← 0b01 (IMODE = 1-line, no address, no data).
    let (a2, v2) = nth_write(&log, 2);
    assert_eq!(a2, super::super::OCTOSPI1_BASE_ADDR + OCTOSPI_CCR_OFFSET);
    assert_eq!(v2, 0b01, "CCR must encode IMODE=1, no address, no data");

    // [3] CR ← EN set (re-enable before IR trigger).
    let (a3, v3) = nth_write(&log, 3);
    assert_eq!(a3, super::super::OCTOSPI1_BASE_ADDR + OCTOSPI_CR_OFFSET);
    assert_eq!(v3 & 1, 1, "CR.EN must be set before IR write");

    // [4] IR ← 0x06 (WREN trigger).
    let (a4, v4) = nth_write(&log, 4);
    assert_eq!(a4, super::super::OCTOSPI1_BASE_ADDR + OCTOSPI_IR_OFFSET);
    assert_eq!(v4, 0x06, "IR must trigger with the WREN opcode");

    // [5] FCR ← 0b10 (clear TCF, W1C bit 1).
    let (a5, v5) = nth_write(&log, 5);
    assert_eq!(a5, super::super::OCTOSPI1_BASE_ADDR + OCTOSPI_FCR_OFFSET);
    assert_eq!(v5, 1 << 1, "FCR must W1C the TCF bit");
}

/// L562: verifies `write_enable` delegates to `issue_command_no_data`
/// with the WREN opcode (0x06). Independent from the full-sequence test
/// so a regression in the delegation surfaces with a focused message
/// without re-asserting every step.
#[test]
fn write_enable_delegates_with_wren_opcode() {
    let mem = MmioMem::new(super::super::OCTOSPI1_BASE_ADDR);
    mem.preload_register(OCTOSPI_SR_OFFSET, 0);

    let ospi = OspiDriver::<_>::new_with_mmio(mem.handle());
    let result = ospi.write_enable();

    assert!(
        result.is_ok(),
        "write_enable must succeed when BUSY is clear"
    );

    let log = mem.write_log();

    // The trigger write is the only Write to IR_OFFSET; locate it and
    // confirm the opcode is WREN (0x06). Manual loop avoids depending on
    // `Vec` / `alloc` import in this `no_std` driver crate.
    let mut ir_writes = 0u32;
    let mut last_ir_value = 0u32;
    let ir_addr = super::super::OCTOSPI1_BASE_ADDR + OCTOSPI_IR_OFFSET;
    for op in &log {
        if let MmioOp::Write { addr, value } = *op {
            if addr == ir_addr {
                ir_writes += 1;
                last_ir_value = value;
            }
        }
    }
    assert_eq!(ir_writes, 1, "write_enable must emit exactly one IR write");
    assert_eq!(
        last_ir_value, 0x06,
        "write_enable must trigger with WREN (0x06)"
    );
}
