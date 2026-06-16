//! Fault handlers for the M-mode monitor.
//!
//! Mirrors the role of `handlers.rs` on the STM32 platforms (which dump fault
//! registers over UART). Here, any trap that is not an `ecall` — most often an
//! SPMP/PMP memory-protection denial, reported by the patched QEMU as a
//! page-fault cause — lands here. The isolation phase will turn the
//! memory-protection cases into structured PASS/FAIL assertions; until then we
//! surface the cause/PC/address and halt.

use umbra_riscv_arch::trap::TrapFrame;

use crate::raw_print;

/// Report an unexpected trap (`mcause` / `mepc` / `mtval`) and halt.
pub fn unexpected_trap(frame: &TrapFrame) -> ! {
    raw_print::put_hex_line(b'C', frame.mcause); // cause
    raw_print::put_hex_line(b'P', frame.mepc); // faulting PC
    raw_print::put_hex_line(b'V', frame.mtval); // faulting addr / insn
    loop {
        core::hint::spin_loop();
    }
}
