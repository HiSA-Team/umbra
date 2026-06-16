//! `debug_print` handler — emit one byte through the monitor-owned UART. Both
//! the host and the enclave use this instead of touching the UART directly, so
//! the monitor remains the sole owner of the device.

use umbra_riscv_arch::trap::TrapFrame;

use crate::raw_print;

/// Handle `ECALL_DEBUG`: print the byte in `a0` and step over the ecall.
pub fn handle(frame: &mut TrapFrame) {
    raw_print::putc(frame.regs[10] as u8); // a0
    frame.mepc += 4;
}
