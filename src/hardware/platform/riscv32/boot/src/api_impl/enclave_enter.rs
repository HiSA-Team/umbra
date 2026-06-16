//! `enclave_enter` handler — switch from the U-mode host into the S-mode
//! enclave `a0`. The kernel snapshots the host context and redirects the trap
//! frame to the enclave entry with the return sentinel in `ra`; `mepc` is NOT
//! advanced here (it is replaced with the enclave entry point).

use umbra_riscv_arch::trap::TrapFrame;

use crate::secure_kernel;

/// Handle `ECALL_ENTER`: enter enclave `a0` (the frame is rewritten in place).
pub fn handle(frame: &mut TrapFrame) {
    let id = frame.regs[10]; // a0 = enclave id
    secure_kernel::enter(frame, id);
}
