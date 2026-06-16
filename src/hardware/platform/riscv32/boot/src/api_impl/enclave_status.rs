//! `enclave_status` handler — return the full result word of a terminated
//! enclave (`a0` = id in, full result out). The host calls this after `enter`
//! reports `STATUS_TERMINATED` to recover the complete result.

use umbra_riscv_arch::trap::TrapFrame;

use crate::secure_kernel;

/// Handle `ECALL_STATUS`: return the stored result for enclave `a0`.
pub fn handle(frame: &mut TrapFrame) {
    let id = frame.regs[10]; // a0 = enclave id
    frame.regs[10] = secure_kernel::status(id);
    frame.mepc += 4;
}
