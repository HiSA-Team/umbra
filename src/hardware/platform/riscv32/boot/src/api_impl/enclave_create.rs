//! `tee_create` handler — register the enclave at the base address in `a0`,
//! return its id in `a0`.

use umbra_riscv_arch::trap::TrapFrame;

use crate::api_impl::status_code;
use crate::secure_kernel;

/// Handle `ECALL_CREATE`: validate + load + measure the enclave at `a0`, return
/// its id (or the mapped [`umbra_error`] status code on failure).
pub fn handle(frame: &mut TrapFrame) {
    let base = frame.regs[10]; // a0 = enclave header base
    frame.regs[10] = match secure_kernel::create(base) {
        Ok(id) => id,
        Err(e) => status_code(e),
    };
    frame.mepc += 4;
}
