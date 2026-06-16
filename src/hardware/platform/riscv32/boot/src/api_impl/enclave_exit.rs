//! `enclave_exit` handler — for an enclave that opts to signal completion via an
//! `exit` ecall (`a0` = result) instead of simply returning. The default
//! payload returns and lets Umbra catch it (see `secure_kernel::try_handle_return`);
//! both paths funnel into `secure_kernel::complete`.

use umbra_riscv_arch::trap::TrapFrame;

use crate::secure_kernel;

/// Handle `ECALL_EXIT`: take the enclave's result (`a0`) and resume the host.
pub fn handle(frame: &mut TrapFrame) {
    let result = frame.regs[10]; // a0
    secure_kernel::complete(frame, result);
}
