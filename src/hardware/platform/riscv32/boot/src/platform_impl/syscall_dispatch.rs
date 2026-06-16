//! Trap entry dispatch + untrusted-world preparation.
//!
//! `_mtrap_entry` (in `start.S`) saves the trap frame and calls [`rust_mtrap`],
//! the single mediation point for every ring transition: `ecall`s route to the
//! enclave API surface, everything else (memory-protection faults) goes to the
//! fault handler. This is the RISC-V analog of the STM32 platforms' SVC/SysTick
//! trampolines.

use umbra_riscv_arch::trap::{self, Trap, TrapFrame};

use super::{timer, Rv32VirtPlatform};
use crate::{api_impl, handlers, secure_kernel};

/// The M-mode trap handler, called from `_mtrap_entry`.
#[no_mangle]
pub extern "C" fn rust_mtrap(frame: &mut TrapFrame) {
    match trap::decode(frame.mcause, frame.mtval) {
        Trap::EcallFromU | Trap::EcallFromS => api_impl::dispatch(frame),
        Trap::TimerInterrupt => {
            // Preemption tick: suspend the running enclave and hand the slice
            // back to the host scheduler. A stray tick while the host ran (no
            // current enclave) just disables the timer.
            if !secure_kernel::try_preempt(frame) {
                timer::disable();
            }
        }
        _ => {
            // A non-ecall trap. In order: (1) the active enclave returning to
            // the sentinel (Umbra handles the exit); (2) an ESS miss — the
            // enclave fetched from a trap-filled, not-yet-resident block, so
            // demand-load it and re-execute; (3) otherwise a genuine fault.
            if !secure_kernel::try_handle_return(frame)
                && !secure_kernel::try_handle_ess_miss(frame)
            {
                handlers::unexpected_trap(frame);
            }
        }
    }
}

impl Rv32VirtPlatform {
    /// Prepare the hand-off to the untrusted world. The PMP/SPMP grants and the
    /// trap vector are already programmed in `init_security`, so there is
    /// nothing further to stage on QEMU; the method exists to match the
    /// platform boot contract.
    pub(super) fn configure_untrusted_boot_impl(&self) {}
}
