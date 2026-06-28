//! Untrusted-world hand-off — the `jump_to_untrusted` path is the last thing the
//! monitor runs at boot, `mret`-ing into the externally-loaded S-mode host
//! (loaded by QEMU at `HOST_ENTRY`). Analogous to the STM32 platforms' NS-world
//! branch.

use super::Rv32VirtPlatform;
use crate::secure_kernel;

extern "C" {
    /// Initial hand-off into S-mode (defined in `start.S`). Does not return.
    fn _enter_smode(entry: usize, sp: usize) -> !;
}

impl Rv32VirtPlatform {
    /// Drop into the S-mode host; the three-ring lifecycle proceeds via ecalls.
    pub(super) fn jump_to_untrusted_impl(&self) -> ! {
        crate::raw_print::print_str("[UMBRASecureBoot] Jumping to Untrusted Supervisor (S-mode)\n");
        // SAFETY: `HOST_ENTRY` is the host image's `_host_start`; the host resets
        // its own stack, so `HOST_SP` is just the initial value.
        unsafe {
            _enter_smode(
                secure_kernel::HOST_ENTRY as usize,
                secure_kernel::HOST_SP as usize,
            )
        }
    }
}
