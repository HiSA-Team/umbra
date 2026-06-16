//! QEMU `virt` RISC-V (RV32) platform implementation — M-mode monitor runtime.
//!
//! Mirrors the STM32 platforms' decomposition:
//! - [`boot`] — clock/uart/security/kernel bring-up (the `init_*` phases)
//! - [`syscall_dispatch`] — the `ecall`/fault trap entry + untrusted-world prep
//! - [`power`] — the hand-off into the untrusted U-mode host
//!
//! The boot sequence is driven by the [`umbra_api::PlatformBoot`] trait, the
//! same contract the STM32 platforms implement.

use umbra_api::PlatformBoot;

pub mod boot;
pub mod power;
pub mod syscall_dispatch;
pub mod timer;

/// The QEMU `virt` board (RV32, M/S/U), as the Umbra M-mode monitor.
pub struct Rv32VirtPlatform;

impl Rv32VirtPlatform {
    pub fn new() -> Self {
        Rv32VirtPlatform
    }
}

impl PlatformBoot for Rv32VirtPlatform {
    fn init_clocks(&self) {
        Rv32VirtPlatform::init_clocks_impl(self);
    }

    fn init_gpio(&self) {
        Rv32VirtPlatform::init_gpio_impl(self);
    }

    fn init_uart(&self) {
        Rv32VirtPlatform::init_uart_impl(self);
    }

    fn init_security(&self) {
        Rv32VirtPlatform::init_security_impl(self);
    }

    fn init_kernel(&self) {
        Rv32VirtPlatform::init_kernel_impl(self);
    }

    fn init_external_flash(&self) -> bool {
        Rv32VirtPlatform::init_external_flash_impl(self)
    }

    fn configure_untrusted_boot(&self) {
        Rv32VirtPlatform::configure_untrusted_boot_impl(self);
    }

    fn jump_to_untrusted(&self) -> ! {
        Rv32VirtPlatform::jump_to_untrusted_impl(self)
    }
}
