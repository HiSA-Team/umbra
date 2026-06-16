//! Umbra M-mode monitor — QEMU `virt` RISC-V (RV32) entry point.
//!
//! `_start` (in the arch crate's `start.S`) sets the stack, zeroes `.bss`, and
//! calls [`secure_boot`]. The boot sequence is driven through the
//! [`umbra_api::PlatformBoot`] trait — the same contract the STM32 platforms
//! implement — and ends by handing off to the U-mode host. From there the
//! three-ring lifecycle runs over the `ecall` trap interface.
#![no_std]
#![no_main]
#![warn(clippy::undocumented_unsafe_blocks)]

mod api_impl;
mod crypto_impl;
mod handlers;
mod master_key;
mod platform_impl;
mod raw_print;
mod secure_kernel;

use platform_impl::Rv32VirtPlatform;
use umbra_api::PlatformBoot;

core::arch::global_asm!(include_str!("../../../../architecture/riscv/asm/start.S"));

#[no_mangle]
pub extern "C" fn secure_boot() -> ! {
    let platform = Rv32VirtPlatform::new();
    platform.init_clocks();
    platform.init_gpio();
    platform.init_uart();
    platform.init_security();
    platform.init_kernel();
    platform.init_external_flash();
    platform.configure_untrusted_boot();
    platform.jump_to_untrusted();
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    raw_print::puts(b"[PANIC]\n");
    loop {
        // SAFETY: `wfi` is always valid in M-mode.
        unsafe { core::arch::asm!("wfi") };
    }
}
