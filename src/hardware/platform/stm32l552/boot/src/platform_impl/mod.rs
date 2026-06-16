//! STM32L5 (L552 + L562) platform implementation — Secure side runtime.
//! # Scope and decomposition target
//! split the original 700-LOC `platform_impl.rs`
//! into four submodules:
//! - [`boot`] — clock + flash + PWR + MPU bring-up
//! - [`syscall_dispatch`] — SVC and SysTick trampolines (security + NS-MPU)
//! - [`dma`] — Dma channel reservation for the kernel-side ESS-miss path
//! - [`power`] — sleep / wakeup hooks (NS hand-off)
//! The four invariants below remain in force across all submodules.
//! # design baseline
//! ## SysTick preemption model
//! SysTick is the only interrupt enabled during enclave execution. The
//! handler in `_systick_handler` saves the enclave context to the per-EFB
//! save area in SRAM2 and returns to the NS host via the SVC #102
//! trampoline. The host is the scheduler; this kernel does not implement
//! one. `SYSTICK_RELOAD` in `secure_kernel.rs` and the matching `=N`
//! immediate literal in `arm/asm/startup.s::_svc_enter` MUST move
//! together — see `rcc.rs` docs for the post-PLL value.
//! ## Unprivileged PSP execution
//! Enclave code runs unprivileged-Thumb on PSP. PSP region is carved at
//! `0x3003_8000.. 0x3003_C000` (4 slots × 2 KB), kernel mode runs
//! privileged on MSP at `0x3003_C000.. 0x3003_DFF8`. The 4 PSP slots
//! support the demo's max of 4 concurrent enclaves; bumping the count
//! requires moving the kernel MSP ceiling too.
//! ## NSC veneers and Secure transition
//! NS callers hit NSC veneers in `arm/asm/nsc_veneers.s` which `SG` into
//! the `_imp` functions in `api_impl.rs`. The `_imp` functions ARE the
//! Secure-side API surface — do NOT bypass to call inner kernel functions
//! directly from NS. CJ4 of the threat model.
//! ## init_clocks ordering is load-bearing
//! See `drivers::rcc` module docs for the 7-step ordering. Inverting any
//! pair causes silent runtime corruption or hang. This file's
//! `init_clocks` mirrors that ordering verbatim.

use kernel::platform::PlatformBoot;

pub mod boot;
pub mod dma;
pub mod power;
pub mod syscall_dispatch;

pub struct Stm32l5Platform;

impl Stm32l5Platform {
    pub fn new() -> Self {
        Stm32l5Platform
    }
}

impl PlatformBoot for Stm32l5Platform {
    fn init_clocks(&self) {
        Stm32l5Platform::init_clocks_impl(self);
    }

    fn init_gpio(&self) {
        Stm32l5Platform::init_gpio_impl(self);
    }

    fn init_uart(&self) {
        Stm32l5Platform::init_uart_impl(self);
    }

    fn init_security(&self) {
        Stm32l5Platform::init_security_impl(self);
    }

    fn init_kernel(&self) {
        Stm32l5Platform::init_kernel_impl(self);
    }

    fn init_external_flash(&self) -> bool {
        Stm32l5Platform::init_external_flash_impl(self)
    }

    fn configure_untrusted_boot(&self) {
        Stm32l5Platform::configure_untrusted_boot_impl(self);
    }

    fn jump_to_untrusted(&self) -> ! {
        Stm32l5Platform::jump_to_untrusted_impl(self)
    }
}
