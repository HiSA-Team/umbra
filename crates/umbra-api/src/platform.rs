//! `PlatformBoot` trait — top-level boot-sequence contract.
//! Moved here () from `src/kernel/src/platform/mod.rs`.
//! The kernel re-exports it for backwards compatibility during the migration.
//! Each method corresponds to an initialization phase in `secure_boot()`:
//! init_clocks → init_gpio → init_uart → init_security → init_kernel
//! → init_external_flash → configure_untrusted_boot → jump_to_untrusted

pub trait PlatformBoot {
    /// Initialize RCC clocks for peripherals used during boot.
    fn init_clocks(&self);

    /// Configure board-specific GPIO (LEDs, debug pins).
    fn init_gpio(&self);

    /// Initialize and return the debug UART. The returned handle is
    /// used for diagnostic printing throughout the boot sequence.
    fn init_uart(&self);

    /// Configure SAU regions, GTZC/RISAF memory firewall, SHCSR fault
    /// enables, and MPU. This is the security-critical initialization.
    fn init_security(&self);

    /// Initialize crypto engines (HASH + AES) and the Umbra kernel.
    fn init_kernel(&self);

    /// Initialize external flash and on-the-fly decryption if present.
    /// Returns `true` if external flash is available and configured.
    fn init_external_flash(&self) -> bool;

    /// Prepare the hand-off to the untrusted world. On ARM TrustZone this
    /// disables Secure SysTick and sets VTOR_NS for the NS host; on RISC-V it
    /// stages the PMP grants and the U-mode host entry.
    fn configure_untrusted_boot(&self);

    /// Transfer control to the untrusted world; does not return. ARM: branch to
    /// the Non-Secure world. RISC-V: `mret` into the U-mode host.
    fn jump_to_untrusted(&self) -> !;
}
