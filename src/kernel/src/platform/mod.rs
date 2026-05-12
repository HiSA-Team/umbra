//! Platform abstraction layer.
//!
//! Each target platform (STM32L552, STM32N657, ...) implements these
//! traits to provide hardware-specific initialization and services.

/// Top-level boot sequence. Each method corresponds to an
/// initialization phase in `secure_boot()`.
pub trait PlatformBoot {
    /// Initialize RCC clocks for peripherals used during boot.
    fn init_clocks(&self);

    /// Configure board-specific GPIO (LEDs, debug pins).
    fn init_gpio(&self);

    /// Initialize and return the debug UART.  The returned handle is
    /// used for diagnostic printing throughout the boot sequence.
    fn init_uart(&self);

    /// Configure SAU regions, GTZC/RISAF memory firewall, SHCSR fault
    /// enables, and MPU.  This is the security-critical initialization.
    fn init_security(&self);

    /// Initialize crypto engines (HASH + AES) and the Umbra kernel.
    fn init_kernel(&self);

    /// Initialize external flash and on-the-fly decryption if present.
    /// Returns `true` if external flash is available and configured.
    fn init_external_flash(&self) -> bool;

    /// Disable Secure SysTick and set VTOR_NS for the NS host.
    fn configure_ns_boot(&self);

    /// Branch to the Non-Secure world.  Does not return.
    fn jump_to_ns(&self) -> !;
}
