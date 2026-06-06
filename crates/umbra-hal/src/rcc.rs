//! Rcc trait — reset & clock control surface.
//! # Scope
//! Forward-looking trait. Today, RCC operations are called from
//! per-platform boot code (`platform_impl.rs::init_clocks`) and the
//! kernel itself doesn't touch RCC, so the trait isn't yet
//! load-bearing. The minimum that captures both platforms' shape:
//! `init_sysclk_pll()` for the production PLL bring-up sequence.
//! Channel enables, kernel-clock selection, peripheral resets — those
//! are platform-specific knobs that stay in the inherent driver API.
//! When the kernel becomes host-buildable, the trait can grow to
//! cover more (e.g. for memory-platform timing tests). Until then,
//! one method is enough for the kernel-side use.

pub trait Rcc {
    type Error: core::fmt::Debug;

    /// Bring SYSCLK from reset speed to the platform's production PLL
    /// frequency. The exact ordering (PWR → FLASH latency → HSI → PLL
    /// → switch) is platform-specific and lives in the inherent driver
    /// (see `drivers::rcc` module docs on each platform); the trait
    /// just exposes the unified "go fast" verb.
    fn init_sysclk_pll(&mut self) -> Result<(), Self::Error>;
}
