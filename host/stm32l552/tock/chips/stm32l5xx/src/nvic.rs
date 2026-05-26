//! IRQ numbers for STM32L552/L562 (RM0438 Table 76).

/// LPUART1 global interrupt — published for future interrupt-driven LPUART
/// or board-side NVIC programming. The current driver is polling-mode.
#[allow(dead_code)]
pub const LPUART1: u32 = 70;
