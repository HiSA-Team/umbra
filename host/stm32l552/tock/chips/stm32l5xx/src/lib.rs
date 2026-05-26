//! Minimal STM32L5xx chip layer used by the Tock host port.
//!
//! Implemented modules:
//!   - [`rcc`]   — HSI16 init, peripheral clock gates, LSE startup, CCIPR1
//!   - [`gpio`]  — GPIOG alternate-function & output control (PG7/PG8 for LPUART1)
//!   - [`lpuart`] — LPUART1 polling transmit + Tock `Transmit` HIL impl
//!   - [`nvic`]  — IRQ number constants

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

pub mod gpio;
pub mod lpuart;
pub mod nvic;
pub mod rcc;
