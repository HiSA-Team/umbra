//! Gpio trait — pin set/reset.
//! The minimum that captures both platforms' shape: drive a pin
//! HIGH or LOW. Mode configuration (input/output/alternate-function)
//! and port selection stay in the inherent driver API — they're
//! platform-specific enough that abstracting them now would lose
//! information.

pub trait Gpio {
    type Error: core::fmt::Debug;

    /// Drive the given pin to logic-1. Pin index is 0-15 on both L552
    /// and N657 platforms (port is implicit via the impl's identity).
    fn set_high(&mut self, pin: u32) -> Result<(), Self::Error>;

    /// Drive the given pin to logic-0.
    fn set_low(&mut self, pin: u32) -> Result<(), Self::Error>;
}
