//! Uart trait — minimal serial output.
//! Just enough surface for a platform-agnostic logger: write a byte
//! slice. Per-platform driver API keeps the configuration knobs
//! (baudrate, parity, etc.); the trait targets the *use* not the
//! *setup*.
//! scope: `write_bytes` only. Read-side, line-discipline,
//! and flow control are + as needed.

pub trait Uart {
    type Error: core::fmt::Debug;

    /// Write `bytes` to the UART, blocking until the TX FIFO accepts
    /// them. UTF-8 callers can pre-encode and pass the &str's bytes.
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;
}
