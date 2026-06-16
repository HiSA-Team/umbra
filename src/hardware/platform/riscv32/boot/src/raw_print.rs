//! Low-level UART output for the monitor (M-mode owns the UART).
//!
//! The 16550 driver implements the Umbra HAL [`umbra_hal::Uart`] trait — the
//! same trait the STM32L552/N657 platforms implement, so the monitor's
//! diagnostic output flows through the shared HAL surface rather than ad-hoc
//! MMIO. Only the monitor uses this; the U-mode host and S-mode enclave emit
//! output through the `debug_print` ecall instead.

use core::convert::Infallible;
use umbra_hal::Uart;

const UART0_BASE: usize = 0x1000_0000;
const REG_THR: usize = 0; // Transmit Holding Register (write)
const REG_LSR: usize = 5; // Line Status Register
const LSR_THRE: u8 = 0x20; // TX holding register empty

/// 16550-compatible UART at a fixed MMIO base (QEMU `virt`: `0x1000_0000`).
pub struct Ns16550 {
    base: *mut u8,
}

impl Ns16550 {
    /// # Safety
    /// `base` must be the MMIO base of a 16550 UART mapped for the current hart.
    pub const unsafe fn new(base: usize) -> Self {
        Ns16550 {
            base: base as *mut u8,
        }
    }

    fn putc(&mut self, byte: u8) {
        // SAFETY: `base` is a valid 16550 MMIO region per the `new` contract.
        unsafe {
            while core::ptr::read_volatile(self.base.add(REG_LSR)) & LSR_THRE == 0 {}
            core::ptr::write_volatile(self.base.add(REG_THR), byte);
        }
    }
}

impl Uart for Ns16550 {
    type Error = Infallible;

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        for &b in bytes {
            self.putc(b);
        }
        Ok(())
    }
}

fn uart() -> Ns16550 {
    // SAFETY: UART0_BASE is the 16550 MMIO base; M-mode has access (no MML).
    unsafe { Ns16550::new(UART0_BASE) }
}

/// Write one byte.
pub fn putc(byte: u8) {
    let _ = uart().write_bytes(&[byte]);
}

/// Write a byte slice.
pub fn puts(bytes: &[u8]) {
    let _ = uart().write_bytes(bytes);
}

/// Write a string (mirrors the STM32 `raw_print::print_str`).
pub fn print_str(s: &str) {
    puts(s.as_bytes());
}

/// Write a `tag=0xXXXXXXXX` diagnostic line (used by the fault handler).
pub fn put_hex_line(tag: u8, value: u32) {
    let mut u = uart();
    let _ = u.write_bytes(&[tag, b'=']);
    let mut buf = [0u8; 8];
    for (i, slot) in buf.iter_mut().enumerate() {
        let nib = ((value >> ((7 - i) * 4)) & 0xF) as u8;
        *slot = if nib < 10 {
            b'0' + nib
        } else {
            b'a' + (nib - 10)
        };
    }
    let _ = u.write_bytes(&buf);
    let _ = u.write_bytes(b"\n");
}
