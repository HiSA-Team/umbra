//! Raw UART print primitives for exception handlers and early boot.
//! These functions use direct volatile pointer access to the UART peripheral,
//! bypassing the `Uart` driver. This is necessary in exception handlers where
//! the system may be in an inconsistent state and driver structs aren't available.

/// UART base address — USART1 on L562, LPUART1 on L552.
#[cfg(feature = "stm32l562")]
const UART_BASE: u32 = 0x40013800;
#[cfg(not(feature = "stm32l562"))]
const UART_BASE: u32 = 0x50008000;

const ISR_OFFSET: u32 = 0x1C;
const TDR_OFFSET: u32 = 0x28;
const TXE_BIT: u32 = 1 << 7;

#[inline(always)]
unsafe fn wait_txe(isr_ptr: *const u32) {
    while (isr_ptr.read_volatile() & TXE_BIT) == 0 {}
}

#[inline(always)]
unsafe fn send_byte(tdr_ptr: *mut u32, isr_ptr: *const u32, byte: u8) {
    wait_txe(isr_ptr);
    tdr_ptr.write_volatile(byte as u32);
}

#[inline(always)]
fn uart_ptrs() -> (*mut u32, *const u32) {
    let base = UART_BASE as *mut u32;
    unsafe {
        (
            base.add(TDR_OFFSET as usize / 4),
            base.add(ISR_OFFSET as usize / 4) as *const u32,
        )
    }
}

/// Print a string slice to UART.
#[inline(never)]
pub fn print_str(s: &str) {
    let (tdr, isr) = uart_ptrs();
    for byte in s.bytes() {
        unsafe {
            send_byte(tdr, isr, byte);
        }
    }
}

/// Print a u32 as 8-digit uppercase hex.
#[inline(never)]
pub fn print_hex(val: u32) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let (tdr, isr) = uart_ptrs();
    for i in (0..8).rev() {
        let nibble = ((val >> (i * 4)) & 0xF) as usize;
        unsafe {
            send_byte(tdr, isr, HEX[nibble]);
        }
    }
}

/// Print a byte slice as lowercase hex (two chars per byte).
#[cfg(feature = "boot_tests")]
#[inline(never)]
pub fn print_hex_bytes(data: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let (tdr, isr) = uart_ptrs();
    for &byte in data {
        unsafe {
            send_byte(tdr, isr, HEX[((byte >> 4) & 0xF) as usize]);
            send_byte(tdr, isr, HEX[(byte & 0xF) as usize]);
        }
    }
}

/// Print a byte slice over UART. Bounded — caller controls length.
/// Use this from NSC-veneer impls so a malicious NS-controlled pointer
/// cannot trigger an unbounded read (see threat model §5 and the NSC
/// veneer audit).
#[inline(never)]
pub fn print_bytes(bytes: &[u8]) {
    let (tdr, isr) = uart_ptrs();
    // SAFETY: `uart_ptrs()` returns the secure-resident UART TDR/ISR MMIO
    // addresses initialised by the boot path before any NSC call. The slice
    // length is caller-controlled; `send_byte` writes one byte at a time
    // with no internal indexing.
    unsafe {
        for &b in bytes {
            send_byte(tdr, isr, b);
        }
    }
}
