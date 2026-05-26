//! Raw LPUART1 print primitives that bypass Tock's `kernel::debug!`.
//!
//! The chip-level LPUART driver is sync-polling: it calls
//! `transmitted_buffer` from inside the same stack as `transmit_buffer`,
//! which violates `UartDebugWriter::publish()`'s async-callback assumption
//! and leaves `output_buffer` permanently `None` after the first call.
//! Compounding that, `DEBUG_BUFFER_SPLIT = 64` truncates longer messages
//! even on the first lucky invocation. This module writes straight to
//! LPUART1's NS-aliased TDR — no buffer, no callback, no truncation.
//!
//! Register addresses (RM0438): LPUART1 NS base 0x40008000,
//! ISR 0x1C (TXE = bit 7), TDR 0x28.

const UART_BASE_NS: u32 = 0x4000_8000;
const ISR_OFFSET:   u32 = 0x1C;
const TDR_OFFSET:   u32 = 0x28;
const TXE_BIT:      u32 = 1 << 7;

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
    let base = UART_BASE_NS as *mut u32;
    unsafe {
        (
            base.add(TDR_OFFSET as usize / 4),
            base.add(ISR_OFFSET as usize / 4) as *const u32,
        )
    }
}

/// Print a string slice to LPUART1 NS, synchronously.
#[inline(never)]
pub fn print_str(s: &str) {
    let (tdr, isr) = uart_ptrs();
    for byte in s.bytes() {
        unsafe { send_byte(tdr, isr, byte); }
    }
}

/// Print a u32 as 8-digit uppercase hex.
#[inline(never)]
pub fn print_hex(val: u32) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let (tdr, isr) = uart_ptrs();
    for i in (0..8).rev() {
        let nibble = ((val >> (i * 4)) & 0xF) as usize;
        unsafe { send_byte(tdr, isr, HEX[nibble]); }
    }
}

/// Print a u32 as decimal (max 10 digits, no padding).
#[inline(never)]
pub fn print_u32(mut val: u32) {
    let (tdr, isr) = uart_ptrs();
    if val == 0 {
        unsafe { send_byte(tdr, isr, b'0'); }
        return;
    }
    // Build digits in reverse.
    let mut buf = [0u8; 10];
    let mut idx = 0;
    while val != 0 {
        buf[idx] = (val % 10) as u8 + b'0';
        val /= 10;
        idx += 1;
    }
    // Emit in correct order.
    while idx > 0 {
        idx -= 1;
        unsafe { send_byte(tdr, isr, buf[idx]); }
    }
}
