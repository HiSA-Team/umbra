//! Raw UART print primitives for exception handlers and early boot.
//!
//! Direct volatile pointer access to USART1 on N657, bypassing the
//! Uart driver. Necessary in exception handlers where the system may
//! be in an inconsistent state and driver structs aren't available.
//!
//! USART1 base: 0x52001000 (Secure)

// Secure alias — Boot ROM may leave USART1 marked Secure in RIFSC SECCFGR.
// Secure alias works regardless of SECCFGR state (we run Secure Privileged).
const UART_BASE: u32 = 0x5200_1000;

const ISR_OFFSET: u32 = 0x1C;
const TDR_OFFSET: u32 = 0x28;
const TXE_BIT: u32 = 1 << 7;
const TC_BIT:  u32 = 1 << 6;

#[inline(always)]
unsafe fn wait_txe(isr_ptr: *const u32) {
    while (isr_ptr.read_volatile() & TXE_BIT) == 0 {}
}

#[inline(always)]
unsafe fn wait_tc(isr_ptr: *const u32) {
    while (isr_ptr.read_volatile() & TC_BIT) == 0 {}
}

#[inline(always)]
unsafe fn send_byte(tdr_ptr: *mut u32, isr_ptr: *const u32, byte: u8) {
    wait_txe(isr_ptr);
    tdr_ptr.write_volatile(byte as u32);
    // Wait for TC (Transfer Complete) — byte fully shifted out on wire.
    // Without this, the last byte of a print (e.g., trailing '\n') can be
    // truncated when the caller enters `wfi` immediately afterward, since
    // the byte is still in the shift register. Mirrors the Secure-side
    // `s_putc` pattern in main.rs.
    wait_tc(isr_ptr);
}

#[inline(always)]
fn uart_ptrs() -> (*mut u32, *const u32) {
    let base = UART_BASE as *mut u32;
    unsafe {
        (base.add(TDR_OFFSET as usize / 4), base.add(ISR_OFFSET as usize / 4) as *const u32)
    }
}

/// Print a string slice to UART.
/// Uses while loop instead of iterator to avoid core::iter::range panics.
#[inline(never)]
pub fn print_str(s: &str) {
    let (tdr, isr) = uart_ptrs();
    let bytes = s.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        unsafe { send_byte(tdr, isr, bytes[i]); }
        i += 1;
    }
}

/// Print a u32 as 8-digit uppercase hex.
/// Uses while loop instead of Range::rev() to avoid core::iter::range panics.
#[inline(never)]
pub fn print_hex(val: u32) {
    let (tdr, isr) = uart_ptrs();
    let mut shift: i32 = 28;
    while shift >= 0 {
        let nibble = ((val >> (shift as u32)) & 0xF) as u8;
        let ch = if nibble < 10 { b'0' + nibble } else { b'A' + nibble - 10 };
        unsafe { send_byte(tdr, isr, ch); }
        shift -= 4;
    }
}

/// Print a byte slice as lowercase hex (two chars per byte).
#[cfg(feature = "boot_tests")]
#[inline(never)]
pub fn print_hex_bytes(data: &[u8]) {
    let (tdr, isr) = uart_ptrs();
    let mut i: usize = 0;
    while i < data.len() {
        let byte = data[i];
        let hi = (byte >> 4) & 0xF;
        let lo = byte & 0xF;
        let ch_hi = if hi < 10 { b'0' + hi } else { b'a' + hi - 10 };
        let ch_lo = if lo < 10 { b'0' + lo } else { b'a' + lo - 10 };
        unsafe {
            send_byte(tdr, isr, ch_hi);
            send_byte(tdr, isr, ch_lo);
        }
        i += 1;
    }
}

/// Print a null-terminated C string. Used by the NSC debug_print API.
#[inline(never)]
pub fn print_cstr(ptr: *const u8) {
    if ptr.is_null() { return; }
    let (tdr, isr) = uart_ptrs();
    let mut curr = ptr;
    unsafe {
        while *curr != 0 {
            send_byte(tdr, isr, *curr);
            curr = curr.add(1);
        }
    }
}
