//! `umbra_uart_read_imp` NSC veneer (slot 9, same ABI as N657).
//! Reads raw bytes from the Secure console UART (LPUART1 on L552, USART1 on
//! L562) into a range-checked NS buffer. RE is enabled in
//! `Uart::new_lpuart1_and_configure`.

use super::arg_validation::ns_range_ok;

#[cfg(feature = "stm32l562")]
const UART_BASE: u32 = 0x4001_3800;
#[cfg(not(feature = "stm32l562"))]
const UART_BASE: u32 = 0x5000_8000;
const UART_ISR: u32 = 0x1C;
const UART_ICR: u32 = 0x20;
const UART_RDR: u32 = 0x24;
const ISR_RXNE: u32 = 1 << 5;
const ISR_ORE: u32 = 1 << 3;
const ICR_ORECF: u32 = 1 << 3;

/// Per-byte RX timeout (poll iterations). At 110 MHz this is ~100 ms, far
/// longer than the ~1 ms between bytes at 9600 baud.
const RX_TIMEOUT_SPINS: u32 = 2_000_000;

/// Poll RXNE with a timeout, clearing a latched overrun (ORE blocks further
/// RXNE). Returns the byte or `None` on timeout.
fn uart_rx_byte_timeout() -> Option<u8> {
    // SAFETY: fixed console-UART MMIO owned by the Secure world.
    unsafe {
        for _ in 0..RX_TIMEOUT_SPINS {
            let isr = core::ptr::read_volatile((UART_BASE + UART_ISR) as *const u32);
            if isr & ISR_ORE != 0 {
                core::ptr::write_volatile((UART_BASE + UART_ICR) as *mut u32, ICR_ORECF);
            }
            if isr & ISR_RXNE != 0 {
                return Some(core::ptr::read_volatile((UART_BASE + UART_RDR) as *const u32) as u8);
            }
        }
    }
    None
}

/// r0 = NS buffer ptr, r1 = length. Returns the COUNT of bytes read
/// (< len on per-byte timeout, 0 on a bad pointer).
#[no_mangle]
#[link_section = ".umbra_api_implementation"]
pub extern "C" fn umbra_uart_read_imp(ptr: u32, len: u32) -> u32 {
    if !ns_range_ok(ptr, len) {
        return 0;
    }
    let mut i = 0u32;
    while i < len {
        let Some(b) = uart_rx_byte_timeout() else {
            break;
        };
        // SAFETY: [ptr, ptr+len) range-checked into NS SRAM above.
        unsafe { core::ptr::write_volatile((ptr as *mut u8).add(i as usize), b) };
        i += 1;
    }
    i
}
