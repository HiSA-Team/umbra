//! Console UART (LPUART1 on L552, USART1 on L562), Secure via GTZC TZSC.
//! RX is interrupt-driven into `CONSOLE` (`kernel::common::uart_rx`), read by:
//! - the NS host, default owner: `umbra_uart_read_imp` NSC veneer (slot 9);
//! - enclaves: `svc #3` (startup.s `_svc_uart`), opcode in r0.

use super::arg_validation::ns_range_ok;
use kernel::common::uart_rx::{ConsoleUart, Owner};

#[cfg(feature = "stm32l562")]
const UART_BASE: u32 = 0x5001_3800;
#[cfg(not(feature = "stm32l562"))]
const UART_BASE: u32 = 0x5000_8000;
const UART_ISR: u32 = 0x1C;
const UART_ICR: u32 = 0x20;
const UART_RDR: u32 = 0x24;
const UART_TDR: u32 = 0x28;
const ISR_ORE: u32 = 1 << 3;
const ISR_RXFNE: u32 = 1 << 5;
const ISR_TXFNF: u32 = 1 << 7;
const ICR_ORECF: u32 = 1 << 3;

/// Per-byte RX timeout of the NS read (poll iterations): ~250 ms measured on
/// L562 at the workspace's opt-level=0, far longer than 1 ms/byte at 9600.
const RX_TIMEOUT_SPINS: u32 = 100_000;

static mut CONSOLE: ConsoleUart = ConsoleUart::new();

/// The UART IRQ shares priority 0 with SVC, so only Thread-mode callers (the
/// NS veneer) could be preempted; masking is cheap, so every caller masks.
fn with_console<R>(f: impl FnOnce(&mut ConsoleUart) -> R) -> R {
    // SAFETY: interrupts are masked, so this is the only live reference.
    cortex_m::interrupt::free(|_| f(unsafe { &mut *(&raw mut CONSOLE) }))
}

fn reg(off: u32) -> *mut u32 {
    (UART_BASE + off) as *mut u32
}

/// Console UART RX IRQ (IRQ 61 USART1 / IRQ 66 LPUART1, startup.s): drain
/// the FIFO. A latched ORE re-raises the IRQ forever unless cleared.
#[no_mangle]
pub extern "C" fn Console_UART_Handler() {
    with_console(|c| loop {
        // SAFETY: fixed MMIO of the console UART, Secure alias.
        let isr = unsafe { reg(UART_ISR).read_volatile() };
        if isr & ISR_ORE != 0 {
            unsafe { reg(UART_ICR).write_volatile(ICR_ORECF) };
        }
        if isr & ISR_RXFNE == 0 {
            break;
        }
        c.rx_push(unsafe { reg(UART_RDR).read_volatile() } as u8);
    });
}

fn tx_byte(b: u8) {
    // SAFETY: fixed MMIO of the console UART, Secure alias.
    unsafe {
        while reg(UART_ISR).read_volatile() & ISR_TXFNF == 0 {}
        reg(UART_TDR).write_volatile(b as u32);
    }
}

/// `svc #3` from an enclave. `frame` is its stacked r0..r3: r0 = opcode,
/// r1 = argument; the result replaces stacked r0. The caller is always the
/// current enclave, never an argument.
///
/// # Safety
/// Called only by startup.s `_svc_uart` with the SVC exception frame.
#[no_mangle]
pub unsafe extern "C" fn umbra_svc_uart(frame: *mut u32) {
    let (op, arg) = (frame.read(), frame.add(1).read());
    let result = match crate::secure_kernel::Kernel::get().and_then(|k| k.current_enclave_id) {
        Some(id) => svc_uart_op(id, op, arg),
        None => u32::MAX,
    };
    frame.write(result);
}

fn svc_uart_op(id: u32, op: u32, arg: u32) -> u32 {
    let me = Owner::Enclave(id);
    match op {
        0 => with_console(|c| c.claim(id).map_or(1, |_| 0)),
        1 => with_console(|c| c.release(id).map_or(1, |_| 0)),
        2 => with_console(|c| c.getc(me)).map_or(u32::MAX, u32::from),
        3 => {
            if !with_console(|c| c.may_transmit(me)) {
                return 1;
            }
            tx_byte(arg as u8); // outside the mask: TX may wait ~1 ms
            0
        }
        4 => with_console(|c| c.overflow(me)).unwrap_or(u32::MAX),
        _ => u32::MAX,
    }
}

/// Enclave `id` stopped for good (terminated or faulted): the UART goes back
/// to the NS host with the buffer flushed.
pub fn console_owner_gone(id: u32) {
    with_console(|c| c.owner_gone(id));
}

/// r0 = NS buffer ptr, r1 = length. Returns the COUNT of bytes read
/// (< len on per-byte timeout, 0 on a bad pointer or while an enclave owns
/// the UART).
#[no_mangle]
#[link_section = ".umbra_api_implementation"]
pub extern "C" fn umbra_uart_read_imp(ptr: u32, len: u32) -> u32 {
    if !ns_range_ok(ptr, len) || with_console(|c| c.owner()) != Owner::Ns {
        return 0;
    }
    let mut i = 0u32;
    'bytes: while i < len {
        let mut spins = 0;
        let b = loop {
            if let Some(b) = with_console(|c| c.getc(Owner::Ns)) {
                break b;
            }
            spins += 1;
            if spins == RX_TIMEOUT_SPINS {
                break 'bytes; // timeout: partial count lets the relay resync
            }
        };
        // SAFETY: [ptr, ptr+len) range-checked into NS SRAM above.
        unsafe { core::ptr::write_volatile((ptr as *mut u8).add(i as usize), b) };
        i += 1;
    }
    i
}
