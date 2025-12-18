// STM32L5xxxx UART Driver
// This driver supports for all the (LP)U(S)ART on the board.
// While U(S)ART and LPUART are two different section in the reference manual (RM0438),
// the registers are mostly the same.
// 
// LPUART1 is the Low Power UART connected to the ST-Link on the NUCLEO-L552ZE-Q board.
// This specific UART is mapped on GPIOG 7 (TX), 8(RX).
//
// WIP: The first draft of this driver will implement a minimal support for LPUART1,
// needed for communicating with the ST-Link.

// Crates
use peripheral_regs::*;

const LPUART1_BASE_ADDR: u32 = 0x50008000; // Secure
type UartRegisters = u32;

// Registers
const UART_CR1_BASE_OFFSET    : u32 = 0x00;
const UART_CR2_BASE_OFFSET    : u32 = 0x04;
const UART_CR3_BASE_OFFSET    : u32 = 0x08;
const UART_BRR_BASE_OFFSET    : u32 = 0x0C;
const UART_GTPR_BASE_OFFSET   : u32 = 0x10; // Reserved in LPUART
const UART_RTOR_BASE_OFFSET   : u32 = 0x14; // Reserved in LPUART
const UART_RQR_BASE_OFFSET    : u32 = 0x18;
const UART_ISR_BASE_OFFSET    : u32 = 0x1C;
const UART_ICR_BASE_OFFSET    : u32 = 0x20;
const UART_RDR_BASE_OFFSET    : u32 = 0x24;
const UART_TDR_BASE_OFFSET    : u32 = 0x28;
const UART_PRESC_BASE_OFFSET  : u32 = 0x2C;

pub struct Uart {
    regs: &'static mut UartRegisters, 
}

impl Uart {
    pub fn new_lpuart1(baud: u32) -> Self {
        let lpuart = Self::get_raw_lpuart1();
        
        // Initialize on RCC

        lpuart
    }

    fn get_raw_lpuart1() -> Self {
        let regs = unsafe { &mut *(LPUART1_BASE_ADDR as *mut UartRegisters) };
        Self { regs }
    }
}
