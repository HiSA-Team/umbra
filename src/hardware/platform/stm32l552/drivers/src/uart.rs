// Author: Giovanni Spera  <giovanni.spera2011@libero.it>
//
// STM32L5xxxx UART Driver
#![allow(dead_code)]
// This driver supports for all the (LP)U(S)ART on the board.
// While U(S)ART and LPUART are two different section in the reference manual (RM0438),
// the registers are mostly the same.
// 
// LPUART1 is the Low Power UART connected to the ST-Link on the NUCLEO-L552ZE-Q board.
// This specific UART is mapped on GPIOG 7 (TX), 8(RX).
//
// Currently provides minimal support for LPUART1 (L552) and USART1 (L562),
// needed for communicating with the ST-Link.

// Crates
use peripheral_regs::*;
use crate::rcc::Rcc;
use crate::rcc;
#[cfg(not(feature = "stm32l562"))]
use crate::pwr::Pwr;
use crate::gpio::Gpio;
use crate::gpio;

const LPUART1_BASE_ADDR: u32 = 0x50008000; // Secure
const USART1_BASE_ADDR:  u32 = 0x40013800; // APB2
type UartRegisters = u32;

// Registers
const UART_CR1_BASE_OFFSET    : u32 = 0x00;
const UART_CR2_BASE_OFFSET    : u32 = 0x04;
const UART_CR3_BASE_OFFSET    : u32 = 0x08;
const UART_BRR_BASE_OFFSET    : u32 = 0x0C;
const UART_GTPR_BASE_OFFSET   : u32 = 0x10; // Reserved in LPUART1
const UART_RTOR_BASE_OFFSET   : u32 = 0x14; // Reserved in LPUART1
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
    fn new_lpuart1() -> Self {
        let regs = unsafe { &mut *(LPUART1_BASE_ADDR as *mut UartRegisters) };
        Self { regs }
    }

    fn new_usart1() -> Self {
        let regs = unsafe { &mut *(USART1_BASE_ADDR as *mut UartRegisters) };
        Self { regs }
    }

    pub fn new_lpuart1_and_configure(_baud: u32) -> Self {
        // STM32L562E-DK uses USART1 (PA9/PA10) for VCP
        #[cfg(feature = "stm32l562")]
        {
            let usart = Self::new_usart1();
            let rcc = Rcc::new();
            
            // Enable Clocks
            rcc.enable_clock(rcc::peripherals::GPIOA);
            rcc.enable_clock(rcc::peripherals::USART1);
            
            // Configure GPIOA PA9(TX) PA10(RX) to AF7
            let gpio = Gpio::new(gpio::Port::GpioA);
            gpio.enable_clock(); // Ensure redundancy
            gpio.set_mode(9, gpio::PinMode::AlternateFunction);
            gpio.set_mode(10, gpio::PinMode::AlternateFunction);
            gpio.set_alternate_function(9, 7);
            gpio.set_alternate_function(10, 7);
            
            // Configure Baud Rate
            // Assuming default MSI 4 MHz clock for now
            // USART1 on APB2. 
            // BRR = fck / baud = 4000000 / 9600 = 416.66 -> 417
            usart.set_baud(417); 
            
            usart.enable_transmit();
            usart.enable();
            
            usart
        }

        // Nucleo-L552ZE-Q uses LPUART1 (PG7/PG8) for VCP
        #[cfg(not(feature = "stm32l562"))]
        {
            let lpuart = Self::new_lpuart1();
            let rcc = Rcc::new();
            
            // Initialize GPIOG
            rcc.enable_clock(rcc::peripherals::LPUART1);
            rcc.enable_clock(rcc::peripherals::GPIOG);
            
            // Configure GPIOG
            let gpio = Gpio::new(gpio::Port::GpioG);
            gpio.enable_clock();
            gpio.set_mode(7, gpio::PinMode::AlternateFunction);
            gpio.set_mode(8, gpio::PinMode::AlternateFunction);
            gpio.set_alternate_function(7, 8);
            gpio.set_alternate_function(8, 8);
            
            // Configure PWR
            let pwr = Pwr::new();
            pwr.enable_clock();

            // Select clock LSE
            rcc.enable_lse();
            rcc.select_lse_to_lpuart1();
            lpuart.enable_transmit();
            
            lpuart.set_baud(0x369); // 9600 with 32768Hz LSE
            lpuart.enable_transmit();
            lpuart.enable();

            lpuart
        }
    }
    
    pub fn write(&self, string: &str) {
        for ch in string.chars() {
            self.write_ch(ch);
        }
    }

    /// Write a single byte as two lowercase hex nibbles (no prefix, no
    /// separator).
    pub fn write_hex_byte(&self, b: u8) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        self.write_ch(HEX[(b >> 4) as usize] as char);
        self.write_ch(HEX[(b & 0x0f) as usize] as char);
    }

    pub fn write_ch(&self, ch: char) {
        loop {
            let isr = unsafe { read_register(self.regs, UART_ISR_BASE_OFFSET) };
            let is_fifo_not_empty = (isr >> 7) & 1;

            if is_fifo_not_empty == 1 {
                break
            }
        }

        unsafe { write_register(self.regs, UART_TDR_BASE_OFFSET, ch as u32) };
    }
    
    pub fn enable(&self) {
        unsafe { set_register_bit(self.regs, UART_CR1_BASE_OFFSET, 0) };
    }

    pub fn enable_transmit(&self) {
        unsafe { set_register_bit(self.regs, UART_CR1_BASE_OFFSET, 3) };
    }

    pub fn set_baud(&self, baud: u16) {
        unsafe { write_register(self.regs, UART_BRR_BASE_OFFSET, baud as u32) };
    }
}
