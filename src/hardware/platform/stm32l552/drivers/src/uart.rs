// Author: Giovanni Spera <giovanni.spera2011@libero.it>
// STM32L5xxxx UART Driver
#![allow(dead_code)]
// This driver supports for all the (LP)U(S)ART on the board.
// While U(S)ART and LPUART are two different section in the reference manual (RM0438),
// the registers are mostly the same.
// LPUART1 is the Low Power UART connected to the ST-Link on the NUCLEO-L552ZE-Q board.
// This specific UART is mapped on GPIOG 7 (TX), 8(RX).
// Currently provides minimal support for LPUART1 (L552) and USART1 (L562),
// needed for communicating with the ST-Link.

// Crates
use crate::gpio;
use crate::gpio::Gpio;
#[cfg(not(feature = "stm32l562"))]
use crate::pwr::Pwr;
use crate::rcc;
use crate::rcc::Rcc;
use peripheral_regs::{MmioAccess, RealMmio};

const LPUART1_BASE_ADDR: u32 = 0x50008000; // Secure
const USART1_BASE_ADDR: u32 = 0x40013800; // APB2

// Registers
const UART_CR1_BASE_OFFSET: u32 = 0x00;
const UART_CR2_BASE_OFFSET: u32 = 0x04;
const UART_CR3_BASE_OFFSET: u32 = 0x08;
const UART_BRR_BASE_OFFSET: u32 = 0x0C;
const UART_GTPR_BASE_OFFSET: u32 = 0x10; // Reserved in LPUART1
const UART_RTOR_BASE_OFFSET: u32 = 0x14; // Reserved in LPUART1
const UART_RQR_BASE_OFFSET: u32 = 0x18;
const UART_ISR_BASE_OFFSET: u32 = 0x1C;
const UART_ICR_BASE_OFFSET: u32 = 0x20;
const UART_RDR_BASE_OFFSET: u32 = 0x24;
const UART_TDR_BASE_OFFSET: u32 = 0x28;
const UART_PRESC_BASE_OFFSET: u32 = 0x2C;

/// Generic over the MMIO backend so host tests
/// can inject [`umbra_pal_test::mmio::MmioHandle`]. Default `M = RealMmio`
/// keeps every existing `Uart::new_lpuart1_and_configure(...)` call site
/// unchanged at the source level.
pub struct Uart<M: MmioAccess = RealMmio> {
    mmio: M,
}

impl Uart<RealMmio> {
    fn new_lpuart1() -> Self {
        Self {
            mmio: RealMmio::new(LPUART1_BASE_ADDR),
        }
    }

    fn new_usart1() -> Self {
        Self {
            mmio: RealMmio::new(USART1_BASE_ADDR),
        }
    }

    pub fn new_lpuart1_and_configure(_baud: u32) -> Self {
        // STM32L562E-DK uses USART1 (PA9/PA10) for VCP
        #[cfg(feature = "stm32l562")]
        {
            let usart = Self::new_usart1();
            let rcc = Rcc::new();
            rcc.enable_clock(rcc::peripherals::GPIOA);
            rcc.enable_clock(rcc::peripherals::USART1);

            // PA9 (TX) / PA10 (RX) routed via AF7.
            let gpio = Gpio::new(gpio::Port::GpioA);
            gpio.enable_clock();
            gpio.set_mode(9, gpio::PinMode::AlternateFunction);
            gpio.set_mode(10, gpio::PinMode::AlternateFunction);
            gpio.set_alternate_function(9, 7);
            gpio.set_alternate_function(10, 7);

            // USART1 kernel clock routed to HSI16 (16 MHz) in init_clocks,
            // making BRR independent of SYSCLK.
            // BRR = fck / baud = 16_000_000 / 9600 = 1666.66 → 1667
            usart.set_baud(1667);

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
}

impl<M: MmioAccess> Uart<M> {
    /// Constructor for host-side tests — accepts any `MmioAccess` backend.
    /// On firmware build, callers use `Uart::new_lpuart1_and_configure(...)`
    /// which monomorphises to `Uart<RealMmio>` and inlines the volatile
    /// accesses.
    #[allow(dead_code)]
    pub fn new_with_mmio(mmio: M) -> Self {
        Self { mmio }
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
            let isr = self.mmio.read(UART_ISR_BASE_OFFSET);
            let is_fifo_not_empty = (isr >> 7) & 1;

            if is_fifo_not_empty == 1 {
                break;
            }
        }

        self.mmio.write(UART_TDR_BASE_OFFSET, ch as u32);
    }

    pub fn enable(&self) {
        self.mmio.set_bit(UART_CR1_BASE_OFFSET, 0);
    }

    pub fn enable_transmit(&self) {
        self.mmio.set_bit(UART_CR1_BASE_OFFSET, 3);
    }

    pub fn set_baud(&self, baud: u16) {
        self.mmio.write(UART_BRR_BASE_OFFSET, baud as u32);
    }
}

// umbra_hal::Uart adapter.
#[derive(Debug)]
pub enum UartError {
    Unreachable,
}

impl<M: MmioAccess> umbra_hal::Uart for Uart<M> {
    type Error = UartError;

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        for &b in bytes {
            self.write_ch(b as char);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umbra_pal_test::mmio::{MmioMem, MmioOp};

    /// Verifies write_ch polls ISR.TXE (bit 7) until the TX FIFO is ready
    /// and then writes the byte to TDR. We preload ISR with bit 7 set so
    /// the poll loop exits on the first read.
    #[test]
    fn write_ch_polls_isr_then_writes_tdr() {
        let mem = MmioMem::new(LPUART1_BASE_ADDR);
        // Preload ISR with TXE (bit 7) set so the poll terminates.
        mem.preload_register(UART_ISR_BASE_OFFSET, 1 << 7);

        let uart = Uart::<_>::new_with_mmio(mem.handle());
        uart.write_ch('A');

        // Expected sequence: one Read of ISR, then one Write of 'A' to TDR.
        let log = mem.write_log();
        assert_eq!(log.len(), 2);
        match log[0] {
            MmioOp::Read { addr, value } => {
                assert_eq!(addr, LPUART1_BASE_ADDR + UART_ISR_BASE_OFFSET);
                assert_eq!((value >> 7) & 1, 1);
            }
            _ => panic!("expected Read of ISR at position 0, got {:?}", log[0]),
        }
        match log[1] {
            MmioOp::Write { addr, value } => {
                assert_eq!(addr, LPUART1_BASE_ADDR + UART_TDR_BASE_OFFSET);
                assert_eq!(value, 'A' as u32);
            }
            _ => panic!("expected Write of TDR at position 1, got {:?}", log[1]),
        }
    }

    /// Verifies set_baud writes the requested divisor to BRR. Uses 0x369
    /// (the LPUART1 LSE→9600-baud divisor used by the firmware path), to
    /// pin behaviour to the canonical configure-time value.
    #[test]
    fn set_baud_writes_divisor_to_brr() {
        let mem = MmioMem::new(LPUART1_BASE_ADDR);
        let uart = Uart::<_>::new_with_mmio(mem.handle());
        uart.set_baud(0x369);

        let log = mem.write_log();
        assert_eq!(log.len(), 1);
        match log[0] {
            MmioOp::Write { addr, value } => {
                assert_eq!(addr, LPUART1_BASE_ADDR + UART_BRR_BASE_OFFSET);
                assert_eq!(value, 0x369);
            }
            _ => panic!("expected single Write to BRR, got {:?}", log[0]),
        }
    }
}
