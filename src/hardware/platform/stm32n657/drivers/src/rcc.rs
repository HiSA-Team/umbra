//! RCC driver for STM32N657 — Reset and Clock Control
//! Base address: 0x56028000 (Secure), 0x46028000 (NS)
//!
//! Register offsets from RM0486:
//!   AHB3ENR  = 0x258  (crypto: RNG=0, HASH=1, CRYP=2, SAES=4, PKA=8, RIFSC=9)
//!   AHB4ENR  = 0x25C  (GPIO A-Q + PWR + CRC)
//!   APB2ENR  = 0x26C  (USART1=4)
//!
//! Note: USART1 kernel clock = 150 MHz (IC mux from PLL), NOT PCLK2.
//!       SYSCLK = HSI = 64 MHz but peripheral clocks use separate IC muxes.

use peripheral_regs::{read_register, write_register};

// Secure alias — works regardless of RIFSC SECCFGR state.
const RCC_BASE: *const u32 = 0x5602_8000 as *const u32;
const CR_OFFSET: u32 = 0x00;
const CFGR1_OFFSET: u32 = 0x1C;
const AHB3ENR_OFFSET: u32 = 0x258;
const AHB4ENR_OFFSET: u32 = 0x25C;
const APB2ENR_OFFSET: u32 = 0x26C;
const AHB5ENR_OFFSET: u32 = 0x260;

pub struct Rcc {
    regs: *const u32,
}

impl Rcc {
    pub fn new() -> Self {
        Rcc { regs: RCC_BASE }
    }

    /// Force system clock back to HSI 64 MHz.
    ///
    /// The Boot ROM may have switched to PLL at a higher frequency.
    /// We need a known clock to calculate UART BRR correctly.
    pub fn force_hsi(&self) {
        unsafe {
            // Ensure HSI is ON (CR bit 0 = HSION)
            let cr = read_register(self.regs, CR_OFFSET);
            write_register(self.regs, CR_OFFSET, cr | 1);

            // Wait for HSI ready (CR bit 2 = HSIRDY)
            while read_register(self.regs, CR_OFFSET) & (1 << 2) == 0 {}

            // Switch system clock to HSI: CFGR1 SW[1:0] = 00
            let cfgr1 = read_register(self.regs, CFGR1_OFFSET);
            write_register(self.regs, CFGR1_OFFSET, cfgr1 & !0x3);

            // Wait for SWS[1:0] = 00 (HSI selected as system clock)
            while read_register(self.regs, CFGR1_OFFSET) & (0x3 << 3) != 0 {}
        }
    }

    /// Enable a clock bit in the AHB3ENR register (crypto: HASH, CRYP, RNG, SAES, PKA).
    pub fn enable_ahb3_clock(&self, bit: u8) {
        unsafe {
            let val = read_register(self.regs, AHB3ENR_OFFSET);
            write_register(self.regs, AHB3ENR_OFFSET, val | (1 << bit));
        }
    }

    /// Enable a clock bit in the AHB4ENR register (GPIO ports + PWR + CRC).
    pub fn enable_ahb4_clock(&self, bit: u8) {
        unsafe {
            let val = read_register(self.regs, AHB4ENR_OFFSET);
            write_register(self.regs, AHB4ENR_OFFSET, val | (1 << bit));
        }
    }

    /// Enable a clock bit in the APB2ENR register (USART1, etc.).
    pub fn enable_apb2_clock(&self, bit: u8) {
        unsafe {
            let val = read_register(self.regs, APB2ENR_OFFSET);
            write_register(self.regs, APB2ENR_OFFSET, val | (1 << bit));
        }
    }

    /// Enable a clock bit in the AHB5ENR register (XSPI, MCE, DMA2D, etc.).
    pub fn enable_ahb5_clock(&self, bit: u8) {
        unsafe {
            let val = read_register(self.regs, AHB5ENR_OFFSET);
            write_register(self.regs, AHB5ENR_OFFSET, val | (1 << bit));
        }
    }

    /// Set VTOR_NS to a Non-Secure SRAM address for the host vector table.
    pub fn set_vtor_ns(vtor_ns: u32) {
        // SCB_NS->VTOR at 0xE002ED08
        unsafe { write_register(0xE002_ED08 as *const u32, 0, vtor_ns); }
    }
}

// AHB4ENR bit positions for GPIO ports
pub const GPIOAEN: u8 = 0;
pub const GPIOBEN: u8 = 1;
pub const GPIOCEN: u8 = 2;
pub const GPIODEN: u8 = 3;
pub const GPIOEEN: u8 = 4;
pub const GPIOFEN: u8 = 5;
pub const GPIOGEN: u8 = 6;

// AHB3ENR bit positions (crypto peripherals)
pub const RNGEN: u8 = 0;
pub const HASHEN: u8 = 1;
pub const CRYP1EN: u8 = 2;
pub const SAESEN: u8 = 4;
pub const PKAEN: u8 = 8;

// APB2ENR bit positions
pub const USART1EN: u8 = 4;

// AHB5ENR bit positions (XSPI, MCE, DMA, etc.)
pub const XSPI2EN: u8 = 12;
pub const XSPIMEN: u8 = 13;
pub const MCE1EN: u8 = 14;
pub const MCE2EN: u8 = 15;
