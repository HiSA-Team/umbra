//! GPIO driver for STM32N657
//!
//! Port base addresses (Secure alias 0x5602xxxx):
//!   GPIOA = 0x56020000   GPIOE = 0x56021000
//!   GPIOB = 0x56020400   GPIOF = 0x56021400
//!   GPIOC = 0x56020800   GPIOG = 0x56021800
//!   GPIOD = 0x56020C00   GPIOH = 0x56021C00
//!
//! Register offsets (standard STM32 GPIO IP):
//!   MODER   = 0x00   (pin mode: 00=input, 01=output, 10=AF, 11=analog)
//!   OTYPER  = 0x04
//!   OSPEEDR = 0x08
//!   PUPDR   = 0x0C
//!   IDR     = 0x10
//!   ODR     = 0x14
//!   BSRR    = 0x18
//!   LCKR    = 0x1C
//!   AFRL    = 0x20   (AF select for pins 0-7)
//!   AFRH    = 0x24   (AF select for pins 8-15)

pub enum Port {
    GpioA, GpioB, GpioC, GpioD, GpioE, GpioF, GpioG, GpioH,
}

pub enum PinMode { Input, Output, Alternate, Analog }

pub struct Gpio {
    base: *mut u32,
}

impl Gpio {
    pub fn new(port: Port) -> Self {
        let base = match port {
            // NS aliases — RIFSC unlock makes all peripherals NS.
            Port::GpioA => 0x4602_0000,
            Port::GpioB => 0x4602_0400,
            Port::GpioC => 0x4602_0800,
            Port::GpioD => 0x4602_0C00,
            Port::GpioE => 0x4602_1000,
            Port::GpioF => 0x4602_1400,
            Port::GpioG => 0x4602_1800,
            Port::GpioH => 0x4602_1C00,
        } as *mut u32;
        Gpio { base }
    }

    /// Set pin mode in MODER register.
    pub fn set_mode(&self, pin: u32, mode: PinMode) {
        let moder_val = match mode {
            PinMode::Input => 0b00,
            PinMode::Output => 0b01,
            PinMode::Alternate => 0b10,
            PinMode::Analog => 0b11,
        };
        unsafe {
            let moder = self.base;
            let val = core::ptr::read_volatile(moder);
            let mask = !(0b11u32 << (pin * 2));
            core::ptr::write_volatile(moder, (val & mask) | (moder_val << (pin * 2)));
        }
    }

    /// Set alternate function for a pin (0-15). AF number is 0-15.
    /// Uses AFRL (offset 0x20) for pins 0-7, AFRH (offset 0x24) for pins 8-15.
    pub fn set_af(&self, pin: u32, af: u32) {
        let offset = if pin < 8 { 0x20 } else { 0x24 };
        let bit_pos = (pin % 8) * 4;
        unsafe {
            let afr = (self.base as usize + offset) as *mut u32;
            let val = core::ptr::read_volatile(afr);
            let mask = !(0xFu32 << bit_pos);
            core::ptr::write_volatile(afr, (val & mask) | ((af & 0xF) << bit_pos));
        }
    }

    /// Set pin HIGH via BSRR.
    pub fn pin_set(&self, pin: u32) {
        unsafe {
            let bsrr = (self.base as usize + 0x18) as *mut u32;
            core::ptr::write_volatile(bsrr, 1 << pin);
        }
    }

    /// Set pin LOW via BSRR (reset half).
    pub fn pin_reset(&self, pin: u32) {
        unsafe {
            let bsrr = (self.base as usize + 0x18) as *mut u32;
            core::ptr::write_volatile(bsrr, 1 << (pin + 16));
        }
    }
}
