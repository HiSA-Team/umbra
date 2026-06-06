//! GPIO driver for STM32N657
//! Port base addresses (Secure alias 0x5602xxxx):
//! GPIOA = 0x56020000 GPIOE = 0x56021000
//! GPIOB = 0x56020400 GPIOF = 0x56021400
//! GPIOC = 0x56020800 GPIOG = 0x56021800
//! GPIOD = 0x56020C00 GPIOH = 0x56021C00
//! Register offsets (standard STM32 GPIO IP):
//! MODER = 0x00 (pin mode: 00=input, 01=output, 10=AF, 11=analog)
//! OTYPER = 0x04
//! OSPEEDR = 0x08
//! PUPDR = 0x0C
//! IDR = 0x10
//! ODR = 0x14
//! BSRR = 0x18
//! LCKR = 0x1C
//! AFRL = 0x20 (AF select for pins 0-7)
//! AFRH = 0x24 (AF select for pins 8-15)

use peripheral_regs::{MmioAccess, RealMmio};

// Register offsets — standard STM32 GPIO IP, identical to L552.
const GPIO_MODER_OFFSET: u32 = 0x00;
const GPIO_BSRR_OFFSET: u32 = 0x18;
const GPIO_AFRL_OFFSET: u32 = 0x20;
const GPIO_AFRH_OFFSET: u32 = 0x24;

pub enum Port {
    GpioA,
    GpioB,
    GpioC,
    GpioD,
    GpioE,
    GpioF,
    GpioG,
    GpioH,
}

impl Port {
    /// NS alias base address — RIFSC unlock makes all peripherals NS, so
    /// every Port resolves into the 0x4602_xxxx half of the alias pair.
    fn base_addr(&self) -> u32 {
        match self {
            Port::GpioA => 0x4602_0000,
            Port::GpioB => 0x4602_0400,
            Port::GpioC => 0x4602_0800,
            Port::GpioD => 0x4602_0C00,
            Port::GpioE => 0x4602_1000,
            Port::GpioF => 0x4602_1400,
            Port::GpioG => 0x4602_1800,
            Port::GpioH => 0x4602_1C00,
        }
    }
}

pub enum PinMode {
    Input,
    Output,
    Alternate,
    Analog,
}

/// Generic over the MMIO backend so
/// host tests can inject [`umbra_pal_test::mmio::MmioHandle`]. Default
/// `M = RealMmio` keeps every existing `Gpio::new(port)` call site
/// unchanged.
pub struct Gpio<M: MmioAccess = RealMmio> {
    mmio: M,
}

impl Gpio<RealMmio> {
    pub fn new(port: Port) -> Self {
        Self {
            mmio: RealMmio::new(port.base_addr()),
        }
    }
}

impl<M: MmioAccess> Gpio<M> {
    /// Constructor for host-side tests — accepts any `MmioAccess` backend.
    /// On firmware build, callers use `Gpio::new(port)` which monomorphises
    /// to `Gpio<RealMmio>` and inlines the volatile accesses.
    #[allow(dead_code)]
    pub fn new_with_mmio(mmio: M) -> Self {
        Self { mmio }
    }

    /// Set pin mode in MODER register.
    pub fn set_mode(&self, pin: u32, mode: PinMode) {
        let moder_val: u32 = match mode {
            PinMode::Input => 0b00,
            PinMode::Output => 0b01,
            PinMode::Alternate => 0b10,
            PinMode::Analog => 0b11,
        };
        let val = self.mmio.read(GPIO_MODER_OFFSET);
        let mask = !(0b11u32 << (pin * 2));
        self.mmio
            .write(GPIO_MODER_OFFSET, (val & mask) | (moder_val << (pin * 2)));
    }

    /// Set alternate function for a pin (0-15). AF number is 0-15.
    /// Uses AFRL (offset 0x20) for pins 0-7, AFRH (offset 0x24) for pins 8-15.
    pub fn set_af(&self, pin: u32, af: u32) {
        let offset = if pin < 8 {
            GPIO_AFRL_OFFSET
        } else {
            GPIO_AFRH_OFFSET
        };
        let bit_pos = (pin % 8) * 4;
        let val = self.mmio.read(offset);
        let mask = !(0xFu32 << bit_pos);
        self.mmio
            .write(offset, (val & mask) | ((af & 0xF) << bit_pos));
    }

    /// Set pin HIGH via BSRR.
    pub fn pin_set(&self, pin: u32) {
        self.mmio.write(GPIO_BSRR_OFFSET, 1 << pin);
    }

    /// Set pin LOW via BSRR (reset half).
    pub fn pin_reset(&self, pin: u32) {
        self.mmio.write(GPIO_BSRR_OFFSET, 1 << (pin + 16));
    }
}

// umbra_hal::Gpio adapter.
#[derive(Debug)]
pub enum GpioError {
    PinOutOfRange,
}

impl<M: MmioAccess> umbra_hal::Gpio for Gpio<M> {
    type Error = GpioError;

    fn set_high(&mut self, pin: u32) -> Result<(), Self::Error> {
        if pin > 15 {
            return Err(GpioError::PinOutOfRange);
        }
        self.pin_set(pin);
        Ok(())
    }

    fn set_low(&mut self, pin: u32) -> Result<(), Self::Error> {
        if pin > 15 {
            return Err(GpioError::PinOutOfRange);
        }
        self.pin_reset(pin);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umbra_pal_test::mmio::{MmioMem, MmioOp};

    /// Verifies set_mode performs a read-modify-write to MODER that
    /// clears the 2-bit field at position 2*pin and then sets it to the
    /// requested mode encoding.
    #[test]
    fn set_mode_issues_correct_register_sequence() {
        let base = Port::GpioA.base_addr();
        let mem = MmioMem::new(base);
        // Preload MODER with all-1s so the clear step is observable.
        mem.preload_register(GPIO_MODER_OFFSET, 0xFFFF_FFFF);

        let gpio = Gpio::<_>::new_with_mmio(mem.handle());
        gpio.set_mode(5, PinMode::Alternate); // mode=2 (0b10), bits [11:10]

        // Expected: 1 read of MODER, then 1 write with bits [11:10] = 10.
        let log = mem.write_log();
        assert_eq!(log.len(), 2);
        assert!(matches!(log[0], MmioOp::Read { addr, .. } if addr == base));
        match log[1] {
            MmioOp::Write { addr, value } => {
                assert_eq!(addr, base);
                // 2-bit field at [11:10]: cleared from 11 -> 10
                assert_eq!((value >> 10) & 0b11, 0b10);
            }
            _ => panic!("expected Write at position 1, got {:?}", log[1]),
        }
    }

    /// Verifies pin_set issues a write to BSRR setting bit `pin` (low half).
    /// N657 GPIO writes BSRR directly (no read-modify-write — BSRR is
    /// write-only and self-clearing), so we expect exactly one Write.
    #[test]
    fn pin_set_writes_bsrr_low_half() {
        let base = Port::GpioA.base_addr();
        let mem = MmioMem::new(base);
        let gpio = Gpio::<_>::new_with_mmio(mem.handle());
        gpio.pin_set(3);

        let log = mem.write_log();
        assert_eq!(log.len(), 1);
        match log[0] {
            MmioOp::Write { addr, value } => {
                assert_eq!(addr, base + GPIO_BSRR_OFFSET);
                assert_eq!(value, 1u32 << 3);
            }
            _ => panic!("expected Write"),
        }
    }
}
