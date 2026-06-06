// STM32L5xxxx GPIO Driver
// This driver implements the General Purpose Input Output (GPIO) peripheral present on STM32L5xxxx.
// Implements a minimal subset of GPIO features needed by the other drivers.
#![allow(dead_code)]

// Crates
use crate::rcc;
use crate::rcc::Rcc;
use peripheral_regs::{MmioAccess, RealMmio};

type GpioBaseAddress = u32;
type GpioRegisters = u32;

// The value is the Base Address
#[repr(u32)]
#[derive(Clone, Copy)]
pub enum Port {
    GpioA = 0x5202_0000, // Secure
    GpioB = 0x5202_0400, // Secure
    GpioC = 0x5202_0800, // Secure
    GpioD = 0x5202_0C00, // Secure
    GpioE = 0x5202_1000, // Secure
    GpioF = 0x5202_1400, // Secure
    GpioG = 0x5202_1800, // Secure
    GpioH = 0x5202_1C00, // Secure
}

// _____ _ _
// | __ \ (_) | |
// | |__) |___ __ _ _ ___| |_ ___ _ __ ___
// | _ // _ \/ _` | / __| __/ _ \ '__/ __|
// | | \ \ __/ (_| | \__ \ || __/ | \__ \
// |_| \_\___|\__, |_|___/\__\___|_| |___/
// __/ |
// |___/
const GPIO_MODER_BASE_OFFSET: GpioRegisters = 0x00;
const GPIO_OTYPER_BASE_OFFSET: GpioRegisters = 0x04;
const GPIO_OSPEEDR_BASE_OFFSET: GpioRegisters = 0x08;
const GPIO_OPUPDR_BASE_OFFSET: GpioRegisters = 0x0C;
const GPIO_IDR_BASE_OFFSET: GpioRegisters = 0x10;
const GPIO_ODR_BASE_OFFSET: GpioRegisters = 0x14;
const GPIO_BSRR_BASE_OFFSET: GpioRegisters = 0x18;
const GPIO_LCKR_BASE_OFFSET: GpioRegisters = 0x1C;
const GPIO_AFRL_BASE_OFFSET: GpioRegisters = 0x20;
const GPIO_AFRH_BASE_OFFSET: GpioRegisters = 0x24;
const GPIO_BRR_BASE_OFFSET: GpioRegisters = 0x28;
const GPIO_SECCFGR_BASE_OFFSET: GpioRegisters = 0x30;

#[repr(u8)]
pub enum PinMode {
    Input = 0,
    Output = 1,
    AlternateFunction = 2,
    Analog = 3,
}

/// Generic over the MMIO backend so host tests can
/// inject [`umbra_pal_test::mmio::MmioHandle`]. Default `M = RealMmio`
/// keeps every existing `Gpio::new(port)` call site unchanged.
pub struct Gpio<M: MmioAccess = RealMmio> {
    mmio: M,
    port: Port,
}

impl Gpio<RealMmio> {
    pub fn new(port: Port) -> Self {
        Self {
            mmio: RealMmio::new(port as u32),
            port,
        }
    }
}

impl<M: MmioAccess> Gpio<M> {
    /// Constructor for host-side tests — accepts any `MmioAccess` backend.
    /// On firmware build, callers use `Gpio::new(port)` which monomorphises
    /// to `Gpio<RealMmio>` and inlines the volatile accesses.
    #[allow(dead_code)]
    pub fn new_with_mmio(port: Port, mmio: M) -> Self {
        Self { mmio, port }
    }

    fn port(&self) -> Port {
        self.port
    }

    pub fn enable_clock(&self)
    where
        M: Copy,
    {
        // enable_clock construct an Rcc HW singleton — only meaningful on the
        // firmware path. Skipped in tests (default M is RealMmio so the bound
        // is satisfied; in-memory backends construct via new_with_mmio + don't
        // invoke enable_clock).
        let rcc = Rcc::new();

        match self.port() {
            Port::GpioA => rcc.enable_clock(rcc::peripherals::GPIOA),
            Port::GpioB => rcc.enable_clock(rcc::peripherals::GPIOB),
            Port::GpioC => rcc.enable_clock(rcc::peripherals::GPIOC),
            Port::GpioD => rcc.enable_clock(rcc::peripherals::GPIOD),
            Port::GpioE => rcc.enable_clock(rcc::peripherals::GPIOE),
            Port::GpioF => rcc.enable_clock(rcc::peripherals::GPIOF),
            Port::GpioG => rcc.enable_clock(rcc::peripherals::GPIOG),
            Port::GpioH => rcc.enable_clock(rcc::peripherals::GPIOH),
        }
    }

    pub fn set_mode(&self, pin: u8, mode: PinMode) {
        assert!(pin < 16);
        let current_value = self.mmio.read(GPIO_MODER_BASE_OFFSET);
        let cleared_value = current_value & !(3u32 << (2 * pin as u32));
        let new_value = cleared_value | ((mode as u32) << (2 * pin));
        self.mmio.write(GPIO_MODER_BASE_OFFSET, new_value);
    }

    pub fn set_alternate_function(&self, pin: u8, alternate_function: u8) {
        assert!(pin < 16);
        assert!(alternate_function < 16);

        let offset = if pin < 8 {
            GPIO_AFRL_BASE_OFFSET
        } else {
            GPIO_AFRH_BASE_OFFSET
        };
        let current_value = self.mmio.read(offset);
        let cleared_value = current_value & !(15u32 << (4 * pin as u32));
        let new_value = cleared_value | ((alternate_function as u32) << (4 * pin));
        self.mmio.write(offset, new_value);
    }

    pub fn pin_set(&self, pin: u8) {
        assert!(pin < 16);
        self.mmio.set_bit(GPIO_BSRR_BASE_OFFSET, pin);
    }

    pub fn pin_reset(&self, pin: u8) {
        assert!(pin < 16);
        self.mmio.set_bit(GPIO_BSRR_BASE_OFFSET, 16 + pin);
    }

    // Should not be used
    pub fn set_bit(&self, reg_offset: GpioRegisters, bit: u8) {
        self.mmio.set_bit(reg_offset, bit);
    }
    pub fn clear_bit(&self, reg_offset: GpioRegisters, bit: u8) {
        self.mmio.clear_bit(reg_offset, bit);
    }
}

// umbra_hal::Gpio adapter.
#[derive(Debug)]
pub enum GpioError {
    /// Pin index exceeded the per-port 16-pin range.
    PinOutOfRange,
}

impl<M: MmioAccess> umbra_hal::Gpio for Gpio<M> {
    type Error = GpioError;

    fn set_high(&mut self, pin: u32) -> Result<(), Self::Error> {
        if pin > 15 {
            return Err(GpioError::PinOutOfRange);
        }
        self.pin_set(pin as u8);
        Ok(())
    }

    fn set_low(&mut self, pin: u32) -> Result<(), Self::Error> {
        if pin > 15 {
            return Err(GpioError::PinOutOfRange);
        }
        self.pin_reset(pin as u8);
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
        let mem = MmioMem::new(Port::GpioA as u32);
        // Preload MODER with all-1s so the clear step is observable.
        mem.preload_register(GPIO_MODER_BASE_OFFSET, 0xFFFF_FFFF);

        let gpio = Gpio::<_>::new_with_mmio(Port::GpioA, mem.handle());
        gpio.set_mode(5, PinMode::AlternateFunction); // mode=2, bits [11:10]

        // Expected: 1 read of MODER, then 1 write with bits [11:10] = 10.
        let log = mem.write_log();
        assert_eq!(log.len(), 2);
        assert!(matches!(log[0], MmioOp::Read { addr, .. } if addr == Port::GpioA as u32));
        match log[1] {
            MmioOp::Write { addr, value } => {
                assert_eq!(addr, Port::GpioA as u32);
                // 2-bit field at [11:10]: cleared from 11 → 10
                assert_eq!((value >> 10) & 0b11, 0b10);
            }
            _ => panic!("expected Write at position 1, got {:?}", log[1]),
        }
    }

    /// Verifies pin_set issues a write to BSRR setting bit `pin` (low half).
    #[test]
    fn pin_set_writes_bsrr_low_half() {
        let mem = MmioMem::new(Port::GpioA as u32);
        let gpio = Gpio::<_>::new_with_mmio(Port::GpioA, mem.handle());
        gpio.pin_set(3);
        // set_bit = read-modify-write — expect one read + one write.
        let log = mem.write_log();
        assert_eq!(log.len(), 2);
        match log[1] {
            MmioOp::Write { value, .. } => assert_eq!(value, 1u32 << 3),
            _ => panic!("expected Write"),
        }
    }
}
