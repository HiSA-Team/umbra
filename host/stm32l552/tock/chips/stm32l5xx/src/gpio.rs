//! Minimal GPIO driver for STM32L5xx (NS alias).
//!
//! GPIO bank base addresses use the Non-Secure alias (Secure − 0x10000000):
//!   GPIOA 0x42020000 .. GPIOH 0x42021C00. Only the registers needed by the
//!   bring-up (MODER, AFRL/AFRH, BSRR, ODR) are wired up; pull / speed /
//!   analog / EXTI configuration is intentionally absent.

use kernel::utilities::registers::interfaces::{Readable, Writeable};
use kernel::utilities::registers::{register_bitfields, register_structs, ReadWrite};
use kernel::utilities::StaticRef;

register_structs! {
    pub GpioRegisters {
        /// Port mode register (2 bits per pin: 00=input, 01=output, 10=alt, 11=analog).
        (0x00 => moder:  ReadWrite<u32>),
        /// Output type register (1 bit per pin; 0=push-pull, 1=open-drain).
        (0x04 => otyper: ReadWrite<u32>),
        /// Output speed register (2 bits per pin).
        (0x08 => ospeedr: ReadWrite<u32>),
        /// Pull-up / pull-down register (2 bits per pin).
        (0x0C => pupdr: ReadWrite<u32>),
        /// Input data register.
        (0x10 => idr: ReadWrite<u32>),
        /// Output data register.
        (0x14 => odr: ReadWrite<u32>),
        /// Bit set/reset register (write-only; bits [15:0]=set, [31:16]=reset).
        (0x18 => bsrr: ReadWrite<u32, BSRR::Register>),
        /// Configuration lock register.
        (0x1C => lckr: ReadWrite<u32>),
        /// Alternate function low register (pins 0–7, 4 bits each).
        (0x20 => afrl: ReadWrite<u32>),
        /// Alternate function high register (pins 8–15, 4 bits each).
        (0x24 => afrh: ReadWrite<u32>),
        /// Bit reset register (write-only; bits [15:0]=reset).
        (0x28 => brr: ReadWrite<u32>),
        (0x2C => @END),
    }
}

register_bitfields![u32,
    BSRR [
        BS OFFSET(0) NUMBITS(16) [],
        BR OFFSET(16) NUMBITS(16) []
    ]
];

/// GPIOG NS alias (PG7/PG8 are LPUART1 TX/RX on NUCLEO-L552ZE-Q).
pub const GPIOG_BASE: StaticRef<GpioRegisters> =
    unsafe { StaticRef::new(0x4202_1800 as *const GpioRegisters) };

pub struct GpioPort {
    regs: StaticRef<GpioRegisters>,
}

impl GpioPort {
    pub const fn new(regs: StaticRef<GpioRegisters>) -> Self {
        Self { regs }
    }

    /// Configure `pin` (0-15) as alternate function `af` (0-15).
    pub fn set_mode_alternate(&self, pin: u8, af: u8) {
        assert!(pin < 16);
        assert!(af < 16);

        let moder = self.regs.moder.get();
        let shift = 2 * pin as u32;
        let moder = (moder & !(3u32 << shift)) | (2u32 << shift);
        self.regs.moder.set(moder);

        if pin < 8 {
            let afrl = self.regs.afrl.get();
            let shift = 4 * pin as u32;
            let afrl = (afrl & !(0xFu32 << shift)) | ((af as u32) << shift);
            self.regs.afrl.set(afrl);
        } else {
            let afrh = self.regs.afrh.get();
            let shift = 4 * (pin - 8) as u32;
            let afrh = (afrh & !(0xFu32 << shift)) | ((af as u32) << shift);
            self.regs.afrh.set(afrh);
        }
    }

    pub fn set_mode_output(&self, pin: u8) {
        assert!(pin < 16);
        let moder = self.regs.moder.get();
        let shift = 2 * pin as u32;
        let moder = (moder & !(3u32 << shift)) | (1u32 << shift);
        self.regs.moder.set(moder);
    }

    pub fn set(&self, pin: u8) {
        assert!(pin < 16);
        self.regs.bsrr.set(1u32 << pin);
    }

    pub fn clear(&self, pin: u8) {
        assert!(pin < 16);
        self.regs.bsrr.set(1u32 << (pin + 16));
    }

    pub fn toggle(&self, pin: u8) {
        assert!(pin < 16);
        let odr = self.regs.odr.get();
        self.regs.odr.set(odr ^ (1u32 << pin));
    }
}
