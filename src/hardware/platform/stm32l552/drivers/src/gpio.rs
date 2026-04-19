// STM32L5xxxx GPIO Driver
// This driver implements the General Purpose Input Output (GPIO) peripheral present on STM32L5xxxx.
// 
// Implements a minimal subset of GPIO features needed by the other drivers.

// Crates
use peripheral_regs::*;
use crate::rcc;
use crate::rcc::Rcc;

type GpioBaseAddress = u32;
type GpioRegisters = u32;

// The value is the Base Address
#[repr(u32)]
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

//   _____            _     _                
//  |  __ \          (_)   | |               
//  | |__) |___  __ _ _ ___| |_ ___ _ __ ___ 
//  |  _  // _ \/ _` | / __| __/ _ \ '__/ __|
//  | | \ \  __/ (_| | \__ \ ||  __/ |  \__ \
//  |_|  \_\___|\__, |_|___/\__\___|_|  |___/
//               __/ |                       
//              |___/                      
//
//
const GPIO_MODER_BASE_OFFSET      : GpioRegisters = 0x00;
const GPIO_OTYPER_BASE_OFFSET     : GpioRegisters = 0x04;
const GPIO_OSPEEDR_BASE_OFFSET    : GpioRegisters = 0x08;
const GPIO_OPUPDR_BASE_OFFSET     : GpioRegisters = 0x0C;
const GPIO_IDR_BASE_OFFSET        : GpioRegisters = 0x10;
const GPIO_ODR_BASE_OFFSET        : GpioRegisters = 0x14;
const GPIO_BSRR_BASE_OFFSET       : GpioRegisters = 0x18;
const GPIO_LCKR_BASE_OFFSET       : GpioRegisters = 0x1C;
const GPIO_AFRL_BASE_OFFSET       : GpioRegisters = 0x20;
const GPIO_AFRH_BASE_OFFSET       : GpioRegisters = 0x24;
const GPIO_BRR_BASE_OFFSET        : GpioRegisters = 0x28;
const GPIO_SECCFGR_BASE_OFFSET    : GpioRegisters = 0x30;

#[repr(u8)]
pub enum PinMode {
    Input             = 0,
    Output            = 1,
    AlternateFunction = 2,
    Analog            = 3,
}

pub struct Gpio {
    regs: &'static mut GpioRegisters, 
}

impl Gpio {
    pub fn new(port: Port) -> Self {
        let regs = unsafe { &mut *((port as u32) as *mut GpioRegisters) };
        Self { regs } 
    }
    
    fn port(&self) -> Port {
        unsafe {
            core::mem::transmute::<GpioRegisters, Port>(*self.regs)
        }
    }
    
    pub fn enable_clock(&self) {
        let rcc = Rcc::new();

        match self.port() {
            Port::GpioA => rcc.enable_clock(rcc::Peripherals::GPIOA),
            Port::GpioB => rcc.enable_clock(rcc::Peripherals::GPIOB),
            Port::GpioC => rcc.enable_clock(rcc::Peripherals::GPIOC),
            Port::GpioD => rcc.enable_clock(rcc::Peripherals::GPIOD),
            Port::GpioE => rcc.enable_clock(rcc::Peripherals::GPIOE),
            Port::GpioF => rcc.enable_clock(rcc::Peripherals::GPIOF),
            Port::GpioG => rcc.enable_clock(rcc::Peripherals::GPIOG),
            Port::GpioH => rcc.enable_clock(rcc::Peripherals::GPIOH),
        }
    }

    pub fn set_mode(&self, pin: u8, mode: PinMode) {
        assert!(pin < 16);
        let current_value = unsafe { read_register(self.regs, GPIO_MODER_BASE_OFFSET) };
        let cleared_value = current_value & !(3u32<<2*(pin as u32));
        let new_value = cleared_value | ((mode as u32) << 2*pin);
        unsafe { write_register(self.regs, GPIO_MODER_BASE_OFFSET, new_value) };
    }

    pub fn set_alternate_function(&self, pin: u8, alternate_function: u8) {
        assert!(pin < 16);
        assert!(alternate_function < 16);

        let offset = if pin < 8 { GPIO_AFRL_BASE_OFFSET } else { GPIO_AFRH_BASE_OFFSET };
        let current_value = unsafe { read_register(self.regs, offset) };
        let cleared_value = current_value & !(15u32 << 4*(pin as u32));
        let new_value = cleared_value | ((alternate_function as u32) << 4*pin);
        unsafe { write_register(self.regs, offset, new_value) };
    }
    
    pub fn pin_set(&self, pin: u8) {
        assert!(pin < 16);
        
        unsafe { set_register_bit(self.regs, GPIO_BSRR_BASE_OFFSET, pin); };
    }
    
    pub fn pin_reset(&self, pin: u8) {
        assert!(pin < 16);

        unsafe { set_register_bit(self.regs, GPIO_BSRR_BASE_OFFSET, 16 + pin); };
    }
    
    // Should not be used
    pub fn set_bit(&self, reg_offset: GpioRegisters, bit: u8) {
        unsafe { set_register_bit(self.regs, reg_offset, bit) }
    }
    pub fn clear_bit(&self, reg_offset: GpioRegisters, bit: u8) {
        unsafe { clear_register_bit(self.regs, reg_offset, bit) }
    }
}
