// STM32L5xxxx RCC Driver
// This driver implements the Reset and Clock Control (RCC) peripheral present on STM32L5xxxx.
// 
// WIP: This draft implements a minimal subset of the features. Mainly used to implement the other drivers.

// Crates
use peripheral_regs::*;

const RCC_BASE_ADDR: u32 = 0x50021000; // Secure
type RccRegisters = u32;

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
// TODO: Implement all registers
const RCC_CR_BASE_OFFSET           : u32 = 0x000;
const RCC_ICSR_BASE_OFFSET         : u32 = 0x004;
const RCC_CFGR_BASE_OFFSET         : u32 = 0x008;
const RCC_PLLCFGGR_BASE_OFFSET     : u32 = 0x00C;
const RCC_PLLSAI1_CFGR_BASE_OFFSET : u32 = 0x010;
const RCC_PLLSAI2_CFGR_BASE_OFFSET : u32 = 0x014;
const RCC_CIER_BASE_OFFSET         : u32 = 0x018;
const RCC_CIFR_BASE_OFFSET         : u32 = 0x01C;
const RCC_CICR_BASE_OFFSET         : u32 = 0x020;

const RCC_CCIPR1_BASE_OFFSET       : u32 = 0x088;
const RCC_BDCR_BASE_OFFSET         : u32 = 0x090;
const RCC_CSR_BASE_OFFSET          : u32 = 0x094;
const RCC_CRRCR_BASE_OFFSET        : u32 = 0x098;
const RCC_CCIPR2_BASE_OFFSET       : u32 = 0x09C;
// AHB 1 Regs
const RCC_AHB1RST_BASE_OFFSET      : u32 = 0x028;
const RCC_AHB1ENR_BASE_OFFSET      : u32 = 0x048;
// AHB 2 Regs
const RCC_AHB2RST_BASE_OFFSET      : u32 = 0x02C;
const RCC_AHB2ENR_BASE_OFFSET      : u32 = 0x04C;
// AHB 3 Regs
const RCC_AHB3RST_BASE_OFFSET      : u32 = 0x030;
const RCC_AHB3ENR_BASE_OFFSET      : u32 = 0x050;
// APB 1 Regs
const RCC_APB1RSTR1_BASE_OFFSET    : u32 = 0x038;
const RCC_APB1RSTR2_BASE_OFFSET    : u32 = 0x03C;
const RCC_APB1ENR1_BASE_OFFSET     : u32 = 0x058;
const RCC_APB1ENR2_BASE_OFFSET     : u32 = 0x05C;
// APB 2 Regs
const RCC_APB2RSTR_BASE_OFFSET     : u32 = 0x040;
const RCC_APB2ENR_BASE_OFFSET      : u32 = 0x060;

//   ______                           
//  |  ____|                          
//  | |__   _ __  _   _ _ __ ___  ___ 
//  |  __| | '_ \| | | | '_ ` _ \/ __|
//  | |____| | | | |_| | | | | | \__ \
//  |______|_| |_|\__,_|_| |_| |_|___/
pub enum Bus {
    AHB1,
    APB1_1, // APB 1 has 2 registers
    APB1_2,
}

pub type Peripheral = (Bus, u8);
    
    // AHB 1
pub mod Peripherals {
    use super::{Peripheral, Bus};
    pub const DMA1  : Peripheral = (Bus::AHB1, 0);
    pub const DMA2  : Peripheral = (Bus::AHB1, 1);
    pub const FLASH : Peripheral = (Bus::AHB1, 8);
    pub const CRC   : Peripheral = (Bus::AHB1, 12);
    pub const TSC   : Peripheral = (Bus::AHB1, 16);
    pub const GTZC  : Peripheral = (Bus::AHB1, 22);
}

//     // APB 1 Reg 1
//     TIM2    = (Bus::APB1_1, 0),
//     TIM3    = (Bus::APB1_1, 1),
//     TIM4    = (Bus::APB1_1, 2),
//     TIM5    = (Bus::APB1_1, 3),
//     TIM6    = (Bus::APB1_1, 4),
//     TIM7    = (Bus::APB1_1, 5),
//     RTCAPB  = (Bus::APB1_1, 10),
//     WWDG    = (Bus::APB1_1, 11),
//     SPI2    = (Bus::APB1_1, 14),
//     SPI3    = (Bus::APB1_1, 15),
//     USART2  = (Bus::APB1_1, 17),
//     USART3  = (Bus::APB1_1, 18),
//     USART4  = (Bus::APB1_1, 19),
//     USART5  = (Bus::APB1_1, 20),
//     I2C1    = (Bus::APB1_1, 21),
//     I2C2    = (Bus::APB1_1, 22),
//     I2C3    = (Bus::APB1_1, 23),
//     CRSEN   = (Bus::APB1_1, 24),
//     PWR     = (Bus::APB1_1, 28),
//     DAC1    = (Bus::APB1_1, 29),
//     OPAMP   = (Bus::APB1_1, 30),
//     LPTIM1  = (Bus::APB1_1, 31),

//     // APB 1 Reg 2
//     LPUART  = (Bus::APB1_2, 0),
//     I2C4    = (Bus::APB1_2, 1),
//     LPTIM2  = (Bus::APB1_2, 5),
//     LPTIM3  = (Bus::APB1_2, 6),
//     FDCAN1  = (Bus::APB1_2, 9),
//     USBFS   = (Bus::APB1_2, 21),
//     UCPD1   = (Bus::APB1_2, 23),
// }

pub struct Rcc {
    regs: &'static mut RccRegisters, 
}

impl Rcc {
    pub fn new() -> Self {
        let regs = unsafe { &mut *(RCC_BASE_ADDR as *mut RccRegisters) };
        Self { regs }
    }

    pub fn enable_clock(self, peripheral: Peripheral) {
        match peripheral {
            (Bus::AHB1, bit)   => unsafe { set_register_bit(self.regs, RCC_AHB1ENR_BASE_OFFSET, bit);  }
            (Bus::APB1_1, bit) => unsafe { set_register_bit(self.regs, RCC_APB1ENR1_BASE_OFFSET, bit); }
            (Bus::APB1_2, bit) => unsafe { set_register_bit(self.regs, RCC_APB1ENR2_BASE_OFFSET, bit); }
        }
    }
}
