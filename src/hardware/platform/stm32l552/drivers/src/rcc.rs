// STM32L5xxxx RCC Driver
// This driver implements the Reset and Clock Control (RCC) peripheral present on STM32L5xxxx.
// 
// Implements a minimal subset of RCC features needed by the other drivers.

// Crates
use peripheral_regs::*;
use crate::pwr::Pwr;

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
    AHB2,
    AHB3,
    APB1_1, // APB 1 has 2 registers
    APB1_2,
    APB2,
}

pub type Peripheral = (Bus, u8);
    
pub mod Peripherals {
    use super::{Peripheral, Bus};

    // AHB 1
    pub const DMA1    : Peripheral = (Bus::AHB1, 0);
    pub const DMA2    : Peripheral = (Bus::AHB1, 1);
    pub const FLASH   : Peripheral = (Bus::AHB1, 8);
    pub const CRC     : Peripheral = (Bus::AHB1, 12);
    pub const TSC     : Peripheral = (Bus::AHB1, 16);
    pub const GTZC    : Peripheral = (Bus::AHB1, 22);
    
    // AHB 2
    pub const GPIOA   : Peripheral = (Bus::AHB2, 0);
    pub const GPIOB   : Peripheral = (Bus::AHB2, 1);
    pub const GPIOC   : Peripheral = (Bus::AHB2, 2);
    pub const GPIOD   : Peripheral = (Bus::AHB2, 3);
    pub const GPIOE   : Peripheral = (Bus::AHB2, 4);
    pub const GPIOF   : Peripheral = (Bus::AHB2, 5);
    pub const GPIOG   : Peripheral = (Bus::AHB2, 6);
    pub const GPIOH   : Peripheral = (Bus::AHB2, 7);
    pub const ADC     : Peripheral = (Bus::AHB2, 13);
    pub const AES     : Peripheral = (Bus::AHB2, 16);
    pub const HASH    : Peripheral = (Bus::AHB2, 17);
    pub const RNG     : Peripheral = (Bus::AHB2, 18);
    pub const PKA     : Peripheral = (Bus::AHB2, 19);
    pub const OTFDEC  : Peripheral = (Bus::AHB2, 21);
    pub const SDMMC1  : Peripheral = (Bus::AHB2, 22);
    
    // AHB 3
    pub const FMC     : Peripheral = (Bus::AHB3, 0);
    pub const OSPI1   : Peripheral = (Bus::AHB3, 8);
    
    // APB 1 Reg 1
    pub const TIM2    : Peripheral = (Bus::APB1_1, 0);
    pub const TIM3    : Peripheral = (Bus::APB1_1, 1);
    pub const TIM4    : Peripheral = (Bus::APB1_1, 2);
    pub const TIM5    : Peripheral = (Bus::APB1_1, 3);
    pub const TIM6    : Peripheral = (Bus::APB1_1, 4);
    pub const TIM7    : Peripheral = (Bus::APB1_1, 5);
    pub const RTCAPB  : Peripheral = (Bus::APB1_1, 10);
    pub const WWDG    : Peripheral = (Bus::APB1_1, 11);
    pub const SPI2    : Peripheral = (Bus::APB1_1, 14);
    pub const SPI3    : Peripheral = (Bus::APB1_1, 15);
    pub const USART2  : Peripheral = (Bus::APB1_1, 17);
    pub const USART3  : Peripheral = (Bus::APB1_1, 18);
    pub const USART4  : Peripheral = (Bus::APB1_1, 19);
    pub const USART5  : Peripheral = (Bus::APB1_1, 20);
    pub const I2C1    : Peripheral = (Bus::APB1_1, 21);
    pub const I2C2    : Peripheral = (Bus::APB1_1, 22);
    pub const I2C3    : Peripheral = (Bus::APB1_1, 23);
    pub const CRSEN   : Peripheral = (Bus::APB1_1, 24);
    pub const PWR     : Peripheral = (Bus::APB1_1, 28);
    pub const DAC1    : Peripheral = (Bus::APB1_1, 29);
    pub const OPAMP   : Peripheral = (Bus::APB1_1, 30);
    pub const LPTIM1  : Peripheral = (Bus::APB1_1, 31);

    // APB 1 Reg 2
    pub const LPUART1 : Peripheral = (Bus::APB1_2, 0);
    pub const I2C4    : Peripheral = (Bus::APB1_2, 1);
    pub const LPTIM2  : Peripheral = (Bus::APB1_2, 5);
    pub const LPTIM3  : Peripheral = (Bus::APB1_2, 6);
    pub const FDCAN1  : Peripheral = (Bus::APB1_2, 9);
    pub const USBFS   : Peripheral = (Bus::APB1_2, 21);
    pub const UCPD1   : Peripheral = (Bus::APB1_2, 23);

    // APB 2
    pub const SYSCFG  : Peripheral = (Bus::APB2, 0);
    pub const USART1  : Peripheral = (Bus::APB2, 14);
}

pub struct Rcc {
    regs: &'static mut RccRegisters, 
}

impl Rcc {
    pub fn new() -> Self {
        let regs = unsafe { &mut *(RCC_BASE_ADDR as *mut RccRegisters) };
        Self { regs }
    }

    pub fn enable_clock(&self, peripheral: Peripheral) {
        match peripheral {
            (Bus::AHB1, bit)   => unsafe { set_register_bit(self.regs, RCC_AHB1ENR_BASE_OFFSET, bit);  }
            (Bus::AHB2, bit)   => unsafe { set_register_bit(self.regs, RCC_AHB2ENR_BASE_OFFSET, bit); }
            (Bus::AHB3, bit)   => unsafe { set_register_bit(self.regs, RCC_AHB3ENR_BASE_OFFSET, bit); }
            (Bus::APB1_1, bit) => unsafe { set_register_bit(self.regs, RCC_APB1ENR1_BASE_OFFSET, bit); }
            (Bus::APB1_2, bit) => unsafe { set_register_bit(self.regs, RCC_APB1ENR2_BASE_OFFSET, bit); }
            (Bus::APB2, bit)   => unsafe { set_register_bit(self.regs, RCC_APB2ENR_BASE_OFFSET, bit); }
        }
    }
    
    pub fn enable_lse(&self)  {
        Pwr::new().enable_to_backup_domain();
        // LSCOEN LSCOSEL Enable and select the LSE
        unsafe { set_register_bit(self.regs, RCC_BDCR_BASE_OFFSET, 24) };
        unsafe { set_register_bit(self.regs, RCC_BDCR_BASE_OFFSET, 25) };
        unsafe { set_register_bit(self.regs, RCC_BDCR_BASE_OFFSET, 0) };
        loop {
            let lse_ready = (unsafe { read_register(self.regs, RCC_BDCR_BASE_OFFSET) } >> 1) & 1;
            if lse_ready == 1 { break };
        }

        // LSESYSEN Enable LSE
        unsafe { set_register_bit(self.regs, RCC_BDCR_BASE_OFFSET, 7) };
        loop {
            let lse_ready = (unsafe { read_register(self.regs, RCC_BDCR_BASE_OFFSET) } >> 11) & 1;
            if lse_ready == 1 { break };
        }
    }

    pub fn select_lse_to_lpuart1(&self) {
        let current_value = unsafe { read_register(self.regs, RCC_CCIPR1_BASE_OFFSET) };
        let new_value = current_value | (3 << 10);
        unsafe { write_register(self.regs, RCC_CCIPR1_BASE_OFFSET, new_value) };
    }
    
    // Sets the Non-Secure VTOR. Placed here for convenience as RCC
    // initialisation is the earliest boot stage with peripheral access.
    pub fn set_vtor_ns(vtor_ns: u32) {
        let vtor_ns_addr = 0xE002ED08 as u32;
        unsafe { write_register(vtor_ns_addr as *const u32, 0, vtor_ns); }
    }

    #[cfg(feature = "stm32l562")]
    pub fn select_ospi_clock_source_sysclk(&self) {
        // CCIPR2.OSPISEL (bits [21:20]) = 00: SYSCLK selected as OCTOSPI clock
        // (00 is default after reset, but we write it explicitly for determinism.)
        unsafe {
            let ccipr2 = read_register(self.regs, RCC_CCIPR2_BASE_OFFSET);
            let new = ccipr2 & !(0b11 << 20); // Clear OSPISEL → 00 = SYSCLK
            write_register(self.regs, RCC_CCIPR2_BASE_OFFSET, new);
        }
    }

    #[cfg(feature = "stm32l562")]
    pub fn reset_ospi(&self) {
        // Pulse AHB3RSTR.OSPI1RST (bit 8) high then low.
        unsafe {
            let rst = read_register(self.regs, RCC_AHB3RST_BASE_OFFSET);
            write_register(self.regs, RCC_AHB3RST_BASE_OFFSET, rst | (1 << 8));
            let _ = read_register(self.regs, RCC_AHB3RST_BASE_OFFSET);
            let _ = read_register(self.regs, RCC_AHB3RST_BASE_OFFSET);
            write_register(self.regs, RCC_AHB3RST_BASE_OFFSET, rst & !(1 << 8));
        }
    }

    #[cfg(feature = "stm32l562")]
    pub fn reset_otfdec(&self) {
        // Pulse AHB2RSTR.OTFDEC1RST (bit 21) high then low. Needed to wipe
        // Region 1 state left over from a previous (non-POR) boot.
        unsafe {
            let rst = read_register(self.regs, RCC_AHB2RST_BASE_OFFSET);
            write_register(self.regs, RCC_AHB2RST_BASE_OFFSET, rst | (1 << 21));
            let _ = read_register(self.regs, RCC_AHB2RST_BASE_OFFSET);
            let _ = read_register(self.regs, RCC_AHB2RST_BASE_OFFSET);
            write_register(self.regs, RCC_AHB2RST_BASE_OFFSET, rst & !(1 << 21));
        }
    }
}
