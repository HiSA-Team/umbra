// STM32L5xxxx RCC Driver
// This driver implements the Reset and Clock Control (RCC) peripheral present on STM32L5xxxx.
//
// Implements a minimal subset of RCC features needed by the other drivers.
#![allow(dead_code)]

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
    
pub mod peripherals {
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

    // ─── HSI16 + PLL + SYSCLK switch (added 2026-05-24) ─────────────────
    //
    // Reference RM0438 §9.4.1 (RCC_CR), §9.4.4 (PLLCFGR), §9.4.3 (CFGR).
    //
    // Bring-up order from caller (mandatory):
    //   1. PWR_CR1.VOS = Range 0 (Boost)             — pwr.rs
    //   2. FLASH_ACR.LATENCY = 5 + ICEN + DCEN + PRF — flash.rs
    //   3. RCC: enable_hsi16()
    //   4. RCC: enable_pll_hsi16_110mhz()
    //   5. RCC: switch_sysclk_to_pll()

    /// Enable HSI16 (16 MHz internal RC) and wait for HSIRDY.
    /// RCC_CR.HSION = bit 8, RCC_CR.HSIRDY = bit 10.
    pub fn enable_hsi16(&self) {
        // Safety: RCC_CR is MMIO; HSION enables an oscillator.
        unsafe { set_register_bit(self.regs, RCC_CR_BASE_OFFSET, 8); }
        loop {
            // Safety: read-only readback to poll readiness flag.
            let cr = unsafe { read_register(self.regs, RCC_CR_BASE_OFFSET) };
            if (cr & (1 << 10)) != 0 { break; }
        }
    }

    /// Configure and enable PLL on HSI16.
    ///   PLLM field = 3 (bits [7:4], encodes M-1) → M = 4 → PLL input = HSI16/4 = 4 MHz
    ///   PLLN = 55 (bits [14:8], value-direct)    → VCO = 4 MHz × 55 = 220 MHz
    ///   PLLR field = 0 (bits [26:25])            → PLLR divider = 2 → PLLR clock = 110 MHz
    ///   PLLREN = 1 (bit 24)                      → enable PLLR output to SYSCLK
    ///   PLLSRC = 2 (bits [1:0])                  → 10 = HSI16 as PLL source
    ///
    /// Caller MUST have called enable_hsi16() first and set VOS Range 0
    /// + flash 5 WS beforehand.
    ///
    /// Encodings per RM0438 §9.4.4 and ST HAL `__HAL_RCC_PLL_PLLM_CONFIG`:
    ///   PLLM field = (M - 1), so PLLM=4 stored as field value 3.
    ///   PLLN field = N directly (range 8-86).
    ///   PLLR field: 00=÷2, 01=÷4, 10=÷6, 11=÷8 — we want ÷2 → 00.
    pub fn enable_pll_hsi16_110mhz(&self) {
        // 1. Make sure PLL is OFF before reconfiguring (RM0438 §9.4.4:
        //    PLLCFGR is writable only when PLL is disabled).
        // Safety: RCC_CR.PLLON = bit 24.
        unsafe { clear_register_bit(self.regs, RCC_CR_BASE_OFFSET, 24); }
        loop {
            // Safety: read-only poll for PLLRDY=0.
            let cr = unsafe { read_register(self.regs, RCC_CR_BASE_OFFSET) };
            if (cr & (1 << 25)) == 0 { break; }
        }

        // 2. Write PLLCFGR atomically: PLLSRC=10, PLLM field=3 (M=4),
        //    PLLN=55, PLLR=00 (÷2), PLLREN=1.
        //    Bit layout: [1:0]=PLLSRC, [7:4]=PLLM, [14:8]=PLLN,
        //                [26:25]=PLLR, [24]=PLLREN.
        let pllcfgr: u32 =
              (0b10  << 0)   // PLLSRC = HSI16
            | (3u32  << 4)   // PLLM field = 3 (encodes M-1 → M=4)
            | (55u32 << 8)   // PLLN   = 55
            | (0u32  << 25)  // PLLR   = ÷2
            | (1u32  << 24); // PLLREN
        // Safety: PLL is disabled (verified above); PLLCFGR is now writable.
        unsafe { write_register(self.regs, RCC_PLLCFGGR_BASE_OFFSET, pllcfgr); }

        // 3. Enable PLL and poll PLLRDY (bit 25).
        // Safety: re-arming PLL with the new config.
        unsafe { set_register_bit(self.regs, RCC_CR_BASE_OFFSET, 24); }
        loop {
            // Safety: read-only poll for PLLRDY=1.
            let cr = unsafe { read_register(self.regs, RCC_CR_BASE_OFFSET) };
            if (cr & (1 << 25)) != 0 { break; }
        }
    }

    /// Switch SYSCLK source from current (MSI after reset) to PLL.
    /// RCC_CFGR.SW = bits [1:0]:
    ///   00 = MSI, 01 = HSI16, 10 = HSE, 11 = PLLR (= PLLCLK)
    /// RCC_CFGR.SWS = bits [3:2] reflects current source.
    pub fn switch_sysclk_to_pll(&self) {
        // Safety: writing SW field of CFGR initiates SYSCLK source switch.
        unsafe {
            let cfgr = read_register(self.regs, RCC_CFGR_BASE_OFFSET);
            let new = (cfgr & !0b11) | 0b11;  // SW = 11 (PLLR)
            write_register(self.regs, RCC_CFGR_BASE_OFFSET, new);
        }
        // Poll SWS until 11 (PLLR is now the active SYSCLK).
        loop {
            // Safety: read-only poll of SWS.
            let cfgr = unsafe { read_register(self.regs, RCC_CFGR_BASE_OFFSET) };
            if ((cfgr >> 2) & 0b11) == 0b11 { break; }
        }
    }

    /// Route USART1 kernel clock to HSI16 (16 MHz) instead of PCLK2.
    /// RCC_CCIPR1.USART1SEL = bits [1:0]:
    ///   00 = PCLK2 (default — varies with SYSCLK)
    ///   01 = SYSCLK
    ///   10 = HSI16
    ///   11 = LSE
    ///
    /// Used only on L562 (the L552 board uses LPUART1, which is already
    /// routed to LSE via select_lse_to_lpuart1). Routing USART1 to HSI16
    /// makes the BRR fixed across SYSCLK changes.
    #[cfg(feature = "stm32l562")]
    pub fn select_usart1_hsi16(&self) {
        // Safety: CCIPR1 controls peripheral kernel clock muxes; modifying
        // USART1SEL takes effect at the next BRR write.
        unsafe {
            let ccipr1 = read_register(self.regs, RCC_CCIPR1_BASE_OFFSET);
            let new = (ccipr1 & !0b11) | 0b10;  // USART1SEL = 10 = HSI16
            write_register(self.regs, RCC_CCIPR1_BASE_OFFSET, new);
        }
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
