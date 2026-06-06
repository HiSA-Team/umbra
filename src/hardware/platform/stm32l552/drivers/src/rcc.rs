#![allow(dead_code)]

//! Reset and Clock Control driver for STM32L5xxxx — minimal subset for
//! the peripheral set Umbra actually uses.
//! # PLL @ 110 MHz bring-up (production setting)
//! Sysclk path is HSI16 → PLL (M=4, N=55, R=÷2) → 110 MHz, replacing the
//! Boot ROM default of MSI 4 MHz. Wall-time speedup measured on the
//! statemate paper-app: 88s → 5s (17.6× cumulative with T-table AES).
//! ## Required ordering in `platform_impl::init_clocks` (cannot invert)
//! 1. `enable_clock(PWR)` — driver gate on PWR registers
//! 2. `Pwr::set_vos_range_boost()` — Range 0 (Boost), mandatory above 80 MHz
//! 3. `Flash::set_latency_5ws_enable_cache()` — 5 WS + ICEN + DCEN + PRFTEN,
//! mandatory above 60 MHz; less = data corruption on the first PLL tick
//! 4. `Rcc::enable_hsi16()` — clock source for the PLL input
//! 5. `Rcc::enable_pll_hsi16_110mhz()` — PLL config + lock-wait
//! 6. `Rcc::switch_sysclk_to_pll()` — `CFGR.SW = 11`, poll `SWS = 11`
//! 7. L562 only: `Rcc::select_usart1_hsi16()` so the UART baud rate stays
//! sysclk-independent (BRR=417 instead of 1667).
//! Inverting any pair = silent hang or runtime corruption that's brutal
//! to bisect.
//! ## PLLM field is encoded as M-1, NOT M directly
//! Cross-validated against ST HAL's `__HAL_RCC_PLL_PLLM_CONFIG`. To divide
//! HSI16 by 4 (M=4), write `PLLM = 3`. PLLN by contrast stores N directly.
//! Two hours of "PLL won't lock" debugging in 2026-05-24 traced to this.
//! ## L562 OCTOSPI prescaler must move with sysclk
//! Bumping sysclk to 110 MHz raises the OCTOSPI clock ~27.5× (1.3 MHz →
//! 36.7 MHz at the original `/3` divider). The MX25LM51245G's Page Program
//! timing is unreliable above ~20 MHz in 1-1-1 SPI mode. See `ospi.rs`
//! for the matching `DCR2.PRESCALER = 0x07` (/8 → 13.75 MHz) change. The
//! L552 has no OCTOSPI so this is L562-only.
//! ## SysTick reload must stay in sync with sysclk
//! `secure_kernel::SYSTICK_RELOAD` (Rust const) AND the immediate literal
//! in `arm/asm/startup.s::_svc_enter` BOTH must move together. Desync =
//! wrong SysTick period silently, which usually manifests as preemption
//! frequency drift (paper apps either run too long or never preempt).
//! Post-PLL value: 1_099_999 (= 10 ms at 110 MHz).

// Crates
use crate::pwr::Pwr;
use peripheral_regs::{write_register, MmioAccess, RealMmio};

pub(crate) const RCC_BASE_ADDR: u32 = 0x50021000; // Secure
type RccRegisters = u32;

// _____ _ _
// | __ \ (_) | |
// | |__) |___ __ _ _ ___| |_ ___ _ __ ___
// | _ // _ \/ _` | / __| __/ _ \ '__/ __|
// | | \ \ __/ (_| | \__ \ || __/ | \__ \
// |_| \_\___|\__, |_|___/\__\___|_| |___/
// __/ |
// |___/
// TODO: Implement all registers
const RCC_CR_BASE_OFFSET: u32 = 0x000;
const RCC_ICSR_BASE_OFFSET: u32 = 0x004;
const RCC_CFGR_BASE_OFFSET: u32 = 0x008;
const RCC_PLLCFGGR_BASE_OFFSET: u32 = 0x00C;
const RCC_PLLSAI1_CFGR_BASE_OFFSET: u32 = 0x010;
const RCC_PLLSAI2_CFGR_BASE_OFFSET: u32 = 0x014;
const RCC_CIER_BASE_OFFSET: u32 = 0x018;
const RCC_CIFR_BASE_OFFSET: u32 = 0x01C;
const RCC_CICR_BASE_OFFSET: u32 = 0x020;

const RCC_CCIPR1_BASE_OFFSET: u32 = 0x088;
const RCC_BDCR_BASE_OFFSET: u32 = 0x090;
const RCC_CSR_BASE_OFFSET: u32 = 0x094;
const RCC_CRRCR_BASE_OFFSET: u32 = 0x098;
const RCC_CCIPR2_BASE_OFFSET: u32 = 0x09C;
// AHB 1 Regs
const RCC_AHB1RST_BASE_OFFSET: u32 = 0x028;
const RCC_AHB1ENR_BASE_OFFSET: u32 = 0x048;
// AHB 2 Regs
const RCC_AHB2RST_BASE_OFFSET: u32 = 0x02C;
const RCC_AHB2ENR_BASE_OFFSET: u32 = 0x04C;
// AHB 3 Regs
const RCC_AHB3RST_BASE_OFFSET: u32 = 0x030;
const RCC_AHB3ENR_BASE_OFFSET: u32 = 0x050;
// APB 1 Regs
const RCC_APB1RSTR1_BASE_OFFSET: u32 = 0x038;
const RCC_APB1RSTR2_BASE_OFFSET: u32 = 0x03C;
const RCC_APB1ENR1_BASE_OFFSET: u32 = 0x058;
const RCC_APB1ENR2_BASE_OFFSET: u32 = 0x05C;
// APB 2 Regs
const RCC_APB2RSTR_BASE_OFFSET: u32 = 0x040;
const RCC_APB2ENR_BASE_OFFSET: u32 = 0x060;

// ______
// | ____|
// | |__ _ __ _ _ _ __ ___ ___
// | __| | '_ \| | | | '_ ` _ \/ __|
// | |____| | | | |_| | | | | | \__ \
// |______|_| |_|\__,_|_| |_| |_|___/
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
    use super::{Bus, Peripheral};

    // AHB 1
    pub const DMA1: Peripheral = (Bus::AHB1, 0);
    pub const DMA2: Peripheral = (Bus::AHB1, 1);
    pub const FLASH: Peripheral = (Bus::AHB1, 8);
    pub const CRC: Peripheral = (Bus::AHB1, 12);
    pub const TSC: Peripheral = (Bus::AHB1, 16);
    pub const GTZC: Peripheral = (Bus::AHB1, 22);

    // AHB 2
    pub const GPIOA: Peripheral = (Bus::AHB2, 0);
    pub const GPIOB: Peripheral = (Bus::AHB2, 1);
    pub const GPIOC: Peripheral = (Bus::AHB2, 2);
    pub const GPIOD: Peripheral = (Bus::AHB2, 3);
    pub const GPIOE: Peripheral = (Bus::AHB2, 4);
    pub const GPIOF: Peripheral = (Bus::AHB2, 5);
    pub const GPIOG: Peripheral = (Bus::AHB2, 6);
    pub const GPIOH: Peripheral = (Bus::AHB2, 7);
    pub const ADC: Peripheral = (Bus::AHB2, 13);
    pub const AES: Peripheral = (Bus::AHB2, 16);
    pub const HASH: Peripheral = (Bus::AHB2, 17);
    pub const RNG: Peripheral = (Bus::AHB2, 18);
    pub const PKA: Peripheral = (Bus::AHB2, 19);
    pub const OTFDEC: Peripheral = (Bus::AHB2, 21);
    pub const SDMMC1: Peripheral = (Bus::AHB2, 22);

    // AHB 3
    pub const FMC: Peripheral = (Bus::AHB3, 0);
    pub const OSPI1: Peripheral = (Bus::AHB3, 8);

    // APB 1 Reg 1
    pub const TIM2: Peripheral = (Bus::APB1_1, 0);
    pub const TIM3: Peripheral = (Bus::APB1_1, 1);
    pub const TIM4: Peripheral = (Bus::APB1_1, 2);
    pub const TIM5: Peripheral = (Bus::APB1_1, 3);
    pub const TIM6: Peripheral = (Bus::APB1_1, 4);
    pub const TIM7: Peripheral = (Bus::APB1_1, 5);
    pub const RTCAPB: Peripheral = (Bus::APB1_1, 10);
    pub const WWDG: Peripheral = (Bus::APB1_1, 11);
    pub const SPI2: Peripheral = (Bus::APB1_1, 14);
    pub const SPI3: Peripheral = (Bus::APB1_1, 15);
    pub const USART2: Peripheral = (Bus::APB1_1, 17);
    pub const USART3: Peripheral = (Bus::APB1_1, 18);
    pub const USART4: Peripheral = (Bus::APB1_1, 19);
    pub const USART5: Peripheral = (Bus::APB1_1, 20);
    pub const I2C1: Peripheral = (Bus::APB1_1, 21);
    pub const I2C2: Peripheral = (Bus::APB1_1, 22);
    pub const I2C3: Peripheral = (Bus::APB1_1, 23);
    pub const CRSEN: Peripheral = (Bus::APB1_1, 24);
    pub const PWR: Peripheral = (Bus::APB1_1, 28);
    pub const DAC1: Peripheral = (Bus::APB1_1, 29);
    pub const OPAMP: Peripheral = (Bus::APB1_1, 30);
    pub const LPTIM1: Peripheral = (Bus::APB1_1, 31);

    // APB 1 Reg 2
    pub const LPUART1: Peripheral = (Bus::APB1_2, 0);
    pub const I2C4: Peripheral = (Bus::APB1_2, 1);
    pub const LPTIM2: Peripheral = (Bus::APB1_2, 5);
    pub const LPTIM3: Peripheral = (Bus::APB1_2, 6);
    pub const FDCAN1: Peripheral = (Bus::APB1_2, 9);
    pub const USBFS: Peripheral = (Bus::APB1_2, 21);
    pub const UCPD1: Peripheral = (Bus::APB1_2, 23);

    // APB 2
    pub const SYSCFG: Peripheral = (Bus::APB2, 0);
    pub const USART1: Peripheral = (Bus::APB2, 14);
}

/// Generic over the MMIO backend so host
/// tests can inject [`umbra_pal_test::mmio::MmioHandle`]. Default
/// `M = RealMmio` keeps every existing `Rcc::new()` call site unchanged at
/// the source level — the firmware build monomorphises to `Rcc<RealMmio>`
/// and inlines the volatile accesses exactly as before.
pub struct Rcc<M: MmioAccess = RealMmio> {
    mmio: M,
}

impl Rcc<RealMmio> {
    pub fn new() -> Self {
        Self {
            mmio: RealMmio::new(RCC_BASE_ADDR),
        }
    }

    /// Compatibility wrapper kept so existing call sites
    /// (`drivers::rcc::Rcc::set_vtor_ns(0x2000_0000)`) continue to compile
    /// unchanged after the `Rcc<M>` migration. New callers should prefer
    /// the free function `rcc::set_vtor_ns` directly.
    #[allow(dead_code)]
    pub fn set_vtor_ns(vtor_ns: u32) {
        set_vtor_ns(vtor_ns);
    }
}

impl<M: MmioAccess> Rcc<M> {
    /// Constructor for host-side tests — accepts any `MmioAccess` backend.
    /// On firmware build, callers use `Rcc::new()` which monomorphises to
    /// `Rcc<RealMmio>` and inlines the volatile accesses.
    #[allow(dead_code)]
    pub fn new_with_mmio(mmio: M) -> Self {
        Self { mmio }
    }

    pub fn enable_clock(&self, peripheral: Peripheral) {
        match peripheral {
            (Bus::AHB1, bit) => self.mmio.set_bit(RCC_AHB1ENR_BASE_OFFSET, bit),
            (Bus::AHB2, bit) => self.mmio.set_bit(RCC_AHB2ENR_BASE_OFFSET, bit),
            (Bus::AHB3, bit) => self.mmio.set_bit(RCC_AHB3ENR_BASE_OFFSET, bit),
            (Bus::APB1_1, bit) => self.mmio.set_bit(RCC_APB1ENR1_BASE_OFFSET, bit),
            (Bus::APB1_2, bit) => self.mmio.set_bit(RCC_APB1ENR2_BASE_OFFSET, bit),
            (Bus::APB2, bit) => self.mmio.set_bit(RCC_APB2ENR_BASE_OFFSET, bit),
        }
    }

    pub fn enable_lse(&self) {
        // Upper bound on LSE-ready spin polls. The 32.768 kHz crystal can take
        // up to ~2 s to stabilise, so this cap is deliberately huge: at any
        // boot clock it corresponds to many tens of seconds of polling and is
        // only ever reached when the crystal is absent or dead. Hitting it
        // `panic!`s (→ panic-policy: UART log + system reset) instead of the
        // former silent `loop {}`, so a missing LSE surfaces a `[PANIC]` line
        // rather than freezing clock bring-up before "Kernel Initialized".
        const LSE_POLL_LIMIT: u32 = 500_000_000;

        // enable_lse constructs a Pwr HW singleton — only meaningful on the
        // firmware path. Host tests should not invoke this directly; they
        // can exercise the BDCR pokes via the lower-level driver hooks.
        Pwr::new().enable_to_backup_domain();
        // LSCOEN LSCOSEL Enable and select the LSE
        self.mmio.set_bit(RCC_BDCR_BASE_OFFSET, 24);
        self.mmio.set_bit(RCC_BDCR_BASE_OFFSET, 25);
        self.mmio.set_bit(RCC_BDCR_BASE_OFFSET, 0);
        let mut spins = 0u32;
        loop {
            let lse_ready = (self.mmio.read(RCC_BDCR_BASE_OFFSET) >> 1) & 1;
            if lse_ready == 1 {
                break;
            };
            spins += 1;
            if spins >= LSE_POLL_LIMIT {
                panic!("LSE LSERDY timeout");
            }
        }

        // LSESYSEN Enable LSE
        self.mmio.set_bit(RCC_BDCR_BASE_OFFSET, 7);
        let mut spins = 0u32;
        loop {
            let lse_ready = (self.mmio.read(RCC_BDCR_BASE_OFFSET) >> 11) & 1;
            if lse_ready == 1 {
                break;
            };
            spins += 1;
            if spins >= LSE_POLL_LIMIT {
                panic!("LSE LSESYSRDY timeout");
            }
        }
    }

    pub fn select_lse_to_lpuart1(&self) {
        let current_value = self.mmio.read(RCC_CCIPR1_BASE_OFFSET);
        let new_value = current_value | (3 << 10);
        self.mmio.write(RCC_CCIPR1_BASE_OFFSET, new_value);
    }

    // ─── HSI16 + PLL + SYSCLK switch ────────────────────────────────────
    // Reference RM0438 §9.4.1 (RCC_CR), §9.4.4 (PLLCFGR), §9.4.3 (CFGR).
    // Bring-up order from caller (mandatory):
    // 1. PWR_CR1.VOS = Range 0 (Boost) — pwr.rs
    // 2. FLASH_ACR.LATENCY = 5 + ICEN + DCEN + PRF — flash.rs
    // 3. RCC: enable_hsi16()
    // 4. RCC: enable_pll_hsi16_110mhz()
    // 5. RCC: switch_sysclk_to_pll()

    /// Enable HSI16 (16 MHz internal RC) and wait for HSIRDY.
    /// RCC_CR.HSION = bit 8, RCC_CR.HSIRDY = bit 10.
    pub fn enable_hsi16(&self) {
        self.mmio.set_bit(RCC_CR_BASE_OFFSET, 8);
        loop {
            let cr = self.mmio.read(RCC_CR_BASE_OFFSET);
            if (cr & (1 << 10)) != 0 {
                break;
            }
        }
    }

    /// Configure and enable PLL on HSI16.
    /// PLLM field = 3 (bits [7:4], encodes M-1) → M = 4 → PLL input = HSI16/4 = 4 MHz
    /// PLLN = 55 (bits [14:8], value-direct) → VCO = 4 MHz × 55 = 220 MHz
    /// PLLR field = 0 (bits [26:25]) → PLLR divider = 2 → PLLR clock = 110 MHz
    /// PLLREN = 1 (bit 24) → enable PLLR output to SYSCLK
    /// PLLSRC = 2 (bits [1:0]) → 10 = HSI16 as PLL source
    /// Caller MUST have called enable_hsi16() first and set VOS Range 0
    /// + flash 5 WS beforehand.
    /// Encodings per RM0438 §9.4.4 and ST HAL `__HAL_RCC_PLL_PLLM_CONFIG`:
    /// PLLM field = (M - 1), so PLLM=4 stored as field value 3.
    /// PLLN field = N directly (range 8-86).
    /// PLLR field: 00=÷2, 01=÷4, 10=÷6, 11=÷8 — we want ÷2 → 00.
    pub fn enable_pll_hsi16_110mhz(&self) {
        // 1. Make sure PLL is OFF before reconfiguring (RM0438 §9.4.4:
        // PLLCFGR is writable only when PLL is disabled).
        // RCC_CR.PLLON = bit 24.
        self.mmio.clear_bit(RCC_CR_BASE_OFFSET, 24);
        loop {
            let cr = self.mmio.read(RCC_CR_BASE_OFFSET);
            if (cr & (1 << 25)) == 0 {
                break;
            }
        }

        // 2. Write PLLCFGR atomically: PLLSRC=10, PLLM field=3 (M=4),
        // PLLN=55, PLLR=00 (÷2), PLLREN=1.
        // Bit layout: [1:0]=PLLSRC, [7:4]=PLLM, [14:8]=PLLN,
        // [26:25]=PLLR, [24]=PLLREN.
        let pllcfgr: u32 = (0b10  << 0)   // PLLSRC = HSI16
            | (3u32  << 4)   // PLLM field = 3 (encodes M-1 → M=4)
            | (55u32 << 8)   // PLLN   = 55
            | (0u32  << 25)  // PLLR   = ÷2
            | (1u32  << 24); // PLLREN
                             // PLL is disabled (verified above); PLLCFGR is now writable.
        self.mmio.write(RCC_PLLCFGGR_BASE_OFFSET, pllcfgr);

        // 3. Enable PLL and poll PLLRDY (bit 25).
        self.mmio.set_bit(RCC_CR_BASE_OFFSET, 24);
        loop {
            let cr = self.mmio.read(RCC_CR_BASE_OFFSET);
            if (cr & (1 << 25)) != 0 {
                break;
            }
        }
    }

    /// Switch SYSCLK source from current (MSI after reset) to PLL.
    /// RCC_CFGR.SW = bits [1:0]:
    /// 00 = MSI, 01 = HSI16, 10 = HSE, 11 = PLLR (= PLLCLK)
    /// RCC_CFGR.SWS = bits [3:2] reflects current source.
    pub fn switch_sysclk_to_pll(&self) {
        let cfgr = self.mmio.read(RCC_CFGR_BASE_OFFSET);
        let new = (cfgr & !0b11) | 0b11; // SW = 11 (PLLR)
        self.mmio.write(RCC_CFGR_BASE_OFFSET, new);
        // Poll SWS until 11 (PLLR is now the active SYSCLK).
        loop {
            let cfgr = self.mmio.read(RCC_CFGR_BASE_OFFSET);
            if ((cfgr >> 2) & 0b11) == 0b11 {
                break;
            }
        }
    }

    /// Route USART1 kernel clock to HSI16 (16 MHz) instead of PCLK2.
    /// RCC_CCIPR1.USART1SEL = bits [1:0]:
    /// 00 = PCLK2 (default — varies with SYSCLK)
    /// 01 = SYSCLK
    /// 10 = HSI16
    /// 11 = LSE
    /// Used only on L562 (the L552 board uses LPUART1, which is already
    /// routed to LSE via select_lse_to_lpuart1). Routing USART1 to HSI16
    /// makes the BRR fixed across SYSCLK changes.
    #[cfg(feature = "stm32l562")]
    pub fn select_usart1_hsi16(&self) {
        let ccipr1 = self.mmio.read(RCC_CCIPR1_BASE_OFFSET);
        let new = (ccipr1 & !0b11) | 0b10; // USART1SEL = 10 = HSI16
        self.mmio.write(RCC_CCIPR1_BASE_OFFSET, new);
    }

    #[cfg(feature = "stm32l562")]
    pub fn select_ospi_clock_source_sysclk(&self) {
        // CCIPR2.OSPISEL (bits [21:20]) = 00: SYSCLK selected as OCTOSPI clock
        // (00 is default after reset, but we write it explicitly for determinism.)
        let ccipr2 = self.mmio.read(RCC_CCIPR2_BASE_OFFSET);
        let new = ccipr2 & !(0b11 << 20); // Clear OSPISEL → 00 = SYSCLK
        self.mmio.write(RCC_CCIPR2_BASE_OFFSET, new);
    }

    #[cfg(feature = "stm32l562")]
    pub fn reset_ospi(&self) {
        // Pulse AHB3RSTR.OSPI1RST (bit 8) high then low.
        let rst = self.mmio.read(RCC_AHB3RST_BASE_OFFSET);
        self.mmio.write(RCC_AHB3RST_BASE_OFFSET, rst | (1 << 8));
        let _ = self.mmio.read(RCC_AHB3RST_BASE_OFFSET);
        let _ = self.mmio.read(RCC_AHB3RST_BASE_OFFSET);
        self.mmio.write(RCC_AHB3RST_BASE_OFFSET, rst & !(1 << 8));
    }

    #[cfg(feature = "stm32l562")]
    pub fn reset_otfdec(&self) {
        // Pulse AHB2RSTR.OTFDEC1RST (bit 21) high then low. Needed to wipe
        // Region 1 state left over from a previous (non-POR) boot.
        let rst = self.mmio.read(RCC_AHB2RST_BASE_OFFSET);
        self.mmio.write(RCC_AHB2RST_BASE_OFFSET, rst | (1 << 21));
        let _ = self.mmio.read(RCC_AHB2RST_BASE_OFFSET);
        let _ = self.mmio.read(RCC_AHB2RST_BASE_OFFSET);
        self.mmio.write(RCC_AHB2RST_BASE_OFFSET, rst & !(1 << 21));
    }
}

// Sets the Non-Secure VTOR. Placed in `rcc` for convenience as RCC
// initialisation is the earliest boot stage with peripheral access.
// Kept as a free function (not a method on `Rcc<M>`) because it writes to
// a fixed system-control address (`SCB_NS.VTOR @ 0xE002_ED08`) that is
// independent of the RCC base — generic-ifying over the in-memory backend
// would not give a useful host-test surface and would force every caller
// to spell out the monomorphisation.
pub fn set_vtor_ns(vtor_ns: u32) {
    let vtor_ns_addr = 0xE002ED08 as u32;
    // SAFETY: SCB_NS.VTOR is a system-control MMIO register; this is the
    // documented mechanism for the Secure world to install the Non-Secure
    // vector table base.
    unsafe {
        write_register(vtor_ns_addr as *const u32, 0, vtor_ns);
    }
}

// umbra_hal::Rcc adapter.
// Wraps the platform-specific PLL bring-up sequence (PWR boost → FLASH
// latency → HSI16 → PLL → SYSCLK switch) into the trait's
// `init_sysclk_pll()`. The PWR + FLASH register pokes still live in
// the inherent boot code on L552 (they reach across drivers), so the
// adapter is a marker — full sequence migration is follow-up work.
#[derive(Debug)]
pub enum RccError {
    /// Reserved — no failure paths yet defined.
    Unreachable,
}

impl<M: MmioAccess> umbra_hal::Rcc for Rcc<M> {
    type Error = RccError;

    fn init_sysclk_pll(&mut self) -> Result<(), Self::Error> {
        self.enable_hsi16();
        self.enable_pll_hsi16_110mhz();
        self.switch_sysclk_to_pll();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umbra_pal_test::mmio::{MmioMem, MmioOp};

    /// Verifies `enable_clock(GPIOA)` issues a read-modify-write to
    /// RCC_AHB2ENR that sets bit 0 (GPIOAEN) while preserving other bits.
    /// Exercises the AHB2 arm of the bus dispatch.
    #[test]
    fn enable_clock_gpioa_sets_ahb2enr_bit0() {
        let mem = MmioMem::new(RCC_BASE_ADDR);
        // Preload AHB2ENR with bit 7 set (GPIOHEN) — must survive the RMW.
        mem.preload_register(RCC_AHB2ENR_BASE_OFFSET, 1 << 7);

        let rcc = Rcc::<_>::new_with_mmio(mem.handle());
        rcc.enable_clock(peripherals::GPIOA);

        let log = mem.write_log();
        // set_bit = 1 Read + 1 Write.
        assert_eq!(log.len(), 2, "log = {:?}", log);
        match log[0] {
            MmioOp::Read { addr, .. } => {
                assert_eq!(addr, RCC_BASE_ADDR + RCC_AHB2ENR_BASE_OFFSET);
            }
            _ => panic!("expected Read AHB2ENR at position 0, got {:?}", log[0]),
        }
        match log[1] {
            MmioOp::Write { addr, value } => {
                assert_eq!(addr, RCC_BASE_ADDR + RCC_AHB2ENR_BASE_OFFSET);
                // bit 0 (GPIOAEN) set, bit 7 (GPIOHEN) preserved.
                assert_eq!(value, (1 << 0) | (1 << 7));
            }
            _ => panic!("expected Write AHB2ENR at position 1, got {:?}", log[1]),
        }
    }

    /// Verifies `select_lse_to_lpuart1` performs a read-modify-write to
    /// RCC_CCIPR1 that ORs in `0b11 << 10` (LPUART1SEL = LSE) while
    /// preserving other bits.
    #[test]
    fn select_lse_to_lpuart1_ors_ccipr1_bits10_11() {
        let mem = MmioMem::new(RCC_BASE_ADDR);
        // Preload CCIPR1 with an unrelated upper bit so it must survive.
        mem.preload_register(RCC_CCIPR1_BASE_OFFSET, 0x8000_0000);

        let rcc = Rcc::<_>::new_with_mmio(mem.handle());
        rcc.select_lse_to_lpuart1();

        let log = mem.write_log();
        // 1 Read + 1 Write.
        assert_eq!(log.len(), 2, "log = {:?}", log);
        match log[1] {
            MmioOp::Write { addr, value } => {
                assert_eq!(addr, RCC_BASE_ADDR + RCC_CCIPR1_BASE_OFFSET);
                // LPUART1SEL bits [11:10] set to 0b11 (LSE).
                assert_eq!((value >> 10) & 0b11, 0b11);
                // Unrelated upper bit must be preserved.
                assert_eq!(value & 0x8000_0000, 0x8000_0000);
            }
            _ => panic!("expected Write CCIPR1 at position 1, got {:?}", log[1]),
        }
    }

    /// Verifies `enable_clock(LPUART1)` routes to AHB1ENR2 (APB1_2 bus)
    /// at bit 0 — exercises the APB1_2 arm of the bus dispatch and
    /// confirms the offset (0x5C) is wired correctly.
    #[test]
    fn enable_clock_lpuart1_sets_apb1enr2_bit0() {
        let mem = MmioMem::new(RCC_BASE_ADDR);
        let rcc = Rcc::<_>::new_with_mmio(mem.handle());
        rcc.enable_clock(peripherals::LPUART1);

        let log = mem.write_log();
        assert_eq!(log.len(), 2, "log = {:?}", log);
        match log[1] {
            MmioOp::Write { addr, value } => {
                assert_eq!(addr, RCC_BASE_ADDR + RCC_APB1ENR2_BASE_OFFSET);
                assert_eq!(value, 1 << 0);
            }
            _ => panic!("expected Write APB1ENR2 at position 1, got {:?}", log[1]),
        }
    }
}

// L562-only RCC tests live in a sibling file so this module stays
// under the 600-LOC hard cap. The `#[path]` attribute attaches
// `rcc_l562_tests.rs` as a child module with the same `super::*`
// access an inline `mod tests` block would have.
#[cfg(all(test, feature = "stm32l562"))]
#[path = "rcc_l562_tests.rs"]
mod l562_tests;
