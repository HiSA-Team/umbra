//! Minimal RCC + PWR driver for STM32L5xx (NS alias).
//!
//! Wires the bring-up clock tree: HSI16 → SYSCLK, LSE crystal for LPUART1,
//! PWR + GPIOG + LPUART1 peripheral clocks. All RCC writes go through the
//! NS alias (0x40021000) — Umbra Secure has already opened up RCC for NS.
//! PLL, MSI, HSE, peripheral resets, low-power modes, and PVD are out of
//! scope.

use kernel::utilities::registers::interfaces::{ReadWriteable, Readable};
use kernel::utilities::registers::{register_bitfields, register_structs, ReadWrite};
use kernel::utilities::StaticRef;

const RCC_BASE: StaticRef<RccRegisters> =
    unsafe { StaticRef::new(0x4002_1000 as *const RccRegisters) };

const PWR_BASE: StaticRef<PwrRegisters> =
    unsafe { StaticRef::new(0x4000_7000 as *const PwrRegisters) };

register_structs! {
    pub RccRegisters {
        (0x000 => cr: ReadWrite<u32, CR::Register>),
        (0x004 => icscr: ReadWrite<u32>),
        (0x008 => cfgr: ReadWrite<u32, CFGR::Register>),
        (0x00C => pllcfgr: ReadWrite<u32>),
        (0x010 => pllsai1cfgr: ReadWrite<u32>),
        (0x014 => pllsai2cfgr: ReadWrite<u32>),
        (0x018 => cier: ReadWrite<u32>),
        (0x01C => cifr: ReadWrite<u32>),
        (0x020 => cicr: ReadWrite<u32>),
        (0x024 => _reserved0),
        (0x028 => ahb1rstr: ReadWrite<u32>),
        (0x02C => ahb2rstr: ReadWrite<u32>),
        (0x030 => ahb3rstr: ReadWrite<u32>),
        (0x034 => _reserved1),
        (0x038 => apb1rstr1: ReadWrite<u32>),
        (0x03C => apb1rstr2: ReadWrite<u32>),
        (0x040 => apb2rstr: ReadWrite<u32>),
        (0x044 => _reserved2),
        (0x048 => ahb1enr: ReadWrite<u32>),
        (0x04C => ahb2enr: ReadWrite<u32, AHB2ENR::Register>),
        (0x050 => ahb3enr: ReadWrite<u32>),
        (0x054 => _reserved3),
        (0x058 => apb1enr1: ReadWrite<u32, APB1ENR1::Register>),
        (0x05C => apb1enr2: ReadWrite<u32, APB1ENR2::Register>),
        (0x060 => apb2enr: ReadWrite<u32>),
        (0x064 => _reserved4),
        (0x088 => ccipr1: ReadWrite<u32, CCIPR1::Register>),
        (0x08C => _reserved5),
        (0x090 => bdcr: ReadWrite<u32, BDCR::Register>),
        (0x094 => csr: ReadWrite<u32>),
        (0x098 => crrcr: ReadWrite<u32>),
        (0x09C => ccipr2: ReadWrite<u32>),
        (0x0A0 => @END),
    }
}

register_structs! {
    /// PWR map truncated to CR1 + CR2 (DBP + IOSV are the only bits we touch
    /// during backup-domain unlock for LSE).
    pub PwrRegisters {
        (0x00 => cr1: ReadWrite<u32, PWRCR1::Register>),
        (0x04 => cr2: ReadWrite<u32, PWRCR2::Register>),
        (0x08 => @END),
    }
}

register_bitfields![u32,
    CR [
        HSION  OFFSET(8)  NUMBITS(1) [],
        HSIRDY OFFSET(10) NUMBITS(1) []
    ],
    CFGR [
        SW    OFFSET(0) NUMBITS(2) [
            Msi   = 0b00,
            Hsi16 = 0b01,
            Hse   = 0b10,
            Pll   = 0b11
        ],
        SWS   OFFSET(2) NUMBITS(2) [
            Msi   = 0b00,
            Hsi16 = 0b01,
            Hse   = 0b10,
            Pll   = 0b11
        ],
        HPRE  OFFSET(4)  NUMBITS(4) [],
        PPRE1 OFFSET(8)  NUMBITS(3) [],
        PPRE2 OFFSET(11) NUMBITS(3) []
    ],
    AHB2ENR [
        GPIOGEN OFFSET(6) NUMBITS(1) []
    ],
    APB1ENR1 [
        PWREN OFFSET(28) NUMBITS(1) []
    ],
    APB1ENR2 [
        LPUART1EN OFFSET(0) NUMBITS(1) []
    ],
    CCIPR1 [
        LPUART1SEL OFFSET(10) NUMBITS(2) [
            Pclk   = 0b00,
            Sysclk = 0b01,
            Hsi16  = 0b10,
            Lse    = 0b11
        ]
    ],
    BDCR [
        LSEON     OFFSET(0)  NUMBITS(1) [],
        LSERDY    OFFSET(1)  NUMBITS(1) [],
        LSESYSEN  OFFSET(7)  NUMBITS(1) [],
        LSESYSRDY OFFSET(11) NUMBITS(1) [],
        LSCOEN    OFFSET(24) NUMBITS(1) [],
        LSCOSEL   OFFSET(25) NUMBITS(1) []
    ],
    PWRCR1 [
        /// Disable backup-domain write protection (required before BDCR writes).
        DBP OFFSET(8) NUMBITS(1) []
    ],
    PWRCR2 [
        /// VDDIO2 supply valid — must be set to unlock GPIOG[15:2] (PG7/PG8).
        IOSV OFFSET(9) NUMBITS(1) []
    ]
];

/// Enable HSI16 and switch SYSCLK to it (16 MHz, no PLL, bus prescalers /1).
pub fn init() {
    let rcc = RCC_BASE;
    rcc.cr.modify(CR::HSION::SET);
    while !rcc.cr.is_set(CR::HSIRDY) {}
    rcc.cfgr.modify(CFGR::SW::Hsi16);
    while rcc.cfgr.read(CFGR::SWS) != 0b01 {}
}

/// Required before `enable_lse` — the backup-domain DBP unlock lives in PWR.
pub fn enable_pwr() {
    RCC_BASE.apb1enr1.modify(APB1ENR1::PWREN::SET);
}

/// Unlock backup domain, enable LSE crystal, wait until system-ready.
pub fn enable_lse() {
    let pwr = PWR_BASE;
    let rcc = RCC_BASE;

    pwr.cr1.modify(PWRCR1::DBP::SET);
    pwr.cr2.modify(PWRCR2::IOSV::SET);

    // LSCOEN/LSCOSEL routes LSE onto the MCO pin — a side effect of mirroring
    // the Secure-side enable_lse() sequence for HW parity. Drop both lines if
    // the MCO pin is ever reclaimed.
    rcc.bdcr.modify(BDCR::LSCOEN::SET);
    rcc.bdcr.modify(BDCR::LSCOSEL::SET);

    rcc.bdcr.modify(BDCR::LSEON::SET);
    while !rcc.bdcr.is_set(BDCR::LSERDY) {}

    rcc.bdcr.modify(BDCR::LSESYSEN::SET);
    while !rcc.bdcr.is_set(BDCR::LSESYSRDY) {}
}

pub fn select_lse_for_lpuart1() {
    RCC_BASE.ccipr1.modify(CCIPR1::LPUART1SEL::Lse);
}

pub fn enable_gpio_port_g() {
    RCC_BASE.ahb2enr.modify(AHB2ENR::GPIOGEN::SET);
}

pub fn enable_lpuart1() {
    RCC_BASE.apb1enr2.modify(APB1ENR2::LPUART1EN::SET);
}
