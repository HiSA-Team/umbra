#![cfg(feature = "stm32l562")]
#![allow(dead_code, unused_imports)]

// Memory-mapped 1-8-8 bringup for the MX25LM51245G Octa-SPI flash on the
// STM32L562E-DK. Pin assignment (per the L562E-DK schematic / UM2617):
// NCS = PA2 AF10
// CLK = PA3 AF10
// IO3 = PA6 AF10
// IO2 = PA7 AF10
// IO1 = PB0 AF10
// IO0 = PB1 AF10
// DQS = PB2 AF10
// IO4 = PC0 AF10
// IO5 = PC1 AF10
// IO6 = PC2 AF10
// IO7 = PC3 AF10

use peripheral_regs::{MmioAccess, RealMmio};

use crate::gpio::{self, Gpio, PinMode, Port};
use crate::rcc::{self, Rcc};

use super::{
    OspiDriver, OCTOSPI1_BASE_ADDR, OCTOSPI_CR_OFFSET, OCTOSPI_DCR1_OFFSET, OCTOSPI_DCR2_OFFSET,
};

impl OspiDriver<RealMmio> {
    pub fn new() -> Self {
        let rcc = Rcc::new();
        rcc.enable_clock(rcc::peripherals::OSPI1);
        rcc.select_ospi_clock_source_sysclk();
        rcc.reset_ospi();
        Self {
            mmio: RealMmio::new(OCTOSPI1_BASE_ADDR),
            base: OCTOSPI1_BASE_ADDR,
        }
    }
}

impl<M: MmioAccess> OspiDriver<M> {
    /// Constructor for host-side tests — accepts any `MmioAccess` backend.
    /// On firmware build, callers use `OspiDriver::new()` which monomorphises
    /// to `OspiDriver<RealMmio>` and inlines the volatile accesses.
    /// Skips the Rcc clock enable + reset_ospi sequence because Rcc itself
    /// is generic over MMIO but its inherent `new()` materialises a
    /// hardware-backed `RealMmio` against the RCC base address — calling it
    /// on host would issue a `read_volatile` against an unmapped page. Tests
    /// inject MMIO state via `MmioMem::preload_register` instead.
    #[allow(dead_code)]
    pub fn new_with_mmio(mmio: M) -> Self {
        Self {
            mmio,
            base: OCTOSPI1_BASE_ADDR,
        }
    }

    /// Initialize GPIOs + OCTOSPI1 to a quiescent state ready for
    /// `enable_memory_mapped_octa()`. Configures the 11 L562E-DK OCTOSPI1
    /// pins (see file header) to AF10 with the GPIO defaults that are
    /// already set by the existing `gpio` driver (push-pull, no pull, and
    /// reset-state max speed).
    ///
    /// Thin wrapper that materialises the HW-singleton drivers (Rcc, Gpio
    /// for each port) and delegates the orchestration to
    /// [`init_with_drivers`](Self::init_with_drivers). The split exists so
    /// host tests can exercise the orchestration logic with
    /// `MmioMem`-backed drivers — `Rcc::new` / `Gpio::new` materialise
    /// `RealMmio` against physical addresses and segfault on host.
    pub fn init(&self) {
        let rcc = Rcc::new();
        let gpioa = Gpio::new(Port::GpioA);
        let gpiob = Gpio::new(Port::GpioB);
        let gpioc = Gpio::new(Port::GpioC);
        self.init_with_drivers(&rcc, &gpioa, &gpiob, &gpioc);
    }

    /// Host-testable variant of [`init`](Self::init).
    ///
    /// Performs the same orchestration as `init`, but against caller-
    /// supplied driver instances. The firmware path goes through `init`
    /// which materialises the HW-singleton variants; tests inject
    /// `MmioMem`-backed instances so every per-peripheral access is
    /// observable in its respective write log.
    ///
    /// Register sequence (cold-path order-sensitive):
    /// 1. RCC `enable_clock` for GPIOA, GPIOB, GPIOC.
    /// 2. GPIOA pins 2, 3, 6, 7 → AlternateFunction + AF10.
    /// 3. GPIOB pins 0, 1, 2 → AlternateFunction + AF10.
    /// 4. GPIOC pin 0 → AlternateFunction + AF3; pins 1, 2, 3 → AF10.
    /// 5. OCTOSPI register bringup (delegated to
    ///    [`configure_octospi_dcr_and_enable`](Self::configure_octospi_dcr_and_enable)).
    pub(crate) fn init_with_drivers<R, G>(
        &self,
        rcc: &Rcc<R>,
        gpioa: &Gpio<G>,
        gpiob: &Gpio<G>,
        gpioc: &Gpio<G>,
    ) where
        R: MmioAccess,
        G: MmioAccess,
    {
        // --- 1. GPIO clocks ---
        rcc.enable_clock(rcc::peripherals::GPIOA);
        rcc.enable_clock(rcc::peripherals::GPIOB);
        rcc.enable_clock(rcc::peripherals::GPIOC);

        // PA2 (NCS), PA3 (CLK), PA6 (IO3), PA7 (IO2) — AF10.
        for pin in [2u8, 3, 6, 7] {
            gpioa.set_mode(pin, PinMode::AlternateFunction);
            gpioa.set_alternate_function(pin, 10);
        }

        // PB0 (IO1), PB1 (IO0), PB2 (DQS) — AF10.
        for pin in [0u8, 1, 2] {
            gpiob.set_mode(pin, PinMode::AlternateFunction);
            gpiob.set_alternate_function(pin, 10);
        }

        // PC0 (IO4) uses AF3 on the L562E-DK muxing; PC1..PC3 (IO5..IO7) are
        // AF10. Confirmed against STMicro's STM32CubeL5
        // Projects/STM32L562E-DK/Examples/OTFDEC/OTFDEC_ExecutingCryptedInstruction
        // stm32l5xx_hal_msp.c HAL_OSPI_MspInit.
        gpioc.set_mode(0, PinMode::AlternateFunction);
        gpioc.set_alternate_function(0, 3);
        for pin in [1u8, 2, 3] {
            gpioc.set_mode(pin, PinMode::AlternateFunction);
            gpioc.set_alternate_function(pin, 10);
        }

        // --- 2-5. OCTOSPI register configuration (cold-path order-sensitive). ---
        self.configure_octospi_dcr_and_enable();
    }

    /// L562 cold-boot territory — disable→DCR1→DCR2→enable register write
    /// recipe must NOT be reordered (see file header on the
    /// `init_external_flash` OCTOSPI state machine sensitivity). Routes
    /// every access through `self.mmio` so host tests can record the
    /// sequence without touching silicon.
    pub(crate) fn configure_octospi_dcr_and_enable(&self) {
        // --- 2. Disable OCTOSPI before configuring ---
        let cr = self.mmio.read(OCTOSPI_CR_OFFSET);
        self.mmio.write(OCTOSPI_CR_OFFSET, cr & !(1 << 0)); // EN=0

        // --- 3. DCR1: MTYP=Standard(0), DEVSIZE=25 (64 MB), CSHT=3 ---
        // MTYP bits [26:24] = 000 (Standard SPI / Micron-compatible —
        // suits 1-1-1 FAST_READ, no DQS)
        // DEVSIZE bits [20:16] = 25 (2^(25+1) = 64 MB, MX25LM51245G)
        // CSHT bits [13:8] = 3 (4 cycles between CS toggles)
        let dcr1 = (0b000u32 << 24) | (25u32 << 16) | (3u32 << 8);
        self.mmio.write(OCTOSPI_DCR1_OFFSET, dcr1);

        // --- 4. DCR2: prescaler = 7 → OCTOSPI = SYSCLK/8 = 13.75 MHz @ 110 MHz SYSCLK.
        // PRESCALER field bits [7:0] encode divider as (N+1).
        // MX25LM51245G in 1-1-1 SPI mode handles Page Program / Sector
        // Erase reliably below ~20 MHz; above ~30 MHz the cold-path OFD
        // encrypt + Page Program starts failing silently (reset back to
        // RSS via TZ fault) on the STM32L562E-DK. /8 = 13.75 MHz leaves
        // a 2× margin to the safe
        // ceiling and keeps memory-mapped reads fast enough that they
        // don't dominate the L562 enclave fetch path.
        self.mmio.write(OCTOSPI_DCR2_OFFSET, 0x0000_0007);

        // --- 5. Re-enable OCTOSPI ---
        let cr2 = self.mmio.read(OCTOSPI_CR_OFFSET);
        self.mmio.write(OCTOSPI_CR_OFFSET, cr2 | (1 << 0)); // EN=1
    }

    /// Bringup trace char — emits a single byte over UART via the kernel's
    /// `serial.write_byte` path. Placeholder here.
    pub fn bringup_trace(&self, _c: u8) {
        // Intentionally empty
    }
}

// L562 init-orchestration tests live in a sibling file. The whole module
// is already `#![cfg(feature = "stm32l562")]`, so a plain `#[cfg(test)]`
// gate is sufficient.
#[cfg(test)]
#[path = "init_l562_tests.rs"]
mod l562_tests;
