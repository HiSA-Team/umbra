// Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>

//! STM32N657 platform implementation — Secure side runtime.
//! # Scope and decomposition target () — currently 1090 LOC
//! This is the largest single file in the codebase. It bundles seven
//! concerns that will be split:
//! - `boot/` — clock + flash + PWR + MPU + RIF / RIFSC bring-up
//! - `syscall_dispatch/` — SVC and SysTick trampolines (mirrors L552)
//! - `xspi/` — XSPI2 + XSPIM reset + MCE2 region disable + RIFSC unlock
//! - `cache/` — M55 D-cache geometry detection and maintenance helpers
//! - `dma/` — HPDMA1 channel reservation (currently unused —.X
//! reverted, see the post-mortem)
//! - `power/` — sleep / wake / SMPS GPIO drive
//! - `npu/` — NPU0 IRQ wiring + Cube-AI bring-up
//! Until the split, code added here MUST preserve the invariants below.
//! #.0 clock tree contract
//! `init_clocks` brings CPUCLK to 800 MHz, AXI to 400 MHz, HCLK to 200
//! MHz (HPRE=DIV2 to stay inside ST's tested envelope) and USART1 to
//! HSI=64 MHz. The six bring-up landmines (PLL1-active-hang, CPUSWS pos+4,
//! HSIRDY=bit 3, PLL-vs-IC encoding asymmetry, write-1-to-act CSR/CCR,
//! SMPS=GPIO PB12) are documented in `drivers::rcc`'s module docs — read
//! them before touching this `init_clocks`.
//! # M55 cache enable ordering
//! `MEMSYSCTL.MSCR.ICACTIVE` / `DCACTIVE` at `0xE001_E000` must be set
//! BEFORE the standard `SCB.CCR.IC` / `DC` enables. Without this the SCB
//! writes silently no-op — caches stay off and `test_enclave` runs ~12×
//! slower than measured (79 ms instead of 14 ms).
//! # XSPI2 + MCE2 + RIFSC bring-up (.4c lessons)
//! Reset XSPI1 + XSPI2 + XSPIM via RSTSR / RSTCR (NOT via AHB5RSTR, which
//! is read-only on this silicon). All three must be reset before XSPIM
//! configuration because XSPIM is shared and only mutable when every XSPI
//! controller is disabled. Use ST's order: XSPIM clock first, then XSPI2,
//! MODE=0, hclk5. Skipping the reset leaves Boot ROM's CID lock on
//! XSPI2 + XSPIM and the first memory-mapped read faults.
//! # SECCFGR3 re-secure of RISUP 106 (NPU) before enclave entry
//! NPU defaults to NS post-Boot ROM. The enclave-side NPU driver targets
//! the Secure alias `0x580E_xxxx`; without the `SECCFGR3 bit 10` re-secure
//! done at the top of `init_clocks`, the secure-guard NS override fires
//! on the first NPU MMIO and the inference enclave faults before output.

use kernel::platform::PlatformBoot;

pub mod boot;
pub mod dma;
pub mod power;
pub mod syscall_dispatch;

pub struct Stm32n657Platform;

impl Stm32n657Platform {
    pub fn new() -> Self {
        Stm32n657Platform
    }
}

impl PlatformBoot for Stm32n657Platform {
    fn init_clocks(&self) {
        boot::init_clocks()
    }
    fn init_gpio(&self) {
        power::init_gpio()
    }
    fn init_uart(&self) {
        power::init_uart()
    }
    fn init_security(&self) {
        syscall_dispatch::init_security()
    }
    fn init_kernel(&self) {
        power::init_kernel()
    }
    fn init_external_flash(&self) -> bool {
        dma::init_external_flash()
    }
    fn configure_ns_boot(&self) {
        syscall_dispatch::configure_ns_boot()
    }
    fn jump_to_ns(&self) -> ! {
        syscall_dispatch::jump_to_ns()
    }
}
