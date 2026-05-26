//! STM32L552 interrupt vector table.
//!
//! Two static arrays are emitted:
//!   - [`BASE_VECTORS`] — 16-entry Cortex-M33 exception table (`.vectors`)
//!   - [`IRQS`] — 110-entry peripheral IRQ table (`.irqs`), sized for the
//!     full IRQ space per RM0438 rev 6 Table 76.
//!
//! All IRQ slots point at `CortexM33::GENERIC_ISR` except where a peripheral
//! has a dedicated handler. SysTick slot 15 routes to the board-owned
//! [`_umbra_systick_handler`] (heartbeat / drift instrumentation).

use cortexm33::{initialize_ram_jump_to_main, unhandled_interrupt, CortexM33, CortexMVariant};

extern "C" {
    /// `_estack` is a linker symbol at the top of the NS stack; declared
    /// `extern "C" fn()` only because the vector slot type requires it.
    fn _estack();

    /// Heartbeat tick callback provided by the board crate. Called from
    /// the SysTick wrapper below.
    fn _umbra_heartbeat_tick();
}

/// SysTick exception wrapper. The board owns NS SysTick exclusively (Tock's
/// `SchedulerTimer` is set to the never-expires `()` stub), so the timer is
/// configured once in `heartbeat::init` and runs continuously — the way
/// FreeRTOS owns SysTick via `prvSetupTimerInterrupt`.
///
/// The standard cortex-v7m SysTick handler forces a kernel-mode return on
/// every tick (`msr CONTROL,#0; bfc lr,#2,#1`). That sequence is for "time
/// slice expired" semantics, which doesn't apply here — heartbeat just
/// updates stats and returns to whatever was running (app PSP-unpriv or
/// kernel MSP-priv), making the tick transparent.
#[cfg(all(target_arch = "arm", target_os = "none"))]
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _umbra_systick_handler() {
    core::arch::naked_asm!(
        "
    push {{r4, lr}}
    bl _umbra_heartbeat_tick
    pop {{r4, lr}}
    bx lr
        "
    );
}

#[cfg(not(all(target_arch = "arm", target_os = "none")))]
pub unsafe extern "C" fn _umbra_systick_handler() {}

#[cfg_attr(
    all(target_arch = "arm", target_os = "none"),
    link_section = ".vectors"
)]
#[cfg_attr(all(target_arch = "arm", target_os = "none"), used)]
pub static BASE_VECTORS: [unsafe extern "C" fn(); 16] = [
    _estack,
    initialize_ram_jump_to_main,
    unhandled_interrupt,            // NMI
    CortexM33::HARD_FAULT_HANDLER,  // HardFault
    unhandled_interrupt,            // MemManageFault
    unhandled_interrupt,            // BusFault
    unhandled_interrupt,            // UsageFault
    unhandled_interrupt,            // SecureFault
    unhandled_interrupt,            // Reserved
    unhandled_interrupt,            // Reserved
    unhandled_interrupt,            // Reserved
    CortexM33::SVC_HANDLER,         // SVCall
    unhandled_interrupt,            // DebugMonitor
    unhandled_interrupt,            // Reserved
    unhandled_interrupt,            // PendSV
    _umbra_systick_handler,         // SysTick
];

#[cfg_attr(
    all(target_arch = "arm", target_os = "none"),
    link_section = ".irqs"
)]
#[cfg_attr(all(target_arch = "arm", target_os = "none"), used)]
pub static IRQS: [unsafe extern "C" fn(); 110] = [
    CortexM33::GENERIC_ISR, // 0   WWDG
    CortexM33::GENERIC_ISR, // 1   PVD_PVM
    CortexM33::GENERIC_ISR, // 2   RTC
    CortexM33::GENERIC_ISR, // 3   RTC_S
    CortexM33::GENERIC_ISR, // 4   TAMP
    CortexM33::GENERIC_ISR, // 5   TAMP_S
    CortexM33::GENERIC_ISR, // 6   FLASH
    CortexM33::GENERIC_ISR, // 7   FLASH_S
    CortexM33::GENERIC_ISR, // 8   GTZC
    CortexM33::GENERIC_ISR, // 9   RCC
    CortexM33::GENERIC_ISR, // 10  RCC_S
    CortexM33::GENERIC_ISR, // 11  EXTI0
    CortexM33::GENERIC_ISR, // 12  EXTI1
    CortexM33::GENERIC_ISR, // 13  EXTI2
    CortexM33::GENERIC_ISR, // 14  EXTI3
    CortexM33::GENERIC_ISR, // 15  EXTI4
    CortexM33::GENERIC_ISR, // 16  EXTI5
    CortexM33::GENERIC_ISR, // 17  EXTI6
    CortexM33::GENERIC_ISR, // 18  EXTI7
    CortexM33::GENERIC_ISR, // 19  EXTI8
    CortexM33::GENERIC_ISR, // 20  EXTI9
    CortexM33::GENERIC_ISR, // 21  EXTI10
    CortexM33::GENERIC_ISR, // 22  EXTI11
    CortexM33::GENERIC_ISR, // 23  EXTI12
    CortexM33::GENERIC_ISR, // 24  EXTI13
    CortexM33::GENERIC_ISR, // 25  EXTI14
    CortexM33::GENERIC_ISR, // 26  EXTI15
    CortexM33::GENERIC_ISR, // 27  DMAMUX_OVR
    CortexM33::GENERIC_ISR, // 28  CORDIC
    CortexM33::GENERIC_ISR, // 29  DMA1_Channel1
    CortexM33::GENERIC_ISR, // 30  DMA1_Channel2
    CortexM33::GENERIC_ISR, // 31  DMA1_Channel3
    CortexM33::GENERIC_ISR, // 32  DMA1_Channel4
    CortexM33::GENERIC_ISR, // 33  DMA1_Channel5
    CortexM33::GENERIC_ISR, // 34  DMA1_Channel6
    CortexM33::GENERIC_ISR, // 35  DMA1_Channel7
    CortexM33::GENERIC_ISR, // 36  DMA1_Channel8
    CortexM33::GENERIC_ISR, // 37  ADC1_2
    CortexM33::GENERIC_ISR, // 38  DAC
    CortexM33::GENERIC_ISR, // 39  FDCAN1_IT0
    CortexM33::GENERIC_ISR, // 40  FDCAN1_IT1
    CortexM33::GENERIC_ISR, // 41  EXTI9_5
    CortexM33::GENERIC_ISR, // 42  TIM1_BRK
    CortexM33::GENERIC_ISR, // 43  TIM1_UP
    CortexM33::GENERIC_ISR, // 44  TIM1_TRG_COM
    CortexM33::GENERIC_ISR, // 45  TIM1_CC
    CortexM33::GENERIC_ISR, // 46  TIM2
    CortexM33::GENERIC_ISR, // 47  TIM3
    CortexM33::GENERIC_ISR, // 48  TIM4
    CortexM33::GENERIC_ISR, // 49  TIM5
    CortexM33::GENERIC_ISR, // 50  TIM6_DAC_UNDER
    CortexM33::GENERIC_ISR, // 51  TIM7
    CortexM33::GENERIC_ISR, // 52  TIM8_BRK
    CortexM33::GENERIC_ISR, // 53  TIM8_UP
    CortexM33::GENERIC_ISR, // 54  TIM8_TRG_COM
    CortexM33::GENERIC_ISR, // 55  TIM8_CC
    CortexM33::GENERIC_ISR, // 56  I2C3_EV
    CortexM33::GENERIC_ISR, // 57  I2C3_ER
    CortexM33::GENERIC_ISR, // 58  SPI3
    CortexM33::GENERIC_ISR, // 59  UART4
    CortexM33::GENERIC_ISR, // 60  UART5
    CortexM33::GENERIC_ISR, // 61  LPTIM1
    CortexM33::GENERIC_ISR, // 62  LPTIM2
    CortexM33::GENERIC_ISR, // 63  TIM15
    CortexM33::GENERIC_ISR, // 64  TIM16
    CortexM33::GENERIC_ISR, // 65  TIM17
    CortexM33::GENERIC_ISR, // 66  COMP
    CortexM33::GENERIC_ISR, // 67  USB_FS
    CortexM33::GENERIC_ISR, // 68  CRS
    CortexM33::GENERIC_ISR, // 69  FMC
    CortexM33::GENERIC_ISR, // 70  LPUART1
    CortexM33::GENERIC_ISR, // 71  OCTOSPI1
    CortexM33::GENERIC_ISR, // 72  PWR_S3WU
    CortexM33::GENERIC_ISR, // 73  SDMMC1
    CortexM33::GENERIC_ISR, // 74  I2C1_EV
    CortexM33::GENERIC_ISR, // 75  I2C1_ER
    CortexM33::GENERIC_ISR, // 76  I2C2_EV
    CortexM33::GENERIC_ISR, // 77  I2C2_ER
    CortexM33::GENERIC_ISR, // 78  I2C4_EV
    CortexM33::GENERIC_ISR, // 79  I2C4_ER
    CortexM33::GENERIC_ISR, // 80  SPI1
    CortexM33::GENERIC_ISR, // 81  SPI2
    CortexM33::GENERIC_ISR, // 82  USART1
    CortexM33::GENERIC_ISR, // 83  USART2
    CortexM33::GENERIC_ISR, // 84  USART3
    CortexM33::GENERIC_ISR, // 85  SAI1
    CortexM33::GENERIC_ISR, // 86  SAI2
    CortexM33::GENERIC_ISR, // 87  TSC
    CortexM33::GENERIC_ISR, // 88  AES
    CortexM33::GENERIC_ISR, // 89  RNG
    CortexM33::GENERIC_ISR, // 90  FPU
    CortexM33::GENERIC_ISR, // 91  HASH
    CortexM33::GENERIC_ISR, // 92  PKA
    CortexM33::GENERIC_ISR, // 93  LPTIM3
    CortexM33::GENERIC_ISR, // 94  Reserved
    CortexM33::GENERIC_ISR, // 95  Reserved
    CortexM33::GENERIC_ISR, // 96  Reserved
    CortexM33::GENERIC_ISR, // 97  LPTIM4
    CortexM33::GENERIC_ISR, // 98  LPTIM5
    CortexM33::GENERIC_ISR, // 99  LPUART2 (L562 only)
    CortexM33::GENERIC_ISR, // 100 Reserved
    CortexM33::GENERIC_ISR, // 101 Reserved
    CortexM33::GENERIC_ISR, // 102 Reserved
    CortexM33::GENERIC_ISR, // 103 Reserved
    CortexM33::GENERIC_ISR, // 104 Reserved
    CortexM33::GENERIC_ISR, // 105 OCTOSPI2 (L562 only)
    CortexM33::GENERIC_ISR, // 106 Reserved
    CortexM33::GENERIC_ISR, // 107 Reserved
    CortexM33::GENERIC_ISR, // 108 ICACHE
    CortexM33::GENERIC_ISR, // 109 Reserved
];

/// Disable all peripheral IRQs, clear pending state, set VTOR to
/// [`BASE_VECTORS`], enable the per-fault handlers (so MemManage / BusFault
/// / UsageFault populate CFSR instead of escalating to HardFault), then
/// re-enable IRQs. Call once early in `main`.
pub unsafe fn init() {
    cortexm33::nvic::disable_all();
    cortexm33::nvic::clear_all_pending();

    let vector_table: *const [unsafe extern "C" fn(); 16] = core::ptr::addr_of!(BASE_VECTORS);
    let vector_table: *const () = vector_table.cast();
    cortexm33::scb::set_vector_table_offset(vector_table);

    // Enable MEMFAULTENA / BUSFAULTENA / USGFAULTENA in SHCSR. The cortexm
    // crate only exposes CLEAR helpers so we touch the register directly.
    const SHCSR: *mut u32 = 0xE000_ED24 as *mut u32;
    // SAFETY: SCB MMIO; called once from main() on the boot thread.
    unsafe {
        let v = core::ptr::read_volatile(SHCSR);
        core::ptr::write_volatile(SHCSR, v | (1 << 16) | (1 << 17) | (1 << 18));
    }

    cortexm33::nvic::enable_all();
}
