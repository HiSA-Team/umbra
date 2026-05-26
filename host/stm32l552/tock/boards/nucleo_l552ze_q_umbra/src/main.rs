//! NUCLEO-L552ZE-Q Tock host board crate.
//!
//! Wires together the chip glue ([`stm32l552::vectors`], [`stm32l5xx::rcc`],
//! GPIO, LPUART1), the Console + Umbra capsules, a RoundRobin scheduler, and
//! the [`heartbeat`] / [`fault_dumper`] / [`raw_print`] modules.
//!
//! Process isolation is provided by the NS-MPU regions Umbra Secure programs
//! during boot — Tock's MPU layer is the [`NoopMpu`] stub. The board owns NS
//! SysTick exclusively for drift instrumentation, so the kernel's
//! `SchedulerTimer` is the never-expires `()` stub (cooperative multitasking).

#![no_std]
#![no_main]

mod fault_dumper;
mod heartbeat;
// `raw_print` writes directly to LPUART1 NS, bypassing Tock's `kernel::debug!`
// / `UartDebugWriter` machinery. Tock master `b35fad8`'s `MuxUart::do_next_op`
// has a sync-callback ordering bug (vendor-patched in
// `lib/tock/capsules/core/src/virtualizers/virtual_uart.rs`), and even with
// the patch `UartDebugWriter`'s 64-byte buffer truncates multi-line dumps —
// raw_print is the reliable path for fault tracing.
mod raw_print;

use capsules_system::process_policies::PanicFaultPolicy;
use capsules_system::scheduler::round_robin::RoundRobinSched;
use kernel::capabilities;
use kernel::component::Component;
use kernel::platform::{KernelResources, SyscallDriverLookup};
use kernel::{create_capability, static_init};

use capsule_umbra::noop_mpu::NoopMpu;
use cortexm33::{CortexM33, CortexMVariant};
use kernel::platform::chip::Chip;

use stm32l552::gpio::{GpioPort, GPIOG_BASE};
use stm32l552::lpuart::Lpuart1;
use stm32l552::rcc;

kernel::stack_size! {0x2000}

pub struct Stm32L552 {
    mpu: NoopMpu,
    userspace_kernel_boundary: cortexm33::syscall::SysCall,
}

impl Stm32L552 {
    /// # Safety
    /// Call exactly once on the boot thread AFTER [`stm32l552::vectors::init`]
    /// has programmed VTOR. Aliases the SysCall hardware singleton otherwise.
    pub unsafe fn new() -> Self {
        Self {
            mpu: NoopMpu,
            userspace_kernel_boundary: cortexm33::syscall::SysCall::new(),
        }
    }
}

impl Chip for Stm32L552 {
    type MPU = NoopMpu;
    type UserspaceKernelBoundary = cortexm33::syscall::SysCall;
    type ThreadIdProvider = cortexm33::thread_id::CortexMThreadIdProvider;

    fn service_pending_interrupts(&self) {
        unsafe {
            while let Some(interrupt) = cortexm33::nvic::next_pending() {
                let n = cortexm33::nvic::Nvic::new(interrupt);
                n.clear_pending();
                n.enable();
            }
        }
    }

    fn has_pending_interrupts(&self) -> bool {
        unsafe { cortexm33::nvic::has_pending() }
    }

    fn mpu(&self) -> &Self::MPU {
        &self.mpu
    }

    fn userspace_kernel_boundary(&self) -> &Self::UserspaceKernelBoundary {
        &self.userspace_kernel_boundary
    }

    fn sleep(&self) {
        unsafe {
            cortexm33::support::wfi();
        }
    }

    unsafe fn with_interrupts_disabled<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        cortexm33::support::with_interrupts_disabled(f)
    }

    unsafe fn print_state(_this: Option<&Self>, writer: &mut dyn core::fmt::Write) {
        CortexM33::print_cortexm_state(writer);
    }
}

const NUM_PROCS: usize = 4;
const FAULT_RESPONSE: PanicFaultPolicy = PanicFaultPolicy {};

type ChipHw = Stm32L552;

pub struct NucleoL552UmbraBoard {
    console: &'static capsules_core::console::Console<'static>,
    umbra: &'static capsule_umbra::UmbraDriver,
    scheduler: &'static RoundRobinSched<'static>,
}

impl SyscallDriverLookup for NucleoL552UmbraBoard {
    fn with_driver<F, R>(&self, driver_num: usize, f: F) -> R
    where
        F: FnOnce(Option<&dyn kernel::syscall::SyscallDriver>) -> R,
    {
        match driver_num {
            capsules_core::console::DRIVER_NUM => f(Some(self.console)),
            capsule_umbra::DRIVER_NUM => f(Some(self.umbra)),
            _ => f(None),
        }
    }
}

impl KernelResources<Stm32L552> for NucleoL552UmbraBoard {
    type SyscallDriverLookup = Self;
    type SyscallFilter = ();
    type ProcessFault = ();
    type Scheduler = RoundRobinSched<'static>;
    /// Never-expires stub; the board owns NS SysTick for heartbeat / drift.
    type SchedulerTimer = ();
    type WatchDog = ();
    type ContextSwitchCallback = ();

    fn syscall_driver_lookup(&self) -> &Self::SyscallDriverLookup {
        self
    }
    fn syscall_filter(&self) -> &Self::SyscallFilter {
        &()
    }
    fn process_fault(&self) -> &Self::ProcessFault {
        &()
    }
    fn scheduler(&self) -> &Self::Scheduler {
        self.scheduler
    }
    fn scheduler_timer(&self) -> &Self::SchedulerTimer {
        &()
    }
    fn watchdog(&self) -> &Self::WatchDog {
        &()
    }
    fn context_switch_callback(&self) -> &Self::ContextSwitchCallback {
        &()
    }
}

#[inline(never)]
unsafe fn start() -> (
    &'static kernel::Kernel,
    NucleoL552UmbraBoard,
    &'static Stm32L552,
) {
    stm32l552::vectors::init();
    heartbeat::init();

    kernel::deferred_call::initialize_deferred_call_state::<
        <ChipHw as Chip>::ThreadIdProvider,
    >();

    // Clock tree: HSI16 → SYSCLK, then enable PWR (DBP unlock), LSE, GPIOG,
    // LPUART1. CCIPR1 selects LSE as LPUART1's input clock; the LPUART BRR
    // formula (256 × f_ck / baud) then yields BRR = 0x369 for 9600 baud.
    rcc::init();
    rcc::enable_pwr();
    rcc::enable_lse();
    rcc::select_lse_for_lpuart1();
    rcc::enable_gpio_port_g();
    rcc::enable_lpuart1();

    // PG7 = LPUART1_TX, PG8 = LPUART1_RX (AF8 per RM0438 Table 24).
    let gpiog = GpioPort::new(GPIOG_BASE);
    gpiog.set_mode_alternate(7, 8);
    gpiog.set_mode_alternate(8, 8);

    let lpuart1 = static_init!(Lpuart1<'static>, Lpuart1::new());
    lpuart1.init();
    lpuart1.write_str("[TOCK] kernel up\r\n");

    // SAFETY: Stm32L552::new must be called once on the boot thread, after
    // VTOR has been programmed (above).
    let chip = static_init!(Stm32L552, unsafe { Stm32L552::new() });

    let processes = components::process_array::ProcessArrayComponent::new()
        .finalize(components::process_array_component_static!(NUM_PROCS));

    let board_kernel = static_init!(kernel::Kernel, kernel::Kernel::new(processes.as_slice()));

    // Lpuart1 implements Configure + Transmit + Receive, so the kernel's
    // blanket `Uart<'a>` impl applies — UartMux can consume it directly.
    let uart_mux = components::console::UartMuxComponent::new(lpuart1, 9600)
        .finalize(components::uart_mux_component_static!());

    let console = components::console::ConsoleComponent::new(
        board_kernel,
        capsules_core::console::DRIVER_NUM,
        uart_mux,
    )
    .finalize(components::console_component_static!());

    components::debug_writer::DebugWriterComponent::new::<
        <ChipHw as Chip>::ThreadIdProvider,
    >(
        uart_mux,
        create_capability!(capabilities::SetDebugWriterCapability),
    )
    .finalize(components::debug_writer_component_static!());

    let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);
    let umbra = static_init!(
        capsule_umbra::UmbraDriver,
        capsule_umbra::UmbraDriver::new(
            board_kernel.create_grant(capsule_umbra::DRIVER_NUM, &grant_cap),
        ),
    );

    let scheduler = components::sched::round_robin::RoundRobinComponent::new(processes)
        .finalize(components::round_robin_component_static!(NUM_PROCS));

    let board = NucleoL552UmbraBoard {
        console,
        umbra,
        scheduler,
    };

    // Linker symbols mark the TBF apps blob (`.apps` section) + the
    // app-memory SRAM region.
    extern "C" {
        static _sapps: u8;
        static _eapps: u8;
        static mut _sappmem: u8;
        static _eappmem: u8;
    }

    let process_management_capability =
        create_capability!(capabilities::ProcessManagementCapability);

    kernel::process::load_processes(
        board_kernel,
        chip,
        core::slice::from_raw_parts(
            core::ptr::addr_of!(_sapps),
            core::ptr::addr_of!(_eapps) as usize - core::ptr::addr_of!(_sapps) as usize,
        ),
        core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(_sappmem),
            core::ptr::addr_of!(_eappmem) as usize
                - core::ptr::addr_of!(_sappmem) as usize,
        ),
        &FAULT_RESPONSE,
        &process_management_capability,
    )
    .unwrap_or_else(|err| {
        kernel::debug!("Error loading processes: {:?}", err);
    });

    raw_print::print_str("[TOCK] init complete, entering kernel loop\r\n");
    let _ = processes;

    (board_kernel, board, chip)
}

#[no_mangle]
pub unsafe fn main() -> ! {
    // Enable the per-fault handlers in SHCSR before anything else so a
    // subsequent MemManage / BusFault / UsageFault populates CFSR instead of
    // escalating to HardFault with CFSR=0.
    unsafe { fault_dumper::shcsr_enable_per_fault_handlers(); }

    let main_loop_capability = create_capability!(capabilities::MainLoopCapability);
    let (board_kernel, platform, chip) = start();

    board_kernel.kernel_loop(
        &platform,
        chip,
        None::<kernel::ipc::IPC<{ NUM_PROCS as u8 }>>.as_ref(),
        &main_loop_capability,
    );
}
