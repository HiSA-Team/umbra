//! DWT-based drift instrumentation + periodic heartbeat marker.
//!
//! Mirrors the FreeRTOS host's `vApplicationTickHook` + `vHeartbeatTask`
//! ([host/stm32l552/freertos/src/main.c]); UART output matches verbatim
//! except for the `[TOCK]`/`[FREERTOS]` prefix.
//!
//! The board owns NS SysTick exclusively (Tock's `SchedulerTimer` is `()`
//! — see board crate). [`init`] configures RVR/CSR once like FreeRTOS's
//! `prvSetupTimerInterrupt`; the SysTick exception then fires
//! [`_umbra_heartbeat_tick`] which updates stats atomically.
//!
//! IRQ context deliberately does NOT print: NS SysTick can preempt
//! Secure-thread-mode code (default `AIRCR.PRIS=0`), so a print from the
//! handler would splice into Umbra Secure's own UART writes mid-message.
//! All `[HEARTBEAT]` + `[DRIFT]` lines are emitted atomically by
//! [`_umbra_drift_dump`] (capsule cmd=6) at end-of-run, with `IN_DUMP=1`
//! holding off any future IRQ-context emitters.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::raw_print;

const DEMCR: *mut u32 = 0xE000_EDFC as *mut u32;
const DWT_CTRL: *mut u32 = 0xE000_1000 as *mut u32;
const DWT_CYCCNT: *mut u32 = 0xE000_1004 as *mut u32;
const DEMCR_TRCENA: u32 = 1 << 24;
const DWT_CTRL_CYCCNTENA: u32 = 1;

// NS SysTick is banked from Secure SysTick; these accesses go through the
// NS view automatically when the CPU is in NS state.
const SYST_CSR: *mut u32 = 0xE000_E010 as *mut u32;
const SYST_RVR: *mut u32 = 0xE000_E014 as *mut u32;
const SYST_CVR: *mut u32 = 0xE000_E018 as *mut u32;
const SYST_CSR_CLKSOURCE: u32 = 1 << 2;
const SYST_CSR_TICKINT: u32 = 1 << 1;
const SYST_CSR_ENABLE: u32 = 1 << 0;

/// SysTick reload (~1 ms at 16 MHz nominal CPU clock, or ~145 µs once the
/// PLL bump to 110 MHz is active).
const SYSTICK_RELOAD: u32 = 16_000 - 1;

/// Yardstick for bucket assignment — per-tick DWT delta target.
const EXPECTED_CYC_PER_TICK: u32 = 16_000;

/// Cycles between successive `[HEARTBEAT]` markers — 100 ms at 16 MHz
/// (matches FreeRTOS's `vHeartbeatTask` cadence).
const HEARTBEAT_PERIOD_CYC: u32 = 1_600_000;

static LAST_DWT: AtomicU32 = AtomicU32::new(0);
static LAST_HEARTBEAT_DWT: AtomicU32 = AtomicU32::new(0);
static MAX_DELTA: AtomicU32 = AtomicU32::new(0);
static TOTAL_TICKS: AtomicU32 = AtomicU32::new(0);
static HEARTBEAT_COUNT: AtomicU32 = AtomicU32::new(0);
static BUCKETS: [AtomicU32; 6] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];

/// True while `_umbra_drift_dump` is mid-print. Held for any future
/// IRQ-context emitter that would otherwise interleave with the dump.
static IN_DUMP: AtomicBool = AtomicBool::new(false);

/// Enable the DWT cycle counter and program NS SysTick. Call once at boot
/// before the Tock kernel starts the scheduler.
pub fn init() {
    // SAFETY: DEMCR + DWT + SYST registers live in the System Control Space
    // at 0xE0000000 — always NS-accessible on Cortex-M33, not GTZC-gated.
    unsafe {
        let demcr = DEMCR.read_volatile();
        DEMCR.write_volatile(demcr | DEMCR_TRCENA);
        DWT_CYCCNT.write_volatile(0);
        let ctrl = DWT_CTRL.read_volatile();
        DWT_CTRL.write_volatile(ctrl | DWT_CTRL_CYCCNTENA);

        // RVR before CVR (ARMv8-M Architecture Reference Manual §B3.3.2);
        // CVR := 0 forces a reload on the next cycle.
        SYST_RVR.write_volatile(SYSTICK_RELOAD);
        SYST_CVR.write_volatile(0);
        SYST_CSR.write_volatile(SYST_CSR_CLKSOURCE | SYST_CSR_TICKINT | SYST_CSR_ENABLE);
    }
}

/// Per-tick callback invoked by `_umbra_systick_handler`. Runs in SysTick
/// handler mode on MSP with same-or-lower-priority interrupts masked.
#[unsafe(no_mangle)]
pub extern "C" fn _umbra_heartbeat_tick() {
    // SAFETY: DWT_CYCCNT is a free-running counter at a fixed architectural
    // address; read_volatile is the canonical access.
    let now = unsafe { DWT_CYCCNT.read_volatile() };
    let last = LAST_DWT.swap(now, Ordering::Relaxed);
    let delta = now.wrapping_sub(last);

    TOTAL_TICKS.fetch_add(1, Ordering::Relaxed);

    let mut current_max = MAX_DELTA.load(Ordering::Relaxed);
    while delta > current_max {
        match MAX_DELTA.compare_exchange_weak(
            current_max,
            delta,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => current_max = actual,
        }
    }

    let expected = EXPECTED_CYC_PER_TICK;
    let bucket = if delta < expected * 3 / 2 {
        0
    } else if delta < expected * 2 {
        1
    } else if delta < expected * 5 {
        2
    } else if delta < expected * 10 {
        3
    } else if delta < expected * 100 {
        4
    } else {
        5
    };
    BUCKETS[bucket].fetch_add(1, Ordering::Relaxed);

    // Count heartbeat moments here; the dump emits the lines later
    // (no UART writes from IRQ context — see module docstring).
    let last_hb = LAST_HEARTBEAT_DWT.load(Ordering::Relaxed);
    if now.wrapping_sub(last_hb) >= HEARTBEAT_PERIOD_CYC {
        LAST_HEARTBEAT_DWT.store(now, Ordering::Relaxed);
        HEARTBEAT_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

/// Emit the end-of-run heartbeat + drift snapshot. Called by the capsule's
/// cmd=6 DUMP_DRIFT path. Replays one `[HEARTBEAT t=0xN]` line per
/// accumulated interval (capped at 64) then the `[DRIFT]` line.
#[unsafe(no_mangle)]
pub extern "C" fn _umbra_drift_dump() {
    IN_DUMP.store(true, Ordering::Relaxed);

    let hb_count = HEARTBEAT_COUNT.load(Ordering::Relaxed);
    let max_delta = MAX_DELTA.load(Ordering::Relaxed);
    let total = TOTAL_TICKS.load(Ordering::Relaxed);
    let buckets: [u32; 6] = [
        BUCKETS[0].load(Ordering::Relaxed),
        BUCKETS[1].load(Ordering::Relaxed),
        BUCKETS[2].load(Ordering::Relaxed),
        BUCKETS[3].load(Ordering::Relaxed),
        BUCKETS[4].load(Ordering::Relaxed),
        BUCKETS[5].load(Ordering::Relaxed),
    ];

    // Cap replay at 64 lines so long runs don't burn many seconds of UART.
    let to_print = if hb_count > 64 { 64 } else { hb_count };
    for i in 0..to_print {
        raw_print::print_str("[HEARTBEAT t=0x");
        raw_print::print_hex(i + 1);
        raw_print::print_str("]\r\n");
    }

    raw_print::print_str("[DRIFT] max=0x");
    raw_print::print_hex(max_delta);
    raw_print::print_str(" total=0x");
    raw_print::print_hex(total);
    raw_print::print_str("\r\n[DRIFT]");
    for (i, b) in buckets.iter().enumerate() {
        raw_print::print_str(" b");
        raw_print::print_u32(i as u32);
        raw_print::print_str("=0x");
        raw_print::print_hex(*b);
    }
    raw_print::print_str("\r\n");

    IN_DUMP.store(false, Ordering::Relaxed);
}
