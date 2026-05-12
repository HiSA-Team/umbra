// Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>
//
// DWT cycle counter driver for Cortex-M33 (STM32L5).
// Used by the benchmark module to measure short code windows with
// 1-cycle resolution. At 110 MHz the 32-bit counter wraps every ~39 s;
// always use `elapsed` (which wraps correctly) rather than a plain
// subtraction on readings.

use arm::mmio::{DEMCR, DWT_CTRL, DWT_CYCCNT};

const DEMCR_TRCENA_BIT:    u32 = 1 << 24;
const DWT_CTRL_CYCCNTENA:  u32 = 1 << 0;

/// Enable the DWT cycle counter and zero it. Safe to call multiple times.
pub fn enable() {
    unsafe {
        core::ptr::write_volatile(DEMCR, core::ptr::read_volatile(DEMCR) | DEMCR_TRCENA_BIT);
        core::ptr::write_volatile(DWT_CYCCNT, 0);
        core::ptr::write_volatile(DWT_CTRL, core::ptr::read_volatile(DWT_CTRL) | DWT_CTRL_CYCCNTENA);
    }
}

/// Read the current cycle count.
#[inline(always)]
pub fn read() -> u32 {
    unsafe { core::ptr::read_volatile(DWT_CYCCNT) }
}

/// Compute elapsed cycles between two readings, handling 32-bit wrap.
#[inline(always)]
pub fn elapsed(start: u32, end: u32) -> u32 {
    end.wrapping_sub(start)
}
