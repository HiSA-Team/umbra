// Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>
// DWT cycle counter driver for Cortex-M33 (STM32L5).
// Used by the benchmark module to measure short code windows with
// 1-cycle resolution. At 110 MHz the 32-bit counter wraps every ~39 s;
// always use `elapsed` (which wraps correctly) rather than a plain
// subtraction on readings.

use arm::mmio::{DEMCR, DWT_CTRL, DWT_CYCCNT};

const DEMCR_TRCENA_BIT: u32 = 1 << 24;
const DWT_CTRL_CYCCNTENA: u32 = 1 << 0;

/// Enable the DWT cycle counter and zero it. Safe to call multiple times.
pub fn enable() {
    unsafe {
        core::ptr::write_volatile(DEMCR, core::ptr::read_volatile(DEMCR) | DEMCR_TRCENA_BIT);
        core::ptr::write_volatile(DWT_CYCCNT, 0);
        core::ptr::write_volatile(
            DWT_CTRL,
            core::ptr::read_volatile(DWT_CTRL) | DWT_CTRL_CYCCNTENA,
        );
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

#[cfg(test)]
mod tests {
    //! Host-side tests for the pure-SW `elapsed` wraparound semantics.
    //! `enable` / `read` touch DWT MMIO and are not testable off-chip.
    use super::elapsed;

    #[test]
    fn elapsed_normal_case() {
        assert_eq!(elapsed(100, 500), 400);
    }

    #[test]
    fn elapsed_wraparound() {
        // At 110 MHz DWT_CYCCNT wraps every ~39 s. `elapsed` must use
        // wrapping_sub so a measurement window that straddles the wrap
        // still yields the true cycle count.
        assert_eq!(elapsed(u32::MAX - 10, 5), 16);
    }

    #[test]
    fn elapsed_zero() {
        assert_eq!(elapsed(42, 42), 0);
    }

    #[test]
    fn elapsed_full_wrap_boundary() {
        // start == 0, end == u32::MAX → all but one cycle of the counter.
        assert_eq!(elapsed(0, u32::MAX), u32::MAX);
        // One more cycle wraps to 0, giving an elapsed of u32::MAX + 1 mod 2^32 == 0.
        // Verify the wrap explicitly: end == start (full revolution) reads as 0.
        assert_eq!(elapsed(u32::MAX, u32::MAX - 1), u32::MAX);
    }
}
