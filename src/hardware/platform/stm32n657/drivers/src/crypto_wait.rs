//! `CryptoWait` — the single seam every coarse crypto wait uses (issue #45).
//!
//! The SAES completion (`CCF`) wait is the only place the boot blocks on the
//! crypto engine, and it must be impossible to hang here. The DHUK wrap/share
//! runs before SysTick (or any periodic interrupt) exists, so a `WFI` would have
//! no wake source and would sleep forever if the SAES op never completes — e.g.
//! the VBAT backup domain is unpowered, so DHUK never derives. Instead
//! [`block_until_done`] busy-polls the ISR-posted [`CRYPTO_DONE`] flag with a
//! hard budget and returns `Err(Timeout)` when it elapses; the caller
//! (`saes::wait_ccf`) panics fail-closed rather than hanging or continuing on a
//! broken crypto path.
//!
//! The IRQ wiring ([`arm`]/[`disarm`]/[`on_saes_irq`]) is kept as the
//! completion-posting seam: a future preemptive kernel can replace the busy
//! budget with a scheduler yield without touching the call sites.
//!
//! Register wiring (CMSIS `stm32n657xx.h`): `SAES_IER` @ 0x5402_1300 `CCFIE`
//! bit 0; `SAES_IRQn` = 36 → NVIC ISER1 bit 4.

use core::sync::atomic::{AtomicBool, Ordering};

/// Set by the SAES completion ISR; cleared by [`arm`].
pub static CRYPTO_DONE: AtomicBool = AtomicBool::new(false);

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoWaitError {
    Timeout,
}

const SAES_IER: u32 = 0x5402_1300;
const SAES_IER_CCFIE: u32 = 1 << 0;
const SAES_ICR: u32 = 0x5402_1308; // write CCF bit to clear the flag
const ICR_CCF: u32 = 1 << 0;
const NVIC_ISER1: u32 = 0xE000_E104; // IRQ 32..63 set-enable
const NVIC_ICER1: u32 = 0xE000_E184; // IRQ 32..63 clear-enable
const NVIC_ICPR1: u32 = 0xE000_E284; // IRQ 32..63 clear-pending
const SAES_IRQ_BIT: u32 = 1 << (36 - 32); // SAES_IRQn = 36

/// Called by the SAES1 ISR (`handlers.rs::SAES1_IRQHandler`). Records
/// completion, clears the CCF flag (deasserts the IRQ line), and disables the
/// CCF interrupt enable so it cannot re-fire before the next [`arm`].
#[allow(dead_code)]
pub fn on_saes_irq() {
    // SAFETY: device-register writes to clear CCF + disable the CCF IRQ enable.
    unsafe {
        core::ptr::write_volatile(SAES_ICR as *mut u32, ICR_CCF);
        let ier = core::ptr::read_volatile(SAES_IER as *const u32);
        core::ptr::write_volatile(SAES_IER as *mut u32, ier & !SAES_IER_CCFIE);
    }
    CRYPTO_DONE.store(true, Ordering::SeqCst);
}

/// Reset the done flag and enable the SAES completion IRQ + its NVIC line.
/// Firmware-only MMIO; host tests call [`block_until_done`] directly.
#[allow(dead_code)]
pub fn arm() {
    CRYPTO_DONE.store(false, Ordering::SeqCst);
    // SAFETY: clear any stale NVIC pending, enable the SAES CCF interrupt and
    // its NVIC line — device registers, idempotent writes. Enabling CCFIE while
    // CCF is already set fires the IRQ immediately (level flag), so arm() may be
    // called after the trigger.
    unsafe {
        core::ptr::write_volatile(NVIC_ICPR1 as *mut u32, SAES_IRQ_BIT);
        let ier = core::ptr::read_volatile(SAES_IER as *const u32);
        core::ptr::write_volatile(SAES_IER as *mut u32, ier | SAES_IER_CCFIE);
        core::ptr::write_volatile(NVIC_ISER1 as *mut u32, SAES_IRQ_BIT);
    }
}

/// Disable the SAES completion IRQ + its NVIC line.
#[allow(dead_code)]
pub fn disarm() {
    // SAFETY: disabling the SAES CCF interrupt and its NVIC line — device
    // registers, idempotent writes.
    unsafe {
        let ier = core::ptr::read_volatile(SAES_IER as *const u32);
        core::ptr::write_volatile(SAES_IER as *mut u32, ier & !SAES_IER_CCFIE);
        core::ptr::write_volatile(NVIC_ICER1 as *mut u32, SAES_IRQ_BIT);
    }
}

/// Busy-poll the ISR-posted [`CRYPTO_DONE`] flag until it is set or `budget`
/// iterations elapse. Always terminates: there is no `WFI`, so a never-firing
/// crypto IRQ (e.g. a stalled SAES op on an unpowered backup domain) trips the
/// budget and returns `Err(Timeout)` instead of hanging the boot. The caller
/// fails closed (panics) on `Err`. The SAES ISR preempts this loop on
/// completion and posts [`CRYPTO_DONE`], so the common path exits promptly.
pub fn block_until_done(budget: u32) -> Result<(), CryptoWaitError> {
    let mut left = budget;
    while !CRYPTO_DONE.load(Ordering::SeqCst) {
        if left == 0 {
            return Err(CryptoWaitError::Timeout);
        }
        left -= 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One test (not two) because `CRYPTO_DONE` is a shared global — parallel
    /// tests would race on it. Timeout path then done path, sequentially.
    #[test]
    fn block_times_out_then_returns_ok_when_done() {
        CRYPTO_DONE.store(false, Ordering::SeqCst);
        assert_eq!(
            block_until_done(8),
            Err(CryptoWaitError::Timeout),
            "no done flag within budget -> fail-closed"
        );

        CRYPTO_DONE.store(true, Ordering::SeqCst);
        assert_eq!(block_until_done(8), Ok(()), "done flag set -> Ok");
        CRYPTO_DONE.store(false, Ordering::SeqCst);
    }
}
