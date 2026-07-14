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

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

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

// ── HASH completion IRQ (SHA-256, HASH_IRQn = 39) ───────────────────────────
// The plain-SHA-256 hot path (checkpoint `read_digest`) runs inside the SVC#2
// exception handler, so the HASH IRQ must be able to PREEMPT SVC. Give HASH the
// most-urgent priority (0x00) and lower SVC + SysTick to 0x40: they stay equal so
// SysTick still can't preempt a running checkpoint, while HASH (0x00 < 0x40) can.
// Enclave preemption by SysTick (SysTick < thread) is unaffected.

/// Set by the HASH DCIS ISR; reset by [`hash_arm`].
pub static HASH_DONE: AtomicBool = AtomicBool::new(false);
/// Diagnostic: number of times the HASH ISR fired (proves the IRQ path works).
pub static HASH_IRQ_HITS: AtomicU32 = AtomicU32::new(0);

const HASH_IMR: u32 = 0x5402_0420; // DCIE = bit 1
const HASH_SR_ADDR: u32 = 0x5402_0424; // DCIS = bit 1
const HASH_IMR_DCIE: u32 = 1 << 1;
const HASH_SR_DCIS: u32 = 1 << 1;
const HASH_IRQ_BIT: u32 = 1 << (39 - 32); // HASH_IRQn = 39 -> ISER1 bit 7
const NVIC_IPR39: u32 = 0xE000_E400 + 39; // per-IRQ priority byte for IRQ 39
const SHPR2: u32 = 0xE000_ED1C; // SVCall priority in bits [31:24]
const SHPR3: u32 = 0xE000_ED20; // SysTick priority in bits [31:24]
const PRIO_LOWER: u32 = 0x40; // SVC + SysTick (level 4 of 16 with 4 prio bits)
const HASH_WAIT_BUDGET: u32 = 2_000_000;

static HASH_SETUP_DONE: AtomicBool = AtomicBool::new(false);

/// One-time (idempotent): lower SVC + SysTick to 0x40 so the HASH IRQ (0x00) can
/// preempt the SVC handler while SysTick still can't, give HASH the most-urgent
/// priority, and enable its NVIC line.
fn hash_irq_setup() {
    if HASH_SETUP_DONE.swap(true, Ordering::SeqCst) {
        return;
    }
    // SAFETY: RMW the top priority byte of SHPR2/SHPR3 (SVCall/SysTick), set the
    // HASH per-IRQ priority byte, clear stale pending, and enable the NVIC line.
    unsafe {
        let s2 = core::ptr::read_volatile(SHPR2 as *const u32);
        core::ptr::write_volatile(SHPR2 as *mut u32, (s2 & 0x00FF_FFFF) | (PRIO_LOWER << 24));
        let s3 = core::ptr::read_volatile(SHPR3 as *const u32);
        core::ptr::write_volatile(SHPR3 as *mut u32, (s3 & 0x00FF_FFFF) | (PRIO_LOWER << 24));
        core::ptr::write_volatile(NVIC_IPR39 as *mut u8, 0x00); // HASH most-urgent
        core::ptr::write_volatile(NVIC_ICPR1 as *mut u32, HASH_IRQ_BIT); // clear stale pending
        core::ptr::write_volatile(NVIC_ISER1 as *mut u32, HASH_IRQ_BIT); // enable IRQ 39
    }
}

/// Per-hash: run the one-time setup, reset the done flag, and unmask the HASH DCIS
/// interrupt. Call after INIT + feed, immediately before triggering DCAL.
#[allow(dead_code)]
pub fn hash_arm() {
    hash_irq_setup();
    HASH_DONE.store(false, Ordering::SeqCst);
    // SAFETY: unmask DCIE — device register.
    unsafe {
        let imr = core::ptr::read_volatile(HASH_IMR as *const u32);
        core::ptr::write_volatile(HASH_IMR as *mut u32, imr | HASH_IMR_DCIE);
    }
}

/// Called by `handlers.rs::HASH_IRQHandler`. Masks DCIE so the level-triggered IRQ
/// can't re-fire before the next [`hash_arm`] (DCIS stays set — harmless, HR holds
/// the digest until INIT), records the hit, and posts [`HASH_DONE`].
#[allow(dead_code)]
pub fn on_hash_irq() {
    // SAFETY: mask DCIE — device register.
    unsafe {
        let imr = core::ptr::read_volatile(HASH_IMR as *const u32);
        core::ptr::write_volatile(HASH_IMR as *mut u32, imr & !HASH_IMR_DCIE);
    }
    HASH_IRQ_HITS.fetch_add(1, Ordering::SeqCst);
    HASH_DONE.store(true, Ordering::SeqCst);
}

/// Wait for the HASH digest. The ISR posts [`HASH_DONE`] (it now preempts even the
/// SVC handler); DCIS is a fail-safe fallback so this can never hang — the digest
/// always completes in bounded time. Masks DCIE on exit in case the fallback ran.
#[allow(dead_code)]
pub fn block_until_hash_done() {
    let mut left = HASH_WAIT_BUDGET;
    while !HASH_DONE.load(Ordering::Acquire) {
        // SAFETY: read the HASH status register — device register.
        if unsafe { core::ptr::read_volatile(HASH_SR_ADDR as *const u32) } & HASH_SR_DCIS != 0 {
            break;
        }
        if left == 0 {
            break;
        }
        left -= 1;
    }
    // SAFETY: ensure DCIE is masked even if the ISR did not run (fallback path).
    unsafe {
        let imr = core::ptr::read_volatile(HASH_IMR as *const u32);
        core::ptr::write_volatile(HASH_IMR as *mut u32, imr & !HASH_IMR_DCIE);
    }
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
