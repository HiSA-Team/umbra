//! Raise the FSBL Hide-Protection Level (HDPL1 → HDPL2) just before the
//! NS handoff. The DHUK wrap/share runs at HDPL1; once the FSBL bumps HDPL
//! to 2, the SAES derives a *different* DHUK, so the HDPL1 DHUK that wrapped
//! `enc_key` can no longer be re-derived by the NS world or by enclaves. The
//! key already shared into CRYP (KEYVALID persists across the bump) keeps
//! working for runtime enclave decrypt — HDPL gates key *derivation*, not
//! peripheral access. RM0486 ch02 §3–4.
//!
//! ## The encoding landmine
//! `BSEC_HDPLSR` low byte is NOT the raw level 0/1/2/3 — it is a fixed 8-bit
//! code per level (STM32Cube HAL `stm32n6xx_hal_bsec.h`):
//!   HDPL0=0xB4  HDPL1=0x51  HDPL2=0x8A  HDPL3=0x6F
//! Comparing the register against the integer `2` would always fail.
//!
//! ## Reversibility
//! HDPL is a counter reset to 0 on POR/cold reset — no OTP fuse is burned. A
//! bad config recovers with a power cycle, so this is safe to validate on the
//! open Nucleo (matches the "debug always open" constraint).

#[cfg(target_arch = "arm")]
use crate::raw_print::{print_hex, print_str};

/// BSEC Secure alias (CMSIS `BSEC_BASE_S` = APB4PERIPH_BASE_S + 0x9000).
#[cfg(target_arch = "arm")]
const BSEC_BASE: u32 = 0x5600_9000;
#[cfg(target_arch = "arm")]
const BSEC_HDPLSR: u32 = BSEC_BASE + 0xE94;
#[cfg(target_arch = "arm")]
const BSEC_HDPLCR: u32 = BSEC_BASE + 0xE98;

/// Writing this magic code to `HDPLCR` increments the monotonic HDPL counter
/// by one (HAL `BSEC_HDPL_INCREMENT_CODE`). No decrement/wrap exists.
#[cfg(target_arch = "arm")]
const HDPL_INCREMENT_CODE: u32 = 0x60B1_66E7;

const HDPL_MASK: u32 = 0xFF;
const HDPL_VALUE_2: u32 = 0x8A;

/// True iff the `HDPLSR` raw read decodes to HDPL2. Pure + `const` so the
/// encoding table (the landmine above) is checked at compile time below.
const fn is_hdpl2(hdplsr_raw: u32) -> bool {
    hdplsr_raw & HDPL_MASK == HDPL_VALUE_2
}

/// Raise HDPL1 → HDPL2 before the NS handoff. Prints the before/after encoded
/// level; panics (fail-fast loop) if the counter does not land on HDPL2 — a
/// stuck HDPL means the DHUK-isolation invariant is broken and continuing to
/// NS would silently keep the HDPL1 DHUK derivable.
#[cfg(target_arch = "arm")]
pub fn raise_hdpl_to_2() {
    // SAFETY: BSEC_HDPLSR/HDPLCR are valid Secure MMIO at the CMSIS-confirmed
    // base; only the FSBL (running Secure at HDPL1) touches them, before NS.
    let before = unsafe { core::ptr::read_volatile(BSEC_HDPLSR as *const u32) };
    if is_hdpl2(before) {
        // Idempotent: already at HDPL2 (e.g. a re-entry). Nothing to do.
        print_str("[UMBRASecureBoot] HDPL already 2\r\n");
        return;
    }
    print_str("[UMBRASecureBoot] HDPL before=0x");
    print_hex(before & HDPL_MASK);
    // SAFETY: single magic-code write that increments the counter; see above.
    unsafe {
        core::ptr::write_volatile(BSEC_HDPLCR as *mut u32, HDPL_INCREMENT_CODE);
        core::arch::asm!("dsb");
    }
    let after = unsafe { core::ptr::read_volatile(BSEC_HDPLSR as *const u32) };
    print_str(" after=0x");
    print_hex(after & HDPL_MASK);
    print_str("\r\n");
    if !is_hdpl2(after) {
        print_str("[UMBRASecureBoot] HDPL raise FAIL — halt\r\n");
        loop {}
    }
    print_str("[UMBRASecureBoot] HDPL raised to 2 (DHUK@1 now unrecoverable)\r\n");
}

// Compile-time guard for the encoding landmine: decode must follow the HAL
// code table, not the raw integer level. Costs nothing, can't rot.
const _: () = assert!(is_hdpl2(0x8A)); // HDPL2 code
const _: () = assert!(is_hdpl2(0xDEAD_BE8A)); // only the low byte matters
const _: () = assert!(!is_hdpl2(0x51)); // HDPL1
const _: () = assert!(!is_hdpl2(2)); // raw level 2 is NOT the encoding
