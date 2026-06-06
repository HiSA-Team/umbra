//! NSC veneer `_imp` implementations for STM32L552.
//! # Pattern: every `*_imp` follows the same template
//! 1. Validate NS-supplied arguments (range, length, nullness). F1 fix
//! lives here.
//! 2. Acquire the Secure-side state needed (CryptoEngine handle, Platform
//! handle, DMA reservation).
//! 3. Perform the operation.
//! 4. Return a `u32` status code — the 6-veneer surface is FROZEN per the
//! NSC ABI spec, no `extern "C"` arg shape changes allowed.
//! # NSC ABI invariants (CJ4 of the threat model)
//! - Every `*_imp` symbol is `pub extern "C"` (the SG instruction expects
//! this calling convention).
//! - Every `*_imp` symbol has `#[link_section = ".umbra_api_implementation"]`
//! so the linker places it in the NSC-callable section.
//! - The 6-veneer surface is FROZEN. Adding a 7th requires an ADR plus a
//! threat-model update — see `the audit report
//! # umbra_debug_print_imp F1 fix ()
//! Pointer range + 256-byte length bound are MANDATORY. See the NSC
//! veneer audit doc for the original finding. Do NOT revert to an
//! unbounded `print_cstr` — that re-introduces the NS-controlled
//! arbitrary-Secure-read primitive that the fix closed.

pub mod arg_validation;
pub mod debug_print;
pub mod enclave_create;
pub mod enclave_enter;
pub mod enclave_exit;
pub mod enclave_status;

pub use debug_print::*;

use umbra_error::UmbraError;

/// Map a typed [`UmbraError`] onto the frozen NSC ABI `u32` status code.
///
/// The NS→S veneers (`umbra_enclave_*_imp`) are `extern "C" -> u32`; an
/// `UmbraError` cannot cross that boundary, so the veneers compute typed
/// errors internally and funnel them through this single translation point.
/// Every code is `>= 0xFFFF_FFF0`, which is the error sentinel band the NS
/// hosts test (`id >= 0xFFFF_FFF0` ⇒ failure — see `host/.../main.c`); the
/// hosts do NOT branch on the specific value, so the exact mapping is free
/// to be 1:1 per variant for log/diagnosis clarity.
pub(crate) fn nsc_status(e: UmbraError) -> u32 {
    match e {
        UmbraError::EnclaveNotFound { .. } => 0xFFFF_FFF0,
        UmbraError::EnclaveStateInvalid => 0xFFFF_FFF2,
        UmbraError::EnclaveAlreadyLoaded { .. } => 0xFFFF_FFF4,
        UmbraError::DmaTimeout => 0xFFFF_FFF5,
        UmbraError::NscArgInvalid { .. } => 0xFFFF_FFF6,
        UmbraError::OffsetOverflow => 0xFFFF_FFF7,
        UmbraError::MeasurementMismatch { .. } => 0xFFFF_FFF8,
        UmbraError::MemProtectDenied { .. } => 0xFFFF_FFF9,
        UmbraError::KeyDerivation => 0xFFFF_FFFA,
        UmbraError::LengthMismatch => 0xFFFF_FFFB,
        UmbraError::HashHardware => 0xFFFF_FFFC,
        UmbraError::EssRegionExhausted => 0xFFFF_FFFD,
        UmbraError::AesHardware => 0xFFFF_FFFE,
        UmbraError::InternalInvariant { .. } => 0xFFFF_FFFF,
    }
}
