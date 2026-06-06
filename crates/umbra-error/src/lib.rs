//! Unified error type for the Umbra TEE.
//! Replaces the ad-hoc `Result<T, ()>` returns that
//! currently saturate the kernel with a typed enum that carries
//! context (what failed, why, what to inspect). Each variant names a
//! single failure mode tied to one of the four crown jewels (CJ1-CJ4)
//! or to a specific kernel subsystem (ESS, NSC, enclave lifecycle).
//! # scope (this commit)
//! Defines the enum skeleton with the most common variants. The
//! migration of existing `Result<T, ()>` call sites is **incremental**:
//! - The migration of existing `Result<T, ()>` call sites is incremental — NSC
//!   veneer entry/exit + kernel public API.
//! - migrates the deeper internal sites alongside the
//!   `umbra-api` crate refactor ().
//! # Design notes
//! - **`Copy` + `'static`**: every variant must be cheap to clone and
//!   carry no borrowed data, so `?` propagation through deep call
//!   chains doesn't impose lifetime gymnastics on the kernel.
//! - **`thiserror-no-std`**: gives `Display` + `Error` impls without
//!   pulling `std`; safe for the bare-metal Secure-side build and the
//!   host-side mem builds alike.
//! - **HW-specific subtypes via `From` impls**: trait-associated error
//!   types (`Hash::Error`, `Aes::Error`) carry HW-specific failure
//!   info (CRYP1 BUSY-timeout, HASH STARTERR bit, etc.). They convert
//!   into the relevant `UmbraError` variant via `From` impls landing
//!   in.

#![no_std]

use thiserror_no_std::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum UmbraError {
    // ── NSC boundary ────────────────────────────────────────────────────
    /// NSC veneer received an invalid argument (out-of-range pointer,
    /// length overflow, malformed handle). CJ4 — guards the only NS→S
    /// entry surface.
    #[error("NSC argument invalid: {which}")]
    NscArgInvalid { which: &'static str },

    // ── Enclave lifecycle ──────────────────────────────────────────────
    #[error("Enclave not found: id={id}")]
    EnclaveNotFound { id: u32 },
    #[error("Enclave already loaded: id={id}")]
    EnclaveAlreadyLoaded { id: u32 },
    #[error("Enclave state machine invariant violated")]
    EnclaveStateInvalid,

    // ── Chained measurement / crown jewel CJ2 ──────────────────────────
    /// Measurement HMAC did NOT match the expected value. First 8 bytes
    /// of each side are carried for diagnostic + UART log inspection
    /// without leaking the full digest off-chip.
    #[error("Measurement mismatch (expected={expected:?}, got={got:?})")]
    MeasurementMismatch { expected: [u8; 8], got: [u8; 8] },

    // ── Crypto hardware ────────────────────────────────────────────────
    #[error("Hash hardware error")]
    HashHardware,
    #[error("AES hardware error")]
    AesHardware,
    #[error("Key derivation failed")]
    KeyDerivation,

    // ── DMA / memory protection / crown jewel CJ3 ──────────────────────
    #[error("DMA timeout")]
    DmaTimeout,
    #[error("ESS region exhausted")]
    EssRegionExhausted,
    /// A memory-protection / isolation controller denied access at `addr`.
    /// Platform-generic: covers GTZC+MPCBB (STM32L5), RIFSC (STM32N6), and a
    /// future RISC-V PMP/PMA backend. The `addr` is the faulting block base so
    /// a kernel-log reader can map it to the offending ESS slot.
    #[error("Memory protection denied at addr=0x{addr:08X}")]
    MemProtectDenied { addr: u32 },

    // ── Integer / offset / size arithmetic ─────────────────────────────
    #[error("Offset overflow")]
    OffsetOverflow,
    #[error("Length mismatch")]
    LengthMismatch,

    // ── Catch-all for internal invariants ──────────────────────────────
    /// Use sparingly — every new use here is a candidate for a more
    /// specific variant. audit will sweep these.
    #[error("Internal invariant violated: {context}")]
    InternalInvariant { context: &'static str },
}

/// Convenience type alias. Use throughout the kernel + drivers in
/// place of `Result<T, ()>`.
pub type UmbraResult<T> = Result<T, UmbraError>;
