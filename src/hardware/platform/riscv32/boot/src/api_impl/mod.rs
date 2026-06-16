//! Enclave API — the `ecall` function-id surface the host calls.
//!
//! Mirrors `api_impl/` on the STM32L552 platform (which routes NSC veneers to
//! per-operation handlers). Here the `ecall` trap dispatcher routes by the
//! function id in `a7` to one handler per operation — the RISC-V analog of the
//! NSC-veneer table: the only sanctioned entry surface into the monitor.

use umbra_error::UmbraError;
use umbra_riscv_arch::trap::TrapFrame;

pub mod debug_print;
pub mod enclave_create;
pub mod enclave_enter;
pub mod enclave_exit;
pub mod enclave_status;

// ── ecall ABI (id in a7, args in a0.., result in a0) ────────────────────────
/// `tee_create` — host registers an enclave (base in `a0`); returns its id.
pub const ECALL_CREATE: u32 = 0;
/// `enclave_enter` — host enters enclave `a0`; returns packed `(status<<8)|...`.
pub const ECALL_ENTER: u32 = 1;
/// `enclave_exit` — optional enclave-initiated completion (`a0` = result).
pub const ECALL_EXIT: u32 = 2;
/// `debug_print` — print a byte (`a0`) via the monitor-owned UART.
pub const ECALL_DEBUG: u32 = 3;
/// `enclave_status` — full result word of a terminated enclave (`a0` = id).
pub const ECALL_STATUS: u32 = 4;

/// Map an [`UmbraError`] to the frozen host-ABI status code (the host only
/// treats ids `>= 0xFFFF_FFF0` as errors). Mirrors the STM32 `nsc_status`.
pub(crate) fn status_code(e: UmbraError) -> u32 {
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

/// Route an `ecall` (function id in `a7`) to its handler.
pub fn dispatch(frame: &mut TrapFrame) {
    let id = frame.regs[17]; // a7
    match id {
        ECALL_CREATE => enclave_create::handle(frame),
        ECALL_ENTER => enclave_enter::handle(frame),
        ECALL_EXIT => enclave_exit::handle(frame),
        ECALL_DEBUG => debug_print::handle(frame),
        ECALL_STATUS => enclave_status::handle(frame),
        _ => frame.mepc += 4, // unknown id: skip the ecall and resume
    }
}
