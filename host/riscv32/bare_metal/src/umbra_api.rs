//! Umbra host API for the RISC-V bare-metal host.
//!
//! Exposes the **same surface** as the STM32L552 bare-metal host
//! (`umbra_enclave_create`, `umbra_debug_print`, `umbra_enclave_enter`,
//! `umbra_enclave_status`, `umbra_u32_to_hex`). On ARM these were NSC veneers
//! (`BL` into a Secure-Gateway); on RISC-V they are `ecall`s into the M-mode
//! monitor, with the function id in `a7`, one argument in `a0`, and the result
//! returned in `a0`.

// ecall function ids — must match the monitor's `api_impl` ABI.
const ECALL_CREATE: u32 = 0;
const ECALL_ENTER: u32 = 1;
const ECALL_DEBUG: u32 = 3;
const ECALL_STATUS: u32 = 4;

/// Issue an `ecall` (id in `a7`, arg in `a0`) and return the monitor's `a0`.
#[inline(always)]
fn ecall1(id: u32, a0: u32) -> u32 {
    let ret;
    // SAFETY: the Umbra ecall ABI; the monitor mediates and returns in a0.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") id,
            inlateout("a0") a0 => ret,
            options(nostack),
        );
    }
    ret
}

/// Register the enclave whose header lives at `base_addr`; returns its id (or a
/// value `>= 0xFFFF_FFF0` on rejection).
pub fn umbra_enclave_create(base_addr: u32) -> u32 {
    ecall1(ECALL_CREATE, base_addr)
}

/// Enter enclave `enclave_id`; returns a packed `(status << 8) | result`.
pub fn umbra_enclave_enter(enclave_id: u32) -> u32 {
    ecall1(ECALL_ENTER, enclave_id)
}

/// Query the full result word of a terminated enclave.
pub fn umbra_enclave_status(enclave_id: u32) -> u32 {
    ecall1(ECALL_STATUS, enclave_id)
}

/// Print a string through the monitor-owned UART (one `debug_print` ecall per
/// byte). The host never touches the UART directly.
pub fn umbra_debug_print(s: &str) {
    for b in s.bytes() {
        let _ = ecall1(ECALL_DEBUG, b as u32);
    }
}

/// Format `val` into `buf` as the NUL-terminated string `"0xXXXXXXXX"` and
/// return it as a `&str` (the RISC-V port of `host/common`'s `umbra_u32_to_hex`).
pub fn umbra_u32_to_hex(val: u32, buf: &mut [u8; 11]) -> &str {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..8 {
        buf[2 + i] = HEX[((val >> ((7 - i) * 4)) & 0xF) as usize];
    }
    buf[10] = 0;
    // SAFETY-free: the first 10 bytes are ASCII hex by construction.
    core::str::from_utf8(&buf[..10]).unwrap_or("0x????????")
}
