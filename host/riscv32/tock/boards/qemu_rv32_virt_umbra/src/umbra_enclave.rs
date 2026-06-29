//! Tock-as-untrusted-loader for the Umbra enclave.
//!
//! Tock runs in S-mode under the Umbra M-mode monitor. Here Tock's kernel drives
//! the enclave API exactly as the bare-metal host does — `ecall` into the monitor
//! with the function id in `a7`, one arg in `a0`, result in `a0` — to register,
//! run, and read back the embedded enclave (see `fibonacci.rs`). It runs once at
//! boot (before the scheduler timer is armed, so there is no timer-coexistence
//! conflict) and prints the result via the monitor-owned UART (`debug_print`
//! ecall), independent of Tock's own console.

// ecall function ids — must match the monitor's `api_impl` ABI.
const ECALL_CREATE: u32 = 0;
const ECALL_ENTER: u32 = 1;
const ECALL_DEBUG: u32 = 3;
const ECALL_STATUS: u32 = 4;

const UMBRA_MAGIC: u32 = 0x524D_4255; // "UMBR" little-endian
const STATUS_SUSPENDED: u32 = 3;
const STATUS_TERMINATED: u32 = 4;
const STATUS_FAULTED: u32 = 5;

extern "C" {
    /// Start of the embedded enclave header (the address Tock passes to create).
    static _enclave_start: u8;
}

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

/// Print a string through the monitor-owned UART (one `debug_print` ecall per
/// byte). Independent of Tock's console driver, so it works at any boot stage.
fn umbra_print(s: &str) {
    for b in s.bytes() {
        let _ = ecall1(ECALL_DEBUG, b as u32);
    }
}

/// Format `val` as `"0xXXXXXXXX"` into `buf` and return it.
fn u32_to_hex(val: u32, buf: &mut [u8; 10]) -> &str {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..8 {
        buf[2 + i] = HEX[((val >> ((7 - i) * 4)) & 0xF) as usize];
    }
    core::str::from_utf8(&buf[..10]).unwrap_or("0x????????")
}

/// Drive the embedded enclave to completion: `create` → loop `enter` (re-entering
/// on a preemption suspend) → read `status`, printing `R0=<result>`. Returns when
/// the enclave terminates or faults. Safe to call before Tock's own subsystems
/// are up — it only `ecall`s the monitor and reads its own flash image.
pub fn drive_enclave() {
    let base = core::ptr::addr_of!(_enclave_start) as u32;
    // SAFETY: reading the magic word of Tock's own (read-only) flash image.
    let magic = unsafe { core::ptr::read_volatile(base as *const u32) };
    if magic != UMBRA_MAGIC {
        umbra_print("[TOCK] no embedded enclave blob\n");
        return;
    }

    let id = ecall1(ECALL_CREATE, base);
    if id >= 0xFFFF_FFF0 {
        umbra_print("[TOCK] enclave create REJECTED\n");
        return;
    }
    umbra_print("[TOCK] enclave created; entering\n");

    loop {
        let ret = ecall1(ECALL_ENTER, id);
        let status = (ret >> 8) & 0xFF;
        match status {
            STATUS_SUSPENDED => { /* preempted by the timer — re-enter to resume */ }
            STATUS_TERMINATED => {
                let r0 = ecall1(ECALL_STATUS, id);
                let mut buf = [0u8; 10];
                umbra_print("[TOCK] enclave R0=");
                umbra_print(u32_to_hex(r0, &mut buf));
                umbra_print("\n");
                return;
            }
            STATUS_FAULTED => {
                umbra_print("[TOCK] enclave FAULTED\n");
                return;
            }
            _ => {
                umbra_print("[TOCK] enclave unexpected status\n");
                return;
            }
        }
    }
}
