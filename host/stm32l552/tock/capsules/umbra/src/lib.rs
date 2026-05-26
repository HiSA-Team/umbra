//! Umbra NSC syscall driver capsule.
//!
//! Exposes the Umbra Secure-side NSC veneers (`umbra_enclave_create`,
//! `umbra_enclave_enter`, `umbra_enclave_exit`, `umbra_enclave_status`) as a
//! Tock [`SyscallDriver`] so libtock-rs userspace apps can drive enclaves.
//!
//! The veneers are resolved at link time by the board crate's linker script via
//! `PROVIDE(umbra_enclave_create = 0x0803c001);` (L5) or
//! `PROVIDE(umbra_enclave_create = 0x341AB401);` (N6).
//!
//! # Command numbers
//!
//! | num | action                               | arg1          | upcall arg0        |
//! |-----|--------------------------------------|---------------|--------------------|
//! | 0   | driver presence check                | (ignored)     | (none)             |
//! | 1   | `umbra_enclave_create(base_addr)`    | base address  | enclave id         |
//! | 2   | `umbra_enclave_enter(enclave_id)`    | enclave id    | return code        |
//! | 3   | `umbra_enclave_exit(enclave_id)`     | enclave id    | return code        |
//! | 4   | `umbra_enclave_status(enclave_id)`   | enclave id    | return code        |
//! | 5   | probe `UMBR` magic at flash addr     | flash addr    | 1 if magic, else 0 |
//! | 6   | dump DWT drift stats over raw_print  | (ignored)     | (none)             |
//!
//! Every command beyond the presence check returns `CommandReturn::success()`
//! and delivers its result through subscribe slot 0; the synchronous
//! `success_u32` path triggers a SecureFault on this build because the SG/BXNS
//! round-trip through the NSC veneers does not preserve all callee-saved
//! registers as the Rust `extern "C"` ABI assumes. The asm wrapper in
//! [`nsc_call`] forces LLVM to spill r4–r11 around each veneer call;
//! see [the milestone memory entry](../../../../docs/contributing/) for the
//! full investigation.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

pub mod noop_mpu;

use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::{ErrorCode, ProcessId};

/// Driver number for the Umbra NSC capsule (vendor range, unused by upstream Tock).
pub const DRIVER_NUM: usize = 0xA0000;

// SAFETY contract for the extern block:
// These symbols resolve to NSC SG veneer addresses embedded by the board
// linker script. Calling them issues a `SG` instruction that transitions
// the CPU from Non-Secure to Secure state; the Secure-side handler validates
// arguments (range, alignment, existence). The capsule forwards values from
// userspace as-is. All four are invoked through `nsc_call` below.
extern "C" {
    fn umbra_enclave_create(base_addr: u32) -> u32;
    fn umbra_enclave_enter(enclave_id: u32) -> u32;
    fn umbra_enclave_exit(enclave_id: u32) -> u32;
    fn umbra_enclave_status(enclave_id: u32) -> u32;

    /// Board-provided drift-stats dump (boards/.../src/heartbeat.rs).
    /// Writes `[HEARTBEAT]` / `[DRIFT]` lines on LPUART1 NS, then returns.
    fn _umbra_drift_dump();
}

/// Invoke one of the Umbra NSC veneers with a full callee-saved register
/// barrier. The asm block manually `push`es/`pop`s r4-r11 around the `blx`
/// so every callee-saved register survives the SG/BXNS round-trip
/// regardless of what the Secure side leaves in them. r4, r5, r8-r11 are
/// also listed as clobbered to force LLVM to spill any in-use values out;
/// r6 (LLVM internal) and r7 (Thumb frame pointer) can't appear in the
/// clobber list, but the manual push/pop preserves them transparently.
#[inline(never)]
fn nsc_call(base_addr: u32, veneer: unsafe extern "C" fn(u32) -> u32) -> u32 {
    let result: u32;
    // SAFETY: `veneer` is one of the four `umbra_enclave_*` extern symbols,
    // each a valid NSC SG entry point in Secure flash.
    unsafe {
        core::arch::asm!(
            "push {{r4, r5, r6, r7, r8, r9, r10, r11}}",
            "blx {f}",
            "pop {{r4, r5, r6, r7, r8, r9, r10, r11}}",
            f = in(reg) veneer,
            inout("r0") base_addr => result,
            out("r1") _, out("r2") _, out("r3") _, out("r12") _,
            out("r4") _, out("r5") _,
            out("r8") _, out("r9") _, out("r10") _, out("r11") _,
            out("lr") _,
        );
    }
    result
}

/// `UMBR` magic in little-endian — first word of every Umbra enclave blob.
const UMBRA_MAGIC: u32 = 0x524D_4255;

/// NS user-flash bounds on STM32L552. Outside this range the probe read
/// could fault (Secure-aliased) or hit MMIO; the scanner uses these bounds
/// to mirror the per-board `_enclave_start`..`NS_FLASH_END` linker window.
const NS_FLASH_START: u32 = 0x0804_0000;
const NS_FLASH_END: u32 = 0x0808_0000;

/// Returns 1 if `addr` is inside NS user flash AND holds the UMBR magic
/// header, 0 otherwise. Tock apps are MPU-sandboxed and can't dereference
/// flash directly; PROBE lets the app reproduce the FreeRTOS scanner
/// `*(volatile uint32_t *)addr == UMBRA_MAGIC` via a syscall.
fn probe_enclave_magic(addr: u32) -> u32 {
    if addr < NS_FLASH_START || addr >= NS_FLASH_END || (addr & 3) != 0 {
        return 0;
    }
    // SAFETY: addr is 4-byte aligned and inside the NS user-flash window
    // opened by Umbra Secure boot; the capsule runs in NS-privileged mode.
    let word = unsafe { core::ptr::read_volatile(addr as *const u32) };
    if word == UMBRA_MAGIC { 1 } else { 0 }
}

#[derive(Default)]
pub struct App;

pub struct UmbraDriver {
    apps: Grant<App, UpcallCount<1>, AllowRoCount<0>, AllowRwCount<0>>,
}

impl UmbraDriver {
    pub fn new(grant: Grant<App, UpcallCount<1>, AllowRoCount<0>, AllowRwCount<0>>) -> Self {
        Self { apps: grant }
    }
}

impl SyscallDriver for UmbraDriver {
    fn command(
        &self,
        command_num: usize,
        arg1: usize,
        _arg2: usize,
        process_id: ProcessId,
    ) -> CommandReturn {
        let result: u32 = match command_num {
            0 => return CommandReturn::success(),
            1 => nsc_call(arg1 as u32, umbra_enclave_create),
            2 => nsc_call(arg1 as u32, umbra_enclave_enter),
            3 => nsc_call(arg1 as u32, umbra_enclave_exit),
            4 => nsc_call(arg1 as u32, umbra_enclave_status),
            5 => probe_enclave_magic(arg1 as u32),
            6 => {
                // SAFETY: `_umbra_drift_dump` is provided by the board crate
                // and only reads atomic statics + writes to LPUART1 via
                // raw_print.
                unsafe { _umbra_drift_dump(); }
                0
            }
            _ => return CommandReturn::failure(ErrorCode::NOSUPPORT),
        };

        let _ = self.apps.enter(process_id, |_app, upcalls| {
            let _ = upcalls.schedule_upcall(0, (result as usize, 0, 0));
        });

        CommandReturn::success()
    }

    fn allocate_grant(&self, process_id: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(process_id, |_, _| {})
    }
}
