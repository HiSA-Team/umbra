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
//! | 7   | read accumulated runtime cycles      | (ignored)     | DWT cycles sum     |
//! | 8   | call `umbra_bench_dump()` NSC veneer | (ignored)     | (none)             |
//! | 9   | measure null-SVC baseline (S3)       | (ignored)     | TrustZone cycles   |
//! | 10  | read NS-side boot cycles             | (ignored)     | CMD 1 wall-clock   |
//!
//! Commands 7+8 are part of theinstrumentation
//!. The capsule transparently brackets every CMD 2 (ENTER)
//! call with DWT reads and accumulates into a per-driver static — cmd
//! 7 returns that accumulator (NS-side runtime measurement, R1 from
//! Q2a). Cmd 8 invokes the Secure-side `umbra_bench_dump` veneer which
//! prints the Secure accumulators (boot + switch) when the kernel is
//! built with `bench-eval`; on a stock kernel it is a no-op. NS
//! user-apps wrap the pair with `[EVAL_DUMP_BEGIN]/[EVAL_DUMP_END]`
//! sentinels so the parser de-interleaves Secure prints from heartbeat
//! noise.
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

use core::sync::atomic::{AtomicU32, Ordering};
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

    /// . Always linkable — when the
    /// kernel is built without `bench-eval` the Secure imp is a no-op
    /// stub. Invoked by CMD 8.
    fn umbra_bench_dump();

    /// . Empty NSC veneer used to
    /// measure the TrustZone round-trip fixed cost. Always emitted.
    fn umbra_null_call();
}

/// cycle accumulator for CMD 2 (ENTER) calls. Reset to 0
/// only on hardware reset (lives in .bss); each successful ENTER adds
/// `end - start` DWT cycles. Read via CMD 7. The single-process sweep
/// harness +) keys the value to (bench, slot, cache,
/// spec) tuples via UART sentinels — no per-app reset needed because
/// each sweep cell runs a fresh boot.
static BENCH_RUNTIME_CYCLES: AtomicU32 = AtomicU32::new(0);

/// NS-side boot bracket around CMD 1 (CREATE). Pairs
/// with the Secure-side `boot_sec_cycles` from `bench_eval` to give
/// the B3 measurement (Q2b): TrustZone fixed cost = ns - sec. Single-
/// shot per process; expects exactly one CREATE call per sweep cell.
static BENCH_BOOT_NS_CYCLES: AtomicU32 = AtomicU32::new(0);

/// DWT cycle counter MMIO (System Control Space). Tock NS-privileged
/// code has access to 0xE000_xxxx; enable lives in the board's
/// heartbeat.rs (already on by the time the capsule runs).
const DWT_CYCCNT: *const u32 = 0xE000_1004 as *const u32;

#[inline(always)]
fn dwt_read() -> u32 {
    // SAFETY: DWT_CYCCNT is a read-only 32-bit hardware register in the
    // System Control Space. NS access is granted on Cortex-M33 and the
    // board enables the counter via heartbeat::enable_dwt_and_systick()
    // before user apps run.
    unsafe { core::ptr::read_volatile(DWT_CYCCNT) }
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

/// Invoke a void→void NSC veneer with the same callee-saved register
/// barrier as `nsc_call`. Used by CMD 8 (`umbra_bench_dump`) which has
/// no input args and discards the return value. We still spill r4-r11
/// because the Secure side may have clobbered them between the SG and
/// the BXNS return.
#[inline(never)]
fn nsc_call_void(veneer: unsafe extern "C" fn()) {
    // SAFETY: `veneer` is `umbra_bench_dump`, a valid NSC SG entry point
    // in Secure flash; the Secure imp is either the bench_eval dump
    // (under `bench-eval`) or a no-op stub (otherwise).
    unsafe {
        core::arch::asm!(
            "push {{r4, r5, r6, r7, r8, r9, r10, r11}}",
            "blx {f}",
            "pop {{r4, r5, r6, r7, r8, r9, r10, r11}}",
            f = in(reg) veneer,
            out("r0") _, out("r1") _, out("r2") _, out("r3") _,
            out("r4") _, out("r5") _,
            out("r8") _, out("r9") _, out("r10") _, out("r11") _,
            out("r12") _, out("lr") _,
        );
    }
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
            1 => {
                // B3 NS bracket (Q2b): mirror of the
                // Secure-side boot bracket. Records the wall-clock
                // cost as seen by the host (TrustZone overhead +
                // Secure work). Single-shot; expects 1 CREATE per
                // sweep cell. Wrapping unconditional (cheap), the
                // value is meaningful only when bench-eval is on.
                let start = dwt_read();
                let ret = nsc_call(arg1 as u32, umbra_enclave_create);
                let end = dwt_read();
                BENCH_BOOT_NS_CYCLES.store(end.wrapping_sub(start), Ordering::Relaxed);
                ret
            }
            2 => {
                // R1 bracket (NS-side): accumulate cycles
                // across every ENTER call. The cost is ~10 cycles per
                // ENTER (2 MMIO reads + 1 atomic add) vs ~1000s of
                // cycles for the call itself — negligible. Wrapping
                // is unconditional because the cfg gate lives on the
                // Secure side only; querying CMD 7 from a non-eval
                // build still returns a meaningful number (sum of all
                // ENTER costs since boot).
                let start = dwt_read();
                let ret = nsc_call(arg1 as u32, umbra_enclave_enter);
                let end = dwt_read();
                let delta = end.wrapping_sub(start);
                BENCH_RUNTIME_CYCLES.fetch_add(delta, Ordering::Relaxed);
                ret
            }
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
            7 => {
                // — sum of DWT
                // deltas around every CMD 2 (ENTER) call since boot.
                BENCH_RUNTIME_CYCLES.load(Ordering::Relaxed)
            }
            8 => {
                // — invokes the NSC
                // veneer that prints the boot + switch accumulators
                // (or nothing, when the Secure side lacks bench-eval).
                nsc_call_void(umbra_bench_dump);
                0
            }
            9 => {
                // — bracket the null-SVC
                // round-trip and return the cycle delta. The capsule
                // (NS-privileged) is the only place we can both read
                // DWT and make an NSC call in tight sequence; a NS
                // user-app would add yield+syscall noise to the
                // measurement.
                let start = dwt_read();
                nsc_call_void(umbra_null_call);
                let end = dwt_read();
                end.wrapping_sub(start)
            }
            10 => {
                // .
                BENCH_BOOT_NS_CYCLES.load(Ordering::Relaxed)
            }
            11 => {
                // Stage A Step 7c — raw DWT_CYCCNT read for native
                // baseline bracket. DWT registers in the PPB
                // (0xE000_xxxx) are NS-privileged on Cortex-M33;
                // libtock-rs userspace apps (unprivileged NS) BusFault
                // on direct reads. native_bench calls this cmd before
                // and after each TACLeBench main; the two-call delta
                // is the bench's native cycle count. Per-call overhead
                // is one Tock SVC + capsule dispatch (~500-1000
                // cycles), negligible vs the millions of cycles each
                // bench takes.
                dwt_read()
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
