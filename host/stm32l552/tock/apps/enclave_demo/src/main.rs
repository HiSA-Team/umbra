//! libtock-rs TBF app: Umbra multi-enclave bring-up.
//!
//! Mirrors the FreeRTOS `vEnclaveTask` flow ([host/stm32l552/freertos/src/main.c]):
//! scan NS user flash in 4 KB pages for the `UMBR` magic, call
//! `umbra_enclave_create` on each match, then round-robin through every
//! created enclave calling `umbra_enclave_enter` until it terminates or
//! faults. UART output matches FreeRTOS verbatim except for the `[TOCK]`
//! prefix, so the same harness assertions match either host.
//!
//! Magic-check goes through the capsule's PROBE command (cmd=5) — Tock apps
//! are MPU-sandboxed and cannot dereference flash directly.

#![no_main]
#![no_std]

use core::cell::Cell;
use core::fmt::Write;
use libtock::console::Console;
use libtock::platform::{share, DefaultConfig, ErrorCode, Subscribe, Syscalls};
use libtock::runtime::{set_main, stack_size, TockSyscalls};

#[cfg(not(any(feature = "board_l552", feature = "board_l562", feature = "board_n657")))]
compile_error!("enclave_demo requires at least one of: board_l552, board_l562, board_n657");

// Capsule protocol — keep in sync with capsule_umbra.
const UMBRA_DRIVER_NUM: u32 = 0xA0000;
const UMBRA_CMD_CREATE: u32 = 1;
const UMBRA_CMD_ENTER: u32 = 2;
const UMBRA_CMD_EXIT: u32 = 3;
const UMBRA_CMD_STATUS: u32 = 4;
const UMBRA_CMD_PROBE: u32 = 5;
const UMBRA_CMD_DUMP_DRIFT: u32 = 6;
// NS-side runtime cycles accumulator
// + Secure-side boot/switch dump.
const UMBRA_CMD_GET_RUNTIME_CYCLES: u32 = 7;
const UMBRA_CMD_BENCH_DUMP: u32 = 8;
// TrustZone null-SVC cost.
const UMBRA_CMD_MEASURE_NULL_SVC: u32 = 9;
// .
const UMBRA_CMD_GET_BOOT_NS_CYCLES: u32 = 10;
const UMBRA_SUBSCRIBE_RESULT: u32 = 0;

// Status nibble in `umbra_enclave_enter`'s return value (bits 15..8).
const STATUS_SUSPENDED: u32 = 3;
const STATUS_TERMINATED: u32 = 4;
const STATUS_FAULTED: u32 = 5;

// Per-board flash-scan window — matches `_enclave_start..NS_FLASH_END`
// from the bare-metal / FreeRTOS linker scripts on each target.
#[cfg(feature = "board_l552")]
const SCAN_START: u32 = 0x0807_8000;
#[cfg(feature = "board_l552")]
const SCAN_END: u32 = 0x0808_0000;

#[cfg(feature = "board_l562")]
const SCAN_START: u32 = 0x9000_0000;
#[cfg(feature = "board_l562")]
const SCAN_END: u32 = 0x9000_8000;

#[cfg(feature = "board_n657")]
const SCAN_START: u32 = 0x7009_0000;
#[cfg(feature = "board_n657")]
const SCAN_END: u32 = 0x7009_8000;

const PAGE_SIZE: u32 = 0x1000;
const MAX_ENCLAVES: usize = 4;

stack_size! { 0x600 }
set_main! { main }

fn main() {
    let mut con = Console::writer();
    let _ = writeln!(con, "[TOCK] Enclave task started");

    let mut ids: [u32; MAX_ENCLAVES] = [0; MAX_ENCLAVES];
    let mut n: usize = 0;

    let mut addr = SCAN_START;
    while addr < SCAN_END && n < MAX_ENCLAVES {
        if umbra_cmd(UMBRA_CMD_PROBE, addr) == 1 {
            let id = umbra_cmd(UMBRA_CMD_CREATE, addr);
            if id < 0xFFFF_FFF0 {
                let _ = writeln!(con, "[TOCK] Enclave created");
                ids[n] = id;
                n += 1;
            } else {
                let _ = writeln!(con, "[TOCK] Enclave creation REJECTED");
            }
        }
        addr += PAGE_SIZE;
    }

    if n == 0 {
        let _ = writeln!(con, "[TOCK] No enclaves found");
        let _ = writeln!(con, "[TOCK] All enclaves done");
        idle();
    }

    let mut active = n;
    while active > 0 {
        for i in 0..n {
            if ids[i] == 0 {
                continue;
            }
            let ret = umbra_cmd(UMBRA_CMD_ENTER, ids[i]);
            let status = (ret >> 8) & 0xFF;
            if status == STATUS_SUSPENDED {
                let _ = writeln!(con, "[TOCK] Enclave preempted (SysTick)");
            } else if status == STATUS_TERMINATED {
                let full_result = umbra_cmd(UMBRA_CMD_STATUS, ids[i]);
                let _ = writeln!(con, "[TOCK] Enclave terminated! R0=0x{:08X}", full_result);
                ids[i] = 0;
                active -= 1;
            } else if status == STATUS_FAULTED {
                let _ = writeln!(con, "[TOCK] Enclave faulted \u{2014} ret=0x{:08X}", ret);
                ids[i] = 0;
                active -= 1;
            }
        }
    }

    // One-shot heartbeat + drift snapshot via the capsule's raw_print path,
    // matching FreeRTOS's pre-`vTaskDelete` dump.
    umbra_cmd(UMBRA_CMD_DUMP_DRIFT, 0);

    // Sentinels make it cheap
    // for the sweep parser to slice this region out of the
    // UART log without confusing it with heartbeat / drift noise. Two
    // EVAL rows:
    //   - runtime: total cycles spent in CMD_ENTER calls (NS-side
    //     accumulator, sum across all entered enclaves since boot)
    //   - boot/switch: printed by the Secure side via the
    //     `umbra_bench_dump` NSC veneer — empty on stock kernels, two
    //     rows on `bench-eval` kernels.
    let _ = writeln!(con, "[EVAL_DUMP_BEGIN]");
    let runtime_cycles = umbra_cmd(UMBRA_CMD_GET_RUNTIME_CYCLES, 0);
    let _ = writeln!(con, "[EVAL]\truntime\tcycles=0x{:08X}", runtime_cycles);
    // NS-side boot bracket — pairs with the Secure-side row
    // emitted by `umbra_bench_dump` below. The difference (ns - sec)
    // gives the TrustZone fixed cost.
    let boot_ns_cycles = umbra_cmd(UMBRA_CMD_GET_BOOT_NS_CYCLES, 0);
    let _ = writeln!(con, "[EVAL]\tboot_ns\tcycles=0x{:08X}", boot_ns_cycles);
    // baseline: measure the null-SVC cost so the switch plot can be
    // normalized against the TrustZone fixed overhead. Single-shot —
    // the capsule brackets a single null call. Repeated invocations
    // would only add jitter; the value is config-independent and the
    // sweep parser uses the median across cells.
    let null_svc_cycles = umbra_cmd(UMBRA_CMD_MEASURE_NULL_SVC, 0);
    let _ = writeln!(con, "[EVAL]\tnull_svc\tcycles=0x{:08X}", null_svc_cycles);
    umbra_cmd(UMBRA_CMD_BENCH_DUMP, 0);
    let _ = writeln!(con, "[EVAL_DUMP_END]");

    let _ = writeln!(con, "[TOCK] All enclaves done");
    idle();
}

/// Issue a command to the Umbra capsule and block until the upcall arrives
/// on subscribe slot 0. Returns `0xFFFF_FFFF` on any kernel error.
fn umbra_cmd(cmd_num: u32, arg1: u32) -> u32 {
    let result: Cell<Option<(u32,)>> = Cell::new(None);
    let outcome = share::scope::<Subscribe<TockSyscalls, UMBRA_DRIVER_NUM, UMBRA_SUBSCRIBE_RESULT>, _, _>(
        |subscribe_handle| -> Result<(), ErrorCode> {
            TockSyscalls::subscribe::<_, _, DefaultConfig, UMBRA_DRIVER_NUM, UMBRA_SUBSCRIBE_RESULT>(
                subscribe_handle,
                &result,
            )?;
            TockSyscalls::command(UMBRA_DRIVER_NUM, cmd_num, arg1, 0)
                .to_result::<(), ErrorCode>()?;
            while result.get().is_none() {
                TockSyscalls::yield_wait();
            }
            Ok(())
        },
    );
    match outcome {
        Ok(()) => result.get().map(|(x,)| x).unwrap_or(0xFFFF_FFFF),
        Err(_) => 0xFFFF_FFFF,
    }
}

/// Spin on `yield_wait` forever — Tock reclaims a process's grant region if
/// it returns from `main`, and the harness expects the UART trace to stay
/// quiescent after `All enclaves done`.
fn idle() -> ! {
    loop {
        TockSyscalls::yield_wait();
    }
}
