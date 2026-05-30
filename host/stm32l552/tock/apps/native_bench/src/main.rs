//! Native TACLeBench baseline TBF (per-bench).
//!
//! Runs ONE TACLeBench main natively (no TrustZone wrap), brackets it
//! with a DWT cycle-counter read, and emits one `[BASELINE_RUNTIME]`
//! UART row. The harness in tools/run_native_baseline.sh rebuilds +
//! reflashes this TBF for each of the 13 benches, so each binary is
//! tiny (< 32 KB) and fits in the standard APPS_NS region.
//!
//! DWT cycle counter is shared with the Umbra Secure side (both read
//! CYCCNT at NS-view 0xE0001004). Enable lives in Umbra Secure boot —
//! NS-userspace writes to DEMCR raise BusFault on this CPU.
//!
//! UART output:
//!   [BASELINE_BEGIN]
//!   [BASELINE_RUNTIME]\tapp=<name>\tcycles=0x<N>\tresult=0x<R>
//!   [BASELINE_END]
//!
//! Each bench-feature gates a different `extern "C"` block + `main`
//! body via `#[cfg(feature = ...)]`. Exactly one `bench_<name>`
//! feature must be active per build.

#![no_main]
#![no_std]

use core::cell::Cell;
use core::fmt::Write;
use libtock::console::Console;
use libtock::platform::{share, DefaultConfig, ErrorCode, Subscribe, Syscalls};
use libtock::runtime::{set_main, stack_size, TockSyscalls};

#[cfg(not(any(feature = "board_l552", feature = "board_l562", feature = "board_n657")))]
compile_error!("native_bench requires at least one of: board_l552, board_l562, board_n657");

// Capsule protocol — keep in sync with capsule_umbra::SyscallDriver.
const UMBRA_DRIVER_NUM: u32 = 0xA0000;
const UMBRA_CMD_READ_CYCCNT: u32 = 11;
const UMBRA_SUBSCRIBE_RESULT: u32 = 0;

// 8 KB PSP stack — fits dijkstra-64's hot-path locals; smaller benches
// don't care.
stack_size! { 0x2000 }
set_main! { main }

/// Read DWT_CYCCNT via the Umbra capsule. DWT registers in the PPB
/// (0xE000_xxxx) are NS-privileged on Cortex-M33 — libtock-rs user
/// space BusFaults on direct PPB access. The capsule runs in
/// NS-privileged kernel mode and exposes CYCCNT via cmd=11.
fn read_cyccnt() -> u32 {
    umbra_cmd(UMBRA_CMD_READ_CYCCNT, 0)
}

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

// ---- fib (custom Umbra demo enclave; just one function) ----
#[cfg(feature = "bench_fib")]
unsafe extern "C" { fn fibonacci() -> i32; }
#[cfg(feature = "bench_fib")]
const BENCH_NAME: &str = "fib";
#[cfg(feature = "bench_fib")]
unsafe fn run_bench() -> (u32, u32) {
    let t0 = read_cyccnt();
    unsafe {
        let r = fibonacci();
        let t1 = read_cyccnt();
        (t1.wrapping_sub(t0), r as u32)
    }
}

// ---- Canonical triplet (_init void, _main void, _return -> i32) ----
macro_rules! triplet_bench {
    ($feat:literal, $name:literal, $init:ident, $main:ident, $ret:ident) => {
        #[cfg(feature = $feat)]
        unsafe extern "C" {
            fn $init();
            fn $main();
            fn $ret() -> i32;
        }
        #[cfg(feature = $feat)]
        const BENCH_NAME: &str = $name;
        #[cfg(feature = $feat)]
        unsafe fn run_bench() -> (u32, u32) {
            unsafe {
                $init();
                let t0 = read_cyccnt();
                $main();
                let t1 = read_cyccnt();
                let r = $ret();
                (t1.wrapping_sub(t0), r as u32)
            }
        }
    };
}

triplet_bench!("bench_bsort",         "bsort",         bsort_init,         bsort_main,         bsort_return);
triplet_bench!("bench_countnegative", "countnegative", countnegative_init, countnegative_main, countnegative_return);
triplet_bench!("bench_insertsort",    "insertsort",    insertsort_init,    insertsort_main,    insertsort_return);
triplet_bench!("bench_ndes",          "ndes",          ndes_init,          ndes_main,          ndes_return);
triplet_bench!("bench_petrinet",      "petrinet",      petrinet_init,      petrinet_main,      petrinet_return);
triplet_bench!("bench_adpcm_dec",     "adpcm_dec",     adpcm_dec_init,     adpcm_dec_main,     adpcm_dec_return);
triplet_bench!("bench_anagram",       "anagram",       anagram_init,       anagram_main,       anagram_return);
triplet_bench!("bench_cjpeg_wrbmp",   "cjpeg_wrbmp",   cjpeg_wrbmp_init,   cjpeg_wrbmp_main,   cjpeg_wrbmp_return);
triplet_bench!("bench_dijkstra",      "dijkstra",      dijkstra_init,      dijkstra_main,      dijkstra_return);

// ---- Returning main (no _return; result is _main's return) ----
macro_rules! returning_bench {
    ($feat:literal, $name:literal, $init:ident, $main:ident) => {
        #[cfg(feature = $feat)]
        unsafe extern "C" {
            fn $init();
            fn $main() -> i32;
        }
        #[cfg(feature = $feat)]
        const BENCH_NAME: &str = $name;
        #[cfg(feature = $feat)]
        unsafe fn run_bench() -> (u32, u32) {
            unsafe {
                $init();
                let t0 = read_cyccnt();
                let r = $main();
                let t1 = read_cyccnt();
                (t1.wrapping_sub(t0), r as u32)
            }
        }
    };
}

returning_bench!("bench_crc", "crc", crc_init, crc_main);
returning_bench!("bench_md5", "md5", md5_init, md5_main);

// ---- Void pair (statemate: _init void, _main void; result = 0) ----
#[cfg(feature = "bench_statemate")]
unsafe extern "C" {
    fn statemate_init();
    fn statemate_main();
}
#[cfg(feature = "bench_statemate")]
const BENCH_NAME: &str = "statemate";
#[cfg(feature = "bench_statemate")]
unsafe fn run_bench() -> (u32, u32) {
    unsafe {
        statemate_init();
        let t0 = read_cyccnt();
        statemate_main();
        let t1 = read_cyccnt();
        (t1.wrapping_sub(t0), 0u32)
    }
}

fn main() {
    let mut con = Console::writer();
    let _ = writeln!(con, "[TOCK] Native baseline task started: {}", BENCH_NAME);
    let _ = writeln!(con, "[BASELINE_BEGIN]");

    let (cycles, result) = unsafe { run_bench() };
    let _ = writeln!(con, "[BASELINE_RUNTIME]\tapp={}\tcycles=0x{:08X}\tresult=0x{:08X}",
                     BENCH_NAME, cycles, result);

    let _ = writeln!(con, "[BASELINE_END]");
    let _ = writeln!(con, "[TOCK] Baseline done: {}", BENCH_NAME);
    idle();
}

fn idle() -> ! {
    loop {
        TockSyscalls::yield_wait();
    }
}
