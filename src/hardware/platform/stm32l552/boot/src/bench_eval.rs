// Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>
// §Evaluation runtime accumulators + UART dump path.
// This module is non-brick instrumentation: unlike `benchmark.rs` (which
// halts boot after printing crypto micro-benchmarks), bench-eval keeps
// the kernel + host running normally and just records cycle counts
// around enclave_create and enclave_enter, exposed via the NSC veneer
// `umbra_bench_dump`.
// Print convention (parsed by tools/run_eval_sweep.sh, Step 5):
// [EVAL]\tboot\tsec_cycles=0xHHHHHHHH
// [EVAL]\tswitch\tmin=0xHHHHHHHH\tmean=0xHHHHHHHH\tmax=0xHHHHHHHH\tcount=0xHHHHHHHH
// NS host wraps each dump call with `[EVAL_DUMP_BEGIN] / [EVAL_DUMP_END]`
// sentinels so the parser can de-interleave Secure prints from heartbeat
// noise (P3 design in the Stage A grilling notes).
// FEATURE GATE: the heavy code is gated to `bench-eval` + the shared
// `i_acknowledge_benchmark_is_research_only` guard (same pattern as the
// brick-mode `benchmark` feature). Without the feature the entry points
// compile to no-ops so the NSC veneer link succeeds in every build, and
// the Secure side carries zero per-call overhead in production.

#[cfg(all(
    feature = "bench-eval",
    not(feature = "i_acknowledge_benchmark_is_research_only")
))]
compile_error!(
    "The `bench-eval` feature is research instrumentation that emits UART \
     traffic and consumes Secure-side static buffers. To build it \
     intentionally, also pass `--features i_acknowledge_benchmark_is_research_only`. \
     Never enable in production firmware."
);

#[cfg(all(feature = "bench-eval", feature = "benchmark"))]
compile_error!(
    "Cannot enable both `benchmark` (brick-mode crypto micro-benchmarks; \
     halts boot) and `bench-eval` (non-brick §Evaluation instrumentation) \
     simultaneously. Pick one."
);

// ── bench-eval ON: real accumulators + dump path ─────────────────────
#[cfg(feature = "bench-eval")]
mod imp {
    use crate::raw_print;
    use core::sync::atomic::{AtomicU32, Ordering};
    use drivers::cycles;

    // Latest Secure-side cycle count from the bracket inside
    // umbra_enclave_create_imp. Single-shot per hardware reset
    // (Q2b "single-shot via N resets") — no min/mean/max needed.
    static BENCH_BOOT_SEC_CYCLES: AtomicU32 = AtomicU32::new(0);

    // Switch accumulators (Q2c): aggregated across every
    // umbra_enclave_enter_imp call within a run. min/mean/max gives
    // the cost distribution; count lets the harness sanity-check
    // against the expected enter() invocations from the host side.
    // Initial min = u32::MAX so the first `fetch_min` wins. Mean is
    // computed at dump time from sum + count.
    // SUM is u32 (not u64) because Cortex-M33 does NOT support 64-bit
    // atomics natively — Rust falls back to libcalls (__atomic_load_8
    // / __atomic_fetch_add_8) which are unresolved at link time on a
    // bare-metal no_std target. u32 is sufficient for any reasonable
    // sweep cell: at 110 MHz, u32 cycles wraps at ~39 s; a sweep cell
    // measures a single bench run (~ms-to-seconds), well within range.
    static BENCH_SWITCH_MIN: AtomicU32 = AtomicU32::new(u32::MAX);
    static BENCH_SWITCH_MAX: AtomicU32 = AtomicU32::new(0);
    static BENCH_SWITCH_SUM: AtomicU32 = AtomicU32::new(0);
    static BENCH_SWITCH_COUNT: AtomicU32 = AtomicU32::new(0);

    /// Enable the DWT cycle counter. Idempotent; safe to call multiple
    /// times. Invoke once from secure_boot() under cfg(bench-eval) so
    /// the first measurement bracket fires with the counter running.
    pub fn init() {
        cycles::enable();
    }

    /// Record the bracketed boot cycle count. Overwrites the previous
    /// value — bench-eval expects exactly one create per reset.
    pub fn record_boot_sec_cycles(cycles_elapsed: u32) {
        BENCH_BOOT_SEC_CYCLES.store(cycles_elapsed, Ordering::Relaxed);
    }

    /// Update the switch accumulators with a single bracketed delta.
    /// Called by `SwitchGuard::drop` on every `umbra_enclave_enter_imp`
    /// exit (success + error paths). Cost: 3 atomic RMW + 1 atomic
    /// store, ~30 cycles, dwarfed by the switch itself (~k cycles).
    pub fn record_switch_cycles(cycles_elapsed: u32) {
        BENCH_SWITCH_MIN.fetch_min(cycles_elapsed, Ordering::Relaxed);
        BENCH_SWITCH_MAX.fetch_max(cycles_elapsed, Ordering::Relaxed);
        BENCH_SWITCH_SUM.fetch_add(cycles_elapsed, Ordering::Relaxed);
        BENCH_SWITCH_COUNT.fetch_add(1, Ordering::Relaxed);
    }

    /// Read the wall-clock DWT counter directly. Caller brackets the
    /// critical section and computes the delta via `cycles::elapsed`.
    #[inline(always)]
    pub fn read_cycles() -> u32 {
        cycles::read()
    }

    /// Print the accumulators to UART (Secure-side). The NSC veneer
    /// `umbra_bench_dump` is the entry point invoked by the NS host.
    /// Format mirrors the NS-side `cycles=0x{:08X}` so the sweep parser
    /// (Step 5) needs only one regex for both rows.
    pub fn dump() {
        let boot_sec = BENCH_BOOT_SEC_CYCLES.load(Ordering::Relaxed);
        let sw_min = BENCH_SWITCH_MIN.load(Ordering::Relaxed);
        let sw_max = BENCH_SWITCH_MAX.load(Ordering::Relaxed);
        let sw_sum = BENCH_SWITCH_SUM.load(Ordering::Relaxed);
        let sw_count = BENCH_SWITCH_COUNT.load(Ordering::Relaxed);

        raw_print::print_str("[EVAL]\tboot\tsec_cycles=0x");
        raw_print::print_hex(boot_sec);
        raw_print::print_str("\n");

        // Switch row. Print min as 0 when no switches happened so the
        // parser sees a sensible value instead of u32::MAX.
        let sw_min_print = if sw_count == 0 { 0 } else { sw_min };
        let sw_mean = if sw_count == 0 { 0 } else { sw_sum / sw_count };

        raw_print::print_str("[EVAL]\tswitch\tmin=0x");
        raw_print::print_hex(sw_min_print);
        raw_print::print_str("\tmean=0x");
        raw_print::print_hex(sw_mean);
        raw_print::print_str("\tmax=0x");
        raw_print::print_hex(sw_max);
        raw_print::print_str("\tcount=0x");
        raw_print::print_hex(sw_count);
        raw_print::print_str("\tspec=");
        #[cfg(feature = "umbra-speculation")]
        raw_print::print_str("on");
        #[cfg(not(feature = "umbra-speculation"))]
        raw_print::print_str("off");
        raw_print::print_str("\n");
    }

    /// RAII bracket for `umbra_enclave_enter_imp`. Records the cycle
    /// delta from creation to drop, ensuring every return path
    /// (including early errors) contributes to the accumulator.
    pub struct SwitchGuard {
        start: u32,
    }

    impl SwitchGuard {
        #[inline(always)]
        pub fn start() -> Self {
            SwitchGuard {
                start: cycles::read(),
            }
        }
    }

    impl Drop for SwitchGuard {
        #[inline(always)]
        fn drop(&mut self) {
            let end = cycles::read();
            record_switch_cycles(end.wrapping_sub(self.start));
        }
    }
}

// ── bench-eval OFF: no-op stubs so the NSC veneer always links ───────
#[cfg(not(feature = "bench-eval"))]
mod imp {
    /// No-op when bench-eval is disabled. Inlined to nothing.
    #[inline(always)]
    pub fn init() {}

    /// No-op when bench-eval is disabled. The NSC veneer still calls
    /// here; the function is empty and returns immediately.
    #[inline(always)]
    pub fn dump() {}
}

// `init` + `dump` are always re-exported: `init` runs unconditionally at
// secure_boot, `dump` is the entry point of the `umbra_bench_dump` NSC
// veneer which links in every build.
pub use imp::{dump, init};

// The bracketed timing primitives are referenced only from
// `#[cfg(feature = "bench-eval")]` call sites in `api_impl::enclave_*`,
// so they are re-exported solely in that build.
#[cfg(feature = "bench-eval")]
pub use imp::{read_cycles, record_boot_sec_cycles, record_switch_cycles, SwitchGuard};

/// NSC veneer entry point: invoked by the NS host via
/// `umbra_bench_dump()`. Prints the Secure-side accumulators to UART
/// (boot cycles in Step 2; switch min/mean/max appended in Step 4).
#[no_mangle]
pub extern "C" fn umbra_bench_dump_imp() {
    dump();
}
