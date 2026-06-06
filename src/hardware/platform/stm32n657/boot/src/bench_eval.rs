//! Minimal `bench_eval` module for N657.
//! The NSC veneer `umbra_bench_dump` in `src/kernel/asm/arm/nsc_veneers.s`
//! unconditionally references `umbra_bench_dump_imp`. The contract documented
//! in that file (lines 63-67) says every platform must provide a stub so the
//! link succeeds; the body is allowed to be a no-op when the bench-eval
//! feature is off.
//! N657 has no bench-eval cycle counters yet (deferred), so the stub body
//! is empty. The Secure-side cost on the hot path is one SVC + bxns — same
//! as the L552 disabled state.

/// NSC veneer back-end. Called via the `umbra_bench_dump` veneer; no-op on
/// N657 until bench-eval lands for this platform.
#[no_mangle]
pub extern "C" fn umbra_bench_dump_imp() {}
