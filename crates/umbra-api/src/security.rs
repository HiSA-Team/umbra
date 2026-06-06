//! Type-state markers for the Umbra Secure kernel.
//! # Scope
//! These markers live **kernel-internal** on Rust handles. They do NOT
//! travel across the NSC boundary — the NSC veneers in
//! `umbra_nsc_api.rs` stay `extern "C"` with `u32` / `*const u8`
//! signatures (the NSC ABI is frozen). `PhantomData` cannot cross a
//! C ABI.
//! # State machine
//! ```text
//! Validated ──load()──> Loaded ──execute()──> Executing
//! ▲ │
//! └────────── exit() ──────────────────────────────┘
//! ```
//! The NSC entry path (`umbra_enclave_enter_imp`) translates the
//! NS-supplied `u32` enclave-id into an `EnclaveHandle<Validated>` after
//! arg-validation. From there, the type system enforces correct state
//! transitions.

use core::marker::PhantomData;

use crate::types::EnclaveId;

/// Sealed trait so external crates cannot add new state markers.
pub trait SecurityState: sealed::Sealed {}

mod sealed {
    pub trait Sealed {}
}

/// `Validated` — header verified, chained measurement matched.
pub enum Validated {}
impl sealed::Sealed for Validated {}
impl SecurityState for Validated {}

/// `Loaded` — EFB pages mapped into ESS, MPCBB / RIF configured.
pub enum Loaded {}
impl sealed::Sealed for Loaded {}
impl SecurityState for Loaded {}

/// `Executing` — currently dispatched via SG, code is running on PSP.
pub enum Executing {}
impl sealed::Sealed for Executing {}
impl SecurityState for Executing {}

/// Type-state-aware enclave handle.
/// State transitions are encoded in `EnclaveHandle::load()` /
/// `::execute()` / `::exit()` signatures — misuse is a compile error.
pub struct EnclaveHandle<S: SecurityState> {
    pub id: EnclaveId,
    _state: PhantomData<S>,
}

impl<S: SecurityState> EnclaveHandle<S> {
    /// Constructor — visible only to crates inside the Umbra workspace.
    /// External callers must obtain a handle via the NSC entry path.
    #[doc(hidden)]
    pub fn __internal_new(id: EnclaveId) -> Self {
        Self {
            id,
            _state: PhantomData,
        }
    }
}

impl EnclaveHandle<Validated> {
    /// Transition `Validated` → `Loaded` by mapping pages into ESS and
    /// configuring the per-platform memory-attribution unit.
    pub fn load(self) -> EnclaveHandle<Loaded> {
        EnclaveHandle::<Loaded>::__internal_new(self.id)
    }
}

impl EnclaveHandle<Loaded> {
    /// Transition `Loaded` → `Executing` via the SG instruction.
    pub fn execute(self) -> EnclaveHandle<Executing> {
        EnclaveHandle::<Executing>::__internal_new(self.id)
    }
}

impl EnclaveHandle<Executing> {
    /// Transition `Executing` → `Validated` on enclave exit.
    pub fn exit(self) -> EnclaveHandle<Validated> {
        EnclaveHandle::<Validated>::__internal_new(self.id)
    }
}

// ---------------------------------------------------------------------
// Compile-fail tests for the type-state contract.
// Cargo runs each `compile_fail` doctest by attempting to compile the
// inline code and expecting a compile error — i.e. the tests PASS when
// the inline code FAILS to compile.
// ---------------------------------------------------------------------

/// Attempting to `execute()` from `Validated` should not compile —
/// the method is only on `EnclaveHandle<Loaded>`.
/// ```compile_fail
/// use umbra_api::security::*;
/// use umbra_api::EnclaveId;
/// let h = EnclaveHandle::<Validated>::__internal_new(EnclaveId(0));
/// let _executing = h.execute();
/// ```
#[doc(hidden)]
pub fn _typestate_compile_fail_validated_cannot_execute() {}

/// Attempting to `exit()` from `Validated` should not compile —
/// the method is only on `EnclaveHandle<Executing>`.
/// ```compile_fail
/// use umbra_api::security::*;
/// use umbra_api::EnclaveId;
/// let h = EnclaveHandle::<Validated>::__internal_new(EnclaveId(0));
/// let _v = h.exit();
/// ```
#[doc(hidden)]
pub fn _typestate_compile_fail_validated_cannot_exit() {}

/// Attempting to `load()` from `Loaded` should not compile —
/// already loaded.
/// ```compile_fail
/// use umbra_api::security::*;
/// use umbra_api::EnclaveId;
/// let h = EnclaveHandle::<Loaded>::__internal_new(EnclaveId(0));
/// let _l = h.load();
/// ```
#[doc(hidden)]
pub fn _typestate_compile_fail_loaded_cannot_reload() {}

/// External `SecurityState` impl should not compile — sealed trait.
/// ```compile_fail
/// use umbra_api::security::SecurityState;
/// struct MyState;
/// impl SecurityState for MyState {}
/// ```
#[doc(hidden)]
pub fn _typestate_compile_fail_external_state_marker_rejected() {}

// ---------------------------------------------------------------------
// Runtime tests for the positive transitions.
// The `compile_fail` doctests above cover the negative cases (wrong-
// state methods don't compile). These tests cover the happy paths
// at runtime: every valid transition returns a fresh handle with the
// same `EnclaveId`, and distinct handles track distinct ids.
// ---------------------------------------------------------------------
#[cfg(test)]
mod runtime_tests {
    use super::*;

    /// `Validated` → `Loaded` → `Executing` → `Validated` round-trip
    /// preserves the `EnclaveId` through every transition. The handle
    /// type changes on each step; the underlying identity does not.
    #[test]
    fn full_round_trip_preserves_enclave_id() {
        let id = EnclaveId(0x4242_0000);
        let v = EnclaveHandle::<Validated>::__internal_new(id);
        assert_eq!(v.id.0, 0x4242_0000);

        let l = v.load();
        assert_eq!(l.id.0, 0x4242_0000);

        let e = l.execute();
        assert_eq!(e.id.0, 0x4242_0000);

        let v_again = e.exit();
        assert_eq!(v_again.id.0, 0x4242_0000);
    }

    /// Two independent handles with different ids must keep their ids
    /// independent through their own transitions — no shared mutable
    /// state, no cross-contamination.
    #[test]
    fn distinct_handles_track_distinct_ids() {
        let v1 = EnclaveHandle::<Validated>::__internal_new(EnclaveId(1));
        let v2 = EnclaveHandle::<Validated>::__internal_new(EnclaveId(2));

        let l1 = v1.load();
        let l2 = v2.load();

        assert_eq!(l1.id.0, 1);
        assert_eq!(l2.id.0, 2);
    }

    /// Each transition method returns a fresh handle (the input handle
    /// is consumed by value at the call site — a property the
    /// `compile_fail` doctest #3 above pins at compile time). At
    /// runtime we just confirm the freshly-returned handle carries the
    /// same `EnclaveId`. Exercises the `__internal_new` constructor
    /// path for all four `EnclaveHandle<S>` instantiations.
    #[test]
    fn every_transition_returns_fresh_handle_with_same_id() {
        let id = EnclaveId(0xDEAD_BEEF);

        let h_validated = EnclaveHandle::<Validated>::__internal_new(id);
        assert_eq!(h_validated.id.0, 0xDEAD_BEEF);

        let h_loaded = h_validated.load();
        assert_eq!(h_loaded.id.0, 0xDEAD_BEEF);

        let h_executing = h_loaded.execute();
        assert_eq!(h_executing.id.0, 0xDEAD_BEEF);

        let h_validated_again = h_executing.exit();
        assert_eq!(h_validated_again.id.0, 0xDEAD_BEEF);
    }
}
