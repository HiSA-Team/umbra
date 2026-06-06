# ADR 004 — Type-state markers for the enclave lifecycle

**Status:** Accepted

## Context

An Umbra enclave moves through a small lifecycle:

```
  Validated  ──load()──>  Loaded  ──execute()──>  Executing
      ▲                                                │
      └────────── exit() ──────────────────────────────┘
```

Every transition has preconditions on the kernel's internal state.
`load()` pages the enclave's encrypted blocks into the Enclave Swap
Space. `execute()` switches the CPU into the enclave's PSP and jumps to
its entry point. `exit()` tears the execution context back down. Skip
a step or call a transition in the wrong state and the kernel is left
in a half-configured shape: a stale ESS mapping, a dangling PSP, or an
enclave running before its measurement has been validated.

Earlier kernel revisions tracked the state with a `u8` field inside a
`Enclave` struct and dispatched on it at the head of every transition
method. That approach has three structural problems:

1. **Runtime checks**. Every call costs a `match` on the state byte
   plus a fallible return. Most calls are not on a hot path, but the
   shape encourages contributors to skip the check "just this once".
2. **No compile-time safety**. A caller can hand any `Enclave` value
   to any transition; the wrong-order call fails at runtime with an
   `EnclaveStateInvalid` error that the reviewer has to spot in tests.
3. **Argument swap is invisible**. An NSC veneer that accepts an
   `enclave_id: u32` and a `block_addr: u32` can have the arguments
   swapped without the type system noticing. The two values have
   the same Rust type but mean entirely different things.

## Decision

The enclave lifecycle is encoded in the type system via uninhabited
marker types and a sealed trait. The implementation lives in
`crates/umbra-api/src/security.rs`:

```rust
pub trait SecurityState: sealed::Sealed {}
mod sealed { pub trait Sealed {} }

pub enum Validated {}
impl sealed::Sealed for Validated {}
impl SecurityState for Validated {}

pub enum Loaded {}
impl sealed::Sealed for Loaded {}
impl SecurityState for Loaded {}

pub enum Executing {}
impl sealed::Sealed for Executing {}
impl SecurityState for Executing {}

pub struct EnclaveHandle<S: SecurityState> {
    pub id: EnclaveId,
    _state: PhantomData<S>,
}
```

State transitions are encoded as method signatures: `load()` is
defined only on `EnclaveHandle<Validated>`; `execute()` only on
`EnclaveHandle<Loaded>`; `exit()` only on `EnclaveHandle<Executing>`.
Each transition consumes the input handle by value and returns a new
handle in the next state, so the old state is unreachable.

The argument-swap class of bug is closed in parallel by
`#[repr(transparent)]` newtypes for distinct domains:

```rust
#[repr(transparent)] pub struct EnclaveId(pub u32);
#[repr(transparent)] pub struct BlockAddr(pub u32);
#[repr(transparent)] pub struct Measurement(pub [u8; 32]);
```

`fn load(id: EnclaveId, addr: BlockAddr)` no longer compiles if the
caller swaps the arguments.

The module ships four `compile_fail` doctests
(`crates/umbra-api/src/security.rs:91-131`) that pass when the inline
code **fails to compile**:

1. `Validated` cannot `execute()`.
2. `Validated` cannot `exit()`.
3. `Loaded` cannot re-`load()`.
4. External `SecurityState` impl rejected (the sealed trait blocks it).

See [Type-State Security Domain](../architecture/type-state.md) for
the full state machine, the trait + marker code, and the end-to-end
example.

## Scope: kernel-internal only

The type-state markers live on Rust handles on the Secure side. They
do **not** travel across the NSC boundary. The NSC veneers stay
`extern "C"` with `u32` / `*const u8` signatures because the NSC ABI
is frozen for backward-compatibility with the existing host
applications, and because `PhantomData` cannot cross a C ABI.

The boundary at which the marker first appears is the NSC veneer body,
after argument validation: a `u32` enclave-id supplied by the NS host
becomes an `EnclaveHandle<Validated>` once the chained-measurement
check passes.

## Alternatives considered

### Alternative A — Runtime state byte inside `Enclave`

Keep the `u8` state field and check it at the head of every transition.

- **Pro**: simplest to implement; no type-system gymnastics.
- **Con**: every kernel reviewer has to keep the state-transition
  table in their head and verify it for each new call site. The
  reviewer cost is unbounded; the compiler is doing nothing.
- **Con**: the "skip the check just this once" anti-pattern is easy
  to land — a caller that *knows* the state can bypass the check
  with no compile-time penalty.
- **Con**: argument-swap (`enclave_id` vs `block_addr`) still flies
  under the type-system radar.

**Rejected** — the failure mode is "kernel runs the wrong transition
because the reviewer missed one call site", which the type system
can eliminate at zero runtime cost.

### Alternative B — Enum with one variant per state

```rust
pub enum Enclave {
    Validated(EnclaveId),
    Loaded(EnclaveId, EssMapping),
    Executing(EnclaveId, EssMapping, PspContext),
}
```

- **Pro**: exhaustive `match` at every call site is a compile-time
  check that all states are handled.
- **Con**: the `match` arms repeat at every call site. Code is
  noisy; an arm omitted because "it can't happen" is exactly the
  shape that fails when invariants drift.
- **Con**: the enum cannot statically encode "this method only
  applies to the Loaded state". The wrong-state caller still
  produces an `unreachable!()` or a fallible return.

**Rejected** — it tightens the compile-time check but does not
eliminate the wrong-call class of bug.

### Alternative C — Trait `Stateful { fn state() -> State; }` with runtime dispatch

Introduce a trait that each state-bearing struct implements, with a
runtime `state()` accessor.

- **Pro**: keeps the door open for future dynamic dispatch on
  state.
- **Con**: nothing about the kernel benefits from dynamic dispatch
  on enclave state — every call site knows which transition it is
  performing. The dynamic-dispatch capability is a hypothetical
  feature paid for by the entire codebase.
- **Con**: same compile-time hole as Alternative A.

**Rejected** — adds infrastructure for a future need that has not
materialised in three years of bring-up.

## Consequences

### Positive

1. **Wrong-order transitions fail at compile time, not at runtime.**
   Calling `handle.execute()` on a `Validated` handle is `E0599`
   "no method named `execute`" — a compile error pointing directly
   at the wrong call site.
2. **Argument swap is closed by the newtypes.** `fn load(id:
   EnclaveId, addr: BlockAddr)` rejects swapped `u32`s at compile
   time. The cost is `#[repr(transparent)]` (zero runtime overhead)
   plus a `.0` accessor where the raw `u32` is genuinely needed.
3. **The sealed trait blocks external state injection.** An external
   crate cannot add an `impl SecurityState for MyState {}` because
   `mod sealed` is private. The three documented states are the
   only ones that exist.
4. **The four `compile_fail` doctests are a regression net.** A
   refactor that accidentally widens a method to a wrong state
   surfaces as a doctest failure.

### Negative

1. **The markers do not cross the NSC ABI.** The veneer body has to
   re-prove the state on entry by performing the validation that
   produces `EnclaveHandle<Validated>`. This is the right cost —
   the NSC boundary is a trust boundary — but it is not free.
2. **Newtype wrappers add `.0` at the few call sites that genuinely
   need the inner `u32`** (mostly inside the NSC veneer and the
   chained-measurement path). The cost is local and visible.
3. **A would-be contributor unfamiliar with type-state Rust** sees
   `EnclaveHandle<Validated>` and may not realise the `Validated`
   marker has no constructor. The module docs and this ADR are the
   place to point them.

## Cross-references

- State machine, code, and end-to-end example: [Type-State Security Domain](../architecture/type-state.md).
- Argument validation at the NSC boundary: [ADR 005](005-nsc-boundary.md).
- Newtype rule for distinct domains: ALWAYS_DO #8 in the
  [contributor guardrails](../contributing/guardrails.md).
