# Type-State Security Domain

The enclave lifecycle state machine is enforced at compile time. The
surface lives in `crates/umbra-api/src/security.rs`. Misuse —
`execute()`-ing an enclave that has not yet been `load()`-ed,
double-loading, swapping enclave-id arguments — is a Rust compile
error, not a runtime check.

## State machine

```text
  Validated  ──load()──>  Loaded  ──execute()──>  Executing
      ▲                                                │
      └────────── exit() ──────────────────────────────┘
```

Reproduced verbatim from `crates/umbra-api/src/security.rs:8-17`. The
NSC entry path (`umbra_enclave_enter_imp`) translates the NS-supplied
`u32` enclave-id into an `EnclaveHandle<Validated>` after arg-validation
(NEVER_DO #6). From there, the type system enforces correct transitions.

## The trait + markers

`crates/umbra-api/src/security.rs:23-43`:

```rust
/// Sealed trait so external crates cannot add new state markers.
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
```

- **`SecurityState` is sealed.** External crates cannot add new markers
  — only the three known states exist. This is enforced by the private
  `mod sealed` containing `trait Sealed {}`; the four `compile_fail`
  doctests assert this is non-bypassable.
- **State markers are uninhabited enums.** `pub enum Validated {}` has
  no constructors — there is no runtime cost to the marker, only a
  type-level tag.

## The handle

`crates/umbra-api/src/security.rs:45-60`:

```rust
pub struct EnclaveHandle<S: SecurityState> {
    pub id: EnclaveId,
    _state: PhantomData<S>,
}
```

State transitions are encoded as method signatures: `load()` is defined
only on `EnclaveHandle<Validated>`; `execute()` only on
`EnclaveHandle<Loaded>`; `exit()` only on `EnclaveHandle<Executing>`.
Calling a transition consumes the input handle (by value) and returns a
new handle in the next state, so the old state is unreachable.

## Scope: kernel-internal only

Per the clarification at the head of the module
(`crates/umbra-api/src/security.rs:4-10`):

> These markers live **kernel-internal** on Rust handles. They do NOT
> travel across the NSC boundary — the NSC veneers in
> `umbra_nsc_api.rs` stay `extern "C"` with `u32` / `*const u8`
> signatures (the NSC ABI is frozen). `PhantomData` cannot cross a C
> ABI.

The NSC ABI is frozen for backward-compatibility with the existing
host applications. The type-state markers cover the Secure-side use of
the kernel API: the path from "veneer entered, args validated" to
"handle returned to veneer for SG return".

## Compile-fail tests

The module ships four `compile_fail` doctests
(`crates/umbra-api/src/security.rs:91-131`). Cargo runs each by
attempting to compile the inline code and expects a compile error —
i.e. the tests **pass** when the inline code **fails to compile**.

1. **`Validated` cannot `execute()`** — `EnclaveHandle<Validated>` has
   no `execute()` method. Calling it produces an unresolved-method error.
2. **`Validated` cannot `exit()`** — `exit()` is defined only on
   `EnclaveHandle<Executing>`.
3. **`Loaded` cannot re-`load()`** — once an enclave is loaded, the
   `load()` method disappears from its API; the BFS scheduler must
   `execute()` it first or destroy it.
4. **External `SecurityState` impl rejected** — `impl SecurityState for
   MyState {}` from an external crate fails because the trait's
   super-bound on `sealed::Sealed` is not satisfiable outside the
   `umbra-api` crate.

Run the negative tests with:

```bash
cargo test -p umbra-api --doc
```

## Newtypes for enclave IDs and block addresses

The NSC boundary uses `repr(transparent)` newtypes to prevent
argument-swap bugs at compile time (`crates/umbra-api/src/types.rs`):

```rust
#[repr(transparent)] pub struct EnclaveId(pub u32);
#[repr(transparent)] pub struct BlockAddr(pub u32);
#[repr(transparent)] pub struct Measurement(pub [u8; 32]);
```

So `fn load(id: EnclaveId, addr: BlockAddr)` no longer compiles if the
caller swaps the arguments. ALWAYS_DO #8 codifies the rule for new
domain types.

## Example: validator → loader → executor

```rust
use umbra_api::security::{EnclaveHandle, Validated, Loaded, Executing};
use umbra_api::EnclaveId;

// Inside the NSC `_imp` veneer, after arg_validation::ns_slice():
let handle: EnclaveHandle<Validated> = validator.validate(blob)?;
//
// validator.validate(...) is a method on the platform's CryptoEngine
// impl that returns EnclaveHandle<Validated> on chained-measurement
// match. Type-state takes over from here.

let handle: EnclaveHandle<Loaded>    = handle.load();      // ESS pages mapped
let handle: EnclaveHandle<Executing> = handle.execute();   // SG dispatched
// ... enclave runs ...
let _handle: EnclaveHandle<Validated> = handle.exit();     // back to start
```

Any attempt to skip a transition — e.g. calling `handle.execute()` on a
`Validated` handle — fails at compile time. The state machine cannot
desynchronise from the code.
