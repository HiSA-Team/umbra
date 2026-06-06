# ALWAYS_DO — eighteen mandatory practices

The positive companion of [NEVER_DO](never-do.md). Reviewer checks new
code against this list; CI enforces a subset via `clippy`, `rustfmt`,
and the file-size check.

---

## Memory & safety

### 1. Borrow over clone

Use `&[u8]` not `Vec<u8>`. In `no_std` without `alloc` this is mostly
forced; in host-side test code, still prefer the borrow.

```rust
// ✅ pass slice
fn measure(data: &[u8]) -> [u8; 32] { ... }
```

**Tooling**: `clippy::needless_pass_by_value` (warn).

---

### 2. Wrap MMIO in `volatile-register` / `tock-registers`

Typed access only, no raw `core::ptr::write_volatile` outside the
wrapper. The HAL traits and the `MmioAccess` abstraction make even
host-side tests honour the typed contract.

```rust
// ✅ typed register access
self.regs.cr().modify(|_, w| w.uesm().set_bit());

// or via the trait:
self.mmio.write(CR_OFFSET, value);
```

**Tooling**: reviewer scan for raw `*const u32` / `*mut u32` writes
outside `peripheral_regs::RealMmio` / `peripheral_regs::write_register`.

---

### 3. Use `try_into()` / `checked_*` for any computed offset or size

Mirrors NEVER_DO #3. The `?` plus `UmbraError::OffsetOverflow` pattern:

```rust
let upper = base.checked_add(len).ok_or(UmbraError::OffsetOverflow)?;
let idx = usize::try_from(field).map_err(|_| UmbraError::LengthMismatch)?;
```

**Tooling**: `clippy::arithmetic_side_effects` (warn) flags raw `+`/`*`
on integer types; `clippy::cast_*` flag the cast.

---

### 4. Every `unsafe` block: minimal scope, real `// SAFETY:` comment

Bound the `unsafe` block to the *one* operation that needs it. The
`// SAFETY:` comment names the invariant — not "this is safe because
we checked".

```rust
let header = unsafe {
    // SAFETY: caller's `ns_slice` returned Ok, so ptr is in
    // [NS_RAM_BASE, NS_RAM_TOP) and len <= MAX_NSC_ARG_LEN.
    core::slice::from_raw_parts(ptr, len)
};
process(header)?;  // back in safe Rust
```

**Tooling**: `clippy::undocumented_unsafe_blocks` (deny in CI).

---

## Errors

### 5. `UmbraError` for every fallible path

The canonical error type. Defined in `crates/umbra-error`, derived via
`thiserror-no-std`. Add a new variant when a new failure mode appears
— do not reuse a tangentially-related one. See
[ADR 002](../decisions/002-umbra-error.md).

```rust
fn validate(&self, blob: &[u8]) -> Result<(), UmbraError> { ... }
```

**Tooling**: `grep -rn 'Result<.*, *()>' src/ crates/` must return
empty (NEVER_DO #8 enforcement).

---

### 6. `?` propagation through all kernel and driver call chains

No silent `let _ = …`; no `match` that swallows the error.

```rust
// ✅
let header = parse_header(blob)?;
let measurement = self.hash.measure(header.bytes)?;
```

**Tooling**: `clippy::let_underscore_must_use` (warn) flags discarded
`Result`s.

---

### 7. Error variants describe *what*, *why*, and *what to inspect*

Each `UmbraError` variant carries the diagnostic data a kernel-log
reader needs.

```rust
// ✅
#[error("Measurement mismatch (expected={expected:?}, got={got:?})")]
MeasurementMismatch { expected: [u8; 8], got: [u8; 8] }

// ✅
#[error("GTZC denied at addr=0x{addr:08x}")]
GtzcDenied { addr: u32 }
```

Reading the panic dump should point to the file / register / address
that the developer needs to inspect next.

---

## Type safety

### 8. Newtypes for distinct domains

`u32` is too coarse. Wrap with `repr(transparent)` newtypes:

```rust
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EnclaveId(pub u32);

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BlockAddr(pub u32);
```

Then `fn load(id: EnclaveId, addr: BlockAddr)` won't accept the
arguments swapped. See [ADR 004](../decisions/004-type-state-security-domain.md).

---

### 9. Enums for exclusive states

Three or more mutually exclusive states ⇒ an enum, not booleans.

```rust
// ❌
let is_secure: bool = ...;
let is_callable: bool = ...;

// ✅
enum SecurityDomain { Secure, NonSecure, Callable }
```

Reviewer rejection signal: any function taking two `bool` args that
together encode a state space.

---

### 10. `PhantomData` markers for compile-time security domains

`EnclaveHandle<S>` with `S: SecurityState` markers
(`Validated` / `Loaded` / `Executing`) makes misuse a compile error.

```rust
// Compiles
let handle: EnclaveHandle<Validated> = validator.validate(blob)?;
let handle: EnclaveHandle<Loaded> = loader.load(handle)?;

// Compile error — can't execute a Validated handle that's never been Loaded
executor.execute(handle_validated);   // E0308: expected `Loaded`, found `Validated`
```

**Tooling**: `crates/umbra-api/src/security.rs` ships four
`compile_fail` doctests asserting the negative cases. See
[ADR 004](../decisions/004-type-state-security-domain.md).

---

## Testing

### 11. TDD red-green-refactor for new kernel logic

Write the failing test first, drive the minimum implementation, then
refactor. `umbra-pal-test` is the host-side test harness.

```rust
// 1. RED
#[test]
fn ess_rejects_oob_block_addr() {
    let mut plat = TestPlatform::new();
    let enclave = plat.create_enclave(0x0801_0000, 4096);
    let err = ess::validate_block_addr(&plat, &enclave, BlockAddr(0x0801_2000))
        .unwrap_err();
    assert_eq!(err, UmbraError::EssRegionExhausted);
}

// 2. GREEN — minimum impl
// 3. REFACTOR — names + extract constants
```

---

### 12. Property tests for invariants

`proptest` host-side for the Enclave Swap Space, BFS scheduling,
chained-measurement, NSC arg validation. Property tests catch corner
cases unit tests miss (saturating arithmetic, off-by-one on size
envelopes).

---

### 13. The host-side test platform is the entry point for kernel-logic tests

`umbra-pal-test` provides `TestPlatform` for kernel-side tests and
`MmioMem` for driver-side tests.

```rust
use umbra_pal_test::TestPlatform;
use umbra_pal_test::mmio::{MmioMem, MmioOp};
```

---

### 14. Every fix lands with a regression test

The test fails on the broken code, passes after the fix. No silent
"just fix it" PRs.

**Reviewer prompt**: "Where's the test that fails on the parent
commit?" If the answer is "manual HW smoke", document that explicitly
in the PR (it is only acceptable when the bug is HW-state-dependent).

---

## Style & hygiene

### 15. `cargo fmt --check`, `cargo clippy -D warnings`, `cargo doc --no-deps` green on every push

CI Job 1 runs all three. The deny-warnings clause is non-negotiable.

**Tooling**: `.github/workflows/build.yml` cargo-check job.

---

### 16. Public items have `///` doc with example or invariant

Every `pub fn` / `pub struct` / `pub enum` either shows a usage
example or names the invariant it maintains.

```rust
/// Validate an NS-supplied slice fits the NSC argument envelope.
///
/// Returns `Err(UmbraError::NscArgInvalid)` if `ptr + len` exceeds
/// `NS_RAM_TOP` or `len > MAX_NSC_ARG_LEN`.
///
/// CJ4: this is the single arg-validation gate for the NSC boundary.
pub fn ns_slice(ptr: *const u8, len: u32) -> Result<&'static [u8], UmbraError> { ... }
```

**Tooling**: `cargo doc --workspace --no-deps` must emit zero
warnings (CI gate in Job 1).

---

### 17. Cross-file hazards observed during debugging become `///` doc

If a bug-class only repeats because the constraint isn't visible at
the call site, promote the diagnostic note to a `///` comment on the
affected item.

Example: the N657 Enclave Swap Space layout comment block in
`src/kernel/src/common/ess.rs` explains *why* the ESS base lives at
`0x340E0000` rather than just *what* the address is.

---

### 18. Conventional commits

Prefix every commit subject with one of:
`feat:` / `fix:` / `refactor:` / `test:` / `docs:` / `chore:` / `perf:`.
