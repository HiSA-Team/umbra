# ADR 005 — `*_imp` / `*_callable` veneer pair as the only NS→S entry surface

**Status:** Accepted

## Context

ARMv8-M TrustZone splits the address space into a Non-Secure (NS) world
and a Secure (S) world. Cross-world calls are physically gated by the
**Secure Gateway (`SG`)** instruction: an NS caller may only enter the
Secure world by branching to an address tagged as Non-Secure Callable
(NSC) whose first instruction is `SG`. The CPU traps any other NS→S
branch as a `SecureFault`.

Umbra exposes a small published API to NS host applications:
`umbra_enclave_create`, `umbra_enclave_enter`, `umbra_enclave_exit`,
`umbra_enclave_status`, plus the load primitive. Each of these has to
be reachable from NS code, and each has to be impossible to misuse —
the NS caller is the **adversary** in Umbra's threat model.

Two structural questions follow:

1. **What sits at the NSC address?** The first instruction must be
   `SG`, but the body must also validate every NS-supplied argument
   before any Secure-side code dereferences it. A pointer from NS
   that points into Secure RAM is a privilege-escalation primitive
   unless rejected up front.
2. **How does the rest of the Secure-side code reach the same
   functionality?** The kernel's internal callers (a kernel
   subsystem invoking another) must not pay the `SG` overhead, and
   they must not go through the NS-argument-validation gate that
   exists for the *external* caller.

The two needs pull in opposite directions: the published symbol must
validate; the internal callers must skip the validation.

## Decision

Each NSC entry point is implemented as a **veneer pair**:

- **`<name>_callable`** — the NSC-tagged symbol. First instruction
  is `SG`; the rest of the function performs nothing more than a
  branch to the matching `_imp` symbol. The `_callable` symbol is
  published to NS code via the NSC veneer table.
- **`<name>_imp`** — the Secure-side implementation. Performs
  argument validation against the NSC envelope (range, length, no
  wrap-around) **before** any deref of NS-supplied pointers, then
  invokes the kernel logic that satisfies the request.

The linker scripts place `_callable` symbols in the
`.umbra_nsc_api` section at fixed offsets (the published NSC table
addresses) and use `PROVIDE` for `_imp` so cross-crate imports of the
`_imp` symbol produce a link error.

```rust
// Conceptual shape — every NSC verb follows this pattern.

// Published NSC entry: NSC-tagged, body is the SG + tail-branch.
#[no_mangle]
#[link_section = ".umbra_nsc_api"]
pub unsafe extern "C" fn umbra_tee_load_callable(blob: *const u8, len: u32) -> u32 {
    // The `SG` is the first instruction; emitted by the build's NSC
    // tooling. The rest of this function tail-calls _imp.
    umbra_tee_load_imp(blob, len)
}

// Secure-side implementation: validates NS arguments before any deref.
#[no_mangle]
pub unsafe extern "C" fn umbra_tee_load_imp(blob: *const u8, len: u32) -> u32 {
    let slice = match arg_validation::ns_slice(blob, len) {
        Ok(s) => s,
        Err(_) => return UmbraError::NscArgInvalid { which: "blob" }.into(),
    };
    handle_load(slice).map(Into::into).unwrap_or_else(Into::into)
}
```

The `arg_validation::ns_slice` helper enforces:

- `blob` lies inside the NS-RAM window (no Secure-RAM pointers);
- `len` is bounded by `MAX_NSC_ARG_LEN`;
- `blob + len` does not wrap around the address space.

Three rules follow from this shape:

1. **Internal Secure-side callers** invoke kernel functionality via
   the published Secure-side API (`umbra_api::Platform`), not by
   declaring `extern "C" { fn umbra_tee_*_imp(…); }`. The `_imp`
   symbol is reachable from the matching `_callable` veneer and
   from the same translation unit; cross-crate imports of `_imp`
   produce a link error by linker-script design.
2. **NS-supplied pointers** are always validated by `arg_validation`
   before any deref. The `// SAFETY:` comment on the eventual
   `core::slice::from_raw_parts` cites this prior check by name.
3. **The veneer return is `u32`**. Structured `UmbraError` values
   convert into the return code via `Into<u32>`; the host receives
   a u32 status while the Secure-side log records the original
   typed variant before the return.

See [NSC Veneers](../api/nsc-veneers.md) for the published API
table.

## Alternatives considered

### Alternative A — Single function, NSC-tagged

Put argument validation directly in the NSC-tagged function and skip
the `_imp` split.

- **Pro**: simpler — one symbol per verb instead of two.
- **Con**: there is no way for the kernel's internal callers to
  reach the same functionality without paying the `SG` overhead
  and the (redundant, for internal callers) NS-argument check.
- **Con**: refactoring the implementation forces a re-layout of the
  NSC table because the symbol address may shift. Splitting the
  veneer from the impl pins the NSC table address while letting
  the impl evolve.

**Rejected** — the cost is paid at every internal call.

### Alternative B — Validate later, deeper in the kernel

Let the NSC veneer pass NS-supplied values straight into the kernel
and validate at the use site.

- **Pro**: pushes validation closer to the code that actually uses
  the value.
- **Con**: every kernel function on a downstream path becomes
  partially trusted with respect to NS input. The reviewer has to
  prove validation for every leaf, not just for the entry point.
- **Con**: a future refactor that adds a new path to the same
  kernel function may forget to add the validation, silently
  re-opening the hole.

**Rejected** — argument validation belongs at the trust boundary,
not at the use site. The boundary is the right place to enforce a
single gate.

### Alternative C — Validation in C, impl in Rust

Write the NSC veneer in C (for direct control over the entry
sequence) and call into a Rust impl.

- **Pro**: classic embedded pattern; some C toolchains have native
  support for the NSC `SG` annotation.
- **Con**: the C↔Rust boundary becomes an additional surface to
  audit. The reviewer has to follow validation from C into Rust,
  with two different lint regimes.
- **Con**: the published `UmbraError` → `u32` mapping has to be
  duplicated in the C side or marshalled through a shared header.

**Rejected** — keeping the entire trust boundary in Rust lets the
reviewer audit one language with one lint configuration.

### Alternative D — Export `_imp` for testing

Make `_imp` symbols pub-extern so host-side tests can call them
directly without spinning up the NSC table.

- **Pro**: easier unit testing of the impl path.
- **Con**: opens exactly the cross-crate-import hole the linker
  script is designed to close. If the test can call `_imp`
  directly, so can a future Secure-side caller — and there is
  nothing to prevent that future caller from skipping the
  `_callable` veneer's validation invariants.
- **Con**: host-side tests should exercise the *Secure-side API*
  surface (`umbra_api::Platform`), which is the same surface
  used by the `_imp` body after validation. There is no missing
  coverage to recover by exporting `_imp`.

**Rejected** — the testability gain is illusory; the security loss
is real.

## Consequences

### Positive

1. **NS-supplied pointers cannot reach Secure-side deref without
   passing `arg_validation` first.** The validation gate is at the
   entry symbol; the impl assumes the slice is valid; the kernel
   functions that the impl calls assume the same. The proof chain is
   short and one-directional.
2. **The NSC table is stable.** The `_callable` symbols are pinned
   at known addresses by the linker scripts; the `_imp`
   implementations can be refactored without disturbing the
   published API.
3. **Internal callers do not pay `SG`.** Kernel subsystems calling
   each other via `umbra_api::Platform` execute as ordinary Secure-
   side Rust calls.
4. **Cross-crate `extern "C" { fn *_imp(…) }` is a link error.**
   The `_imp` symbol is intentionally not provided to other Secure-
   side modules; the linker enforces what the convention asks for.

### Negative

1. **Every new NSC verb requires touching three files**: the impl
   site (`_imp`), the veneer table (`_callable` in
   `umbra_nsc_api.rs`), and the linker script pinning the address.
   The cost is small per addition but is not zero.
2. **Argument validation is not free**. The `arg_validation::ns_slice`
   call adds two comparisons and a `checked_add` per entry. This is
   acceptable for the NSC entry rate Umbra targets; it would not be
   acceptable for a hypothetical hot-loop NSC verb.
3. **The `_imp` symbol is named, not numbered.** A future change to
   the validation helpers (e.g. a new bound) requires touching every
   `_imp` body. There is no shared scaffolding that would make this
   automatic; the cost is paid in reviewer attention at every
   change.

## Cross-references

- The published NSC verbs and their status-code conventions: [NSC Veneers](../api/nsc-veneers.md).
- `UmbraError::NscArgInvalid` and the `Into<u32>` mapping: [Error Handling](../architecture/error-handling.md).
- Type-state markers that the `_imp` body produces on success: [ADR 004](004-type-state-security-domain.md).
