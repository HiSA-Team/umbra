# ADR 002 — `UmbraError` enum as the canonical fallible-path type

**Status:** Accepted

## Context

Before this decision, fallible paths in the kernel and drivers returned
`Result<T, ()>`. The unit-typed error throws away every piece of
diagnostic information that a UART-log reader needs to triage a
failure:

- which NSC argument was rejected;
- whether a chained-measurement mismatch occurred at validation or at
  load;
- which DMA channel timed out;
- which GTZC-denied address aborted a transaction.

The cost shows up at two places. First, debugging a Secure-side fault
becomes a guess-and-check loop in GDB because the failure mode is not
encoded in the return value. Second, the NSC veneer cannot return
anything useful to the NS host: an `Err(())` collapses to a single
status code regardless of the underlying reason.

A second constraint is the build environment. The Secure-side kernel
runs `no_std` without `alloc`. The error type cannot box dynamic
trait objects, format strings into owned buffers, or carry a heap
allocation. Anything bigger than a small `Copy` enum is unaffordable.

## Decision

Every fallible kernel and driver path returns `UmbraResult<T> =
Result<T, UmbraError>`, where `UmbraError` is a single typed enum
defined in the `umbra-error` crate.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UmbraError {
    NscArgInvalid { which: &'static str },
    EnclaveNotFound { id: u32 },
    EnclaveAlreadyLoaded { id: u32 },
    EnclaveStateInvalid,
    MeasurementMismatch { expected: [u8; 8], got: [u8; 8] },
    HashHardware,
    AesHardware,
    KeyDerivation,
    DmaTimeout,
    EssRegionExhausted,
    GtzcDenied { addr: u32 },
    OffsetOverflow,
    LengthMismatch,
    InternalInvariant { context: &'static str },
}

pub type UmbraResult<T> = Result<T, UmbraError>;
```

Three load-bearing properties of this type:

1. **`Copy + 'static`** — every variant is cheap to clone and carries
   no borrowed data, so `?` propagation through deep call chains does
   not impose lifetime gymnastics on the kernel.
2. **`thiserror-no-std`** — gives `Display` and `Error` impls without
   pulling `std`; safe across all Umbra build targets.
3. **HW-specific subtypes via `From` impls** — trait-associated error
   types (`Hash::Error`, `Aes::Error`) carry HW-specific failure info
   (CRYP1 BUSY-timeout, HASH STARTERR bit, OTFDEC key clash) and
   convert into the matching `UmbraError` variant via `From` impls at
   each HAL boundary.

`Result<T, ()>` is banned. CI greps for the pattern and the reviewer
rejects it.

See [Error Handling](../architecture/error-handling.md) for the full
variant surface and the canonical NSC-veneer usage.

## Alternatives considered

### Alternative A — Keep `Result<T, ()>` and rely on logs

Continue to return `Err(())` and emit a UART line at each failure
site for context.

- **Pro**: zero migration effort.
- **Con**: the structured information is gone from the type system.
  The NSC return code can only signal "something failed"; the NS host
  cannot react differently to "bad argument" vs "enclave not found".
- **Con**: every site that propagates an error has to remember to log
  before returning. A missed log produces a silent failure.

**Rejected** — the type system is the right place for the failure
taxonomy. Logs are diagnostic supplements, not the source of truth.

### Alternative B — `anyhow::Error` with context strings

Use `anyhow::Error` and chain `.context("…")` at each propagation
site.

- **Pro**: very flexible, no need to enumerate failure modes upfront.
- **Con**: `anyhow` allocates. Without `alloc` available on the
  Secure side it is unusable.
- **Con**: error matching at the boundary becomes string comparison
  or downcasting, which defeats the purpose of an exhaustive
  `match`.

**Rejected** — incompatible with `no_std`-without-`alloc` and with
the exhaustiveness checks the reviewer relies on.

### Alternative C — `Box<dyn Error>` with custom error types

Each subsystem defines its own error type; cross-subsystem
propagation boxes the underlying error.

- **Pro**: each subsystem owns its taxonomy and can evolve
  independently.
- **Con**: `Box` requires `alloc`, which the Secure-side kernel does
  not have.
- **Con**: the NSC ABI cannot transport a `Box<dyn Error>` — the
  veneer return is a `u32`. A single enum maps cleanly to a `u32`;
  a trait object does not.

**Rejected** — same `alloc` blocker as Alternative B, plus the NSC
ABI constraint.

### Alternative D — One `#[repr(u32)]` enum per subsystem with manual conversion

Define `KernelError`, `DriverError`, `NscError` as `#[repr(u32)]`
enums and convert between them at the boundaries with explicit
`From` impls.

- **Pro**: subsystem boundaries are surfaced in the type system.
- **Con**: three enums and N×N `From` impls multiply faster than
  the kernel grows. Reviewers have to follow the conversion chain
  to understand the original failure mode.
- **Con**: the NSC return code becomes ambiguous — two enums could
  reuse the same `u32` value, and the reader at the NS host has no
  way to disambiguate without out-of-band knowledge.

**Rejected** — one enum with `From` impls only at the HAL HW-error
boundary is the simpler shape that the codebase actually needs.

## Consequences

### Positive

1. **Exhaustive `match` at the NSC boundary**. The veneer can decide
   which variants are worth surfacing to the NS host and which to
   collapse to a generic error.
2. **`?` propagation is cheap**. `UmbraError: Copy` means the
   propagation chain `ess::load_block → handle_ess_miss → dma.copy
   → mpcbb_flip` does not burn lifetime parameters into every
   signature.
3. **Diagnostic strings name the inspection target**. Variants like
   `GtzcDenied { addr }` and `MeasurementMismatch { expected, got }`
   carry the data a UART-log reader needs to walk straight to the
   right register or address.
4. **Banning `Result<T, ()>` is a CI gate**, not a reviewer-only
   convention. A `grep -rn 'Result<.*, *()>'` over `src/` and
   `crates/` returns empty as a build invariant.

### Negative

1. **Adding a new failure mode means adding a variant**, and the
   variant must be classified into one of the documented buckets
   (NSC, enclave lifecycle, crypto HW, ESS, arithmetic, internal).
   The cost is low (one PR) but it is not zero.
2. **`InternalInvariant { context }` is a long-lived backlog**. Each
   unique `context` string is a candidate for promotion to a more
   specific variant. The bucket exists so that adding a new failure
   site can land without an immediately blocking ADR discussion.
3. **The truncated digest in `MeasurementMismatch`** (8 bytes per
   side, not the full 32) is a deliberate compromise. Enough for a
   UART reader to spot a known-bad value; not enough to leak the
   full digest off-chip if logs are exfiltrated. The trade-off is
   that very near-collisions cannot be told apart by the log alone.

## Cross-references

- Full variant surface and the canonical NSC veneer shape: [Error Handling](../architecture/error-handling.md).
- HAL trait error subtypes: [HAL Traits](../architecture/hal-traits.md).
- Guardrail enforcing the ban on `Result<T, ()>`: NEVER_DO #8 in the
  [contributor guardrails](../contributing/guardrails.md).
