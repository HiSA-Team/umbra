# Error Handling

Umbra uses a typed enum `UmbraError` (defined in
`crates/umbra-error/src/lib.rs`) for every fallible kernel and driver
path. Every variant names a single failure mode tied to one of the
four Crown Jewels (CJ1–CJ4 from the project's threat model) or to a
specific kernel subsystem (ESS, NSC, enclave lifecycle).

`Result<T, ()>` is banned (NEVER_DO #8): CI greps for the pattern and
the reviewer rejects it.

## The crate

`crates/umbra-error/` is a leaf crate. It depends only on
`thiserror-no-std`, which gives it `Display` + `Error` impls safe for
both bare-metal Secure-side builds and host-side test builds. Three
design notes from the module documentation
(`crates/umbra-error/src/lib.rs:17-30`):

- **`Copy + 'static`**: every variant is cheap to clone and carries no
  borrowed data, so `?` propagation through deep call chains does not
  impose lifetime gymnastics on the kernel.
- **`thiserror-no-std`**: gives `Display` + `Error` impls without
  pulling `std`; safe across all Umbra build targets.
- **HW-specific subtypes via `From` impls**: trait-associated error
  types (`Hash::Error`, `Aes::Error`) carry HW-specific failure info
  (CRYP1 BUSY-timeout, HASH STARTERR bit, OTFDEC key clash). They
  convert into the relevant `UmbraError` variant via `From` impls
  landing alongside each HAL boundary.

## The variant surface

Reproduced from `crates/umbra-error/src/lib.rs:36-87`:

| Bucket | Variant | Diagnostic data |
|---|---|---|
| NSC boundary | `NscArgInvalid { which: &'static str }` | which argument failed validation (CJ4) |
| Enclave lifecycle | `EnclaveNotFound { id: u32 }` | the enclave id |
|  | `EnclaveAlreadyLoaded { id: u32 }` | the enclave id |
|  | `EnclaveStateInvalid` | (none — state machine bug; promoted to a more specific variant if it ever fires) |
| Chained measurement (CJ2) | `MeasurementMismatch { expected: [u8; 8], got: [u8; 8] }` | first 8 bytes of each side for diagnostic without leaking the full digest off-chip |
| Crypto HW | `HashHardware` | from `Hash::Error` via `From` |
|  | `AesHardware` | from `Aes::Error` via `From` |
|  | `KeyDerivation` | KDF failure |
| Memory protection (CJ3) | `DmaTimeout` | DMA never completed |
|  | `EssRegionExhausted` | BFS could not allocate a slot |
|  | `GtzcDenied { addr: u32 }` | the denied address |
| Arithmetic | `OffsetOverflow` | size/offset arithmetic over-/underflowed |
|  | `LengthMismatch` | input/output length disagreement |
| Internal | `InternalInvariant { context: &'static str }` | catch-all for invariant breaks; the `context` string identifies the call site for triage and is expected to be promoted to a specific variant during periodic error-surface review |

`UmbraResult<T>` is the canonical alias:

```rust
pub type UmbraResult<T> = Result<T, UmbraError>;
```

## Why no `Box<dyn Error>` or string payloads

Two constraints kept the variants small and `Copy`:

1. **`no_std` without `alloc`**. The Secure-side kernel cannot allocate;
   variants must own their data inline. The 8-byte truncated digest in
   `MeasurementMismatch` is the deliberate compromise — enough for a
   UART-log reader to spot a known-bad value, not enough to leak CJ1
   secrets.
2. **`Copy` simplifies `?` propagation**. The kernel's deepest error
   chain — `ess::load_block → handle_ess_miss → dma.copy → mpcbb_flip`
   — would otherwise burn lifetime parameters into every signature.
   Keeping `UmbraError: Copy` lets the compiler inline the propagation.

## Example: NSC veneer

The canonical NSC veneer shape, per NEVER_DO #6:

```rust
#[no_mangle]
pub unsafe extern "C" fn umbra_tee_load_imp(blob: *const u8, len: u32) -> u32 {
    let slice = match arg_validation::ns_slice(blob, len) {
        Ok(s) => s,
        Err(_) => return UmbraError::NscArgInvalid { which: "blob" }.into(),
    };
    handle_load(slice).map(Into::into).unwrap_or_else(Into::into)
}
```

The `Into<u32>` impl on `UmbraError` is what carries the variant across
the NSC ABI without breaking the frozen `extern "C"` signature. The
host receives a `u32`; the Secure-side log records the structured
variant before the return.

## Adding a new variant

1. Pick the bucket (NSC, enclave lifecycle, crypto HW, ESS, arithmetic,
   internal). If the existing buckets do not fit, propose a new one in
   the PR — adding a bucket is an ADR-worthy change.
2. Name the variant after the *failure mode*, not the call site. Carry
   the diagnostic data a UART-log reader needs (ALWAYS_DO #7).
3. Add a `From` impl in the HAL-trait error file if a HW-specific
   subtype maps into the new variant.
4. Update the variant-surface table in this chapter.

Existing `InternalInvariant { context }` usages are a backlog item:
each unique `context` string is a candidate for promotion to a more
specific variant.
