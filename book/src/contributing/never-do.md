# NEVER_DO — twelve prohibitions

This page holds the full text of the twelve `NEVER_DO` rules. The
summary table lives in the [Guardrails overview](guardrails.md); each
rule below carries the canonical bad/good shape and the CI or
reviewer step that catches it.

Cross-reference: [ALWAYS_DO](always-do.md) is the positive form;
[Code review checklist](code-review-checklist.md) is the reviewer's
runtime walk; [Threat Model (ADR 000)](../decisions/000-threat-model.md)
defines the Crown Jewels `CJ1–CJ4` cited below.

---

## 1. Never `.unwrap()` / `.expect()` on attacker-influenceable data

Return `UmbraError` via `?`. Initialisation or encoding paths may keep
`.unwrap()` only with a `// SAFETY:` comment naming the invariant.

```rust
// ❌ NEVER  (parsed length comes from NS-supplied header)
let len: usize = header_buf[4..8].try_into().unwrap();

// ✅ ALWAYS
let len: u32 = u32::from_le_bytes(
    header_buf[4..8].try_into()
        .map_err(|_| UmbraError::NscArgInvalid { which: "header.len" })?
);
```

**Why CJ4**: an unwrap on an NS-influenced path turns input fuzz into a
crash, which under the [panic policy](../decisions/007-panic-policy.md)
becomes `SYSRESETREQ` and is therefore a DoS surface.

**Enforcement**: `cargo clippy --workspace -- -D clippy::unwrap_used
-D clippy::expect_used` in CI. Suppress only with
`#[allow(clippy::unwrap_used)]` + a real `// SAFETY:` comment.

---

## 2. Never `unsafe { ... }` without a real `// SAFETY:` comment

An empty `// SAFETY:` line is slop. Either name the invariant or
refactor the block out (HAL trait, `volatile-register` wrapper, etc.).

```rust
// ❌ NEVER
unsafe {
    // SAFETY:
    core::slice::from_raw_parts(ptr, len)
}

// ✅ ALWAYS
let slice = unsafe {
    // SAFETY: `ptr` was validated by `arg_validation::check_ns_range`
    // (CJ4) to point inside the NS RAM window 0x2000_0000..0x2003_0000;
    // `len` was bound-checked against MAX_NSC_ARG_LEN earlier in this
    // function. The lifetime borrow ends when this NSC veneer returns.
    core::slice::from_raw_parts(ptr, len)
};
```

**Enforcement**: `cargo clippy --workspace -- -D
clippy::undocumented_unsafe_blocks` in CI. Reviewer spot-checks that
the comment text says something load-bearing about the invariant.

---

## 3. Never `as`-cast on size or offset calculations

Use `try_into()?` or `checked_add` / `checked_mul`. Truncation on an
offset is a CJ3 (EFB confidentiality) hazard.

```rust
// ❌ NEVER  (block_idx could exceed (u32::MAX - base) / size)
let block_addr = (base + block_idx * SLOT_SIZE) as usize;

// ✅ ALWAYS
let block_addr: u32 = block_idx
    .checked_mul(SLOT_SIZE)
    .and_then(|delta| base.checked_add(delta))
    .ok_or(UmbraError::OffsetOverflow)?;
let block_addr = usize::try_from(block_addr)
    .map_err(|_| UmbraError::OffsetOverflow)?;
```

**Why CJ3**: a wrapping multiplication on the ESS block offset lets an
attacker steer a DMA write into an adjacent enclave's region.

**Enforcement**: `cargo clippy --workspace -- -W
clippy::cast_possible_truncation -W clippy::cast_possible_wrap` —
currently a warning, expected to deny once the residual call-site
backlog is migrated.

---

## 4. Never `transmute` without `#[repr(C)]` on both sides

`transmute` between non-`#[repr(C)]` types is undefined behaviour. If
you need it on a `#[repr(Rust)]` type, redesign — usually a
`From`/`TryFrom` impl plus `zerocopy::FromBytes` covers it.

```rust
// ❌ NEVER
let header: EnclaveHeader = unsafe { core::mem::transmute(raw_buf[0..32]) };

// ✅ ALWAYS  (header is #[repr(C)] + derives zerocopy::FromBytes)
let header = EnclaveHeader::ref_from(&raw_buf[0..32])
    .ok_or(UmbraError::NscArgInvalid { which: "header.shape" })?;
```

**Enforcement**: `cargo clippy --workspace -- -D
clippy::transmute_undefined_repr` in CI. Reviewer checks both source
and target carry `#[repr(C)]` or `#[repr(transparent)]`.

---

## 5. Never block in fault handlers without consulting the panic policy

`loop {}` in a fault handler is a DoS surface. The accepted policy
([ADR 007](../decisions/007-panic-policy.md)) is: log +
`SCB.AIRCR.SYSRESETREQ`, with `debug-halt` feature flag preserving
the halt for attached-debugger sessions.

```rust
// ❌ NEVER
#[exception]
fn HardFault(_ef: &ExceptionFrame) -> ! {
    panic_dump();
    loop {}                       // device hangs until power cycle
}

// ✅ ALWAYS
#[exception]
fn HardFault(_ef: &ExceptionFrame) -> ! {
    panic_dump();
    panic_policy::handle_fault();  // SYSRESETREQ in production, WFI under debug-halt
}
```

**Enforcement**: reviewer greps new handlers for `loop {}` / `wfi` —
must route through `panic_policy::handle_fault()` or
`panic_policy::halt_for_debug()`.

---

## 6. Never trust NS-supplied pointers in NSC veneer impls

NS callers may pass any value; validate `range + length` before any
deref. The NSC ABI is the *only* NS→S entry surface (CJ4).

```rust
// ❌ NEVER
#[no_mangle]
pub unsafe extern "C" fn umbra_tee_load_imp(blob: *const u8, len: u32) -> u32 {
    let slice = core::slice::from_raw_parts(blob, len as usize);
    handle_load(slice)
}

// ✅ ALWAYS
#[no_mangle]
pub unsafe extern "C" fn umbra_tee_load_imp(blob: *const u8, len: u32) -> u32 {
    let slice = match arg_validation::ns_slice(blob, len) {
        Ok(s) => s,
        Err(_) => return UmbraError::NscArgInvalid { which: "blob" }.into(),
    };
    handle_load(slice).map(Into::into).unwrap_or_else(Into::into)
}
```

`arg_validation::ns_slice` enforces: `blob ∈ NS-RAM range`,
`len ≤ MAX_NSC_ARG_LEN`, `blob + len` does not wrap.

**Enforcement**: every new NSC veneer (`*_imp` symbol) must call into
`arg_validation` for each pointer arg. See
[ADR 005](../decisions/005-nsc-boundary.md) for the `_callable` /
`_imp` split that makes this enforceable.

---

## 7. Never re-implement a driver per platform when a HAL trait exists

If `umbra-hal` already defines the trait, implement it in the relevant
PAL crate. Per-platform forks of `Hash` / `Aes` / `Dma` lead to drift
and double-bug surface.

```rust
// ❌ NEVER  (per-platform copy of the same SHA-256 routine)
// src/hardware/platform/stm32l552/drivers/src/sha256.rs    — copy A
// src/hardware/platform/stm32n657/drivers/src/sha256_sw.rs — copy B

// ✅ ALWAYS  (one trait, multiple impls)
// crates/umbra-hal/src/hash.rs                — trait Hash { fn update(&mut self, data: &[u8]); ... }
// crates/umbra-pal-l552/.../hash.rs           — impl Hash for L552Hash { ... HW HASH peripheral }
// crates/umbra-pal-n657/.../hash.rs           — impl Hash for N657Hash { ... SW SHA-256 (RIF blocks HW) }
```

**Enforcement**: when adding a driver in `umbra-pal-*`, first check
`crates/umbra-hal/src/` for an existing trait. If the new driver
category isn't there yet, extend `umbra-hal` first. See
[ADR 003](../decisions/003-hal-traits.md).

---

## 8. Never use `Result<T, ()>`

Every error must carry context. If a fallible function has only one
failure mode, name it in `UmbraError`.

```rust
// ❌ NEVER
fn measure(blob: &[u8]) -> Result<[u8; 32], ()> { ... }

// ✅ ALWAYS
fn measure(blob: &[u8]) -> Result<[u8; 32], UmbraError> {
    if blob.is_empty() {
        return Err(UmbraError::NscArgInvalid { which: "blob.empty" });
    }
    ...
}
```

**Enforcement**: `grep -rn 'Result<.*, *()>' --include='*.rs' src/
crates/` must return empty as a CI invariant. See
[ADR 002](../decisions/002-umbra-error.md).

---

## 9. Never reorder DMA → MPCBB / RIF operations

The MPCBB pre-flip / post-flip pattern around DMA is load-bearing.
The authoritative reference is the `handle_ess_miss` implementation
in `src/kernel/src/...`.

```rust
// ❌ NEVER
dma.transfer(src, dst, len);
mpcbb_set_slot_secure(dst, false);    // already too late — GTZC dropped the writes

// ✅ ALWAYS
mpcbb_set_slot_secure(dst, false);    // flip NS BEFORE DMA
dma.transfer(src, dst, len);
mpcbb_set_slot_secure(dst, true);     // re-secure AFTER DMA
icache_invalidate_range(dst, len);    // if destination is executable code
```

For slot sizes greater than 256 bytes, flip every 256-byte sub-block.

**Enforcement**: every new DMA call site has a paired MPCBB pre/post-
flip *in the same function*. Splitting the pre-flip into a caller is a
code smell — review for race windows.

---

## 10. Never modify the master key as a side-effect

`master_key.rs` and `tools/master_key.bin` live behind the
`xtask flash` auto-revert; modifying them in an unrelated PR breaks
the chain of trust on every deployed board. See
[ADR 006](../decisions/006-master-key-chain.md).

**Enforcement**: any diff touching `master_key.rs` or
`tools/master_key.bin` must be from a PR titled `feat(crypto):` or
`fix(crypto):` and reference the master-key tracker.

---

## 11. Never commit binaries

`*.bin`, `*.o`, `*.elf`, `*.a` are build outputs. Source belongs in
git; artefacts belong in `target/` (gitignored).

```bash
# ❌ NEVER
git add host/stm32l552/bare_metal/enclaves_plain.bin
git add host/stm32l552/bare_metal/lib/libumbra.a

# ✅ ALWAYS
# Add the offending path to .gitignore. Build outputs regenerate.
```

**Enforcement**: optional CI step `find . -name '*.bin' -not -path
'./tools/*' | grep .` must exit 1. `.gitignore` already lists `*.o`,
`*.bin`, `host/.../app/`, `host/.../obj/`. Add new patterns when new
build artefacts appear.

---

## 12. Never invoke a `_imp` symbol from outside its NSC veneer pair

The `*_callable` (Secure-callable veneer) ↔ `*_imp` (Secure-side
implementation) linker pair *is* the security boundary. Direct calls
from another Secure-side module skip the arg-validation gate.

```rust
// ❌ NEVER  (calling _imp directly from a different Secure module)
extern "C" {
    fn umbra_tee_create_imp(...);
}
umbra_tee_create_imp(...);

// ✅ ALWAYS  (call via the published Secure-side API)
use umbra_api::Platform;
platform.create_enclave(...)?;
```

The `_imp` symbol is only callable from within its own translation
unit and from the matching NSC veneer.

**Enforcement**: `extern "C" { fn *_imp(...) }` declarations outside
the veneer's own file are always a defect. The `*_imp` `PROVIDE` in
the linker scripts intentionally doesn't export; cross-crate calls
produce a link error. See [ADR 005](../decisions/005-nsc-boundary.md).
