# ADR 001 — Single Cargo workspace with leaf-crate dependency tree

**Status:** Accepted

## Context

Umbra targets multiple STM32 platforms (L552, L562, N657) and must
build at least three artefact families simultaneously:

- a Secure-side firmware binary per platform (`umbra-<mcu>-boot`),
- a per-platform driver crate (`umbra-<mcu>-drivers`),
- the shared Secure kernel (`umbra-kernel`),
- host-side test harnesses runnable under `cargo test`.

A single-crate organisation would couple the boot binary, the kernel,
the platform drivers, and the test harness into one compilation unit.
That has three concrete drawbacks:

1. **Feature-flag explosion**. Per-platform divergence (MMIO layouts,
   linker scripts, NSC veneer tables) would all live behind `cfg`
   blocks in one crate. New platforms multiply the matrix.
2. **No host-side tests**. The Secure boot crate links a vector table
   and a master key; it cannot compile under the host target. Kernel
   logic that wants `cargo test` coverage has to be physically separate.
3. **Re-use across PALs**. The HAL trait surface (`Hash`, `Aes`,
   `Dma`, …) and the canonical error type (`UmbraError`) are consumed
   by every platform. Without crate boundaries the dependency direction
   is implicit and easy to break.

## Decision

Umbra is organised as a **single Cargo workspace** rooted at the repo
top level, with a strict **leaf-crate dependency tree** that flows from
shared definitions outward to platform-specific code:

```
umbra-error  <-  umbra-hal  <-  umbra-api  <-  umbra-kernel  <-  per-platform PAL crates
                                            ^
                                       umbra-pal-test (host-side testing)
```

Each leaf crate is small and has a narrow purpose:

| Crate | Role |
|---|---|
| `umbra-error` | `UmbraError` enum + `UmbraResult<T>` alias. Depends only on `thiserror-no-std`. |
| `umbra-hal` | Peripheral traits (`Hash`, `Aes`, `Dma`, `Rcc`, `Uart`, `Gpio`). |
| `umbra-api` | `Platform`, `CryptoEngine`, and the `SecurityState` markers consumed by the kernel and by every PAL impl. |
| `umbra-pal-test` | Host-side test platform (`TestPlatform`, `MmioMem`) used by `cargo test`. |
| `umbra-kernel` | Secure-side enclave logic, `no_std`, no MMIO. |
| `umbra-<mcu>-boot` | Per-platform binary: vector table, master key, boot flow. |
| `umbra-<mcu>-drivers` | Per-platform impls of the HAL traits. |

The workspace root `Cargo.toml` is the single owner of `[profile.dev]`
and `[profile.release]` (per-crate profile blocks are silently ignored
inside a workspace, so the root is the only honest place for them).

See [Crate Structure](../architecture/crate-structure.md) for the
on-disk layout.

## Alternatives considered

### Alternative A — One crate per platform, no shared workspace

Each platform would carry its own `Cargo.toml`, its own copy of the
kernel sources, and its own driver code.

- **Pro**: zero cross-platform coupling; a regression on one MCU
  cannot break another.
- **Con**: every kernel fix has to be applied three times by hand.
  Cross-platform drift is guaranteed within a release cycle.
- **Con**: shared types (`UmbraError`, the NSC ABI constants) would
  diverge silently.

**Rejected** because the cost of keeping three copies of the kernel in
sync exceeds the cost of one workspace with cfg-gated platform
selection in the kernel.

### Alternative B — Binary + library (no separate leaf crates)

A `src/lib.rs` exposing the kernel and HAL traits plus a `src/main.rs`
per platform.

- **Pro**: simpler build graph than a 13-crate workspace.
- **Con**: there is no place for `umbra-pal-test` — host-side test
  impls cannot share a crate with `no_std` Secure-side code. The cfg
  attributes on every public item would multiply.
- **Con**: per-platform binaries would all link the same library, so
  feature-flag inheritance between binaries is implicit and surprising.

**Rejected** because the project has more than two deployment targets
and needs host-side coverage. The library + binary pattern fits a
single-platform service, not a multi-target embedded codebase.

### Alternative C — Cargo workspace with deeply nested module trees per crate

Same crate count as Decision, but with deep module hierarchies
(`umbra-kernel::secure::ess::cache::block::*`) and no further
crate-level decomposition.

- **Pro**: fewer `Cargo.toml` files to maintain.
- **Con**: re-export discipline is harder to enforce. Without crate
  boundaries, an internal module can be imported from anywhere, and
  the leaf-crate dependency direction is informal.
- **Con**: `cargo check -p umbra-error` cannot prove that the error
  type has no kernel dependencies if the crates are merged.

**Rejected** because the leaf-crate boundaries are a load-bearing part
of the dependency-direction invariant.

## Consequences

### Positive

1. **Dependency direction is mechanically enforced**. `umbra-error`
   has no path back to the kernel; `umbra-hal` has no path back to a
   PAL crate. Adding an accidental upward edge fails `cargo check`.
2. **Per-crate `cargo check`** gives fast feedback on the leaf crates
   without touching platform code: `cargo check -p umbra-error` runs
   in seconds and gates `UmbraError` changes before the kernel rebuild.
3. **Host-side tests are first-class**. `umbra-pal-test::TestPlatform`
   substitutes for the per-MCU PAL in `cargo test`, exercising the
   kernel logic without HW.
4. **Platform-specific code is isolated**. Adding a fourth MCU touches
   only two new crates (`umbra-<mcu>-boot`, `umbra-<mcu>-drivers`) and
   one feature flag in the kernel.

### Negative

1. **More `Cargo.toml` files** to keep aligned (versions, edition,
   `rust-version`). Mitigated by `[workspace.package]` at the root,
   which lets member crates inherit the common metadata.
2. **`*-boot` vs `*-drivers` package-name uniqueness** required a
   per-platform rename: the boot crate aliases the drivers crate via
   `package = "umbra-<mcu>-drivers"` so source files can keep
   writing `use drivers::*` while Cargo sees a unique workspace name.
3. **Per-crate profile blocks are silently ignored**. The workspace
   root is the only place where `panic = "abort"`, `opt-level`, and
   `debug` settings take effect; per-crate overrides are dead code.

## Cross-references

- Crate-by-crate description: [Crate Structure](../architecture/crate-structure.md).
- HAL trait list: [HAL Traits](../architecture/hal-traits.md).
- `umbra-api` re-export surface: [The umbra-api Leaf Crate](../architecture/api-crate.md).
