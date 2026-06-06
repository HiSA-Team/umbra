# The `umbra-api` Leaf Crate

`crates/umbra-api/` is the leaf of the workspace dependency graph. It
contains only trait definitions, shared newtypes, and constants —
everything else (kernel, drivers, boot, host tests) depends on it. The
kernel itself is just another consumer of `umbra-api`, not the
re-export hub it would naturally become without this discipline.

The result: the dependency graph becomes a tree, not a hub-and-spoke
mesh. See `crates/umbra-api/src/lib.rs:3-25` for the rationale in full.

## What's in the crate

`crates/umbra-api/src/lib.rs:27-38`:

```rust
pub mod platform;       // PlatformBoot
pub mod crypto;         // CryptoEngine
pub mod memory_guard;   // MemorySecurityGuardTrait shape
pub mod types;          // EnclaveId, BlockAddr, Measurement
pub mod constants;      // MEMORY_BLOCK_SIZE, etc.
pub mod security;       // SecurityState markers + EnclaveHandle<S>

pub use crypto::CryptoEngine;
pub use platform::PlatformBoot;
pub use types::{EnclaveId, BlockAddr, Measurement};
```

Per-module summary:

- **`platform.rs`** (`PlatformBoot`) — the boot-time PAL contract. Each
  `umbra-<mcu>-boot` crate implements this. Methods: `init_clocks`,
  `init_gpio`, `init_uart`, `init_security`, `init_kernel`,
  `init_external_flash`, `configure_ns_boot`, `jump_to_ns`. See
  [Boot Flow](boot-flow.md).
- **`crypto.rs`** (`CryptoEngine`) — the kernel's boundary to per-platform
  crypto. Three methods: `hmac(key, data, output)`, `hash(data, output)`,
  `aes_decrypt(key, iv, data)`. Each returns `UmbraResult<()>`. See
  `crates/umbra-api/src/crypto.rs:12-26`.
- **`memory_guard.rs`** — `MemorySecurityGuardTrait` shape (the L552
  MPCBB / N657 RISAF abstraction). Migration deferred: the trait
  depends on `MemoryBlockList` → `MEMORY_BLOCK_SIZE`, which the kernel
  `build.rs` generates from the `UMBRA_SLOT_SIZE_BYTES` env var. Moving
  the trait to `umbra-api` requires either mirroring that build script
  or parametrising the trait over slot size — out of scope for the
  refactor. Kernel currently re-exports its existing trait.
- **`types.rs`** — `repr(transparent)` newtypes for NSC arguments
  (`EnclaveId`, `BlockAddr`, `Measurement`). ALWAYS_DO #8.
- **`constants.rs`** — kernel-wide constants such as `MEMORY_BLOCK_SIZE`
  that drivers and kernel must agree on.
- **`security.rs`** — `SecurityState` markers + `EnclaveHandle<S>`. See
  [Type-state security domain](type-state.md).

## Dependency-graph invariant

`cargo tree -p umbra-api` shows exactly one dependency:

```
umbra-api v0.1.0
└── umbra-error v0.1.0
    └── thiserror-no-std v...
```

Nothing else. The crate is forbidden from importing the kernel, any
driver, or `core` modules that would couple it to a platform. A
periodic `cargo tree -p umbra-api` check is the canonical way to
verify the invariant has not regressed.

## How the kernel consumes it

The kernel imports trait + type symbols from `umbra-api` and re-exports
them at `kernel::*` paths for backwards compatibility with existing
call sites. See `src/kernel/Cargo.toml`:

```toml
[dependencies]
umbra-error = { path = "../../crates/umbra-error" }
umbra-api   = { path = "../../crates/umbra-api" }
```

The kernel's `lib.rs` then has shims of the form:

```rust
pub use umbra_api::PlatformBoot;
pub use umbra_api::CryptoEngine;
pub use umbra_api::types::{EnclaveId, BlockAddr, Measurement};
```

So existing code at `use kernel::PlatformBoot;` keeps compiling
unchanged. The shims are scheduled for removal as in-tree call sites
switch to `use umbra_api::PlatformBoot;` directly.

## How the driver / boot crates consume it

Each platform's driver crate implements one or more `umbra-api` /
`umbra-hal` traits. For example, `umbra-l552-drivers` implements
`umbra_hal::Hash` for the HW HASH peripheral, and the L552 boot crate's
`crypto_impl.rs` then implements `umbra_api::CryptoEngine` on top of
that. The boot crate also implements `umbra_api::PlatformBoot` in
`platform_impl.rs`.

The pattern:

1. Drivers implement `umbra-hal` traits (the low-level peripheral verbs).
2. The boot crate's `crypto_impl.rs` lifts those traits into the
   `CryptoEngine` shape the kernel expects.
3. The boot crate's `platform_impl.rs` implements `PlatformBoot` for
   the platform and threads everything together.

## Why a separate crate (and not a `pub mod api` inside the kernel)

Two reasons:

1. **Cycle break.** The pre-refactor kernel could not be host-built
   because some platform driver re-exported a kernel type, which the
   kernel re-imported through a feature, which re-pulled the
   driver, … `umbra-api` as a leaf breaks every such cycle by being
   the only place those types live.
2. **Test surface scoping.** `cargo test -p umbra-api` runs the four
   `compile_fail` doctests (see [Type-state](type-state.md)) without
   pulling in the kernel's whole transitive dep tree. Faster CI, easier
   bisect.

## Symbol surface

| Symbol | Location | Notes |
|---|---|---|
| `PlatformBoot` | `crates/umbra-api/src/platform.rs` | Kernel re-exports for source-compat. |
| `CryptoEngine` | `crates/umbra-api/src/crypto.rs` | Kernel re-exports for source-compat. |
| `EnclaveId` / `BlockAddr` / `Measurement` | `crates/umbra-api/src/types.rs` | `repr(transparent)` newtypes. |
| `SecurityState` markers | `crates/umbra-api/src/security.rs` | See [Type-state](type-state.md). |
| `MemorySecurityGuardTrait` | `crates/umbra-api/src/memory_guard.rs` | Skeleton only — see deferral note below. |
| `MEMORY_BLOCK_SIZE` | `crates/umbra-api/src/constants.rs` | Build-script driven (see kernel `build.rs`). |
