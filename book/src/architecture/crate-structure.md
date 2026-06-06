# Crate Structure

Umbra is organised as a single Cargo workspace rooted at the repo top
level. Every firmware crate, the host-side test platform, and the build-orchestrator
`xtask` live in the same `Cargo.lock` (workspace `Cargo.toml` lines 10–23).

Each crate has a unique workspace name (`umbra-<mcu>-boot`,
`umbra-<mcu>-drivers`) and sits next to four leaf crates: `umbra-api`,
`umbra-hal`, `umbra-error`, `umbra-pal-test`.

## Workspace layout

```
umbra/
├── Cargo.toml                    # workspace root, single Cargo.lock
├── crates/
│   ├── umbra-api/                # leaf: traits + types consumed everywhere
│   ├── umbra-error/              # leaf: UmbraError + UmbraResult<T>
│   ├── umbra-hal/                # leaf: peripheral traits (Hash, Aes, …)
│   └── umbra-pal-test/           # host-side test impls for `cargo test`
├── src/
│   ├── kernel/                   # umbra-kernel: enclave logic, no MMIO
│   └── hardware/
│       ├── architecture/arm/     # arm: ARMv8-M primitives (SAU, MPU, startup.s)
│       ├── common/peripheral_regs/  # MmioAccess trait + RealMmio
│       └── platform/
│           ├── stm32l552/
│           │   ├── boot/         # umbra-l552-boot (binary) — see "Boot crate layout" below
│           │   ├── drivers/      # umbra-l552-drivers — see "Driver crate layout" below
│           │   └── linker/
│           └── stm32n657/
│               ├── boot/         # umbra-n657-boot (binary)
│               ├── drivers/      # umbra-n657-drivers
│               └── linker/
├── xtask/                        # build/flash/test orchestrator
└── tools/                        # CI scripts (check_file_size.sh, …)
```

### Submodule layout pattern

Large compilation units are decomposed using Rust's mixed `file.rs +
folder/` module form so the public API path stays stable while the
implementation splits across smaller files. Two examples:

```
src/hardware/platform/stm32l552/boot/src/
├── api_impl/                    # 7 NSC veneer impls + arg_validation
│   ├── mod.rs                   # facade: `pub mod` declarations
│   ├── arg_validation.rs
│   ├── debug_print.rs
│   ├── enclave_create.rs
│   ├── enclave_enter.rs
│   ├── enclave_exit.rs
│   └── enclave_status.rs
├── secure_kernel/               # ESS-residency lifecycle
│   ├── mod.rs                   # `pub mod {init, enter, exit, lifecycle};`
│   ├── init.rs                  # singleton bootstrap, key chain, SysTick
│   ├── enter.rs                 # block-into-residency at boot
│   ├── exit.rs                  # block-out-of-residency (UDF + MPCBB flip)
│   └── lifecycle.rs             # runtime ESS miss recovery
├── platform_impl/               # PlatformBoot trait impl, split by concern
│   ├── mod.rs
│   ├── boot.rs
│   ├── dma.rs
│   ├── power.rs
│   └── syscall_dispatch.rs
└── …                            # flat files: main.rs, handlers.rs, validator.rs, …

src/hardware/platform/stm32l552/drivers/src/
├── dma.rs                       # core controller (Dma<M>, Request, …)
├── dma/
│   ├── copier.rs                # umbra-hal::Dma trait adapter (CpuDmaCopier)
│   └── tests.rs                 # #[cfg(test)] unit tests
├── hash.rs                      # core HASH driver
├── hash/
│   └── tests.rs                 # split per hard-cap; same pattern on N657
├── aes/                         # ecb / ctr / keyreg / gcm / hal_adapter / emulated
└── …
```

The pattern is mechanical: `foo.rs` declares `mod sub;` (or
`#[cfg(test)] mod tests;`) for each file in the sibling `foo/`
directory, and re-exports user-facing items with `pub use sub::Item;`.
External callers never see the split — `crate::drivers::dma::Request`
and `crate::secure_kernel::Kernel` resolve the same as before.

## Per-crate responsibilities

### `umbra-api` — leaf API

`crates/umbra-api/` is the dependency-graph leaf. It contains only traits,
shared newtypes (`EnclaveId`, `BlockAddr`, `Measurement`), constants, and
the type-state security markers. `cargo tree -p umbra-api` shows a single
dependency: `umbra-error`. Every other crate — `kernel`, drivers, boot,
host tests — depends on `umbra-api`, never the other way around.

What lives here:

- `platform.rs` — `PlatformBoot` trait (the boot-time PAL contract). See
  `crates/umbra-api/src/platform.rs:10-37`.
- `crypto.rs` — `CryptoEngine` trait (HMAC, hash, AES decrypt). See
  `crates/umbra-api/src/crypto.rs:12-26`.
- `security.rs` — `SecurityState` markers + `EnclaveHandle<S>` newtype +
  4 `compile_fail` doctests. See [Type-state security domain](type-state.md).
- `types.rs` — `EnclaveId`, `BlockAddr`, `Measurement` newtypes.
- `memory_guard.rs` — `MemorySecurityGuardTrait` shape (migration in
  progress; kernel re-exports from here once stabilised).
- `constants.rs` — kernel-wide constants such as `MEMORY_BLOCK_SIZE`.

The kernel re-exports symbols from `umbra-api` so existing
`use kernel::PlatformBoot` call sites stay green during the migration.

### `umbra-error` — typed kernel errors

`crates/umbra-error/src/lib.rs` defines `UmbraError` plus the type alias
`pub type UmbraResult<T> = Result<T, UmbraError>;`. Each variant names a
single failure mode and carries the diagnostic data a UART-log reader
needs (`MeasurementMismatch { expected: [u8; 8], got: [u8; 8] }`,
`GtzcDenied { addr: u32 }`, …).

Implementation notes from `crates/umbra-error/src/lib.rs:19-30`:

- `Copy + 'static` — `?` propagation through deep call chains carries no
  lifetime burden.
- `thiserror-no-std` — gives `Display` + `Error` impls without pulling
  `std`, safe on both bare-metal and host-side builds.
- HW-specific subtypes (`Hash::Error`, `Aes::Error`) convert into
  `UmbraError` via `From` impls landing alongside each HAL boundary.

See [Error handling](error-handling.md) for the full surface and the
NEVER_DO #8 enforcement (`Result<T, ()>` banned).

### `umbra-hal` — peripheral trait surface

`crates/umbra-hal/src/lib.rs` exposes six traits: `Hash`, `Aes`, `Dma`,
`Rcc`, `Uart`, `Gpio`. The traits are Secure-side aware (their semantics
assume operation from the Secure world of an ARMv8-M / ARMv8.1-M MCU) —
they are deliberately narrower than `embedded-hal`.

- L552/L562 impls live in `umbra-l552-drivers`.
- N657 impls live in `umbra-n657-drivers`.
- Host-side impls live in `umbra-pal-test`.

Trait files: `hash.rs`, `aes.rs`, `dma.rs`, `rcc.rs`, `uart.rs`, `gpio.rs`
under `crates/umbra-hal/src/`. See [HAL traits](hal-traits.md) for the
per-trait contract.

### `umbra-pal-test` — host-side test platform

`crates/umbra-pal-test/src/lib.rs` provides `TestHash` (SHA-256 backed by
the `sha2` crate, byte-for-byte identical to the L552 HW HASH output) and
`MmioMem` / `MmioHandle` (in-memory register-space for driver-level tests).
The test crate is what makes `cargo test` work without an STM32 attached.

Every host-buildable driver carries `Driver<M: MmioAccess = RealMmio>` so
the firmware build monomorphises to `RealMmio` (zero overhead) and host
tests inject `MmioMem`'s handle.

Test coverage at the time of writing:

- L552 `umbra-l552-drivers`: 35 tests on the default build + 6 more under
  `--features stm32l562` (`ofd`, `aes/hw`, `ospi`) for a total of 41.
- N657 `umbra-n657-drivers`: 32 tests across the full surface
  (`gpio`, `rcc`, `uart`, `cryp`, `saes`, `hash`, `mce`, `risaf`,
  `aes/{ecb, gcm, hal_adapter, hardware}`).

### `umbra-kernel` (`src/kernel/`)

Architecture-agnostic core logic:

- Enclave descriptor management + lifecycle.
- Key storage server (key generation, derivation, master-key handling).
- Memory protection traits (`MemorySecurityGuardTrait`).
- Enclave Swap Space (ESS) data structures and BFS scheduler.
- NSC API symbol declarations (`umbra_*_callable` / `umbra_*_imp`).
- Trait re-exports from `umbra-api` for backwards compatibility.

The kernel does *no* MMIO. Every peripheral access goes through the HAL
traits, which means the kernel is host-buildable and the tests in
`src/kernel/src/*/tests.rs` run under `cargo xtask test --host`.
`opt-level = "z"` for production size.

### `arm` (`src/hardware/architecture/arm/`)

ARM Cortex-M33 / Cortex-M55 hardware abstraction:

- **SAU driver** — Secure Attribution Unit region configuration.
- **MPU driver** — Memory Protection Unit, ARMv8-M RBAR/RLAR format.
- **mmio.rs** — volatile register read/write helpers with DSB/ISB
  barriers (every platform driver uses this to make ordering explicit).
- **startup.s** — vector table, exception handlers,
  `save_enclave_context`, SVC dispatch. The M33 build is the canonical
  source; M55 reuses the same code path with an optional Q-register
  save when MVE is in use.

### `umbra-l552-boot` + `umbra-l552-drivers`

`src/hardware/platform/stm32l552/boot/` (package `umbra-l552-boot`,
binary crate) and `src/hardware/platform/stm32l552/drivers/` (package
`umbra-l552-drivers`). Covers both **L552** (no HW AES, AesEmulated path)
and **L562** (HW AES + OTFDEC + OCTOSPI) via the `stm32l562` Cargo
feature. The boot crate is the reset-vector binary; three of its
compilation units use the [submodule layout pattern](#submodule-layout-pattern):

- `main.rs` — `secure_boot()` initialization sequence calling the
  `PlatformBoot` methods in order.
- `platform_impl/` — `PlatformBoot` impl, split into `boot.rs`,
  `dma.rs`, `power.rs`, `syscall_dispatch.rs`.
- `secure_kernel/` — `Kernel` struct + ESS-residency lifecycle, split
  into `init.rs` (singleton bootstrap), `enter.rs` (block-into-residency
  at boot), `exit.rs` (block-out-of-residency runtime), `lifecycle.rs`
  (runtime miss recovery).
- `handlers.rs` — exception handlers routed through
  `panic_policy::handle_fault()` (NEVER_DO #5).
- `api_impl/` — NSC API implementations (`_imp` functions), one file
  per veneer (`enclave_create.rs`, `enclave_enter.rs`, `enclave_exit.rs`,
  `enclave_status.rs`, `debug_print.rs`) plus shared `arg_validation.rs`.
- `validator.rs` — HMAC verification + AES decryption.
- `crypto_impl.rs` — `CryptoEngine` impl + bridges to the `umbra-hal`
  `Hash` / `Aes` traits.

The drivers crate covers: RCC, GPIO, UART (LPUART1 / USART1), DMA,
HASH, AES (HW on L562, emulated on L552), GTZC MPCBB, OTFDEC, OCTOSPI.
`dma`, `hash`, `aes`, and `ospi` use the submodule layout pattern
(`dma.rs + dma/copier.rs + dma/tests.rs`, etc.) so each parent file
stays under the 600-LOC hard-cap.
Note: `src/hardware/platform/stm32l552/drivers/Cargo.toml` declares the
package name `umbra-l552-drivers` but the boot crate aliases it back to
`drivers` via Cargo's `package = "…"` directive so the in-source
`use drivers::*` keeps working.

### `umbra-n657-boot` + `umbra-n657-drivers`

`src/hardware/platform/stm32n657/boot/` and
`src/hardware/platform/stm32n657/drivers/`. The boot crate adds
`boot_measurements.rs` (generated by `tools/measure_blobs.py`) for the
NPU object-detection demo.

The boot crate is **partially decomposed**: `platform_impl/` follows the
L552 submodule layout, but `secure_kernel.rs` and `api_impl.rs` are
still flat single files — they sit under the 600-LOC hard-cap on this
platform.
The drivers crate matches the L552 pattern, with `aes/` and `hash/`
already split.

The drivers crate covers: RCC (IC1..IC20 kernel clocks, PLL1/2/3,
peripheral gating), GPIO (port-based, NS-aliased base + AF up to 15),
UART (USART1 at 115200), HASH (HW HMAC-SHA256), AES (`CRYP1` HW engine
via `AesHardware`; SAES1 reserved for DHUK-wrap), Aead trait surface
(GCM placeholder), RISAF, MCE (passthrough today), XSPI / XSPIM
(memory-mapped at `0x70000000`).

### `xtask` — build orchestrator

`xtask/src/main.rs` exposes `build`, `flash`, `test --host`, and
`check-binary-size` subcommands. Each platform maps to a
`MCU_VARIANT` (`stm32l552` / `stm32l562` / `stm32n657`) and either calls
the legacy shell flow (`rebuild_all.sh`, `debug.sh`) or runs the native
Rust pipeline. See [Build and Run](../getting-started/build-and-run.md)
for the user-facing surface.

### `host/common`

Shared C helpers for the Non-Secure host applications:

- `umbra_hex.{c,h}` — `umbra_u32_to_hex()` formatter for C NS hosts.
- `umbra_mem.c` — minimal `memset` / `memcpy` for `-nostdlib` builds.

Included from every C host crate: `host/stm32l552/bare_metal`,
`host/stm32l552/freertos`, `host/stm32n657/bare_metal`,
`host/stm32n657/freertos`, `host/stm32n657/object_detection`. The
[`host/stm32l552/tock/`](../examples/tock.md) host is Rust and uses
libtock-rs primitives instead.

## Dependency tree

```
                     ┌─────────────────────────┐
                     │       umbra-error       │  (leaf)
                     └─────────────────────────┘
                                  ▲
                                  │
                     ┌─────────────────────────┐
                     │        umbra-api        │  (leaf — only depends on umbra-error)
                     │  PlatformBoot           │
                     │  CryptoEngine           │
                     │  SecurityState markers  │
                     └─────────────────────────┘
                                  ▲
                                  │
            ┌─────────────────────┼─────────────────────┐
            │                     │                     │
   ┌────────────────┐  ┌──────────────────┐  ┌──────────────────┐
   │   umbra-hal    │  │  umbra-kernel    │  │ umbra-pal-test   │
   │ Hash, Aes,     │  │ ESS, scheduler,  │  │ TestHash,        │
   │ Dma, Rcc, …    │  │ NSC, validator   │  │ MmioMem          │
   └────────────────┘  └──────────────────┘  └──────────────────┘
            ▲                     ▲
            │                     │
   ┌────────┴───────┐    ┌────────┴────────┐
   │ umbra-l552-    │    │ umbra-n657-     │
   │  drivers       │    │  drivers        │
   └────────────────┘    └─────────────────┘
            ▲                     ▲
            │                     │
   ┌────────┴───────┐    ┌────────┴────────┐
   │ umbra-l552-    │    │ umbra-n657-     │
   │  boot (bin)    │    │  boot (bin)     │
   └────────────────┘    └─────────────────┘
```

Both `arm` (ARMv8-M primitives) and `peripheral_regs` (`MmioAccess` trait
+ `RealMmio`) sit between the drivers and `umbra-hal` / `umbra-api`; they
are platform-agnostic but not on the leaf path, so they are omitted from
the diagram for clarity.

## Cross-cutting policies

- **File-size cap**: hard 600 LOC / soft 400 LOC, enforced by
  `tools/check_file_size.sh`. The cap is CI-blocking; soft warnings
  surface in the job log but do not fail the build.
- **NSC ABI freeze**: the NSC veneers in
  `src/kernel/src/umbra_nsc_api.rs` keep their `extern "C"` `u32` /
  `*const u8` signatures. The `umbra-api` type-state markers stay
  kernel-internal — see `crates/umbra-api/src/security.rs:4-10` for
  the rationale.
- **Guardrails**: every PR is reviewed against the
  [Guardrails](../contributing/guardrails.md) chapter — NEVER_DO 12
  rules, ALWAYS_DO 18 rules, code-review checklist 15 rows.
