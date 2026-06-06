# ADR 003 — HAL trait surface in `umbra-hal`, impls in PAL crates

**Status:** Accepted

## Context

Umbra's Secure kernel reaches the silicon through a dozen-odd
peripherals: a hash engine, an AES block, a DMA controller, a clock
tree, a UART for logs, GPIOs for indicators, plus an address-attribution
unit per platform. Each of the three supported MCUs (L552, L562, N657)
exposes a different MMIO layout for every one of these, and a fourth
target on the roadmap multiplies that matrix.

Two options recur in embedded codebases of this shape:

- **Per-platform direct calls**. The kernel writes raw register
  accesses guarded by `cfg(feature = "platform-…")`. Easy at first;
  diverges fast.
- **A reusable HAL crate** with traits the kernel calls and impls the
  platform crates supply.

The first option lost on its own merits during the early bring-up
phase: a hash routine that worked on the L552 broke on the N657
because the polling loop assumed the L552 `HASH.SR.DCIS` semantics.
Twin copies of the same SHA-256 driver appeared, drifted, and produced
two distinct bug classes.

The constraint that makes this decision interesting is that Umbra's
peripheral usage is **Secure-side aware**. The kernel hashes into
pre-allocated buffers (no heap on bare-metal). It reuses a key
schedule across many AES blocks (the T-table fast path on L552 and the
CRYP1 streaming path on N657 both benefit). It honours an
address-attribution unit on every DMA transfer. None of this maps
cleanly to the generic `embedded-hal` traits, which are tuned for
single-block one-shot operations on hobbyist boards.

## Decision

Define the peripheral surface as a small set of traits in the
`umbra-hal` crate. Each per-platform PAL crate
(`umbra-<mcu>-drivers`) implements the traits against the real
silicon. `umbra-pal-test` implements them against in-memory MMIO
backends for `cargo test`.

```rust
// crates/umbra-hal/src/hash.rs (abridged)
pub trait Hash {
    type Error: core::fmt::Debug;

    fn init(&mut self) -> Result<(), Self::Error>;
    fn update(&mut self, data: &[u8]) -> Result<(), Self::Error>;
    fn finalize(&mut self, out: &mut [u8; 32]) -> Result<(), Self::Error>;
}
```

Six traits today: `Hash`, `Aes`, `Dma`, `Rcc`, `Uart`, `Gpio`. Each
trait carries an associated `Error: core::fmt::Debug` so impls surface
HW-specific failure info (CRYP1 BUSY-timeout, HASH `STARTERR`,
OTFDEC key-region clash). The HW-specific error types convert into
`UmbraError` via `From` impls landing at each HAL boundary; see
[ADR 002](002-umbra-error.md).

Two shape rules apply to every trait in this crate:

1. **Narrow trait surface, wide inherent API**. The trait is the verb
   the kernel uses (`copy`, `write_bytes`, `set_high`). Platform-specific
   knobs (DMA channel reservation, RCC kernel-clock multiplexers, GPIO
   alternate-function numbers) stay in the inherent driver API on each
   PAL crate. The trait stays portable; the inherent API stays
   expressive.
2. **Secure-side aware, not generic-embedded**. `Hash::finalize` writes
   into a `[u8; 32]` out-parameter rather than returning a `[u8; 32]`
   because the kernel hashes into pre-allocated buffers in
   chained-measurement. `Aes::configure` is separated from
   `Aes::process` so the kernel can reuse an expanded key schedule
   across many blocks.

See [HAL Traits](../architecture/hal-traits.md) for the six
trait shapes, per-platform impl details, and the host-side
`umbra-pal-test` stand-ins.

## Alternatives considered

### Alternative A — Per-platform direct calls inside the kernel

The kernel keeps platform-specific code behind `cfg` features and
calls peripheral registers directly.

- **Pro**: zero abstraction. The kernel reads exactly like the
  reference manual.
- **Con**: bring-up showed twin SHA-256 routines drifting within a
  single sprint. Multiply by `Aes`, `Dma`, `Rcc`, …, and the
  divergence becomes structural.
- **Con**: host-side tests for kernel logic cannot run, because the
  kernel directly touches MMIO that is not present on the host.
- **Con**: every kernel test would have to mock MMIO ad-hoc, with no
  shared infrastructure.

**Rejected** — already tried during early bring-up; cost in drift was
visible within weeks.

### Alternative B — Reuse `embedded-hal` directly

Take the standard `embedded-hal` traits (`blocking::Sha`, `digital`,
`serial`, `dma::*`) as the surface.

- **Pro**: standard, well-known interface; potentially reusable
  drivers from the wider Rust embedded ecosystem.
- **Con**: `embedded-hal` does not model Secure/Non-Secure address
  attribution. The DMA traits do not encode "this transfer must
  honour the GTZC". Wrapping every call in additional safety
  scaffolding loses the benefit of using the standard.
- **Con**: `embedded-hal` hash traits return owned digests; the
  Secure-side kernel hashes into stable buffers for chained
  measurement. Adapting between the two shapes adds a copy on every
  hash, which is non-trivial at the granularity Umbra hashes (every
  enclave block).
- **Con**: `embedded-hal` AES traits expose one-block-at-a-time
  semantics; the T-table fast path on L552 and the CRYP1 streaming
  path on N657 both want a stateful `configure → process(stream)`
  shape.

**Rejected** — the shape mismatch is per-trait, not a single point of
adaptation. Forcing the Umbra-specific semantics through
`embedded-hal` would degrade either correctness or performance on
every call site.

### Alternative C — One mega-trait `Platform` instead of six small ones

A single trait `Platform { fn hash(&mut self, …); fn aes(&mut self, …); … }`
covering every peripheral.

- **Pro**: fewer trait imports at call sites.
- **Con**: any change to one peripheral signature invalidates every
  impl. The PAL crates would rebuild on unrelated edits.
- **Con**: `umbra-pal-test` could not stub a single peripheral —
  every test platform impl would have to implement every method,
  with most stubbed as `unimplemented!()`.
- **Con**: `Platform` ends up holding mutable references to every
  peripheral simultaneously; the borrow checker becomes the bottleneck.

**Rejected** — six small traits compose better and keep impl PRs
focused. The `umbra-api` `Platform` struct aggregates them at the
boundary where the kernel really does need everything in one place.

## Consequences

### Positive

1. **One driver per peripheral, three impls per peripheral**. Bug
   fixes apply to one trait impl, not to a tree of cfg-gated forks.
2. **Host-side tests via `umbra-pal-test`**. `TestHash` wraps the
   `sha2` crate; its byte-for-byte output matches every HW path.
   `MmioMem` records driver MMIO writes so a test can assert the
   exact register recipe a driver issued.
3. **New peripherals follow a documented flow**. Add a trait in
   `umbra-hal`, implement it once per PAL crate, add a host-side
   stand-in, add at least one test using `MmioMem` or `TestPlatform`.
   See [HAL Traits](../architecture/hal-traits.md) for the full
   procedure.
4. **Per-platform optimisations live in the impl**. The L552
   T-table AES path and the N657 CRYP1 path implement the same
   `Aes` trait with very different inner loops; the kernel does not
   care.

### Negative

1. **Adding a new trait requires touching three PAL crates plus
   `umbra-pal-test`**. Sometimes a peripheral genuinely exists on
   only one MCU (e.g. OTFDEC on L562). The convention is to stub it
   on the other PAL crates as "not yet supported" returning the
   appropriate `UmbraError` variant.
2. **Trait + impl indirection costs one vtable lookup** at call
   sites that take `&mut dyn Trait`. The kernel uses generics
   (`<H: Hash>`) on the hot paths, so the indirection is eliminated
   at monomorphisation. The non-hot paths absorb the lookup with no
   measurable impact.
3. **`Rcc` is intentionally minimal**. The trait exposes one verb
   (`init_sysclk_pll`); per-peripheral clock-gating control stays
   on the inherent driver API. This is the right shape for the
   kernel but is sometimes surprising to contributors looking for a
   "set every clock" mega-method.

## Cross-references

- The six traits and per-platform impl tables: [HAL Traits](../architecture/hal-traits.md).
- HW-error → `UmbraError` boundary: [ADR 002](002-umbra-error.md).
- Crate-tree placement: [ADR 001](001-workspace-layout.md).
