# HAL Traits

The `umbra-hal` crate (`crates/umbra-hal/`) defines the trait surface
that Umbra's kernel and architecture-agnostic code use to reach
peripherals. Per-platform driver crates (`umbra-l552-drivers`,
`umbra-n657-drivers`) implement the traits against real silicon;
`umbra-pal-test` implements them in software for host-side tests.

`umbra-hal` is a leaf in the workspace dependency graph: it depends on
nothing except `core`. The trait shapes are Secure-side aware (their
semantics assume operation from the Secure world of an ARMv8-M /
ARMv8.1-M TrustZone-enabled MCU). They are deliberately narrower than
`embedded-hal` — the focus is the cryptographic and memory-protection
peripherals on which the TEE depends.

See `crates/umbra-hal/src/lib.rs:1-36` for the crate-level module
documentation.

## The six traits

| Trait | File | Three-line shape |
|---|---|---|
| `Hash`  | `crates/umbra-hal/src/hash.rs`  | `init() → update(&[u8])* → finalize(&mut [u8; 32])`. 32-byte digest hard-coded to SHA-256 / SHA3-256. |
| `Aes`   | `crates/umbra-hal/src/aes.rs`   | `configure(key, mode) → set_iv(&[u8; 16])? → process(in, out)`. Modes: `EcbEncrypt`, `EcbDecrypt`, `CtrEncrypt`. |
| `Dma`   | `crates/umbra-hal/src/dma.rs`   | `copy(src: usize, dst: usize, len: usize)`. Memory-to-memory, blocking. Honours the platform's address-attribution unit. |
| `Rcc`   | `crates/umbra-hal/src/rcc.rs`   | `init_sysclk_pll()`. The unified "go fast" verb; per-peripheral gating stays in the inherent driver API. |
| `Uart`  | `crates/umbra-hal/src/uart.rs`  | `write_bytes(&[u8])`. Minimal logger surface. |
| `Gpio`  | `crates/umbra-hal/src/gpio.rs`  | `set_high(pin)` / `set_low(pin)`. Mode + AF config stay in the inherent driver. |

Each trait carries an associated `type Error: core::fmt::Debug` so impls
can surface HW-specific failure info (e.g. L552 HASH `CR.STARTERR`,
CRYP1 BUSY-timeout, OTFDEC key-region clash). The HW-specific error
types convert into `UmbraError` via `From` impls landing at each HAL
boundary — see [Error handling](error-handling.md).

## Why narrow + Secure-side aware

Two design choices, both visible in the trait modules' doc comments:

1. **Narrow surface, wide inherent API**. The HAL trait is the verb the
   *kernel* uses (`copy`, `write_bytes`, `set_high`). Platform-specific
   knobs (DMA channel reservation, RCC kernel-clock multiplexers, GPIO
   alternate-function numbers) stay in the inherent driver API on each
   `umbra-<mcu>-drivers` crate. The trait stays portable; the inherent
   API stays expressive.
2. **Secure-side aware, not generic-embedded**. `Hash::finalize` writes
   into a `[u8; 32]` out-parameter rather than returning a `[u8; 32]`,
   because the kernel hashes into pre-allocated buffers in
   chained-measurement (no heap on bare-metal). `Aes::process` separates
   `configure` from `process` so the kernel can reuse an expanded key
   schedule across many blocks — material on both the L552 AesEmulated
   T-table path and the N657 CRYP1 HW path.

## Per-platform impls

### `umbra-l552-drivers`

Implements all six traits for STM32L552/L562:

- `Hash` → HW HASH peripheral, SHA-256, with `CR.STARTERR` mapped to
  `UmbraError::HashHardware`.
- `Aes` → `AesHardware` on L562 (CRYP) / `AesEmulated` on L552 (T-table
  software).
- `Dma` → 16-channel queue-based transfer manager.
- `Rcc` → PLL @ 110 MHz on L552/L562 (selected to give the T-table AES
  fast-path adequate cycles per block while staying inside the SMPS
  envelope on the dev kit).
- `Uart` → LPUART1 (L552) / USART1 (L562) at 9600 baud.
- `Gpio` → port-based, AF0..AF15.

### `umbra-n657-drivers`

Implements all six traits for STM32N657:

- `Hash` → HW HMAC-SHA256 via the AHB5 HASH peripheral. Pre-N657-port,
  this path was blocked by RIFSC; the SW SHA-256 fallback remains
  behind the `n657_sw_sha256` feature.
- `Aes` → `AesHardware` on `CRYP1` with the N657 ALGOMODE encoding
  (ECB single-block + native CTR streaming, ALGOMODE=0x6). T-table
  software fallback behind `n657_aes_hw`.
- `Dma` → CPU-memcpy fallback (HPDMA integration deferred: a stack of
  HW errata observed during bring-up made the polling/memcpy path the
  reliable production option).
- `Rcc` → IC1..IC20 kernel clock dividers; PLL1 = 800 MHz, AXI = 400 MHz,
  HCLK = 200 MHz.
- `Uart` → USART1 at 115200 baud, HSI 64 MHz, BRR = 556.
- `Gpio` → port-based, NS-aliased base, AF up to 15.

### `umbra-pal-test`

The host-side test harness. `TestHash` (in `crates/umbra-pal-test/src/lib.rs`)
wraps the `sha2` crate; its byte-for-byte output matches every HW path.
`MmioMem` (sibling module) is a generic in-memory register-space backend with a
recording log so a driver test can assert the exact MMIO write recipe
the driver issued. The `MmioHandle` returned by `MmioMem` satisfies
`peripheral_regs::MmioAccess`, so drivers parameterised as
`Driver<M: MmioAccess = RealMmio>` accept it in tests with no plumbing.

## Adding a new trait

Spec rule (NEVER_DO #7): never re-implement a driver per platform when
a HAL trait could exist. The flow:

1. Add the new trait module under `crates/umbra-hal/src/`. Doc-comment
   the error semantics + the Secure-side caveat.
2. Re-export it from `crates/umbra-hal/src/lib.rs`.
3. Implement it once in each `umbra-pal-*` driver crate (or stub it as
   "not yet supported" with a documented `UmbraError` variant).
4. Add the host-side stand-in in `umbra-pal-test`.
5. Add at least one host-side test using `MmioMem` (driver layer) or
   `TestPlatform` (kernel-layer call site).

The trait surface is reviewed against ALWAYS_DO #2 (typed MMIO only,
no raw `core::ptr::write_volatile` outside the wrapper).
