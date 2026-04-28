# Crate Structure

Umbra is organized as four Rust crates with clear responsibilities:

```
kernel (no_std, no external deps)
  |
  +-- arm (depends on: cortex-m, kernel)
  |     Architecture-specific: SAU, MPU, vector table (.s)
  |
  +-- drivers (depends on: peripheral_regs, kernel)
  |     Platform-specific: RCC, GPIO, UART, DMA, HASH, AES, GTZC, OTFDEC, OCTOSPI
  |
  +-- boot (depends on: arm, drivers, kernel, peripheral_regs, cortex-m)
        Entry point: secure_boot(). Handlers, API implementations, validator
```

## kernel

Architecture-agnostic core logic:
- Enclave descriptor management
- Key storage server (key generation, derivation)
- Memory protection traits (`MemorySecurityGuardTrait`)
- Enclave Swap Space (ESS) data structures
- NSC API symbol declarations

Optimized for size (`opt-level = "z"`).

## arm

ARM Cortex-M33 hardware abstraction:
- **SAU driver** — Secure Attribution Unit region configuration
- **MPU driver** — Memory Protection Unit with ARMv8-M RBAR/RLAR format
- **startup.s** — vector table, exception handlers, `save_enclave_context`, SVC dispatch

## drivers

STM32L552/L562 peripheral drivers:
- **RCC** — clock gating for all peripherals
- **GPIO** — pin mode, alternate function, set/reset
- **UART** — LPUART1 (L552) / USART1 (L562) at 9600 baud
- **DMA** — 16-channel queue-based transfer manager
- **HASH** — SHA-256, HMAC with context save/restore
- **AES** — hardware (L562) or software emulated (L552)
- **GTZC** — MPCBB block-level SRAM security
- **OTFDEC** — on-the-fly decryption (L562 only)
- **OCTOSPI** — memory-mapped external flash (L562 only)

## boot

The binary crate (entry point):
- `main.rs` — `secure_boot()` initialization sequence
- `secure_kernel.rs` — `Kernel` struct, ESS miss handling, block loading
- `handlers.rs` — exception handlers (HardFault, MemManage, UsageFault, SecureFault, BusFault)
- `api_impl.rs` — NSC API implementations (`_imp` functions)
- `validator.rs` — HMAC verification + AES decryption (formal model analog)
- `raw_print.rs` — low-level UART output for exception contexts
