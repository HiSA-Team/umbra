# Boot Flow

## Startup Sequence

This page documents the **common** Secure-boot flow that every platform
follows once execution reaches Umbra's `secure_boot()`. The flow is
expressed as calls to the `PlatformBoot` trait (see
[Crate Structure](crate-structure.md)).

The STM32L5 path enters this flow directly from reset (Umbra is the
reset vector in internal flash). The STM32N6 path enters it after the
Boot ROM has authenticated and copied the FSBL — see
[FSBL Boot (STM32N6)](fsbl-boot.md) for the pre-amble that runs before
this flow begins.

### Step-by-step

1. **Reset_Handler** (assembly, `startup.s` for L5 or `startup_n657.s`
   for N6) sets `MSPLIM`/`PSPLIM`, copies `.data` from flash/load address
   to SRAM, zeros `.bss`, then calls `secure_boot()` in Rust.

2. **secure_boot()** (Rust, `main.rs`) — calls into the platform's
   `PlatformBoot` impl in this order:

   | PAL method | What | Why |
   |---|---|---|
   | `init_clocks` | Configure RCC clocks (PLLs, kernel dividers, peripheral gates) | Bring CPU and peripherals to their target frequencies |
   | `init_gpio` | Configure board LED + UART pins | Visual boot indicator + debug output |
   | `init_uart` | Bring up the debug UART (9600 / 115200 baud) | Diagnostic printing for the rest of the boot |
   | `init_security` | SAU regions, GTZC/RISAF, MPU, SHCSR fault enables | Establish S / NS / NSC boundaries; isolate kernel from enclaves |
   | `init_kernel` | DMA, HASH (SHA-256), AES, `Kernel` instance, session-key derivation | Crypto + central state for enclave management |
   | `init_external_flash` | Memory-mapped OCTOSPI/XSPI + (optional) OTFDEC/MCE | Make enclave ciphertext accessible without bus exposure of plaintext |
   | `configure_ns_boot` | Disable Secure SysTick (enabled per-enclave by SVC handler), set `VTOR_NS` | Hand off the NS vector table without leaving an active Secure tick |
   | `jump_to_ns` | Set `MSP_NS`, `BLXNS` to host entry | Transfer to Non-Secure World; does not return |

## Variants

| Platform | `init_security` | `init_external_flash` | NS host start |
|---|---|---|---|
| STM32L552 | SAU + GTZC MPCBB + MPU | returns `false` (no external flash) | `VTOR_NS = 0x08040000` (NS flash bank 1) |
| STM32L562 | SAU + GTZC MPCBB + MPU | OCTOSPI + OTFDEC region setup | `VTOR_NS = 0x08040000` |
| STM32N657 | SAU + RISAF + RIFSC + RIMC + MPU | XSPI2 memory-mapped + MCE2 (passthrough) | `VTOR_NS = 0x24000000` (AXISRAM1 NS view) |

## After Boot

The host application runs in Non-Secure World. It discovers enclaves
(L5: scans NS flash for the `UMBR` magic; N6: computes the XSPI2
address of the linker-known enclave header from the AXISRAM1 NS view),
creates them via `umbra_enclave_create()`, and schedules them via
`umbra_enclave_enter()`. Each enter triggers an SVC into Secure World
where the kernel restores enclave context and enables SysTick for
preemption.
