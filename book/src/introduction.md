# Introduction

**Umbra** is a lightweight Rust-based kernel designed to wrap binaries into runtime Trusted Execution Environments (TEEs) for Arm TrustZone-M.

It is distributed as a static library, enabling integration with third-party software such as RTOSes or bare-metal applications to create TEEs dynamically or statically. By leveraging Rust, Umbra minimizes the Trusted Computing Base (TCB) and enhances code safety.

## What Umbra Does

Umbra runs in the **Secure World** of a Cortex-M33 (ARMv8-M) or Cortex-M55 (ARMv8.1-M) microcontroller with TrustZone-M. It provides a set of Non-Secure Callable (NSC) APIs that allow a **Non-Secure** host application to:

- **Create enclaves** from signed and encrypted binaries stored in flash
- **Enter and exit enclaves** with full context save/restore (preemptive via SysTick, cooperative via SVC)
- **Query enclave status** (running, suspended, terminated, faulted)
- **Demand-page enclave code** from flash to SRAM on first access (Enclave Swap Space)

## Supported Hardware

| Board | MCU | Core | Key Features |
|---|---|---|---|
| NUCLEO-L552ZE-Q | STM32L552 | Cortex-M33 | Software AES, DMA block loading, LPUART1 debug |
| STM32L562E-DK | STM32L562 | Cortex-M33 | Hardware AES, OCTOSPI + OTFDEC transparent decryption, USART1 debug |
| NUCLEO-N657X0-Q | STM32N657 | Cortex-M55 | FSBL boot from XSPI2, 4.2 MB SRAM, HW HMAC-SHA256, HW AES (CRYP1), NPU-in-enclave demo |

## Current Status

Umbra supports creating TEEs from a bare-metal host with:
- Chained measurement (boot-time integrity verification)
- Runtime ESS miss recovery (demand-paged enclave blocks with HMAC validation)
- Preemptive scheduling via Secure SysTick
- Cooperative yield via SVC
- Formal verification of the integrity model via ProVerif
- ML inference inside an enclave on the STM32N6 NPU (Tiny YOLO v2 person detector)

## Project Structure

```
umbra/
  src/
    kernel/                       # Architecture-agnostic kernel + PlatformBoot PAL trait
    hardware/
      architecture/arm/           # ARMv8-M / ARMv8.1-M primitives (SAU, MPU, mmio, vector tables)
      common/peripheral_regs/     # Shared register map crate
      platform/stm32l552/         # STM32L5 platform (boot + drivers)
      platform/stm32n657/         # STM32N6 platform (boot + drivers, FSBL model)
  host/
    common/                       # Shared C helpers (umbra_hex, umbra_mem)
    stm32l552/                    # STM32L5 family (L552 + L562 via MCU_VARIANT)
      bare_metal/                 #   Bare-metal NS host
      freertos/                   #   FreeRTOS NS host
      tock/                       #   Tock NS host (L552 only)
      taclebench/                 #   Standalone TACLeBench enclave blobs
    stm32n657/                    # STM32N6
      bare_metal/                 #   Bare-metal NS host
      freertos/                   #   FreeRTOS NS host
      object_detection/           #   NPU object-detection enclave
  tools/                          # Enclave protection, key gen, flash_n657.sh, smoke tests
  linker/                         # Kernel linker scripts
  book/                           # This documentation (mdBook)
```
