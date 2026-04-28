# Introduction

**Umbra** is a lightweight Rust-based kernel designed to wrap binaries into runtime Trusted Execution Environments (TEEs) for Arm TrustZone-M.

It is distributed as a static library, enabling integration with third-party software such as RTOSes or bare-metal applications to create TEEs dynamically or statically. By leveraging Rust, Umbra minimizes the Trusted Computing Base (TCB) and enhances code safety.

## What Umbra Does

Umbra runs in the **Secure World** of a Cortex-M33 microcontroller with TrustZone-M. It provides a set of Non-Secure Callable (NSC) APIs that allow a **Non-Secure** host application to:

- **Create enclaves** from signed and encrypted binaries stored in flash
- **Enter and exit enclaves** with full context save/restore (preemptive via SysTick, cooperative via SVC)
- **Query enclave status** (running, suspended, terminated, faulted)
- **Demand-page enclave code** from flash to SRAM on first access (Enclave Swap Space)

## Supported Hardware

| Board | MCU | Key Features |
|---|---|---|
| NUCLEO-L552ZE-Q | STM32L552 | Software AES, DMA block loading, LPUART1 debug |
| STM32L562E-DK | STM32L562 | Hardware AES, OCTOSPI + OTFDEC transparent decryption, USART1 debug |

## Current Status

Umbra supports creating TEEs from a bare-metal host with:
- Chained measurement (boot-time integrity verification)
- Runtime ESS miss recovery (demand-paged enclave blocks with HMAC validation)
- Preemptive scheduling via Secure SysTick
- Cooperative yield via SVC
- Formal verification of the integrity model via ProVerif

## Project Structure

```
umbra/
  src/
    kernel/               # Architecture-agnostic kernel (enclave management, key storage)
    hardware/
      architecture/arm/   # ARM Cortex-M33 primitives (SAU, MPU, vector table)
      platform/stm32l552/ # STM32L5 platform (boot, drivers)
  host/
    bare_metal_arm/       # Bare-metal NS host (round-robin enclave scheduler)
    freertos_arm/         # FreeRTOS NS host (RTOS coexistence demo)
  tools/                  # Enclave protection, key generation, smoke tests
  linker/                 # Kernel linker scripts
  book/                   # This documentation (mdBook)
```
