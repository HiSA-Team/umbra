# Build and Run

## Configure Environment

Load environment variables and verify dependencies:

```bash
source settings.sh
```

The script auto-detects the target MCU (STM32L552 or STM32L562) and configures paths, flash addresses, and feature flags.

## Select Host Application

Umbra ships with two NS host examples. Select one before building:

```bash
# Bare-metal round-robin (default)
source ./settings.sh

# FreeRTOS RTOS demo
export HOST_APP=freertos
source ./settings.sh
```

See the [Host Examples](../examples/README.md) section for details on each.

## Build Everything

```bash
./rebuild_all.sh
```

This performs a full clean build:

1. Generates a fresh master key (`tools/master_key.bin`)
2. Builds the Secure Boot ELF (`secureboot_build` + `secureboot_bin`)
3. Builds the Umbra kernel static library (`lib/libumbra.a`)
4. Builds the selected host application (`HOST_APP`, default: `bare_metal`)
5. Protects enclave binaries (encryption, HMAC signing via `tools/protect_enclave.py`)

## Flash and Run

```bash
./debug.sh
```

This flashes both the secure bootloader and the host application to the target via GDB + OpenOCD. On STM32L562, it also programs the plaintext enclave blob to external OCTOSPI flash.

## Expected UART Output (STM32L552)

Connect to the ST-Link UART at **9600 baud**:

```
[UMBRASecureBoot] Secure Boot started
[UMBRASecureBoot] Kernel Initialized
[UMBRASecureBoot] Jumping to Non-Secure World
[USER] Hello Non-Secure World!
[USER] Enclave created
[USER] Enclave terminated! R0=0x72CA33A8
[USER] All enclaves done
```

Note: additional diagnostic output (stack info, SAU/GTZC/MPU status, HASH/AES tests) is available by building with the `boot_tests` feature enabled.

## Smoke Tests

Automated UART validation against golden baselines:

```bash
export UMBRA_UART=/dev/cu.usbmodem211203  # your serial device
tools/smoke_test.sh
```

The script resets the target, captures UART output, and diffs against `tools/golden_uart.log`.
