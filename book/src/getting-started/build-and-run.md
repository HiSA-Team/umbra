# Build and Run

## Configure Environment

Load environment variables and verify dependencies:

```bash
source settings.sh
```

The script reads `MCU_VARIANT` from the environment (default lives at
the top of `settings.sh`) and configures paths, flash addresses, kernel
features, OpenOCD config, and which host directory to build.

```bash
# Cortex-M33 boards
export MCU_VARIANT=stm32l552         # default L5 target
export MCU_VARIANT=stm32l562         # adds --features stm32l562

# Cortex-M55 board
export MCU_VARIANT=stm32n657
```

## Select Host Application

`HOST_APP` selects the Non-Secure host built into the final image.

| `HOST_APP` | L552 / L562 | N657 |
|---|---|---|
| `bare_metal` *(default)* | `host/bare_metal_arm` | `host/bare_metal_n657` |
| `freertos` | `host/freertos_arm` | `host/freertos_n657` |
| `object_detection` | — | `host/object_detection_n657` |

```bash
export HOST_APP=freertos            # any platform
export HOST_APP=object_detection    # N657 only — Tiny YOLO v2 on the NPU
source ./settings.sh
```

See the [Host Examples](../examples/README.md) chapter for what each
host does.

## Build Everything

```bash
./rebuild_all.sh
```

This performs a full clean build:

1. (Optional) regenerate a master key via `tools/gen_key.py` (synced to
   both the L552 and N657 FSBL Rust constants).
2. (`object_detection` only) extract NPU bytecode and compute boot-time
   chained HMAC over bytecode + weights (`extract_bytecode.py` +
   `measure_blobs.py` → `boot_measurements.rs`).
3. Build the Secure Boot ELF (`secureboot_build` + `secureboot_bin`).
4. Build the Umbra kernel static library (`lib/libumbra.a`).
5. Build the selected host application.
6. Protect enclave binaries via `tools/protect_enclave.py` (HMAC signing,
   AES encryption on L552, no encryption on N657 Path B-lite).

## Flash and Run

### STM32L5 (L552, L562)

```bash
./debug.sh
```

This flashes both the Secure bootloader and the host application to
internal flash via GDB + OpenOCD. On STM32L562, it also programs the
plaintext enclave blob to external OCTOSPI flash. Connect to the
ST-Link UART at **9600 baud**.

### STM32N6 (N657)

The N6 has no internal flash. The Boot ROM loads a signed FSBL image
from XSPI2 into AXISRAM2 on every reset. To flash:

```bash
# Set JP2 (BOOT1) to Dev-Boot (position 2-3) before plugging the board in.
tools/flash_n657.sh
# Move JP2 to Flash-Boot (position 1-2) and reset.
```

`flash_n657.sh` runs:
1. `objcopy` the FSBL ELF to a flat binary.
2. `STM32_SigningTool_CLI` to wrap a 0x400-byte signed header around it.
3. `STM32_Programmer_CLI` to write FSBL (0x70000000), host bin
   (0x70080000), and — for the NPU demo — the model bytecode and
   weights into XSPI2 via the `MX25UM51245G_STM32N6570-NUCLEO.stldr`
   external loader.

Connect to the ST-Link UART at **115200 baud** (USART1 / PE5–PE6, routed
to the VCP via the on-board ST-Link).

## Expected UART Output (default `bare_metal`)

```
[UMBRASecureBoot] Secure Boot started
[UMBRASecureBoot] Kernel Initialized
[UMBRASecureBoot] Jumping to Non-Secure World
[USER] Hello Non-Secure World!
[USER] Enclave created
[USER] Enclave terminated! R0=0x72CA33A8
[USER] All enclaves done
```

Note: additional diagnostic output (stack info, SAU/GTZC/MPU/RISAF
status, HASH/AES tests) is available by building with the `boot_tests`
feature enabled.

## Smoke Tests

Automated UART validation against golden baselines:

```bash
# STM32L5 defaults to 9600 baud; STM32N657 to 115200.
export UMBRA_UART=/dev/cu.usbmodem211203
tools/smoke_test.sh
```

The script resets the target, captures UART output, and diffs against
`tools/golden_uart.log` for the active MCU.
