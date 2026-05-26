# Host Examples

Umbra ships with six Non-Secure host applications that demonstrate
enclave lifecycle management through the NSC API.

| Example | Path | Platforms | Scheduler | Use case |
|---|---|---|---|---|
| [Bare-Metal](bare-metal.md) | `host/stm32l552/bare_metal/` | STM32L5 | Hand-rolled round-robin | Minimal footprint, no dependencies |
| Bare-Metal (N6) | `host/stm32n657/bare_metal/` | STM32N657 | Single re-entry loop | N6 mirror of the L5 bare-metal example |
| [FreeRTOS](freertos.md) | `host/stm32l552/freertos/` | STM32L5 | FreeRTOS V11.1.0 preemptive | RTOS coexistence proof |
| FreeRTOS (N6) | `host/stm32n657/freertos/` | STM32N657 | FreeRTOS V11.1.0 preemptive | N6 mirror of the FreeRTOS example |
| [Tock](tock.md) | `host/stm32l552/tock/` | STM32L552 | Tock kernel + libtock-rs | Cooperative multitasking with MPU-sandboxed Rust apps |
| [NPU Object Detection](object-detection.md) | `host/stm32n657/object_detection/` | STM32N657 | FreeRTOS task | Tiny YOLO v2 person detector running on the NPU **inside the enclave** |

## Selecting an Example

`HOST_APP` selects the host. The host tree is organized by target
platform (`host/<platform>/<app>/`), and `HOST_DIR` resolves to
`host/$MCU/$HOST_APP` (`$MCU` is `stm32l552` for both L552 and L562, or
`stm32n657`):

| `HOST_APP` | STM32L552 | STM32L562 | STM32N657 |
|---|---|---|---|
| `bare_metal` (default) | `host/stm32l552/bare_metal` | `host/stm32l552/bare_metal` | `host/stm32n657/bare_metal` |
| `freertos` | `host/stm32l552/freertos` | `host/stm32l552/freertos` | `host/stm32n657/freertos` |
| `tock` | `host/stm32l552/tock` | *(unsupported)* | *(unsupported)* |
| `object_detection` | *(unsupported)* | *(unsupported)* | `host/stm32n657/object_detection` |

```bash
# Bare-metal on the active MCU (default)
source ./settings.sh
./rebuild_all.sh
./debug.sh                          # L5
tools/flash_n657.sh                 # N657

# FreeRTOS on the active MCU
export HOST_APP=freertos
source ./settings.sh
./rebuild_all.sh

# Tock (STM32L552 only)
export MCU_VARIANT=stm32l552 HOST_APP=tock
source ./settings.sh
./rebuild_all.sh
./debug.sh

# Object detection (N657 only — requires ST Edge AI artifacts)
export MCU_VARIANT=stm32n657 HOST_APP=object_detection
source ./settings.sh
./rebuild_all.sh
tools/flash_n657.sh
```

`settings.sh` resolves `HOST_DIR = host/$MCU/$HOST_APP` and exports
`HOST_NAME = $HOST_APP` plus `HOST_ELF = $HOST_DIR/bin/$HOST_APP.elf`.
These variables are consumed by `rebuild_all.sh`, `debug.sh`,
`tools/flash_n657.sh`, and the root Makefile targets
(`program_elf_host`, `program_enclaves_extload`).

## Common Enclave Payload

The bare-metal, FreeRTOS, and Tock examples (L5 and N6) all use the same
Fibonacci enclave (`app/fibonacci.c`). The enclave code is linked into
the `._enclave_code` section, then encrypted and HMAC-signed by
`tools/protect_enclave.py` at build time. At runtime, the Secure kernel
validates and loads the enclave into the Enclave Swap Space (ESS) in
Secure SRAM.

The NPU object-detection example uses a separate enclave that runs
Tiny YOLO v2 INT8 inference on the NPU; see
[NPU Object Detection](object-detection.md).

## Shared Host Helpers

All C-based hosts include `host/common/inc/umbra_hex.h`
(`umbra_u32_to_hex`) and `host/common/src/umbra_mem.c` (minimal
`memset`/`memcpy` for `-nostdlib` builds). The Tock host is Rust and
doesn't use these helpers.

## UART Output

Connect to the ST-Link UART:

- **STM32L5**: 9600 baud
- **STM32N657**: 115200 baud

Line-prefix conventions:

- Bare-metal: `[USER]`
- FreeRTOS:   `[FREERTOS]`
- Tock:       `[TOCK]`
- NPU demo:   `[obj-det]` / `[USER]`
