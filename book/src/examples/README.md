# Host Examples

Umbra ships with five Non-Secure host applications that demonstrate
enclave lifecycle management through the NSC API. Each is a
self-contained C project under `host/` with its own Makefile, linker
scripts, and startup code.

| Example | Path | Platforms | Scheduler | Use case |
|---|---|---|---|---|
| [Bare-Metal](bare-metal.md) | `host/bare_metal_arm/` | STM32L5 | Hand-rolled round-robin | Minimal footprint, no dependencies |
| Bare-Metal (N6) | `host/bare_metal_n657/` | STM32N657 | Single re-entry loop | N6 mirror of the L5 bare-metal example |
| [FreeRTOS](freertos.md) | `host/freertos_arm/` | STM32L5 | FreeRTOS V11.1.0 preemptive | RTOS coexistence proof |
| FreeRTOS (N6) | `host/freertos_n657/` | STM32N657 | FreeRTOS V11.1.0 preemptive | N6 mirror of the FreeRTOS example |
| [NPU Object Detection](object-detection.md) | `host/object_detection_n657/` | STM32N657 | FreeRTOS task | Tiny YOLO v2 person detector running on the NPU **inside the enclave** |

## Selecting an Example

`HOST_APP` selects the host. The resolved directory depends on the
active `MCU_VARIANT`:

| `HOST_APP` | STM32L5 | STM32N657 |
|---|---|---|
| `bare_metal` (default) | `bare_metal_arm` | `bare_metal_n657` |
| `freertos` | `freertos_arm` | `freertos_n657` |
| `object_detection` | *(unsupported)* | `object_detection_n657` |

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

# Object detection (N657 only — requires ST Edge AI artifacts)
export MCU_VARIANT=stm32n657 HOST_APP=object_detection
source ./settings.sh
./rebuild_all.sh
tools/flash_n657.sh
```

`settings.sh` maps `HOST_APP` × `MCU_VARIANT` to the corresponding
directory and exports `HOST_DIR`, `HOST_NAME`, and `HOST_ELF`. These
variables are consumed by `rebuild_all.sh`, `debug.sh`,
`tools/flash_n657.sh`, and the root Makefile targets
(`program_elf_host`, `program_enclaves_extload`).

## Common Enclave Payload

The bare-metal and FreeRTOS examples (both L5 and N6) use the same
Fibonacci enclave (`app/fibonacci.c`). The enclave code is linked into
the `._enclave_code` section, then encrypted and HMAC-signed by
`tools/protect_enclave.py` at build time. At runtime, the Secure kernel
validates and loads the enclave into the Enclave Swap Space (ESS) in
Secure SRAM.

The NPU object-detection example uses a separate enclave that runs
Tiny YOLO v2 INT8 inference on the NPU; see
[NPU Object Detection](object-detection.md).

## Shared Host Helpers

All hosts include `host/common/inc/umbra_hex.h` (`umbra_u32_to_hex`)
and `host/common/src/umbra_mem.c` (minimal `memset`/`memcpy` for
`-nostdlib` builds), so each host's `Makefile` adds `../common/{inc,src}`
to its include / source paths.

## UART Output

Connect to the ST-Link UART:

- **STM32L5**: 9600 baud
- **STM32N657**: 115200 baud

Bare-metal hosts prefix lines with `[USER]`; FreeRTOS hosts with
`[FREERTOS]`; the NPU demo with `[obj-det]` / `[USER]`.
