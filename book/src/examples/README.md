# Host Examples

Umbra ships with two Non-Secure host applications that demonstrate enclave lifecycle management through the NSC API. Both are self-contained C projects under `host/` with their own Makefile, linker scripts, and startup code.

| Example | Path | Scheduler | Use case |
|---|---|---|---|
| [Bare-Metal](bare-metal.md) | `host/bare_metal_arm/` | Hand-rolled round-robin | Minimal footprint, no dependencies |
| [FreeRTOS](freertos.md) | `host/freertos_arm/` | FreeRTOS V11.1.0 preemptive | RTOS coexistence proof |

## Selecting an Example

The active host is controlled by the `HOST_APP` environment variable:

```bash
# Bare-metal (default)
source ./settings.sh
./rebuild_all.sh
./debug.sh

# FreeRTOS
export HOST_APP=freertos
source ./settings.sh
./rebuild_all.sh
./debug.sh
```

`settings.sh` maps `HOST_APP` to the corresponding directory and exports `HOST_DIR`, `HOST_NAME`, and `HOST_ELF`. These variables are consumed by `rebuild_all.sh`, `debug.sh`, and the root Makefile targets (`program_elf_host`, `program_enclaves_extload`).

## Common Enclave Payload

Both examples use the same Fibonacci enclave (`app/fibonacci.c`). The enclave code is linked into the `._enclave_code` section, then encrypted and HMAC-signed by `tools/protect_enclave.py` at build time. At runtime, the Secure kernel validates and loads the enclave into the Enclave Swap Space (ESS) in Secure SRAM.

## UART Output

Connect to the ST-Link UART at **9600 baud**. Both examples print status messages prefixed with `[USER]` (bare-metal) or `[FREERTOS]` (FreeRTOS).
