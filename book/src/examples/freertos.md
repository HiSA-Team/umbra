# FreeRTOS Example

The FreeRTOS host (`host/freertos_arm/`) demonstrates that Umbra's TrustZone isolation works transparently with a standard RTOS. A single FreeRTOS task manages the entire enclave lifecycle, proving that the Secure SysTick (enclave preemption) and the NS SysTick (FreeRTOS tick) operate independently on the dual-SysTick Cortex-M33 architecture.

## How It Works

```
main()
  ├── Set VTOR to SRAM vector table
  ├── Enable NS fault handlers (SHCSR)
  ├── xTaskCreate(vEnclaveTask, ...)
  └── vTaskStartScheduler()        // never returns

vEnclaveTask(pvParameters)
  ├── Scan NS flash for enclave headers (same logic as bare-metal)
  ├── umbra_tee_create(addr) for each enclave found
  ├── Loop: umbra_enclave_enter(id)
  │     ├── SUSPENDED  → print, re-enter
  │     ├── TERMINATED → print R0, mark done
  │     └── FAULTED    → print error, mark done
  └── vTaskDelete(NULL)            // self-delete when all done
```

FreeRTOS manages task scheduling in the NS world. The enclave task calls into the Secure kernel via NSC veneers — Umbra doesn't know or care that an RTOS is running.

## Building and Running

```bash
export HOST_APP=freertos
source ./settings.sh
./rebuild_all.sh
./debug.sh
```

The first build will clone the FreeRTOS-Kernel submodule automatically if needed:

```bash
git submodule update --init host/freertos_arm/lib/FreeRTOS-Kernel
```

## Expected UART Output

```
[UMBRASecureBoot] Secure Boot started
[UMBRASecureBoot] Kernel Initialized
[UMBRASecureBoot] Jumping to Non-Secure World
[FREERTOS] Starting FreeRTOS demo
[FREERTOS] Enclave task started
[FREERTOS] Enclave created
[FREERTOS] Enclave terminated! R0=0x72CA33A8
[FREERTOS] All enclaves done
```

## File Structure

```
host/freertos_arm/
  ├── lib/
  │   └── FreeRTOS-Kernel/    Git submodule (V11.1.0, ARM_CM33_NTZ port)
  ├── src/
  │   ├── main.c              FreeRTOS init + enclave task
  │   ├── vectors.c           SRAM vector table (aligned 512B, non-const)
  │   ├── handlers.c          NS fault handlers (in C for Thumb bit correctness)
  │   ├── port_overrides.c    vStartFirstTask override (avoids flash data read)
  │   ├── startup.s           Reset_Handler only (.data/.bss init)
  │   ├── mem.c               Minimal memset/memcpy for -nostdlib
  │   └── FreeRTOSConfig.h    Kernel config (NTZ, 4MHz, 32KB heap)
  ├── app/
  │   └── fibonacci.c         Enclave payload (same as bare-metal)
  ├── inc/
  │   └── fibonacci.h
  ├── linker/
  │   ├── memory.ld           Self-contained memory regions + Umbra aliases
  │   └── host.ld             Section layout + NSC veneer PROVIDE addresses
  └── Makefile                Standalone build (FreeRTOS sources compiled from submodule)
```

## FreeRTOS Configuration

| Parameter | Value | Rationale |
|---|---|---|
| `configCPU_CLOCK_HZ` | 4 MHz | MSI default clock |
| `configTICK_RATE_HZ` | 1000 | 1ms tick |
| `configTOTAL_HEAP_SIZE` | 32 KB | From SRAM_0 (128KB total) |
| `configENABLE_TRUSTZONE` | 0 | NTZ port — Secure context managed by Umbra |
| `configENABLE_MPU` | 0 | MPU managed by Umbra Secure side |
| `configENABLE_FPU` | 0 | No floating point in demo |
| `configCHECK_FOR_STACK_OVERFLOW` | 2 | Canary + watermark check |

## TrustZone Porting Notes

Porting FreeRTOS to the NS world of an STM32L5 with an active Secure kernel required solving several non-obvious issues:

### SRAM Vector Table

The STM32L5 IDAU classifies `0x08040000` (NS flash) as Secure for **data reads**. The SAU override only applies to instruction fetch. Since the Cortex-M33 vector table fetch is architecturally a data read, the NS vector table must reside in SRAM (`0x20000000+`), not flash.

The vector table is defined as a non-const C array with `__attribute__((aligned(512)))`. It lands in `.data` and is copied to SRAM by the startup code. VTOR_NS is set to `0x20000000` by the Secure boot.

### vStartFirstTask Override

The FreeRTOS `ARM_CM33_NTZ` port reads `*(VTOR[0])` (a data read from the vector table base) to reset MSP. This faults on STM32L5 if VTOR points to flash. `port_overrides.c` provides a replacement that loads MSP from the linker symbol `_host_estack` instead.

The override uses `--allow-multiple-definition` in LDFLAGS, with our object listed before FreeRTOS objects in link order.

### SVC Number

FreeRTOS V11 uses **SVC #102** (not #0) for `START_SCHEDULER`, defined in `portmacrocommon.h`. The override must use the correct number or the SVC handler ignores the call.

### Fault Handlers in C

Assembly-defined `.thumb_func` labels lose the Thumb interworking bit (LSB) in `R_ARM_ABS32` data relocations used by the SRAM vector table initializer. Defining fault handlers in C guarantees correct Thumb bit propagation.

### NS Fault Handler Enable

The Secure boot enables Secure SHCSR but not NS SHCSR. Without `SCB_SHCSR |= (1<<16)|(1<<17)|(1<<18)` in NS code, all configurable NS faults silently escalate to HardFault with no diagnostic CFSR bits.
