# Bare-Metal Example

The bare-metal host (`host/bare_metal_arm/`) is the simplest way to interact with Umbra. It runs a hand-coded round-robin loop that scans flash for enclaves, creates them via NSC veneers, and executes them until termination.

## How It Works

```
main()
  ├── Scan NS flash (0x08040000–0x08080000) for UMBR magic at 4KB page boundaries
  ├── umbra_tee_create(addr) for each enclave found
  └── Round-robin loop:
        ├── umbra_enclave_enter(id) → returns status
        │     ├── SUSPENDED  → enclave was preempted by Secure SysTick
        │     ├── TERMINATED → print R0 result, mark done
        │     └── FAULTED    → print error, mark done
        └── Repeat until all enclaves done
```

No RTOS, no heap, no interrupts in the NS world. The Secure SysTick handles enclave preemption; the host just re-enters suspended enclaves.

## Building and Running

```bash
# Bare-metal is the default — no HOST_APP needed
source ./settings.sh
./rebuild_all.sh
./debug.sh
```

## Expected UART Output

```
[UMBRASecureBoot] Secure Boot started
[UMBRASecureBoot] Kernel Initialized
[UMBRASecureBoot] Jumping to Non-Secure World
[USER] Hello Non-Secure World!
[USER] Enclave created
[USER] Enclave preempted (SysTick)
[USER] Enclave preempted (SysTick)
...
[USER] Enclave terminated! R0=0x72CA33A8
[USER] All enclaves done
```

The number of `Enclave preempted` lines varies depending on the SysTick quantum (~10ms at 4 MHz MSI).

## File Structure

```
host/bare_metal_arm/
  ├── src/
  │   ├── main.c          Entry point, enclave header, round-robin scheduler
  │   └── startup.s       NS vector table + Reset_Handler (.data/.bss init)
  ├── app/
  │   └── fibonacci.c     Enclave payload (Fibonacci + filler functions)
  ├── inc/
  │   └── fibonacci.h
  ├── linker/
  │   ├── memory.ld       MCU memory regions + Umbra aliases
  │   └── host.ld         Section layout + NSC veneer addresses (PROVIDE)
  └── Makefile
```

## Key Design Points

- **No vector table fetch**: the NS VTOR is not used at runtime — the bare-metal host never triggers SVC, PendSV, or SysTick exceptions. All scheduling is done cooperatively via the round-robin loop.
- **Enclave header in flash**: the 48-byte header (magic, trust level, HMAC) is placed in `._enclave_header` by a section attribute. `protect_enclave.py` overwrites the HMAC field at build time.
- **NSC veneer addresses**: hardcoded via `PROVIDE()` in `host.ld`. These must be updated if the Secure boot is rebuilt and veneer offsets change.
