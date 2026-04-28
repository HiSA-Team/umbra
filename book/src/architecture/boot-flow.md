# Boot Flow

## Startup Sequence

1. **Reset_Handler** (assembly, `startup.s`)
   - Copies `.data` from flash to SRAM
   - Zeros `.bss`
   - Calls `secure_boot()` in Rust

2. **secure_boot()** (Rust, `main.rs`)

   | Step | What | Why |
   |---|---|---|
   | GPIO + LED | Configure board LED | Visual boot indicator |
   | UART | Init LPUART1/USART1 at 9600 baud | Debug output |
   | SAU | Configure Secure Attribution Unit regions | Define S/NS/NSC memory boundaries |
   | GTZC | Configure MPCBB for SRAM block security | 256-byte granularity SRAM protection |
   | MPU | Enable Memory Protection Unit | Isolate kernel from enclaves |
   | Fault enables | MEMFAULT, BUSFAULT, USGFAULT, SECUREFAULT | Fault isolation for ESS recovery |
   | DMA | Enable DMA1/DMA2 + NVIC interrupts | Block loading from flash to SRAM |
   | Crypto | Init HASH (SHA-256) + AES (HW or SW) | Integrity verification + decryption |
   | Kernel | Create `Kernel` instance, derive session keys | Central state for enclave management |
   | OCTOSPI (L562) | Memory-mapped external flash + OTFDEC | Transparent enclave decryption |
   | SysTick | Disable (enabled per-enclave by SVC handler) | Preemptive scheduling |
   | VTOR_NS | Set NS vector table to 0x08040000 | Host exception handling |
   | `trampoline_to_ns()` | Set MSP_NS, `BLXNS` to host entry | Transfer to Non-Secure World |

## After Boot

The host application runs in Non-Secure World. It discovers enclaves in flash, creates them via `umbra_tee_create()`, and schedules them via `umbra_enclave_enter()`. Each enter triggers an SVC into Secure World where the kernel restores enclave context and enables SysTick for preemption.
