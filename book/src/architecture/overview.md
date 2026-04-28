# Architecture Overview

## TrustZone-M

Arm TrustZone-M splits the Cortex-M33 processor into two security states:

- **Secure World** — runs Umbra (bootloader, kernel, drivers). Has access to all memory.
- **Non-Secure World** — runs the host application. Cannot access Secure memory.

Transitions between worlds are controlled by hardware:
- **NS to S**: Via Non-Secure Callable (NSC) regions containing `SG` (Secure Gateway) instructions
- **S to NS**: Via `BLXNS` instruction or exception return with special EXC_RETURN values

## Umbra's Role

Umbra provides the Secure World runtime. It:

1. **Boots first** — the vector table is in Secure flash; Umbra initializes SAU, GTZC, MPU, and peripherals before handing control to the Non-Secure host
2. **Provides APIs** — 6 NSC veneers allow the host to create, enter, exit, and query enclaves
3. **Manages enclaves** — loads encrypted code from flash, validates integrity (HMAC), decrypts (AES), and installs into Secure SRAM
4. **Enforces isolation** — MPU regions protect kernel memory from enclave code; MPCBB controls 256-byte block-level SRAM security

## Memory Map

```
Flash Bank 0 (256 KB) — Secure
  0x08000000  +-- Secure Boot (68 KB) --- vector table, handlers, boot logic
  0x08011000  +-- Kernel Text (172 KB) -- NSC API implementations, kernel code
  0x0803C000  +-- NSC Region (16 KB) ---- SG veneers (umbra_tee_create, etc.)

Flash Bank 1 (256 KB) — Non-Secure
  0x08040000  +-- Host Application ------ user code, enclave headers + encrypted blocks

SRAM0 (128 KB) — Non-Secure
  0x20000000  +-- Host stack + data

SRAM1 (64 KB) — Secure (alias 0x30020000)
  0x20020000  +-- ESS (Enclave Swap Space) -- loaded enclave code blocks
  0x30030000  +-- Kernel .data / .bss (56 KB)
  0x3003E000  +-- NSC data (8 KB)
```
