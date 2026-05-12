# Architecture Overview

## TrustZone-M

Arm TrustZone-M splits the processor into two security states:

- **Secure World** — runs Umbra (bootloader, kernel, drivers). Has access to all memory.
- **Non-Secure World** — runs the host application. Cannot access Secure memory.

Transitions between worlds are controlled by hardware:
- **NS to S**: Via Non-Secure Callable (NSC) regions containing `SG` (Secure Gateway) instructions
- **S to NS**: Via `BLXNS` instruction or exception return with special EXC_RETURN values

The same TrustZone-M model applies to Cortex-M33 (ARMv8-M Mainline,
STM32L5) and Cortex-M55 (ARMv8.1-M, STM32N6). The two cores differ in
the available extensions (MVE/Helium, double FPU, integrated caches on
M55) but not in the security state machine.

## Umbra's Role

Umbra provides the Secure World runtime. It:

1. **Boots first** — on STM32L5 from internal Secure flash, on STM32N6
   as an FSBL loaded by Boot ROM from XSPI2 into AXISRAM. Umbra
   initializes SAU, the platform memory firewall (GTZC on L5, RISAF +
   RIFSC + RIMC on N6), MPU, and peripherals before handing control to
   the Non-Secure host.
2. **Provides APIs** — 5 NSC veneers allow the host to create, enter,
   exit, and query enclaves.
3. **Manages enclaves** — loads encrypted code from flash, validates
   integrity (HMAC-SHA256, hardware-accelerated on L562 and N657),
   decrypts (AES), and installs into Secure SRAM.
4. **Enforces isolation** — MPU regions protect kernel memory from
   enclave code; MPCBB (L5) or RISAF (N6) controls block-level SRAM
   security.

## Memory Map — STM32L5

```
Flash Bank 0 (256 KB) — Secure
  0x08000000  +-- Secure Boot (68 KB) --- vector table, handlers, boot logic
  0x08011000  +-- Kernel Text (172 KB) -- NSC API implementations, kernel code
  0x0803C000  +-- NSC Region (16 KB) ---- SG veneers (umbra_enclave_create, etc.)

Flash Bank 1 (256 KB) — Non-Secure
  0x08040000  +-- Host Application ------ user code, enclave headers + encrypted blocks

SRAM0 (128 KB) — Non-Secure
  0x20000000  +-- Host stack + data

SRAM1 (64 KB) — Secure (alias 0x30020000)
  0x20020000  +-- ESS (Enclave Swap Space) -- loaded enclave code blocks
  0x30030000  +-- Kernel .data / .bss (56 KB)
  0x3003E000  +-- NSC data (8 KB)
```

## Memory Map — STM32N657

STM32N6 has no internal flash. All code lives in XSPI2 (memory-mapped
at `0x70000000`) and is copied or executed from SRAM. IDAU aliasing
uses the top nibble: **odd top nibble = Secure** (`0x1x`, `0x3x`, `0x5x`),
**even top nibble = Non-Secure** (`0x0x`, `0x2x`, `0x4x`).

```
External flash (XSPI2, 512 Mb / 64 MB) — bus-level protected by RISAF12 + MCE2
  0x70000000  +-- FSBL signed image (signing header 0x400 + payload)
  0x70080000  +-- Host bin (placed by flash_n657.sh)
  0x70090000  +-- Enclave header + ciphertext blocks
  0x700A0000+ +-- (Path B-lite plaintext / future MCE2 region 1 ciphertext)

AXISRAM2 (512 KB) — Secure (0x34180000)
  0x34180000  +-- FSBL signing header (0x400 bytes, Boot ROM-copied)
  0x34180400  +-- Umbra Secure boot + kernel code/data
              +-- NSC veneers (.umbra_nsc_api section)

AXISRAM1 (1 MB) — Secure / Non-Secure aliases (0x34000000 / 0x24000000)
  0x24000000  +-- Host application (NS view, ~896 KB)
  0x340E0000  +-- ESS (Enclave Swap Space, 128 KB, Secure-only via RISAF2)
  0x340F0000+ +-- Kernel scratch (EFBC, PSPs)

AXISRAM3-6 (~1.8 MB) — Secure aliases (0x34200000 / 0x34270000 / 0x342E0000 / 0x34350000)
              +-- Power-gated by default; opened for the NPU object-detection demo

Boot ROM (128 KB) — 0x08000000 NS / 0x18000000 S
ITCM Secure veneer alias — 0x10000000+
DTCM — 0x20000000 (NS) / 0x30000000 (S)
```

## Memory firewall — GTZC vs RIF

| Concern | STM32L5 | STM32N6 |
|---|---|---|
| Per-block SRAM security | GTZC MPCBB (256-byte blocks) | RISAF (per-memory, 4 KB / 512 B granularity, 7 regions each) |
| Per-peripheral security | GTZC TZSC | RIFSC (CID-based, 8 compartments) |
| Bus master tagging | (none) | RIMC (DMA/NPU master CID assignment) |
| External flash decryption | OTFDEC (L562 only) | MCE1–MCE4 (4 instances, AES-128/256 or NOEKEON) |
| Fault reporting | SecureFault | RIF → IAC (Illegal Access Controller) |

The Umbra kernel hides this difference behind the `PlatformBoot::init_security`
trait method (see [Crate Structure](crate-structure.md)).
