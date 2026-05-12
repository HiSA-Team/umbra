# FSBL Boot (STM32N6)

The STM32N6 family has no internal flash. On every reset the **Boot
ROM** runs first, reads an FSBL (first-stage bootloader) image from
external XSPI flash, authenticates it, copies it into SRAM, and jumps
into it. On NUCLEO-N657X0-Q the FSBL **is** Umbra's Secure Boot.

This chapter documents the pre-amble that runs before
[the common Boot Flow](boot-flow.md).

## Boot ROM contract

The Boot ROM at `0x08000000` (NS) / `0x18000000` (S):

1. Selects a boot source based on the JP2 (BOOT1) jumper and the
   BOOT pads / option bytes:
   - **Dev-Boot** (JP2 = 2-3) — accept an image via UART/USB DFU and the
     STM32CubeProgrammer. Used when programming a new FSBL.
   - **Flash-Boot** (JP2 = 1-2) — read the FSBL from XSPI2 at
     `0x70000000` and run it.
2. Reads the **signing header** at offset 0 of the image.
   `STM32_SigningTool_CLI` wrote this header (0x400 = 1024 bytes) with a
   load address, entry point, alignment, and optional ECC signature.
3. In **BSEC-open** (development) state, the Boot ROM accepts the header
   without a real signature. In **BSEC-closed** (production) the
   signature is mandatory and is checked against a fused public key.
4. Copies the **entire** signed image (header + payload) into AXISRAM2
   at the load address `0x34180000`. The actual code therefore starts
   at `0x34180400` — the linker scripts must offset all addresses by
   the 1024-byte header.
5. Branches to the entry point recorded in the header (`0x34180641` for
   Umbra — vector table reset address with the Thumb LSB set).

## Image layout flashed to XSPI2

```
0x70000000  +-- FSBL signed image
            |     - signing header (0x400 bytes)
            |     - Umbra Secure Boot + kernel binary
            |
0x70080000  +-- Host bin (raw, plaintext)
            |     - 0x10000 padding for the AXISRAM1 layout
            |
0x70090000  +-- Enclave header ("UMBR" magic) + ciphertext blocks
            |
0x700A0000+ +-- (reserved for future MCE2 region 1 encrypted enclaves)
            |
... (NPU object-detection demo only)
            +-- Model bytecode (extracted by tools/extract_bytecode.py)
            +-- Model weights (network_data.xSPI2.bin from ST Edge AI)
```

All offsets above are produced by `tools/flash_n657.sh`, which calls
`STM32_SigningTool_CLI` and then `STM32_Programmer_CLI` with the
`MX25UM51245G_STM32N6570-NUCLEO.stldr` external loader.

## What Umbra does once Boot ROM hands off

`startup_n657.s` (`src/hardware/platform/stm32n657/boot/asm/arm/`) runs at
the entry point and:

1. Sets `MSPLIM` to the bottom of the Secure stack and **MSP** to
   `_umb_estack` (just above AXISRAM1 NS view's reserved upper 128 KB).
2. Copies `.data` from its load address (already in AXISRAM2) to its
   runtime address.
3. Zeros `.bss`.
4. Calls `_umb_start`, which is Rust `secure_boot()`.

From here the boot follows the standard [`PlatformBoot`](boot-flow.md)
flow. Notable N6-specific work inside that flow:

- **`init_clocks`** retunes PLL1 to 800 MHz (CPU = 800, AXI = 400,
  HCLK = 200) and PLL3 to 900 MHz (NPU). USART1 is kept on HSI = 64 MHz
  so the UART baud (115200) is insulated from PLL1 retuning. IC6 is
  enabled to clock the NPU at its rated 900 MHz.
- **`init_security`** programs RIFSC to open USART1, HASH, CRYP1, and
  XSPI2 to Secure access; programs RISAF2 (AXISRAM1) so the upper
  128 KB is Secure-only (ESS / EFBC / PSP); leaves RISAF12 (XSPI2) at
  its default Secure-only configuration so NS code cannot read
  ciphertext directly; configures RIMC so the NPU and HPDMA1 are tagged
  as Secure masters. Enables I-cache, D-cache, and SAU regions.
- **`init_kernel`** validates the boot-time **chained HMAC** over the
  enclave plus, for the NPU demo, the model bytecode and weights
  blob. The expected HMACs are baked in at build time by
  `tools/measure_blobs.py` (`boot_measurements.rs`) and verified with
  the hardware HASH peripheral, which brought boot time from ~30 s
  (software HMAC over 11 MB of weights) down to ~9 s.
- **`configure_ns_boot`** sets `VTOR_NS = 0x24000000` (AXISRAM1 NS
  view) so the NS host's vector table is in SRAM. The NS host bin is
  already in AXISRAM1 NS view because the Boot ROM copied the host
  bin from XSPI2 → AXISRAM1 in a separate Boot-ROM stage *that we do
  not depend on*; the FSBL instead copies the NS host into AXISRAM1
  itself during `init_kernel` so the layout is deterministic.

## Why the 0x400 offset matters

A common bring-up trap is `.rodata` corruption — symbols read back
zero or garbled. Root cause: the linker `ORIGIN` was set to
`0x34180000` (the load address) instead of `0x34180400` (where the
payload actually starts after the Boot-ROM-copied signing header).
The fix shipped in this branch: every linker script that targets the
N657 FSBL accounts for `_signing_header_size = 0x400`. See
[`src/hardware/platform/stm32n657/boot/asm/arm/startup_n657.s`](https://github.com/HiSA-Team/umbra/blob/main/src/hardware/platform/stm32n657/boot/asm/arm/startup_n657.s)
and the host's `linker/memory.ld`.

## Debugging through Boot ROM

OpenOCD + GDB cannot reset the M55 cleanly because Boot ROM holds the
core until authentication is done. Use **attach without reset**:

```bash
openocd -f openocd_scripts/stm32n6x.cfg
arm-none-eabi-gdb path/to/boot \
    -ex 'target extended-remote :3333'
# do NOT call `monitor reset`; the FSBL is already running
```

For symbol inspection only (no execution), `arm-none-eabi-objdump -d`
on the unsigned ELF works as usual — the signing header only matters
at runtime.
