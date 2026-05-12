# Phase E.4c Manual Test Procedures

These tests cannot run in `smoke_test.sh` — they require physical
intervention or non-standard build configurations.

## Prerequisites

- VBAT pin connected to external 3.3V supply (after cutting SB36 — see
  `docs/superpowers/specs/2026-05-05-phase-e4c-mce2-encryption-design.md`
  hardware setup section)
- JP2 in position 1-2 (Flash Boot) for normal runs, 2-3 (Dev Boot) for
  flashing
- UART monitor connected: `screen /dev/cu.usbmodem211203 115200`
- OpenOCD configured: `openocd_scripts/stm32n6x.cfg`
- STM32CubeProgrammer installed at the standard path expected by
  `tools/flash_n657.sh`

## T1 — first boot happy path (baseline)

1. Move JP2 to 2-3 (Dev Boot).
2. Run `./tools/flash_n657.sh`. Expected output: 6 phases (BKP clear,
   FSBL header, BKP[0] clear via Programmer, XSPI2 erase, FSBL flash,
   host flash).
3. Move JP2 to 1-2 (Flash Boot).
4. Press RST.
5. Expected UART tail (4 MB default layout):

       [UMBRASecureBoot] XSPI2 + MCE2 ready
       [UMBRASecureBoot] oracle: BKP[0]=0x00000000 PT[0]=0x52424D55
       [UMBRASecureBoot] oracle: first boot, full encryption
       [UMBRASecureBoot] oracle: erase dst sectors
       [UMBRASecureBoot] oracle: DMA copy + MCE2 encrypt
       [UMBRASecureBoot] oracle: BKP[0]=0x52424D55 stamped
       [UMBRASecureBoot] oracle: erase plaintext source
       [UMBRASecureBoot] oracle: complete
       [USER] Hello Non-Secure World!
       [USER] Enclave at flash=0x70500000
       [USER] Enclave created
       [USER] Enclave terminated! R0=0x72CA33A8

6. Verify TAMP_BKP[0] is set (optional):

       openocd -f openocd_scripts/stm32n6x.cfg \
         -c "init; halt; mdw 0x56004100; exit"

   Expected: `0x56004100: 52424d55`

## T2 — warm reset fast-path (BKP persistence)

1. With T1 having succeeded, press the RST button (do not power-cycle).
2. Expected UART tail:

       [UMBRASecureBoot] oracle: BKP[0]=0x52424D55 PT[0]=0xFFFFFFFF
       [UMBRASecureBoot] oracle: skip (already encrypted)
       [USER] Hello Non-Secure World!
       [USER] Enclave at flash=0x70500000
       [USER] Enclave terminated! R0=0x72CA33A8

3. The boot is fast (~0 s oracle overhead) compared to T1.

## T3 — USB cycle with VBAT alive

1. With T1 having succeeded, unplug the USB cable.
2. Verify the external VBAT 3.3V supply remains powered (multimeter on
   the VBAT pin should still read ~3.3V).
3. Plug USB back in. The board powers up.
4. Press RST if the board does not boot automatically.
5. Expected: same fast-path UART log as T2 — BKP[0] persisted via VBAT.

If the boot instead triggers a full re-encryption like T1, your VBAT
external supply was momentarily lost during the USB cycle. Diagnose
with a multimeter — typical culprits are a power source that browns
out below 1.65V (the VBAT lower limit per DS14091) or a missed solder
on the SB36 cut.

## T4 — VBAT loss → E4P00 fatal halt

This test exercises the S3 fatal state in the design state machine.

1. Run T1 → verify `BKP[0] = 0x52424D55` via OpenOCD `mdw 0x56004100`.
2. Disconnect external VBAT 3.3V supply.
3. Verify `BKP[0] = 0` via OpenOCD (battery-backed register cleared).
4. Reconnect VBAT supply (the register stays at 0 — it's already lost).
5. Press RST.
6. Expected UART:

       [UMBRASecureBoot] oracle: BKP[0]=0x00000000 PT[0]=0xFFFFFFFF
       [UMBRASecureBoot] E4P00 plaintext missing - run flash_n657.sh
       [UMBRASecureBoot]   plaintext_addr=0x70090000 first_word=0xFFFFFFFF bkp[0]=0
       [UMBRASecureBoot]   recovery: ./tools/flash_n657.sh
       [UMBRASecureBoot] HALT

7. Recovery: run `./tools/flash_n657.sh` again to return to S1, then RST.

**Alternative (no physical disconnect)**: run `./tools/sim_vbat_loss_n657.sh`.
This clears `TAMP_BKP[0]` via OpenOCD `mww` without unplugging the VBAT
supply. Faster for repeated CI-style testing.

## T5 — reflash without BKP clear (graceful re-oracle)

This test exercises the graceful recovery path Q8 — `(BKP_done=true,
plaintext_present=true)` triggers a full re-oracle even though BKP says
"done".

1. Run T1 → S2 reached, BKP[0] = 0x52424D55, plaintext erased.
2. Manually program a new host blob via STM32CubeProgrammer **without**
   invoking `flash_n657.sh` (which would clear BKP[0]):

       PROGRAMMER='/Applications/STMicroelectronics/STM32Cube/STM32CubeProgrammer/STM32CubeProgrammer.app/Contents/Resources/bin/STM32_Programmer_CLI'
       EXT_LOADER='/Applications/STMicroelectronics/STM32Cube/STM32CubeProgrammer/STM32CubeProgrammer.app/Contents/Resources/bin/ExternalLoader/MX25UM51245G_STM32N6570-NUCLEO.stldr'
       HOST_BIN=host/bare_metal_n657/bin/bare_metal_n657.bin

       "$PROGRAMMER" -c port=SWD mode=HOTPLUG ap=1 \
           -el "$EXT_LOADER" -hardRst \
           -w "$HOST_BIN" 0x70080000

3. Press RST.
4. Expected UART: BKP=0x52424D55 + PT[0]=0x52424D55 → graceful re-oracle:

       [UMBRASecureBoot] oracle: BKP[0]=0x52424D55 PT[0]=0x52424D55
       [UMBRASecureBoot] oracle: graceful re-oracle (reflash w/o BKP clear)
       [UMBRASecureBoot] oracle: erase dst sectors
       [UMBRASecureBoot] oracle: DMA copy + MCE2 encrypt
       [UMBRASecureBoot] oracle: BKP[0]=0x52424D55 stamped
       [UMBRASecureBoot] oracle: erase plaintext source
       [USER] Enclave terminated! R0=0x72CA33A8

5. Penalty: full re-encryption time (~22 s for 4 MB layout). Use
   `flash_n657.sh` instead of manual programming to avoid this in
   normal dev cycles.

## T6 — enclave too big (E4S01)

This test exercises the size validation in `full_oracle_inner`.

1. Add a large constant array to the enclave so its `code_size` exceeds
   `ENCLAVE_REGION_SIZE` (4 MB by default):

       /* in host/bare_metal_n657/app/test_enclave.c */
       const uint8_t huge_array[5 * 1024 * 1024] \
           __attribute__((section(".app.enclave_code"))) = {0};

2. Build the host: `cd host/bare_metal_n657 && make`
3. Flash: `./tools/flash_n657.sh`
4. Press RST.
5. Expected UART:

       [UMBRASecureBoot] oracle: BKP[0]=0x00000000 PT[0]=0x52424D55
       [UMBRASecureBoot] oracle: first boot, full encryption
       [UMBRASecureBoot] E4S01 enclave too big for MCE2 region
       [UMBRASecureBoot]   header.code_size=0x500000 > REGION_SIZE=0x400000
       [UMBRASecureBoot]   recovery: rebuild with larger ENCLAVE_REGION_SIZE
       [UMBRASecureBoot] HALT

6. Recovery options:
   - **Revert**: `git checkout host/bare_metal_n657/app/test_enclave.c`,
     rebuild, reflash.
   - **Bump region**: rebuild with the 16 MB layout:

         cd host/bare_metal_n657
         make ENCLAVE_REGION_SIZE=0x1000000 ENCLAVE_DST_START=0x71100000

     Then update the matching constants in
     `src/hardware/platform/stm32n657/boot/src/oracle.rs`
     (`ENCLAVE_CIPHERTEXT_FLASH = 0x71100000`,
     `ENCLAVE_REGION_SIZE = 0x0100_0000`), rebuild the FSBL, reflash.

## NPU inference benchmark (deferred — for the publication)

When integrating Neural-ART NPU inference into the enclave:

1. Use the 16 MB region:

       cd host/bare_metal_n657
       make ENCLAVE_REGION_SIZE=0x1000000 ENCLAVE_DST_START=0x71100000

   And update `oracle.rs` constants accordingly (see T6 step 6 above).

2. First-boot oracle time: ~90 s (BE64 × 256 sectors × ~350 ms typ +
   DMA copy + plaintext erase × 256). Subsequent boots: fast-path BKP
   skip — no overhead.

3. Inference latency unaffected: MCE2 transparent decrypt is bus-level,
   ~14 AXI cycles per 16 B (RM0486 §51.4.5 Table 436). Read throughput
   is therefore close to the bare-metal XSPI2 memory-mapped baseline.

## Diagnostics quick reference

| Symptom | Likely cause | First check |
|---|---|---|
| `E4P00 plaintext missing` | VBAT lost or never connected | Multimeter on VBAT pin |
| `E4S01 enclave too big` | Enclave > region size | `header.code_size` vs `REGION_SIZE` |
| `E4S02 size not 64KB-aligned` | protect_enclave.py bug or zero size | `header.code_size & 0xFFFF` |
| `E4X10 XSPI erase timeout` | Flash chip wedged | `mdw 0x5802A024` (SR), check WIP bit |
| `E4D20 DMA transfer error` | Bad src/dst address | Verify addresses are in valid memory |
| `E4D22 DMA user setting error` | TR1/TR2 misconfigured | Likely SAP/DAP polarity |
| `E4D21 DMA timeout` | DMA channel hung | `mdw 0x5802A060` (CxSR) |
| `E4D23 DMA bytes>0xFFF0` | Chunking math bug in oracle.rs | Code review |
| Boot completes but HMAC fail | Stale ciphertext + new plaintext | Confirm `flash_n657.sh` cleared BKP |

## Reference

- Design spec: [docs/superpowers/specs/2026-05-05-phase-e4c-mce2-encryption-design.md](../docs/superpowers/specs/2026-05-05-phase-e4c-mce2-encryption-design.md)
- Implementation plan: [docs/superpowers/plans/2026-05-05-phase-e4c-mce2-encryption.md](../docs/superpowers/plans/2026-05-05-phase-e4c-mce2-encryption.md)
- RM0486 §51 (MCE), §62 (TAMP), §18 (HPDMA), §28 (XSPI), §3.6 (Battery backup)
- DS14091 (STM32N657 datasheet) — VBAT range
- Macronix MX25UM51245G datasheet rev 2.6 — SPI/OPI command opcodes
