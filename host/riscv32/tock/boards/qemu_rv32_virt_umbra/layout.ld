/* Licensed under the Apache License, Version 2.0 or the MIT License. */
/* SPDX-License-Identifier: Apache-2.0 OR MIT                         */
/* Copyright Tock Contributors 2023.                                  */

/*
 * qemu_rv32_virt board relinked for Umbra: the Tock kernel image lives in the
 * untrusted S-mode host region [0x80100000, 0x80200000). Umbra (M-mode monitor)
 * owns 0x80000000; the enclave ESS starts at 0x80200000. `_enter_smode` drops
 * into S-mode at 0x80100000, which must be the kernel entry — so ORIGIN(rom)
 * holds `.riscv.start` (initialize_ram_jump_to_main) as the first instruction.
 *
 * NAPOT constraint (load-bearing): Tock's MML ePMP builds the flash and RAM PMP
 * regions via NAPOTRegionSpec::from_start_end(...).unwrap(), which REQUIRES each
 * region to be a power-of-two size, base-aligned to that size — else the Rust
 * `.unwrap()` panics during boot (before any CSR effect, so shadowing mseccfg
 * does NOT save us). Hence:
 *   flash = [_sflash, _eflash) = [0x80100000, 0x80180000) spanning rom+prog+encl
 *           = 0x80000 (512 KB), base 0x80100000 aligned to 0x80000   -> NAPOT ok
 *   ram   = [0x80180000, 0x80200000) = 0x80000 (512 KB), aligned     -> NAPOT ok
 * The whole image stays inside the 1 MB host window [0x80100000, 0x80200000).
 *
 * sub-slice 3d: a dedicated `encl` region [0x80170000, 0x80180000) holds the
 * embedded Umbra enclave (encrypted + chain-HMAC-signed in place by
 * tools/protect_enclave.py). It is its OWN MEMORY region (separate location
 * counter) so it cannot disturb the kernel's rom/prog/ram placement, yet stays
 * inside the flash NAPOT window so Tock's ePMP grants it R (Tock only reads the
 * magic; the M-mode monitor reads the blob during tee_create — M bypasses PMP;
 * Tock never executes it). prog shrinks to 64 KB (this board loads no apps), and
 * the app scan range [_sapps, _eapps) = [0x80160000, 0x80170000) excludes encl.
 */

MEMORY
{
  rom  (rx) : ORIGIN = 0x80100000, LENGTH = 0x00060000  /* 384 KB kernel text+rodata */
  prog (rx) : ORIGIN = 0x80160000, LENGTH = 0x00010000  /* 64 KB apps; _eapps = 0x80170000 */
  encl (rx) : ORIGIN = 0x80170000, LENGTH = 0x00010000  /* 64 KB embedded Umbra enclave */
  ram (rwx) : ORIGIN = 0x80180000, LENGTH = 0x00080000  /* 512 KB; _esram = 0x80200000 */
}

SECTIONS {
    /* Export the start & end of SRAM and flash as symbols for setting up the
     * ePMP. Flash spans rom+prog+encl so it is a single NAPOT region; .text is
     * made executable by a separate (TOR) PMP region. */
    _sflash = ORIGIN(rom);
    _eflash = ORIGIN(encl) + LENGTH(encl);

    _ssram  = ORIGIN(ram);
    _esram  = ORIGIN(ram) + LENGTH(ram);

    /* Embedded Umbra enclave (sub-slice 3d) — its own `encl` region, so the
     * location counter is independent of rom/prog/ram. Mirrors the enclave
     * sections in host/riscv32/bare_metal/linker/host.ld. */
    ._enclave_header : ALIGN(4) {
        _enclave_start = .;
        KEEP(*(.app.enclave_header))
    } > encl
    ._enclave_code : ALIGN(4) {
        _enclave_code_start = .;
        KEEP(*(.app.enclave_entry))    /* entry FIRST: lands at base + 48 */
        KEEP(*(.app.enclave_code))
        KEEP(*(.app.*))
        . = ALIGN(4);
        _enclave_code_end = .;         /* real code+data end (protect_enclave.py
                                          reads this for the block-split length) */
        /* Reserve room for the protected blob (N 320-byte EFBC blocks + reloc
           table); 0x600 covers up to 4 blocks. */
        . = _enclave_code_start + 0x600;
    } > encl
}

INCLUDE tock_kernel_layout.ld
