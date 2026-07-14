/*
 * Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>
 *
 * STM32N657 STANDALONE enclave-blob linker script.
 *
 * Mirrors host/stm32l552/taclebench/linker/enclave_blob.ld: it links ONE
 * enclave (a header-only object carrying `.app.enclave_header` + the
 * partial-linked `obj/enclave_combined_<name>.o` carrying `.app.enclave_code`
 * and `.app.enclave_bss`) into a minimal ELF containing exactly two output
 * sections — `._enclave_header` at VMA 0 and `._enclave_code` right after.
 *
 * After `protect_enclave.py` rewrites `._enclave_code` in place with the
 * protected blocks and patches `._enclave_header`, an
 *   objcopy -O binary --only-section=._enclave_header --only-section=._enclave_code
 * extraction yields a flat `<name>.bin` that is flashed at any XSPI2 offset
 * and passed to `umbra_enclave_create(flash_addr)` by the host. This is the
 * SAME on-flash blob shape the L552 bare_metal host scans for; here the host
 * knows the two flash offsets directly (RISAF12 blocks NS scanning of XSPI2).
 *
 * ORIGIN = 0x0 is intentional: the enclave is compiled PIC
 * (-fpic -mpic-data-is-text-relative), so only the relative layout inside the
 * blob matters — the kernel copies the blocks to a dynamically-allocated ESS
 * address at runtime. Both blobs link against ORIGIN 0x0 so they overlay at
 * the same EFBC runtime base (0x340E0000) when loaded one at a time.
 */

ENTRY(enclave_entry)

MEMORY {
    /* 32 KB window. ammunition is ~60 blocks (~15 KB plaintext), ndes ~20
     * blocks (~4.5 KB plaintext) — both well inside the 0x6000 reservation
     * below. Sized to match the host sections.ld reservation. */
    FLASH_BLOB (RX) : ORIGIN = 0x0, LENGTH = 32K
}

SECTIONS {
    ._enclave_header 0x0 : {
        KEEP(*(.app.enclave_header))
    } > FLASH_BLOB

    ._enclave_code : ALIGN(4) {
        _enclave_code_start = .;

        /* Entry wrapper first (offset 0 of the code region = the kernel's
         * PSP-frame PC). The partial link already put .app.enclave_code.entry
         * at offset 0 of the combined object's .app.enclave_code, but KEEP the
         * discrete .entry section too as belt-and-suspenders. */
        KEEP(*(.app.enclave_code.entry))
        KEEP(*(.app.enclave_code))

        /* Writable globals folded INSIDE ._enclave_code, before
         * _enclave_code_end, so they are text-relative-addressable and covered
         * by the kernel's ESS allocation (mirrors the host sections.ld and the
         * L552 enclave_blob.ld layout). */
        KEEP(*(.app.enclave_bss))

        . = ALIGN(4);
        /* End of real content (code + rodata + data + bss), BEFORE the
         * reservation padding. protect_enclave.py reads this via nm to size
         * the protected blob so it covers globals, not just code. */
        _enclave_code_end = .;

        /* Reserve space for protect_enclave.py's in-place write-back of the
         * protected blocks. N657 chained_measurement layout = 288 B/block
         * (Meta 32 + CT 256). ammunition ~60 blocks -> ~17 KB protected;
         * 0x6000 (24 KB) gives headroom. Must be >= the protect output or
         * objcopy truncates the ciphertext on extraction. */
        . = _enclave_code_start + 0x6000;
    } > FLASH_BLOB

    /DISCARD/ : {
        *(.note.*)
        *(.comment)
        *(.eh_frame*)
        *(.ARM.*)
        *(.debug_*)
    }
}
