/* Minimal linker script for the standalone fibonacci enclave payload.
 *
 * Output layout in flash (matches bare_metal's host.ld:46-59):
 *   0x08078000  ._enclave_header  48 bytes      ← from src/header.c
 *   0x08078030  ._enclave_code    ≤ 1024 bytes  ← from app/fibonacci.c
 *
 * protect_enclave.py expects:
 *   - sections ._enclave_header and ._enclave_code
 *   - symbols _enclave_code_start (mandatory) and _enclave_code_end (optional,
 *     used to size the encrypted region accurately; without it the fallback
 *     uses the last instruction's address which can under-size when there's
 *     .rodata / .data after .text).
 *
 * The enclave code MUST live at 0x08078030 (header_size = 0x30 = 48 bytes)
 * so the runtime entry-point arithmetic in umbra_enclave_create matches.
 */

MEMORY {
    FLASH (rx) : ORIGIN = 0x08078000, LENGTH = 32K
}

SECTIONS {
    ._enclave_header 0x08078000 : {
        _enclave_start = .;
        KEEP(*(.app.enclave_header))
    } > FLASH

    ._enclave_code : {
        _enclave_code_start = .;
        KEEP(*(.app.enclave_code))
        KEEP(*(.app.*))
        /* Reserve 0x400 bytes total for code (matches code_size in the header).
         * protect_enclave.py reads _enclave_code_end to know the exact extent. */
        . = _enclave_code_start + 0x400;
        _enclave_code_end = .;
    } > FLASH

    /DISCARD/ : {
        *(.text*)            /* No __libc / startup code in this minimal blob */
        *(.rodata*)
        *(.data*)
        *(.bss*)
        *(.comment)
        *(.ARM.attributes)
        *(.ARM.exidx*)
        *(.eh_frame*)
    }
}
