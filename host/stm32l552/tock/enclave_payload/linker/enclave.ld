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
        /* `_enclave_code_end` marks the END OF ACTUAL CODE (before
         * any padding). protect_enclave.py reads this symbol to size
         * the encrypted region and split into blocks. If we set it
         * after a `. = ... + 0xN` reservation, protect.py would treat
         * the padding zeros as code, split them into spurious blocks,
         * generate a fake reachability chain, and the kernel would
         * fail to validate the chained HMAC at create-time.
         *
         * At SLOT_SIZE=1024 a reservation+end-after-padding layout
         * would inflate fib's blob to 9 blocks of ~zero data and trip
         * `chained-measurement FAIL`. Splitting the end-marker from
         * the reservation keeps each blob block-count accurate.
         *
         * `_enclave_blob_max` = section size = end-of-actual + max
         * protected overhead. Worst case at SLOT_SIZE=8192:
         *   1 block X (32 HMAC + 32 meta + 8192 CT) + 48 hdr = 8304 B.
         * Round up to 0x2400 = 9216 for headroom. */
        _enclave_code_end = .;
        . = _enclave_code_start + 0x2400;
        _enclave_blob_max = .;
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
