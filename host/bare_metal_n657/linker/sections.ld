/*
 * STM32N657 NS host sections — placed in AXISRAM3 (NS).
 *
 * Layout in AXISRAM3 (0x24200000, 448K):
 *   0x24200000: .isr_vector (vector table, ALIGN 0x100)
 *   0x24200100: _host_entry_point (Reset_Handler — trampoline_to_ns target)
 *   ...      : .text + .rodata
 *   ...      : .data (initialized at startup)
 *   ...      : .bss (zeroed at startup)
 *   _host_estack: top of AXISRAM3 (NS MSP, set by trampoline)
 *
 * NSC veneer addresses (umbra_*) are PROVIDEd at the NSC region in AXISRAM2.
 * The Secure linker fixes the actual veneer code at these absolute addresses.
 */

ENTRY(_host_Reset_Handler)

/* Top of AXISRAM3 = host MSP (set by trampoline_to_ns) */
_host_estack = ORIGIN(AXISRAM3_NS) + LENGTH(AXISRAM3_NS);

SECTIONS
{
    .isr_vector ORIGIN(AXISRAM3_NS) :
    {
        KEEP(*(.isr_vector))
        /* Pad to 0x100 so Reset_Handler lands at _host_entry_point */
        . = ALIGN(0x100);
    } > AXISRAM3_NS

    .text :
    {
        /* Reset_Handler must be the first code symbol after vector table */
        KEEP(*(.text._host_Reset_Handler))
        *(.text*)
        *(.rodata*)
        . = ALIGN(4);
        _etext = .;
    } > AXISRAM3_NS

    _sidata = LOADADDR(.data);

    .data :
    {
        . = ALIGN(4);
        _sdata = .;
        *(.data*)
        . = ALIGN(4);
        _edata = .;
    } > AXISRAM3_NS

    .bss :
    {
        . = ALIGN(4);
        _sbss = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        _ebss = .;
    } > AXISRAM3_NS

    /* ── Enclave region — Phase E.4a real loader ──────────────────────
     * Pinned at 0x24010000 (offset 0x10000 from AXISRAM3_NS base) via
     * an explicit section start address — `. = ALIGN(N)` between
     * `> REGION` placements doesn't carry across the region directive,
     * so we follow the L552 host.ld pattern of using a fixed address.
     *
     * When flashed at XSPI2 0x70080000, the enclave header lands at
     * 0x70090000 — outside the MCE2 region 1 (0x700A0000+), so the
     * FSBL Secure side reads plaintext directly via memory-mapped XSPI2.
     *
     * `_enclave_start` is exported so the host can compute the flash
     * address: 0x70080000 + (_enclave_start - 0x24000000).
     * protect_enclave.py patches the chained-measurement HMAC into
     * ._enclave_header post-link.
     */
    ._enclave_header 0x24010000 :
    {
        _enclave_start = .;
        KEEP(*(.app.enclave_header))
    } > AXISRAM3_NS

    ._enclave_code :
    {
        _enclave_code_start = .;
        /* Entry function placed first so its address coincides with the
         * enclave entry point (start of ._enclave_code). The kernel
         * configures the PSP frame's PC = ess_addr + 0, which after
         * BFS-load corresponds to the first byte of the entry function.
         * Without this ordering GCC emits functions in source order and
         * the wrong helper ends up at offset 0. */
        KEEP(*(.app.enclave_code.entry))
        KEEP(*(.app.enclave_code))
        KEEP(*(.app.*))
        . = _enclave_code_start + 0x400;  /* Reserve 1024 bytes for code */
    } > AXISRAM3_NS

    /* NSC veneer addresses — must match the Secure linker's NSC region.
     * NSC region on N657: 0x341AB400 (after +0x400 signing header shift).
     * Each veneer is 16 bytes (sg + push + bl + pop + bxns).
     * The +1 is the Thumb bit required for BLXNS to jump to Thumb code.
     */
    PROVIDE(umbra_enclave_create     = 0x341AB401);
    PROVIDE(umbra_debug_print    = 0x341AB411);
    PROVIDE(umbra_enclave_enter  = 0x341AB421);
    PROVIDE(umbra_enclave_exit   = 0x341AB431);
    PROVIDE(umbra_enclave_status = 0x341AB441);
}

/* Phase E.4c MCE2 — linker symbols consumed by:
 *   - Rust FSBL oracle: extern "C" { static _enclave_plaintext_flash_addr; ... }
 *   - C host main.c:    extern uint32_t _enclave_ciphertext_flash_addr;
 * `_enclave_ciphertext_flash_addr` is what enclave_create() will be passed
 * after the oracle re-encrypts plaintext into the MCE2 region.
 */
PROVIDE(_enclave_ciphertext_flash_addr = ENCLAVE_DST_START);
PROVIDE(_enclave_region_size           = ENCLAVE_REGION_SIZE);
PROVIDE(_enclave_plaintext_flash_addr  = ENCLAVE_PLAINTEXT_FLASH);
