/*
 * Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>
 *
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

    /* ── Enclave region ────────────────────────────────────────────────
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

        /* The enclave arrives as one partial-linked object
         * (obj/enclave_combined.o, built by linker/enclave_partial.ld) with
         * two sections: .app.enclave_code (entry first, then all reachable
         * code + rodata + data) and .app.enclave_bss (the 8 B of writable
         * globals). enclave_entry is already at offset 0 of .app.enclave_code,
         * so it lands at the start of ._enclave_code — the address the kernel
         * uses for the PSP-frame PC (= ess_addr + 0). The .entry KEEP below is
         * a belt-and-suspenders for any stack-only app source that still emits
         * a discrete .app.enclave_code.entry section. */
        KEEP(*(.app.enclave_code.entry))
        KEEP(*(.app.enclave_code))

        /* ndes's writable .bss (ndes_bit[], ndes_inp/key/out, ndes_icd,
         * ndes_ipc1/2, the ndes_des() function-local statics, etc.).
         * Folded INSIDE ._enclave_code — NOT a separate NOLOAD section — so
         * that (a) it stays contiguous with the code for the
         * -mpic-data-is-text-relative (PC-relative) global addressing, and
         * (b) it falls below _enclave_code_end, which protect_enclave.py uses
         * to size the kernel's ESS allocation. If .bss lived past
         * _enclave_code_end the first global write would land outside the
         * allocated ESS region and MemManage-fault. The bytes are
         * deterministic zeros, so measuring them in a block is harmless.
         * (Mirrors the proven L552 taclebench enclave_blob.ld layout.) */
        KEEP(*(.app.enclave_bss))

        . = ALIGN(4);
        /* End of real content (code + rodata + data + bss), BEFORE the
         * reservation padding. protect_enclave.py reads _enclave_code_end
         * via nm to size the protected blob so it covers globals, not just
         * code. */
        _enclave_code_end = .;

        /* Reserve space for protect_enclave.py's in-place write-back of the
         * protected blocks. N657 chained_measurement layout = 288 B/block
         * (Meta 32 + CT 256). ndes is ~18-22 blocks → ~6 KB protected;
         * 0x6000 (24 KB) gives headroom. If you hit "cannot move location
         * counter backwards", the plaintext exceeded this — bump it. NOTE:
         * this is the ELF-image reservation, not the runtime EFBC window; the
         * kernel ESS window is a separate 16 KB (MAX_EFBS*256), and the
         * plaintext code+data+bss must fit THAT (≤ 64 blocks). */
        . = _enclave_code_start + 0x6000;
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

/* MCE2 linker symbols consumed by:
 *   - Rust FSBL oracle: extern "C" { static _enclave_plaintext_flash_addr; ... }
 *   - C host main.c:    extern uint32_t _enclave_ciphertext_flash_addr;
 * `_enclave_ciphertext_flash_addr` is what enclave_create() will be passed
 * after the oracle re-encrypts plaintext into the MCE2 region.
 */
PROVIDE(_enclave_ciphertext_flash_addr = ENCLAVE_DST_START);
PROVIDE(_enclave_region_size           = ENCLAVE_REGION_SIZE);
PROVIDE(_enclave_plaintext_flash_addr  = ENCLAVE_PLAINTEXT_FLASH);
