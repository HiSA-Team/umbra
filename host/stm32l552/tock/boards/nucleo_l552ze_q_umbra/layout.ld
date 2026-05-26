/* NUCLEO-L552ZE-Q Tock host linker script.
 *
 * Memory map:
 *   FLASH_BANK_0  0x08000000-0x0803FFFF (256K)  Umbra Secure (boot + kernel + NSC veneers)
 *   FLASH_BANK_1  0x08040000-0x0807FFFF (256K)  Non-Secure host:
 *     FLASH_KERNEL_NS  192K  Tock kernel: .vectors + .irqs + .text + .rodata
 *     APPS_NS           32K  TBF apps blob (injected by elf2tab+objcopy)
 *     ENCLAVE_NS        32K  Pre-flashed enclave (reservation only — see below)
 *   SRAM_NS       0x20000000-0x2001FFFF (128K)  Host NS RAM (capped at 64K +
 *                                                64K app-memory, see ASSERTs)
 *   EFBC          0x20020000-0x2002FFFF  (64K)  GTZC-Secure (Umbra enclave cache).
 *                                                NS writes here raise AUVIOL.
 *   SRAM2         0x20030000-0x2003FFFF  (64K)  Umbra Secure
 *
 * Why we don't INCLUDE tock_kernel_layout.ld: that file expects region names
 * `rom`/`ram`/`prog`, while we name them FLASH_KERNEL_NS / APPS_NS / SRAM_NS.
 * The symbols `initialize_ram_jump_to_main` reads (`_srelocate`/`_erelocate`/
 * `_szero`/`_ezero`/`_etext`/`_sstack`/`_estack`) are defined directly below.
 */

MEMORY {
    FLASH_KERNEL_NS (rx)  : ORIGIN = 0x08040000, LENGTH = 192K
    APPS_NS         (rx)  : ORIGIN = 0x08070000, LENGTH = 32K
    ENCLAVE_NS      (rx)  : ORIGIN = 0x08078000, LENGTH = 32K
    SRAM_NS         (rwx) : ORIGIN = 0x20000000, LENGTH = 128K
}

/* NSC veneer addresses provided by Umbra Secure. Slot layout (16-byte slots):
 *   0  0x0803c000  umbra_enclave_create
 *   1  0x0803c010  umbra_debug_print
 *   2  0x0803c020  umbra_enclave_enter
 *   3  0x0803c030  umbra_enclave_exit
 *   4  0x0803c040  umbra_enclave_status
 * Each provides a Thumb function pointer (low bit set).
 */
PROVIDE(umbra_enclave_create = 0x0803c001);
PROVIDE(umbra_debug_print    = 0x0803c011);
PROVIDE(umbra_enclave_enter  = 0x0803c021);
PROVIDE(umbra_enclave_exit   = 0x0803c031);
PROVIDE(umbra_enclave_status = 0x0803c041);

/* Tock's reset path: initialize_ram_jump_to_main reads ENTRY from the vector
 * table's reset slot. */
ENTRY(initialize_ram_jump_to_main)

SECTIONS {
    .vectors ORIGIN(FLASH_KERNEL_NS) : {
        KEEP(*(.vectors .vectors.*))
    } > FLASH_KERNEL_NS

    .irqs : {
        KEEP(*(.irqs))
    } > FLASH_KERNEL_NS

    .text : {
        . = ALIGN(4);
        _stext = .;
        *(.text .text.* .gnu.linkonce.t.*)
        *(.glue_7t) *(.glue_7)
        . = ALIGN(4);
        KEEP(*(.init))
        __preinit_array_start = .;
        KEEP(*(.preinit_array))
        __preinit_array_end = .;
        __init_array_start = .;
        KEEP(*(SORT(.init_array.*)))
        KEEP(*(.init_array))
        __init_array_end = .;
        KEEP(*(.fini))
        __fini_array_start = .;
        KEEP(*(.fini_array))
        KEEP(*(SORT(.fini_array.*)))
        __fini_array_end = .;
        . = ALIGN(4);
    } > FLASH_KERNEL_NS

    .rodata : {
        . = ALIGN(4);
        *(.rodata .rodata.* .gnu.linkonce.r.*)
        . = ALIGN(4);
    } > FLASH_KERNEL_NS

    .ARM.exidx : {
        PROVIDE_HIDDEN(__exidx_start = .);
        *(.ARM.exidx* .gnu.linkonce.armexidx.*)
        PROVIDE_HIDDEN(__exidx_end = .);
    } > FLASH_KERNEL_NS

    .ARM.extab : {
        *(.ARM.extab* .gnu.linkonce.armextab.*)
    } > FLASH_KERNEL_NS

    .tock.attr : {
        KEEP(*(.tock.attr*))
    } > FLASH_KERNEL_NS

    /* End-of-flash marker; serves as the LMA of .data. */
    . = ALIGN(4);
    _etext = .;

    /* Kernel stack at the bottom of SRAM_NS so overflow hits unmapped memory. */
    .stack (NOLOAD) : {
        . = ALIGN(8);
        _sstack = .;
        KEEP(*(.stack_buffer))
        . = ALIGN(8);
        _estack = .;
    } > SRAM_NS AT > SRAM_NS

    .data : AT (_etext) {
        . = ALIGN(4);
        _srelocate = .;
        *(.ramfunc .ramfunc.*)
        *(.data .data.* .gnu.linkonce.d.*)
        . = ALIGN(4);
        _erelocate = .;
    } > SRAM_NS

    .bss (NOLOAD) : {
        . = ALIGN(4);
        _szero = .;
        *(.bss .bss.* .gnu.linkonce.b.*)
        *(COMMON)
        . = ALIGN(4);
        _ezero = .;
    } > SRAM_NS

    /* App RAM forced to start at the NS-MPU region-3/region-4 boundary
     * (0x20010000). Region 3 (kernel-RAM, priv-RW) covers 0x20000000-0x2000FFFF;
     * region 4 (app-RAM, unpriv-RW) starts at 0x20010000. If `_sappmem` falls
     * in region 3 the first user-mode PSP push faults.
     *
     * Explicit VMA `(ORIGIN(SRAM_NS) + 0x10000)` in the header is required —
     * `> SRAM_NS` uses the region cursor and would ignore any `. = expr;`
     * assignment between sections.
     */
    .app_memory (ORIGIN(SRAM_NS) + 0x10000) (NOLOAD) : {
        _sappmem = .;
        *(.app_memory)
    } > SRAM_NS
    _eappmem = ORIGIN(SRAM_NS) + LENGTH(SRAM_NS);

    /* TBF apps blob is filled post-link by `objcopy --update-section .apps`.
     * Force the section to span the full 32 KB region (filling with 0xFF =
     * flash erase value) so `_eapps - _sapps` matches the region length at
     * link time — otherwise the kernel's process loader scans zero bytes. */
    .apps ORIGIN(APPS_NS) : {
        _sapps = .;
        KEEP(*(.tbf_headers))
        KEEP(*(.tbf_apps))
        . = ORIGIN(APPS_NS) + LENGTH(APPS_NS);
        _eapps = .;
    } > APPS_NS = 0xFF

    /* ENCLAVE_NS is intentionally not referenced: the pre-flashed enclave
     * lives there independently of this link, and the MEMORY entry above
     * reserves the range so no other output section can be placed there. */

    /DISCARD/ : {
        *(.eh_frame*)
    }
}

/* `_etext - ORIGIN(FLASH_KERNEL_NS)` covers every section that landed in
 * flash (.vectors, .irqs, .text, .rodata, .ARM.exidx, .ARM.extab, .tock.attr,
 * plus the .data load-image at AT(_etext)). Summing SIZEOFs would silently
 * undercount and let the kernel image overflow into APPS_NS. */
ASSERT(_etext - ORIGIN(FLASH_KERNEL_NS) <= LENGTH(FLASH_KERNEL_NS),
       "kernel image (including .data LMA) exceeds FLASH_KERNEL_NS (192K)");

ASSERT(_ezero <= ORIGIN(SRAM_NS) + LENGTH(SRAM_NS),
       "kernel RAM (.bss + .data) exceeds SRAM_NS (192K) — would clobber SRAM2");
ASSERT(_eappmem <= ORIGIN(SRAM_NS) + LENGTH(SRAM_NS),
       "app memory region extends past SRAM_NS — would clobber SRAM2");

/* NS-MPU region 3 (kernel-priv-RW) ends at 0x20010000; the kernel's
 * BSS+.data+MSP-stack must fit below it or the first user-mode PSP push
 * MemFaults. Shrink the kernel or rebalance regions in
 * src/hardware/platform/stm32l552/boot/src/ns_mpu_layout.rs. */
ASSERT(_ezero <= 0x20010000,
       "kernel RAM (.bss+.data) exceeds region-3 (kernel-only) boundary at 0x20010000");
