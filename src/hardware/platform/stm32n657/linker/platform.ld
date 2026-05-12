/*********************************************************************************************************
*
*   STM32N657 platform linker script — Umbra Secure Boot
*
*   Umbra runs as FSBL from DTCM (Secure alias 0x3xxxxxxx).
*   Boot ROM copies the entire image from XSPI2 to SRAM, so .text and .data
*   are both in SRAM — no separate flash LMA needed.
*
*   Code + data run from AXISRAM2 Secure (0x34100000+), not DTCM, because
*   TCM is not accessible via the debug port (AHB-AP / AXI bus).
*
*   Stack pointer: _umb_estack is at the NS alias (0x24xxx). The vector
*   table in startup_n657.s adds +0x10000000 to get the Secure alias.
*
**********************************************************************************************************/

_umb_stack_size = 0x6000;
_umb_estack = 0x241CC3FC;  /* Top of _SECURE_KERNEL_DATA_MEMORY_ (0x341CC400 - 4, NS alias) */

SECTIONS
{
    /********************
    * Secure Boot Area  *
    *********************/

    ._umb_vector_table :
    {
        KEEP(*(._umb_vectors))
    } > _SECURE_BOOT_TEXT_MEMORY_

    ._umb_handlers :
    {
        KEEP(*(._umb_handlers))
    } > _SECURE_BOOT_TEXT_MEMORY_

    ._umb_startup :
    {
        KEEP(*(.text._umb_start));
        KEEP(*(.text.main));
    } > _SECURE_BOOT_TEXT_MEMORY_

    /********************
    * Secure Functions  *
    *********************/

    .secure :
    {
        KEEP(*(.text.secure));
    } > _SECURE_BOOT_TEXT_MEMORY_

    .text :
    {
        *(.text*);
    } > _SECURE_BOOT_TEXT_MEMORY_

    .rodata :
    {
        *(.rodata*)
    } > _SECURE_BOOT_TEXT_MEMORY_

    /* Mark the end of the FSBL image in the text region.
     * On XSPI2 flash, enclave storage starts at:
     *   0x70000000 + (_umb_fsbl_image_end - 0x34180000), aligned up to 4KB.
     */
    _umb_fsbl_image_end = .;

    /*
     * On N657, code runs from SRAM (copied by Boot ROM). For debugging
     * via GDB/OpenOCD we load the ELF directly. In both cases .data VMA
     * and LMA are the same region (DTCM). The startup .data copy loop
     * becomes a no-op (source == destination) which is harmless.
     */
    .data :
    {
        . = ALIGN(4);
        _sdata = .;
        *(.data*)
        . = ALIGN(4);
        _edata = .;
    } > _SECURE_KERNEL_DATA_MEMORY_

    _sidata = LOADADDR(.data);

    .bss :
    {
        . = ALIGN(4);
        _sbss = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        _ebss = .;
    } > _SECURE_KERNEL_DATA_MEMORY_
}
