/*
 * Sections layout for FreeRTOS NS host demo.
 * FreeRTOS allocates per-task stacks from heap_4 in .bss.
 * MSP stack is ISR-only (4KB is sufficient).
 */

ENTRY(_host_Reset_Handler)

_host_stack_size = 0x1000;
_host_estack = ORIGIN(SRAM_0) + LENGTH(SRAM_0) - 0x4;
_host_sstack = _host_estack - _host_stack_size;

_host_app_address = ORIGIN(FLASH_BANK_1) + LENGTH(FLASH_BANK_1) - 0x8000;

SECTIONS
{
    /* FreeRTOS needs a valid VTOR — vectors must start at a naturally
     * aligned address (no 0x20 skip like bare_metal_arm).  VTOR is set
     * in startup.s to _host_vector_base. */
    ._host_vector_table :
    {
        _host_vector_base = .;
        KEEP(*(._host_vectors))
    } > FLASH_BANK_1

    ._host_handlers _host_entry_point :
    {
        KEEP(*(._host_handlers))
    } > FLASH_BANK_1

    ._host_text :
    {
        KEEP(*(.text))
        KEEP(*(.text.*))
    } > FLASH_BANK_1

    /* Enclave Header */
    ._enclave_header _host_app_address :
    {
        _enclave_start = .;
        KEEP(*(.app.enclave_header))
    } > FLASH_BANK_1

    /* Enclave Code */
    ._enclave_code :
    {
        _enclave_code_start = .;
        KEEP(*(.app.enclave_code))
        KEEP(*(.app.*))
        . = _enclave_code_start + 0x400;
    } > FLASH_BANK_1

    .rodata :
    {
        *(.rodata*)
    } > FLASH_BANK_1

    .data :
    {
        _sdata = .;
        *(.data*)
        _edata = .;
    } > SRAM_0 AT > FLASH_BANK_1

    _sidata = LOADADDR(.data);

    .bss :
    {
        _sbss = .;
        *(.bss*)
        *(COMMON)
        _ebss = .;
    } > SRAM_0
}

/* Guard: .bss (includes FreeRTOS 32KB heap) must not collide with MSP stack */
ASSERT(_ebss < _host_sstack, "ERROR: BSS/heap overlaps MSP stack region!");

/* NSC veneer addresses — same as bare_metal_arm */
PROVIDE(umbra_tee_create = 0x0803c001);
PROVIDE(umbra_debug_print = 0x0803c011);
PROVIDE(umbra_enclave_enter = 0x0803c021);
PROVIDE(umbra_enclave_exit = 0x0803c031);
PROVIDE(umbra_enclave_status = 0x0803c041);
