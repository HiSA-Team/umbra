/*********************************************************************************************************
*
*   Author: Stefano Mercogliano <stefano.mercogliano@unina.it>
*   Notes:
*       This host example file defines memory blocks and host data structures and sections.
*       In general, this linker script is assumed to be a vanilla one, that originally did not include Umbra.
*       A minor modification is required to define memory region block aliases that umbra linkers will use.
*   
**********************************************************************************************************/

/*******************
*   Host Sections  *
********************/

ENTRY(_host_Reset_Handler)

_host_stack_size = 0x1000;
_host_estack = ORIGIN(SRAM_0) + LENGTH(SRAM_0) - 0x4;
_host_sstack = _host_estack - _host_stack_size;

_host_app_address = ORIGIN(FLASH_BANK_1) + LENGTH(FLASH_BANK_1) - 0x8000;

/* Sections */
SECTIONS
{
    ._host_vector_table : 
    {
        . += 0x20;
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

    /* Let's use a region for host application */
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
        . = _enclave_code_start + 0x400; /* Reserve 1024 bytes */
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



/* Provide addresses for Secure Gateway (NSC) veneers in the Secure Boot binary */
/* These are the SG entry points in _NSC_TEXT_MEMORY_, not the _imp implementations */
/* Addresses from 'nm boot | grep umbra_' after building secureboot */
/* TODO: Update these addresses after each secure rebuild, or use import lib mechanism */
PROVIDE(umbra_tee_create = 0x0803c001);     /* Thumb mode address of umbra_tee_create veneer */
PROVIDE(umbra_debug_print = 0x0803c011);    /* Thumb mode address of umbra_debug_print veneer */
PROVIDE(umbra_enclave_enter = 0x0803c021);  /* Thumb mode address of umbra_enclave_enter veneer */
PROVIDE(umbra_enclave_exit = 0x0803c031);   /* Thumb mode address of umbra_enclave_exit veneer */
PROVIDE(umbra_enclave_status = 0x0803c041); /* Thumb mode address of umbra_enclave_status veneer */
