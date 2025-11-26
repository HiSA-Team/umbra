/*********************************************************************************************************
*
*   Author: Stefano Mercogliano <stefano.mercogliano@unina.it>
*   Notes:
*       This host example file defines memory blocks and host data structures and sections.
*       In general, this linker script is assumed to be a vanilla one, that originally did not include Umbra.
*       A minor modification is required to define memory region block aliases that umbra linkers will use.
*   
**********************************************************************************************************/

/* Including memory blocks definitions */
INCLUDE /Users/salvatorebramante/Downloads/test_L552_NUCLEO/oldest/umbra/host/bare_metal_arm/linker/memory.ld
INCLUDE /Users/salvatorebramante/Downloads/test_L552_NUCLEO/oldest/umbra/linker/umbra.ld

/*******************
*   Host Sections  *
********************/

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
    ._host_app _host_app_address : 
    {
        KEEP(*(.app.*))
    } > FLASH_BANK_1

}

