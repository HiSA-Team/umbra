/*********************************************************************************************************
*
*   Author: Stefano Mercogliano <stefano.mercogliano@unina.it>
*   Notes:
*       Secure Flash and Non Secure Flash can be statically defined on stm32lxxx-based boards.
*       Currently, we assume the first bank on stm32l552 to be secure, and the second to be non-secure.
*       Watermatking could also be included in the bootloader, or statically defined at a finer level
*       Than bank (e.g. pages). 
*
**********************************************************************************************************/

_umb_stack_size = 0x6000;
_umb_estack = 0x2003DFFC;

/* Define the sections */
SECTIONS
{

    /********************
    * Secure Boot Area  *
    *********************/
    /* 
    *  Umbra first part of code contains the vector tables and the handlers
    */
    ._umb_vector_table :
    {
        KEEP(*(._umb_vectors))
    } > _SECURE_BOOT_TEXT_MEMORY_

    ._umb_handlers :
    {
        KEEP(*(._umb_handlers))
    } > _SECURE_BOOT_TEXT_MEMORY_

    /* .text section in FLASH, with .start input section */
    ._umb_startup :
    {
        KEEP(*(.text._umb_start));  /* Ensure .start section is kept in .text */
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

    .data :
    {
        . = ALIGN(4);
        _sdata = .;
        *(.data*)
        . = ALIGN(4);
        _edata = .;
    } > _SECURE_KERNEL_DATA_MEMORY_ AT > _SECURE_BOOT_TEXT_MEMORY_
    
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
