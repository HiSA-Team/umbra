/*********************************************************************************************************
*
*   Author: Stefano Mercogliano <stefano.mercogliano@unina.it>
*   Notes:
*       TBD
*   
**********************************************************************************************************/

/************************
*   Host Memory Blocks  *
*************************/

MEMORY
{
    FLASH_BANK_0         (RXAL)  : ORIGIN = 0x08000000,                                      LENGTH = 256K,
    FLASH_BANK_1         (RX)    : ORIGIN = ORIGIN(FLASH_BANK_0) + LENGTH(FLASH_BANK_0),     LENGTH = 256K,
    SRAM_0               (RWX)   : ORIGIN = 0x20000000,                                      LENGTH = 192K,
    SRAM_1               (RWX)   : ORIGIN = ORIGIN(SRAM_0) + LENGTH(SRAM_0),                 LENGTH = 64K
}

_host_entry_point = 0x08040100;

/**********************************
*   Umbra Memory Block Aliases    *
***********************************/

/* 
    Aliases must be defined here to let umbra know where its code will be placed.
    Both Umbra Kernel and Secure Boot expects the following sections:
        - _SECURE_BOOT_TEXT_MEMORY_
        - _SECURE_KERNEL_TEXT_MEMORY_
        - _SECURE_KERNEL_DATA_MEMORY_
        - _NSC_TEXT_MEMORY_
        - _NSC_DATA_MEMORY_
*/


MEMORY
{
    _SECURE_BOOT_TEXT_MEMORY_   (RXAL)   : ORIGIN = ORIGIN(FLASH_BANK_0),                                                       LENGTH = 64K,
    _SECURE_KERNEL_TEXT_MEMORY_ (RXAL)   : ORIGIN = ORIGIN(_SECURE_BOOT_TEXT_MEMORY_) + LENGTH(_SECURE_BOOT_TEXT_MEMORY_),      LENGTH = 176K,
    _NSC_TEXT_MEMORY_           (RXAL)   : ORIGIN = ORIGIN(_SECURE_KERNEL_TEXT_MEMORY_) + LENGTH(_SECURE_KERNEL_TEXT_MEMORY_),  LENGTH = 16K,
    _SECURE_KERNEL_DATA_MEMORY_ (RWX)    : ORIGIN = ORIGIN(SRAM_1),                                                             LENGTH = 56K,
    _NSC_DATA_MEMORY_           (RWX)    : ORIGIN = ORIGIN(_SECURE_KERNEL_DATA_MEMORY_) + LENGTH(_SECURE_KERNEL_DATA_MEMORY_),  LENGTH = 8K
}

