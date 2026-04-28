/*
 * Memory regions for STM32L552 — FreeRTOS NS host demo.
 * Self-contained copy (no dependency on bare_metal_arm/).
 */

MEMORY
{
    FLASH_BANK_0         (RXAL)  : ORIGIN = 0x08000000,                                      LENGTH = 256K,
    FLASH_BANK_1         (RX)    : ORIGIN = ORIGIN(FLASH_BANK_0) + LENGTH(FLASH_BANK_0),     LENGTH = 256K,
    SRAM_0               (RWX)   : ORIGIN = 0x20000000,                                      LENGTH = 128K,
    SRAM_1               (RWX)   : ORIGIN = ORIGIN(SRAM_0) + LENGTH(SRAM_0),                 LENGTH = 64K
}

_host_entry_point = 0x08040100;

/* Umbra Memory Block Aliases */
MEMORY
{
    _SECURE_BOOT_TEXT_MEMORY_   (RXAL)   : ORIGIN = ORIGIN(FLASH_BANK_0),                                                       LENGTH = 68K,
    _SECURE_KERNEL_TEXT_MEMORY_ (RXAL)   : ORIGIN = ORIGIN(_SECURE_BOOT_TEXT_MEMORY_) + LENGTH(_SECURE_BOOT_TEXT_MEMORY_),      LENGTH = 172K,
    _NSC_TEXT_MEMORY_           (RXAL)   : ORIGIN = ORIGIN(_SECURE_KERNEL_TEXT_MEMORY_) + LENGTH(_SECURE_KERNEL_TEXT_MEMORY_),  LENGTH = 16K,
    _SECURE_KERNEL_DATA_MEMORY_ (RWX)    : ORIGIN = 0x30030000,                                                                 LENGTH = 56K,
    _NSC_DATA_MEMORY_           (RWX)    : ORIGIN = ORIGIN(_SECURE_KERNEL_DATA_MEMORY_) + LENGTH(_SECURE_KERNEL_DATA_MEMORY_),  LENGTH = 8K
}

ASSERT(ORIGIN(_SECURE_BOOT_TEXT_MEMORY_) + LENGTH(_SECURE_BOOT_TEXT_MEMORY_) == ORIGIN(_SECURE_KERNEL_TEXT_MEMORY_), "ERROR: SECURE_BOOT and SECURE_KERNEL regions are not contiguous!");
ASSERT(ORIGIN(_SECURE_KERNEL_TEXT_MEMORY_) + LENGTH(_SECURE_KERNEL_TEXT_MEMORY_) == ORIGIN(_NSC_TEXT_MEMORY_),     "ERROR: SECURE_KERNEL and NSC regions are not contiguous!");
ASSERT(ORIGIN(_NSC_TEXT_MEMORY_) + LENGTH(_NSC_TEXT_MEMORY_) <= ORIGIN(FLASH_BANK_1),                              "ERROR: Secure Flash Regions overlap with Host Flash (FLASH_BANK_1)!");
ASSERT(ORIGIN(_SECURE_KERNEL_DATA_MEMORY_) + LENGTH(_SECURE_KERNEL_DATA_MEMORY_) == ORIGIN(_NSC_DATA_MEMORY_),     "ERROR: SECURE_KERNEL_DATA and NSC_DATA regions are not contiguous!");
ASSERT(LENGTH(_SECURE_KERNEL_DATA_MEMORY_) + LENGTH(_NSC_DATA_MEMORY_) <= 64K,                                     "ERROR: Secure Data Regions exceed SRAM_1 size (64K)!");
