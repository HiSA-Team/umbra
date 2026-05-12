/*********************************************************************************************************
*
*   STM32N657X0 memory map for Umbra
*
*   No internal flash — Umbra runs as FSBL from AXISRAM (copied by Boot ROM from XSPI2).
*
*   SIGNING HEADER OFFSET: Boot ROM copies the ENTIRE signed image (header + payload)
*   to AXISRAM2. The STM32_SigningTool header is 0x400 (1024) bytes. The actual FSBL
*   binary starts at 0x34180400, NOT 0x34180000. All linker origins must account for this.
*
*   Enclaves live in AXISRAM1 (ESS). Host runs from AXISRAM3 (NS).
*
*   IDAU aliasing: Secure = odd top nibble (0x3x), NS = even (0x2x).
*   Alias offset: +0x10000000.
*
*   For GDB debug: load ELF directly (addresses already at +0x400 offset).
*   For FSBL boot: Boot ROM copies signed image to 0x34180000, binary at +0x400.
*
**********************************************************************************************************/

/* Signing header size (STM32_SigningTool_CLI) */
_signing_header_size = 0x400;

/************************
*   Physical Regions    *
*************************/

MEMORY
{
    AXISRAM1_S     (RWX)  : ORIGIN = 0x34000000, LENGTH = 1M
    AXISRAM2_S     (RXAL) : ORIGIN = 0x34180000 + 0x400, LENGTH = 512K - 0x400
    /* Host runs from AXISRAM1 NS alias (0x24000000) — AXISRAM3 (0x24200000)
     * is power-gated and RAMCFG is RIFSC-blocked from FSBL, so we use AXISRAM1
     * which is always powered by Boot ROM (RCC_MEMENR.AXISRAM1EN=1 default).
     *
     * Length capped at 0xE0000 (896 KB): the upper 128 KB of AXISRAM1 view
     * (0x340E0000–0x340FFFFF) is reserved for the Secure ESS / EFBC / PSP
     * regions (kernel constants in src/kernel/src/common/ess.rs under
     * feature platform-n657). RISAF2 region 1 ends at 0x340DFFFF so default
     * region 0 (Secure+CID=1+priv) governs the carved-out Secure portion. */
    AXISRAM3_NS    (RWX)  : ORIGIN = 0x24000000, LENGTH = 0xE0000
}

/* Host entry point in AXISRAM1 (NS view) */
_host_entry_point = 0x24000100;

/**********************************
*   Umbra Memory Block Aliases    *
***********************************/

/*
    Umbra sections in AXISRAM2 Secure (after 0x400 signing header):
      - _SECURE_BOOT_TEXT_MEMORY_    : 68 KB  (0x34180400) — boot .text + .rodata
      - _SECURE_KERNEL_TEXT_MEMORY_  : 104 KB (0x34191400) — kernel API implementations
      - _NSC_TEXT_MEMORY_            : 4 KB   (0x341AB400) — NSC veneers (SAU-configured)
      - _SECURE_KERNEL_DATA_MEMORY_  : 128 KB (0x341AC400) — .data + .bss + stack
      - _NSC_DATA_MEMORY_            : 8 KB   (0x341CC400)
*/

MEMORY
{
    _SECURE_BOOT_TEXT_MEMORY_     (RXAL) : ORIGIN = ORIGIN(AXISRAM2_S),           LENGTH = 68K
    _SECURE_KERNEL_TEXT_MEMORY_   (RXAL) : ORIGIN = 0x34191400,                   LENGTH = 104K
    _NSC_TEXT_MEMORY_             (RXAL) : ORIGIN = 0x341AB400,                   LENGTH = 4K
    _SECURE_KERNEL_DATA_MEMORY_  (RWX)  : ORIGIN = 0x341AC400,                   LENGTH = 128K
    _NSC_DATA_MEMORY_            (RWX)  : ORIGIN = 0x341CC400,                   LENGTH = 8K
}

/* Contiguity assertions */
ASSERT(ORIGIN(_SECURE_BOOT_TEXT_MEMORY_) + LENGTH(_SECURE_BOOT_TEXT_MEMORY_) == ORIGIN(_SECURE_KERNEL_TEXT_MEMORY_), "ERROR: SECURE_BOOT and SECURE_KERNEL text regions are not contiguous!");
ASSERT(ORIGIN(_SECURE_KERNEL_TEXT_MEMORY_) + LENGTH(_SECURE_KERNEL_TEXT_MEMORY_) == ORIGIN(_NSC_TEXT_MEMORY_), "ERROR: SECURE_KERNEL and NSC text regions are not contiguous!");
ASSERT(ORIGIN(_NSC_TEXT_MEMORY_) + LENGTH(_NSC_TEXT_MEMORY_) == ORIGIN(_SECURE_KERNEL_DATA_MEMORY_), "ERROR: NSC_TEXT and SECURE_KERNEL_DATA regions are not contiguous!");
ASSERT(ORIGIN(_SECURE_KERNEL_DATA_MEMORY_) + LENGTH(_SECURE_KERNEL_DATA_MEMORY_) == ORIGIN(_NSC_DATA_MEMORY_), "ERROR: SECURE_KERNEL_DATA and NSC_DATA regions are not contiguous!");

/* ── Phase E.4c MCE2 encryption: configurable region size ────────────────
 * Default: 4 MB. Override via --defsym from the Makefile.
 * Three canonical layouts (must update BOTH ENCLAVE_REGION_SIZE and
 * ENCLAVE_DST_START together):
 *   4 MB:  size=0x400000   dst=0x70500000
 *   16 MB: size=0x1000000  dst=0x71100000
 *   24 MB: size=0x1800000  dst=0x71900000
 */
ENCLAVE_REGION_SIZE = DEFINED(ENCLAVE_REGION_SIZE) ? ENCLAVE_REGION_SIZE : 0x400000;
ENCLAVE_DST_START   = DEFINED(ENCLAVE_DST_START)   ? ENCLAVE_DST_START   : 0x70500000;
ENCLAVE_PLAINTEXT_FLASH = 0x70090000;

ASSERT(ENCLAVE_PLAINTEXT_FLASH + ENCLAVE_REGION_SIZE + 0x10000 <= ENCLAVE_DST_START,
       "ENCLAVE_DST_START too low - overlaps plaintext source range");
ASSERT(ENCLAVE_DST_START + ENCLAVE_REGION_SIZE <= 0x74000000,
       "Encrypted region overflows 64 MB XSPI2 flash");
