/*
 * Sections layout for FreeRTOS NS host + inference enclave on STM32N657.
 *
 * All code/data lives in AXISRAM3_NS (= AXISRAM1 NS alias, base 0x24000000).
 * Vector table at AXISRAM3_NS base (0x24000000); Reset_Handler at offset
 * 0x100 (=_host_entry_point=0x24000100). The Secure FSBL sets VTOR_NS to
 * 0x24000000 and BLXNS to _host_entry_point.
 *
 * FreeRTOS allocates per-task stacks from heap_4 in .bss; MSP stack
 * (host_stack_size below) is ISR-only.
 *
 * Enclave sections (._enclave_header at 0x24010000, ._enclave_code right
 * after) are pinned by absolute address so they map to the same flash
 * offset (0x70090000 = 0x70080000 + 0x10000) the Secure FSBL reads when
 * enclave_create() is called with `_enclave_start` (computed in main.c).
 *
 * M1.2: enclave sections restored (._enclave_header + ._enclave_code),
 * mirroring host/freertos_n657/linker/host.ld. protect_enclave.py patches
 * the chained-measurement HMAC into ._enclave_header post-link.
 *
 * M2.1: .input_shared (0x24080000) and .output_shared (0x240C0000) added
 * as NOLOAD regions backed by separate MEMORY entries — the inference
 * enclave will access them via dedicated MPU regions (M2.2).
 */

ENTRY(_host_Reset_Handler)

_host_stack_size = 0x1000;
_host_estack = ORIGIN(AXISRAM3_NS) + LENGTH(AXISRAM3_NS) - 0x4;
_host_sstack = _host_estack - _host_stack_size;

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

    /* Enclave region — pinned at 0x24010000 (offset 0x10000 from
     * AXISRAM3_NS base). When the bin is flashed at XSPI2 0x70080000,
     * the enclave header lands at 0x70090000 — outside MCE2 region 1
     * (currently disabled, MCE2 in passthrough), so the FSBL reads
     * plaintext directly via memory-mapped XSPI2.
     *
     * `_enclave_start` is exported so the host can compute the flash
     * address: HOST_FLASH_BASE + (_enclave_start - HOST_RAM_BASE).
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
        /* Entry function placed first so its address coincides with the
         * enclave entry point. Mirrors the bare_metal_n657 and
         * freertos_n657 host.ld pattern. */
        KEEP(*(.app.enclave_code.entry))
        KEEP(*(.app.enclave_code))
        KEEP(*(.app.*))
        . = _enclave_code_start + 0x400;  /* Reserve 1024 bytes for code */
    } > AXISRAM3_NS

    /* Test image (224×224×3 = 150528 bytes from a COCO val2017 sample)
     * lives AFTER the enclave region so it doesn't push .text past the
     * enclave header's hard-pinned VMA at 0x24010000. Anything tagged
     * with __attribute__((section(".test_image_data"))) lands here.
     * Note the section name DOES NOT start with ".rodata" — otherwise
     * .text's `*(.rodata*)` wildcard absorbs it first. */
    .test_image :
    {
        . = ALIGN(4);
        KEEP(*(.test_image_data*))
        . = ALIGN(4);
    } > AXISRAM3_NS

    /* G.2.b shared-memory regions — NOLOAD so they don't get initialised
     * from .data, just reserved as RAM ranges the host (NS) and the
     * inference enclave (Secure unprivileged via MPU R6/R7) both touch.
     * Backed by the INPUT_SHARED / OUTPUT_SHARED MEMORY regions in
     * memory.ld. */
    .input_shared (NOLOAD) :
    {
        . = ALIGN(16);
        _input_shared_start = .;
        . += LENGTH(INPUT_SHARED);
        _input_shared_end = .;
    } > INPUT_SHARED

    .output_shared (NOLOAD) :
    {
        . = ALIGN(16);
        _output_shared_start = .;
        . += LENGTH(OUTPUT_SHARED);
        _output_shared_end = .;
    } > OUTPUT_SHARED
}

/* Guard: .bss (includes FreeRTOS 32 KB heap) must not collide with MSP stack */
ASSERT(_ebss < _host_sstack, "ERROR: BSS/heap overlaps MSP stack region!");

/* NSC veneer addresses — must match the Secure linker's NSC region on N657
 * (0x341AB400 after the +0x400 signing-header shift). +1 is the Thumb bit
 * required for BLXNS to jump to Thumb code. */
PROVIDE(umbra_enclave_create     = 0x341AB401);
PROVIDE(umbra_debug_print    = 0x341AB411);
PROVIDE(umbra_enclave_enter  = 0x341AB421);
PROVIDE(umbra_enclave_exit   = 0x341AB431);
PROVIDE(umbra_enclave_status = 0x341AB441);
