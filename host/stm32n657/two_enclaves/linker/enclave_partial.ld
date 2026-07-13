/*
 * Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>
 *
 * Partial-link (ld -r) script for the vendored TACLeBench "ndes" (DES)
 * enclave on STM32N657.
 *
 * Invoked as:
 *     arm-none-eabi-ld -r --gc-sections -e enclave_entry \
 *         -T linker/enclave_partial.ld -o obj/enclave_combined.o <ndes objs>
 *
 * Purpose: take the per-function/per-data input sections that
 * -ffunction-sections/-fdata-sections produced (.text.<fn>, .rodata.<x>,
 * .bss.<var>, …) and (a) --gc-sections away everything the entry wrapper
 * can't reach, then (b) fold the survivors into exactly two output sections:
 *
 *   .app.enclave_code  — entry first, then all reachable code + rodata + data.
 *                        This is the in-image, measured/encrypted region.
 *   .app.enclave_bss   — ndes's writable globals (ndes_bit[], ndes_inp/key/out,
 *                        ndes_icd, ndes_ipc1/2, the ndes_des() function-local
 *                        statics kns[]/initflag, etc.). NOLOAD here; the host
 *                        link (linker/sections.ld) folds it contiguously INSIDE
 *                        ._enclave_code, before _enclave_code_end, so it is
 *                        text-relative-addressable and covered by the kernel's
 *                        ESS allocation.
 *
 * The single merged section names are what objcopy --rename-section could not
 * produce (it renames only the exact ".text", not the ".text.<fn>" that
 * -ffunction-sections emits), which is why the fold lives here.
 *
 * enclave_entry must be the first byte of .app.enclave_code so it coincides
 * with the enclave entry point (the kernel sets PSP-frame PC = ess_addr + 0).
 */
ENTRY(enclave_entry)

SECTIONS
{
    .app.enclave_code :
    {
        KEEP(*(.app.enclave_code.entry))
        *(.text*)
        *(.rodata*)
        *(.data*)
        *(.data.rel.ro*)
    }

    .app.enclave_bss (NOLOAD) :
    {
        *(.bss*)
        *(COMMON)
    }

    /* ld -r keeps most metadata sections by default; drop the ones that would
     * otherwise ride along into the host link. Debug info is retained (it is
     * dropped later by objcopy -O binary). */
    /DISCARD/ :
    {
        *(.ARM.exidx*)
        *(.ARM.extab*)
        *(.ARM.attributes)
        *(.comment)
        *(.note.*)
    }
}
