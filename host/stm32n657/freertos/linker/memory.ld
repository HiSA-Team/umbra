/*
 * Memory regions for STM32N657 — FreeRTOS NS host demo.
 *
 * Host runs from AXISRAM1 NS alias (0x24000000). Upper 128 KB of AXISRAM1
 * (0x340E0000-0x340FFFFF) is reserved for the Secure ESS / EFBC region
 * — host length capped at 0xE0000 (896 KB) to match the bare-metal N657
 * host layout and the Secure linker's RISAF2 region carve-out.
 *
 * NSC veneers are PROVIDEd by host.ld at 0x341AB400 (Secure address; the
 * SAU configures this range as NSC so SG instructions work from NS).
 *
 * Vector table lives at 0x24000000; Reset_Handler at offset 0x100
 * (=_host_entry_point=0x24000100). The Secure FSBL sets VTOR_NS to
 * 0x24000000 before BLXNS to the host.
 */

MEMORY
{
    AXISRAM3_NS (RWX) : ORIGIN = 0x24000000, LENGTH = 0xE0000
}

_host_entry_point = 0x24000100;
