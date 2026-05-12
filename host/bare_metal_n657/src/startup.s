/*
 * STM32N657 NS host startup — vector table in AXISRAM3 + C runtime init.
 *
 * Boot flow:
 *   FSBL (Secure) → trampoline_to_ns → BLXNS to _host_Reset_Handler @ 0x24200100
 *   Reset_Handler → copy .data, zero .bss → call main
 *
 * Vector table lives at 0x24200000 (AXISRAM3 base). Per linker script,
 * Reset_Handler is at 0x24200000 + 0x100 = 0x24200100 (NS host entry point).
 *
 * Cortex-M55, NS state, ARMv8.1-M Mainline.
 */

    .syntax unified
    /* .cpu controlled by Makefile -mcpu flag.
     * M55 is a strict superset of M33 for Thumb-2+TrustZone, so we use
     * cortex-m33 (no MVE/Helium instructions in this file). */
    .thumb

    /* Vector table — placed in .isr_vector by sections.ld at AXISRAM3 base.
     * Aligned to 0x100 so the table itself starts at 0x24200000 and the
     * Reset_Handler entry sits at offset 0x04, but main.rs trampoline
     * jumps to 0x24200100 = symbol _host_entry_point in linker (the
     * actual Reset_Handler code address is what matters for BLXNS).
     */
    .section .isr_vector, "a"
    .align 2
    .global _host_vector_table
_host_vector_table:
    .word   _host_estack            /* 0x00: MSP initial value */
    .word   _host_Reset_Handler     /* 0x04: Reset */
    .word   _host_Default_Handler   /* 0x08: NMI */
    .word   _host_Default_Handler   /* 0x0C: HardFault */
    .word   _host_Default_Handler   /* 0x10: MemManage */
    .word   _host_Default_Handler   /* 0x14: BusFault */
    .word   _host_Default_Handler   /* 0x18: UsageFault */
    .word   0                       /* 0x1C: Reserved (SecureFault on ARMv8-M, NS=0) */
    .word   0                       /* 0x20: Reserved */
    .word   0                       /* 0x24: Reserved */
    .word   0                       /* 0x28: Reserved */
    .word   _host_Default_Handler   /* 0x2C: SVC */
    .word   _host_Default_Handler   /* 0x30: DebugMon */
    .word   0                       /* 0x34: Reserved */
    .word   _host_Default_Handler   /* 0x38: PendSV */
    .word   _host_Default_Handler   /* 0x3C: SysTick */

    /* Reset Handler at offset 0x100 = _host_entry_point.
     * The trampoline does BLXNS to this address; the linker places this
     * code immediately after the vector table padded to 0x100.
     */
    .section .text._host_Reset_Handler, "ax"
    .align 2
    .thumb_func
    .global _host_Reset_Handler
_host_Reset_Handler:
    /* Copy .data from LMA (load addr) to VMA (run addr).
     * On N657 host, both are in AXISRAM3 (no flash), so this is a no-op.
     * Kept for portability with the bare_metal_arm L5 host.
     */
    ldr r0, =_sdata
    ldr r1, =_edata
    ldr r2, =_sidata
1:  cmp r0, r1
    bge 2f
    ldr r3, [r2], #4
    str r3, [r0], #4
    b 1b

    /* Zero .bss */
2:  ldr r0, =_sbss
    ldr r1, =_ebss
    movs r2, #0
3:  cmp r0, r1
    bge 4f
    str r2, [r0], #4
    b 3b

    /* Call main(); should never return. */
4:  bl main
    b .

    /* Default handler: trap any unhandled exception. */
    .thumb_func
    .global _host_Default_Handler
_host_Default_Handler:
    b .
