///////////////////////////////////////////////////////////////////////
// FreeRTOS NS host startup for STM32L552 Cortex-M33
// Only Reset_Handler lives here (needs .data/.bss init in assembly).
// Vector table is in vectors.c, fault handlers in handlers.c.
///////////////////////////////////////////////////////////////////////

    .global _host_Reset_Handler
    .extern _host_estack
    .extern _sdata
    .extern _edata
    .extern _sidata
    .extern _sbss
    .extern _ebss

    .thumb
    .syntax unified
    .section ._host_handlers, "ax"

    .type _host_Reset_Handler, %function
    .thumb_func
    _host_Reset_Handler:
        ldr sp, =_host_estack

        // Copy .data from Flash to RAM
        ldr r0, =_sdata
        ldr r1, =_edata
        ldr r2, =_sidata
        movs r3, #0
        b 2f
    1:
        ldr r4, [r2, r3]
        str r4, [r0, r3]
        adds r3, r3, #4
    2:
        add r4, r0, r3
        cmp r4, r1
        bcc 1b

        // Zero .bss
        ldr r0, =_sbss
        ldr r1, =_ebss
        movs r2, #0
        b 4f
    3:
        str r2, [r0]
        adds r0, r0, #4
    4:
        cmp r0, r1
        bcc 3b

        bl main
        b .
