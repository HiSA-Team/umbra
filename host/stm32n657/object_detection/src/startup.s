/*
 * FreeRTOS NS host startup for STM32N657 Cortex-M55.
 *
 * Boot flow:
 *   FSBL (Secure) → trampoline_to_ns → BLXNS to _host_Reset_Handler @ 0x24000100
 *   Reset_Handler → copy .data, zero .bss → call main → vTaskStartScheduler
 *
 * Vector table lives at 0x24000000 (AXISRAM1 NS view base). Per host.ld,
 * the table is padded to 0x100 so Reset_Handler lands at 0x24000100
 * (= _host_entry_point). FreeRTOS-V11 ARM_CM33_NTZ port hooks into the
 * SVC / PendSV / SysTick vector entries.
 *
 * Cortex-M55, NS state, ARMv8.1-M Mainline (no Helium used here).
 */

    .syntax unified
    /* .cpu controlled by Makefile -mcpu flag (cortex-m33 is a strict
     * subset of M55 for non-Helium ARMv8-M Main code, matches the
     * bare-metal N657 host build.) */
    .thumb

    /* ── Vector table ─────────────────────────────────────────────
     * Placed in `.isr_vector` by host.ld at the base of AXISRAM3_NS
     * (= 0x24000000). The linker pads to 0x100 so the
     * `.text._host_Reset_Handler` section that follows lands at
     * _host_entry_point = 0x24000100.
     *
     * SVC / PendSV / SysTick are wired to FreeRTOS handler aliases
     * (SVC_Handler / PendSV_Handler / SysTick_Handler — see
     * FreeRTOSConfig.h vPortSVCHandler / xPortPendSVHandler /
     * xPortSysTickHandler defines). The other system vectors trap
     * to _host_Default_Handler defined in handlers.c.
     */
    .section .isr_vector, "a"
    .align 2
    .global _host_vector_table
_host_vector_table:
    .word   _host_estack             /* 0x00: MSP initial value */
    .word   _host_Reset_Handler      /* 0x04: Reset */
    .word   _host_NMI_Handler        /* 0x08: NMI */
    .word   _host_HardFault_Handler  /* 0x0C: HardFault */
    .word   _host_MemManage_Handler  /* 0x10: MemManage */
    .word   _host_BusFault_Handler   /* 0x14: BusFault */
    .word   _host_UsageFault_Handler /* 0x18: UsageFault */
    .word   0                        /* 0x1C: SecureFault (NS=0) */
    .word   0                        /* 0x20: Reserved */
    .word   0                        /* 0x24: Reserved */
    .word   0                        /* 0x28: Reserved */
    .word   SVC_Handler              /* 0x2C: SVC (FreeRTOS) */
    .word   _host_DebugMon_Handler   /* 0x30: DebugMon */
    .word   0                        /* 0x34: Reserved */
    .word   PendSV_Handler           /* 0x38: PendSV (FreeRTOS) */
    .word   SysTick_Handler          /* 0x3C: SysTick (FreeRTOS tick) */

    /* ── External (peripheral) IRQs 0..57 ─────────────────────────────
     * G.1.b.3: stai_network_run() expects the NPU's "epoch done"
     * interrupt at NPU0_IRQn (53) to fire and unblock the SYNC poll.
     * The runtime's NPU0_IRQHandler is a strong symbol from
     * ll_aton_runtime.c (ATON_STD_IRQHandler → CDNN0_IRQHandler →
     * NPU0_IRQHandler via platform.h macros); the linker resolves
     * the weak default below to it.
     *
     * Slots 0-52 + 54-57 are weak-defaulted to _host_Default_Handler
     * (an infinite loop) — if any of those IRQs fire unexpectedly,
     * the system halts cleanly.
     */
    .rept 53
    .word   _host_Default_Handler   /* IRQs 0-52 (default) */
    .endr
    .word   NPU0_IRQHandler         /* IRQ 53 — ATON_STD (NPU done) */
    .word   NPU1_IRQHandler         /* IRQ 54 */
    .word   NPU2_IRQHandler         /* IRQ 55 */
    .word   NPU3_IRQHandler         /* IRQ 56 */
    .word   CACHEAXI_IRQHandler     /* IRQ 57 */

    /* Weak defaults — override with a strong definition if needed.
     *
     * G.2.b (enclave-driven inference): the NPU runs entirely on the Secure
     * side inside the Umbra enclave.  It never delivers IRQs to NS, so
     * NPU0_IRQHandler is "should never fire in NS" and the weak default to
     * _host_Default_Handler (infinite loop / fault) is the correct sentinel.
     * The stale G.1.b.3 note about leaving NPU0 undefined so the Cube-AI
     * runtime's strong def wins is no longer applicable — Cube-AI is gone. */
    .weak   NPU0_IRQHandler
    .thumb_set NPU0_IRQHandler, _host_Default_Handler
    .weak   NPU1_IRQHandler
    .thumb_set NPU1_IRQHandler, _host_Default_Handler
    .weak   NPU2_IRQHandler
    .thumb_set NPU2_IRQHandler, _host_Default_Handler
    .weak   NPU3_IRQHandler
    .thumb_set NPU3_IRQHandler, _host_Default_Handler
    .weak   CACHEAXI_IRQHandler
    .thumb_set CACHEAXI_IRQHandler, _host_Default_Handler

    /* ── Reset Handler at offset 0x100 = _host_entry_point ──────── */
    .section .text._host_Reset_Handler, "ax"
    .align 2
    .thumb_func
    .global _host_Reset_Handler
_host_Reset_Handler:
    /* Copy .data from LMA to VMA. On N657 LMA == VMA (both in
     * AXISRAM1 NS), so this is a no-op. Kept for portability. */
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

    /* Zero .bss */
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

    /* Call main(); should never return — vTaskStartScheduler() runs forever. */
    bl main
    b .
