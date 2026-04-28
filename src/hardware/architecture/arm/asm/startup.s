//////////////////////////////////////////////////////////////////////
//                                                                  //
// Author: Stefano Mercogliano <stefano.mercogliano@unina.it>       //
//         Salvatore Bramante <salvatore.bramante@imtlucca.it>      //
//                                                                  //
// Description:                                                     //
//      ARM startup assembly: vector table, exception/fault         //
//      handlers, save_enclave_context, and C-runtime init          //
//      (_umb_start). Extracted from startup.rs global_asm! block.  //
//                                                                  //
//////////////////////////////////////////////////////////////////////

    .syntax unified
    .cpu cortex-m33
    .thumb

    .global _umb_start              // Define the entry point
    .global _umb_Reset_Handler      // Main reset handler
    .global _umb_Default_Handler    // Default handler for undefined interrupts
    .global save_enclave_context
    .extern _umb_estack

    // Symbols defined in linker script
    .extern _sdata
    .extern _edata
    .extern _sidata
    .extern _sbss
    .extern _ebss
    .extern DMA1_Channel1_Handler
    .extern DMA1_Channel2_Handler
    .extern DMA1_Channel3_Handler
    .extern DMA1_Channel4_Handler
    .extern DMA1_Channel5_Handler
    .extern DMA1_Channel6_Handler
    .extern DMA1_Channel7_Handler
    .extern DMA1_Channel8_Handler
    .extern umbra_yield_handler

    // Vector Table - must be at the beginning of the Flash
    // The reason for it is that ARM first initialized its stack and then jumps
    // to the reset handler
    .section ._umb_vectors, "a"    // Marked as 'a' for allocation in memory

        // Handler entries must have bit 0 set to select Thumb state on
        // exception entry. Labels inside global_asm! aren't implicitly
        // .thumb_func, so we OR `+1` into every vector word. Without this,
        // exception entry lands in ARM mode → UsageFault.INVSTATE and the
        // fault cascades through HardFault escalation.
        .word _umb_estack+0x10000000               // Initial stack pointer
        .word _umb_Reset_Handler+0x04000001        // Reset (bit 0 Thumb, bit 26 for secure-reset semantics)
        .word _umb_NMI_Handler+1        // Non-maskable interrupt handler
        .word _umb_HardFault_Handler+1  // Hard Fault handler
        .word _umb_MemManage_Handler+1  // Memory Management fault handler
        .word _umb_BusFault_Handler+1   // Bus Fault handler
        .word _umb_UsageFault_Handler+1 // Usage Fault handler
        .word _umb_SecureFault_Handler+1// SecureFault handler (Armv8-M, offset 0x1C)
        .word 0                         // Reserved
        .word 0                         // Reserved
        .word 0                         // Reserved
        .word _umb_SVC_Handler+1        // SVCall handler
        .word _umb_DebugMon_Handler+1   // Debug Monitor handler
        .word 0                         // Reserved
        .word _umb_PendSV_Handler+1     // PendSV handler
        .word _umb_SysTick_Handler+1    // SysTick handler

    // External Interrupts
    // TODO: Assign handlers for external interrupts
        .word _umb_Default_Handler      // IRQ0:  WWDG
        .word _umb_Default_Handler      // IRQ1:  PVD_PVM
        .word _umb_Default_Handler      // IRQ2:  RTC
        .word _umb_Default_Handler      // IRQ3:  RTC_S
        .word _umb_Default_Handler      // IRQ4:  TAMP
        .word _umb_Default_Handler      // IRQ5:  TAMP_S
        .word _umb_Default_Handler      // IRQ6:  FLASH
        .word _umb_Default_Handler      // IRQ7:  FLASH_S
        .word _umb_Default_Handler      // IRQ8:  GTZC
        .word _umb_Default_Handler      // IRQ9:  RCC
        .word _umb_Default_Handler      // IRQ10: RCC_S
        .word _umb_Default_Handler      // IRQ11: EXTI0
        .word _umb_Default_Handler      // IRQ12: EXTI1
        .word _umb_Default_Handler      // IRQ13: EXTI2
        .word _umb_Default_Handler      // IRQ14: EXTI3
        .word _umb_Default_Handler      // IRQ15: EXTI4
        .word _umb_Default_Handler      // IRQ16: EXTI5
        .word _umb_Default_Handler      // IRQ17: EXTI6
        .word _umb_Default_Handler      // IRQ18: EXTI7
        .word _umb_Default_Handler      // IRQ19: EXTI8
        .word _umb_Default_Handler      // IRQ20: EXTI9
        .word _umb_Default_Handler      // IRQ21: EXTI10
        .word _umb_Default_Handler      // IRQ22: EXTI11
        .word _umb_Default_Handler      // IRQ23: EXTI12
        .word _umb_Default_Handler      // IRQ24: EXTI13
        .word _umb_Default_Handler      // IRQ25: EXTI14
        .word _umb_Default_Handler      // IRQ26: EXTI15
        .word _umb_Default_Handler      // IRQ27: DMA1_Channel1 (IRQ 29?? No, DMA1_CH1 is IRQ 29 in SVD? Let me double check if I missed any. 0-26 is 27 vectors.)
        .word _umb_Default_Handler      // IRQ28
        .word DMA1_Channel1_Handler     // IRQ29: DMA1_Channel1
        .word DMA1_Channel2_Handler     // IRQ30: DMA1_Channel2
        .word DMA1_Channel3_Handler     // IRQ31: DMA1_Channel3
        .word DMA1_Channel4_Handler     // IRQ32: DMA1_Channel4
        .word DMA1_Channel5_Handler     // IRQ33: DMA1_Channel5
        .word DMA1_Channel6_Handler     // IRQ34: DMA1_Channel6
        .word DMA1_Channel7_Handler     // IRQ35: DMA1_Channel7
        .word DMA1_Channel8_Handler     // IRQ36: DMA1_Channel8

    // Define Handlers for exceptions
    .section ._umb_handlers, "a"
    .thumb_func
    _umb_Reset_Handler:
        bl _umb_start                   // Call main (Rust function, typically defined in main.rs)
        b .

    // .section .text.Default_Handler
    .thumb_func
    _umb_Default_Handler:
        b .                             // Infinite loop (hangs here if an undefined interrupt occurs)

    .thumb_func
    _umb_HardFault_Handler:
        // Armv8-M TrustZone: when secure takes a fault from NS code the
        // exception frame is pushed to the NS stack, NOT MSP_S. Reading sp
        // here would dump secure-boot leftovers. Pick the correct stack
        // from EXC_RETURN bits:
        //   LR[6] (S)     : 1 = secure was active, 0 = NS was active
        //   LR[2] (SPSEL) : 1 = PSP, 0 = MSP
        // Pass EXC_RETURN in r1 so the Rust handler can print it too.
        tst lr, #(1<<6)
        beq _umb_hf_ns
        // Secure-state fault
        tst lr, #(1<<2)
        beq _umb_hf_msp_s
        mrs r0, psp
        b _umb_hf_dump
    _umb_hf_msp_s:
        mov r0, sp
        b _umb_hf_dump
    _umb_hf_ns:
        tst lr, #(1<<2)
        beq _umb_hf_msp_ns
        mrs r0, psp_ns
        b _umb_hf_dump
    _umb_hf_msp_ns:
        mrs r0, msp_ns
    _umb_hf_dump:
        mov r1, lr
        bl umbra_hard_fault_handler
        b .

    // Custom Handlers - redirect to Rust functions
    // We pass the Stack Pointer (SP) in R0
    // If we were using Process Stack Pointer (PSP) we'd need to check EXC_RETURN,
    // but here in bare metal bootloader we largely rely on MSP.
    // For simplicity, we just pass implicit SP (which is MSP or PSP depending on context, usually MSP here).

    .thumb_func
    _umb_NMI_Handler:
        mov r0, sp
        bl umbra_nmi_handler
        b .

    .thumb_func
    _umb_MemManage_Handler:
        // Same trampoline pattern as UsageFault: push callee-saved + EXC_RETURN,
        // call the Rust handler with psp, and branch on its return value:
        //   0           = recover (resume enclave via original EXC_RETURN)
        //   non-zero    = terminate (store encoded status into the SVC-entry
        //                 r0 slot on MSP so `umbra_enclave_enter_imp` sees it).
        push {r4-r11}
        push {r12, lr}
        mrs r0, psp
        bl umbra_mem_manage_handler
        cmp r0, #0
        beq _mmfault_recover
        str r0, [sp, #40]
        add sp, sp, #8
        pop {r4-r11}
        movs r1, #0
        msr control, r1
        isb
        ldr lr, =0xFFFFFFF9
        bx lr
    _mmfault_recover:
        pop {r12, lr}
        pop {r4-r11}
        bx lr

    .thumb_func
    _umb_BusFault_Handler:
        tst lr, #4
        ite eq
        moveq r0, sp
        mrsne r0, psp
        b umbra_bus_fault_handler

    .thumb_func
    _umb_UsageFault_Handler:
        ldr r0, =CURRENT_ENCLAVE_CTX_PTR
        ldr r0, [r0]
        cbz r0, _usage_fault_real
        // Preserve r4-r11 (callee-saved) plus the EXC_RETURN value currently in
        // LR. r12 is a 4-byte pad to keep the 8-byte stack alignment AAPCS
        // requires at the `bl` call site. Layout after both pushes:
        //   sp+ 0: r4
        //   sp+ 4: r5
        //    ...
        //   sp+28: r11
        //   sp+32: r12 (pad)
        //   sp+36: lr  (original EXC_RETURN for enclave resume)
        //   sp+40: MSP frame r0 (from the umbra_enclave_enter_imp SVC entry;
        //          re-stacked when we exception-return to kernel via 0xFFFFFFF9)
        push {r4-r11}
        push {r12, lr}
        mrs r0, psp
        bl umbra_usage_fault_dispatch
        cmp r0, #0
        beq _usage_fault_recover
        // Terminate path: dispatcher returned status in r0. Write it into the
        // SVC-entry stacked r0 slot on MSP so umbra_enclave_enter_imp sees it
        // as the SVC return value.
        str r0, [sp, #40]
        add sp, sp, #8        // discard r12/lr pad pair (lr is overridden below)
        pop {r4-r11}
        movs r1, #0
        msr control, r1
        isb
        ldr lr, =0xFFFFFFF9
        bx lr
    _usage_fault_recover:
        // Recover path: dispatcher already ran handle_ess_miss and cleared
        // UFSR.UNDEFINSTR. Restore original EXC_RETURN and let the CPU re-run
        // the faulting instruction against the now-loaded block.
        pop {r12, lr}
        pop {r4-r11}
        bx lr
    _usage_fault_real:
        mov r0, sp
        bl umbra_usage_fault_handler
        b .

    .thumb_func
    _umb_SecureFault_Handler:
        tst lr, #4
        ite eq
        moveq r0, sp
        mrsne r0, psp
        b umbra_secure_fault_handler

    .thumb_func
    _umb_SVC_Handler:
        // Dispatch on SVC number. Determine caller stack from EXC_RETURN bit 2.
        tst lr, #4
        ite eq
        mrseq r0, msp
        mrsne r0, psp
        ldr r1, [r0, #24]
        ldrb r1, [r1, #-2]
        cmp r1, #1
        beq _svc_yield

    // svc #0: enclave enter (existing logic)
    _svc_enter:
        ldr r1, [sp, #0]
        ldr r2, =CURRENT_ENCLAVE_CTX_PTR
        str r1, [r2]
        ldm r1, {r4-r11}
        ldr r2, [r1, #32]
        msr psp, r2
        ldr r2, [r1, #40]
        msr control, r2
        isb
        ldr lr, [r1, #36]
        ldr r2, =0xE000E014
        ldr r3, =39999
        str r3, [r2]
        movs r3, #0
        str r3, [r2, #4]
        movs r3, #7
        str r3, [r2, #-4]
        bx lr

    // svc #1: cooperative yield
    _svc_yield:
        push {r4-r11}
        mov r12, lr
        bl save_enclave_context
        bl umbra_yield_handler
        str r0, [sp, #32]
        pop {r4-r11}
        movs r1, #0
        msr control, r1
        isb
        ldr lr, =0xFFFFFFF9
        bx lr

    .thumb_func
    _umb_DebugMon_Handler:
        mov r0, sp
        bl umbra_debug_mon_handler
        b .

    .thumb_func
    _umb_PendSV_Handler:
        mov r12, lr
        mov r0, sp
        bl umbra_pendsv_handler
        bx r12

    // Reusable context save. Caller MUST have done push {r4-r11}
    // and mov r12, lr (to preserve EXC_RETURN before bl clobbers lr).
    // Returns CURRENT_ENCLAVE_CTX_PTR in r0 (NULL if no enclave).
    .thumb_func
    save_enclave_context:
        ldr r0, =CURRENT_ENCLAVE_CTX_PTR
        ldr r0, [r0]
        cbz r0, _save_ctx_done
        ldr r1, [sp, #0]
        str r1, [r0, #0]
        ldr r1, [sp, #4]
        str r1, [r0, #4]
        ldr r1, [sp, #8]
        str r1, [r0, #8]
        ldr r1, [sp, #12]
        str r1, [r0, #12]
        ldr r1, [sp, #16]
        str r1, [r0, #16]
        ldr r1, [sp, #20]
        str r1, [r0, #20]
        ldr r1, [sp, #24]
        str r1, [r0, #24]
        ldr r1, [sp, #28]
        str r1, [r0, #28]
        mrs r1, psp
        str r1, [r0, #32]
        str r12, [r0, #36]
        mrs r1, control
        str r1, [r0, #40]
    _save_ctx_done:
        bx lr

    .thumb_func
    _umb_SysTick_Handler:
        push {r4-r11}
        mov r12, lr
        bl save_enclave_context
        bl umbra_systick_handler
        str r0, [sp, #32]
        pop {r4-r11}
        movs r1, #0
        msr control, r1
        isb
        ldr lr, =0xFFFFFFF9
        bx lr

    .section .text._umb_start
    // .type _start, %function

    .thumb_func
    _umb_start:
        // Copy .data section from Flash to RAM
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
        // Calculate current destination address (r0 + r3)
        add r4, r0, r3
        cmp r4, r1
        bcc 1b

        // Zero .bss section
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

        bl secure_boot                    // Branch to main
