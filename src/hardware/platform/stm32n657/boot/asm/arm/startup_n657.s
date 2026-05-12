//////////////////////////////////////////////////////////////////////
//                                                                  //
// STM32N657 startup assembly                                       //
//                                                                  //
// Differs from the shared startup.s in two ways:                   //
//   1. Vector table uses direct Secure-alias addresses (no         //
//      +0x04000000 offset — code is already at 0x34xxxxxx).        //
//   2. Stack pointer uses +0x10000000 offset (same as L5 —         //
//      converts NS alias 0x24xxx to Secure alias 0x34xxx).         //
//   3. IRQ vector entries are N657-specific (all default for now). //
//                                                                  //
// Handlers, _umb_start, and save_enclave_context are identical     //
// to the shared file.                                              //
//                                                                  //
//////////////////////////////////////////////////////////////////////

    .syntax unified
    // .cpu is controlled by the build.rs -mcpu flag
    .thumb

    .global _umb_start
    .global _umb_Reset_Handler
    .global _umb_Default_Handler
    .global save_enclave_context
    .extern _umb_estack

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

    // =====================================================================
    // Vector Table
    // =====================================================================
    // On N657 code runs from AXISRAM2 Secure (0x34100000+).
    // The linker resolves symbols to Secure-alias addresses directly,
    // so the Reset vector only needs the Thumb bit (+1), NOT the
    // +0x04000000 offset that L5 uses for flash NS→Secure aliasing.
    //
    // The stack pointer still needs +0x10000000 because _umb_estack
    // is defined at the NS alias (0x24xxx) by convention.
    // =====================================================================

    .section ._umb_vectors, "a"

        .word _umb_estack+0x10000000               // Initial stack pointer (NS→Secure alias)
        .word _umb_Reset_Handler+1                  // Reset (Thumb bit only — already Secure alias)
        .word _umb_NMI_Handler+1
        .word _umb_HardFault_Handler+1
        .word _umb_MemManage_Handler+1
        .word _umb_BusFault_Handler+1
        .word _umb_UsageFault_Handler+1
        .word _umb_SecureFault_Handler+1
        .word 0                                     // Reserved
        .word 0                                     // Reserved
        .word 0                                     // Reserved
        .word _umb_SVC_Handler+1
        .word _umb_DebugMon_Handler+1
        .word 0                                     // Reserved
        .word _umb_PendSV_Handler+1
        .word _umb_SysTick_Handler+1

    // External Interrupts — N657 IRQ layout. 128 slots default to the
    // shared default handler; specific drivers override their slot.
        .rept 128
        .word _umb_Default_Handler
        .endr

    // =====================================================================
    // Handlers — identical to shared startup.s
    // =====================================================================

    .section ._umb_handlers, "a"
    .thumb_func
    _umb_Reset_Handler:
        bl _umb_start
        b .

    .thumb_func
    _umb_Default_Handler:
        b .

    .thumb_func
    _umb_HardFault_Handler:
        tst lr, #(1<<6)
        beq _umb_hf_ns
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

    .thumb_func
    _umb_NMI_Handler:
        mov r0, sp
        bl umbra_nmi_handler
        b .

    .thumb_func
    _umb_MemManage_Handler:
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
        push {r4-r11}
        push {r12, lr}
        mrs r0, psp
        bl umbra_usage_fault_dispatch
        cmp r0, #0
        beq _usage_fault_recover
        str r0, [sp, #40]
        add sp, sp, #8
        pop {r4-r11}
        movs r1, #0
        msr control, r1
        isb
        ldr lr, =0xFFFFFFF9
        bx lr
    _usage_fault_recover:
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
        // Pass EXC_RETURN as r1 (second arg) — handler decides whether to read
        // psp/msp/psp_ns/msp_ns from it. Mirrors the Hard Fault handler pattern,
        // and lets the Rust handler avoid an inline `mov ..., lr`.
        mov r1, lr
        b umbra_secure_fault_handler

    .thumb_func
    _umb_SVC_Handler:
        tst lr, #4
        ite eq
        mrseq r0, msp
        mrsne r0, psp
        ldr r1, [r0, #24]
        ldrb r1, [r1, #-2]
        cmp r1, #1
        beq _svc_yield

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
        // SYST_RVR (0xE000E014) — SysTick reload value, 24-bit max.
        // 40000 cycles at 800 MHz = 50 µs window for short enclaves.
        // 800000 cycles = 1 ms — used for NPU inference workloads where
        // the inline EPC.IRQ ack poll runs millions of iterations per
        // epoch and preempt overhead (~10 µs per cycle) dominates the
        // shorter window. Bumping 20x cuts reentries 20x while keeping
        // the enclave from hogging the CPU for >1 ms unrecoverably.
        ldr r2, =0xE000E014
        ldr r3, =799999
        str r3, [r2]
        movs r3, #0
        str r3, [r2, #4]
        movs r3, #7
        str r3, [r2, #-4]
        bx lr

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

        // If IN_ORACLE != 0, take the oracle early-return path (kick IWDG,
        // skip enclave preempt). This avoids `str r0, [sp, #32]` overwriting
        // FSBL's stacked R0 when the oracle is running.
        ldr r0, =IN_ORACLE
        ldr r0, [r0]
        cbnz r0, _systick_oracle_path

        // Normal path — enclave is running.
        bl save_enclave_context
        bl umbra_systick_handler
        str r0, [sp, #32]

    _systick_done:
        pop {r4-r11}
        movs r1, #0
        msr control, r1
        isb
        ldr lr, =0xFFFFFFF9
        bx lr

    _systick_oracle_path:
        // Oracle is running: kick IWDG (0x56004800 = 0xAAAA). Do NOT call
        // save_enclave_context and do NOT touch sp+32 — FSBL is the
        // interrupted code, not an enclave.
        ldr r0, =0x56004800
        movw r1, #0xAAAA
        str r1, [r0]
        b _systick_done

    // =====================================================================
    // C-runtime init (_umb_start) — identical to shared startup.s
    // =====================================================================

    .section .text._umb_start

    .thumb_func
    _umb_start:

        // ── N657 FSBL pre-init ──────────────────────────────────────
        // Boot ROM DMA'd the FSBL image into AXISRAM2 — caches may have
        // stale pre-copy data. Disable + invalidate D-cache + I-cache
        // before .data copy / .bss zero / Rust function calls.
        // Doing this in assembly (rather than at the top of secure_boot)
        // keeps main.rs minimal and matches the L5 main.rs structure.
        //
        // CCR (0xE000ED14): bit 16 = DC, bit 17 = IC
        // ICIALLU (0xE000EF50): write any value to invalidate I-cache.
        ldr r0, =0xE000ED14
        ldr r1, [r0]
        bic r1, r1, #(1 << 16)
        bic r1, r1, #(1 << 17)
        str r1, [r0]
        dsb sy
        isb
        ldr r0, =0xE000EF50
        movs r1, #0
        str r1, [r0]
        dsb sy
        isb

        // VTOR relocation to AXISRAM2 vector table (after 0x400 signing
        // header that the FSBL signing tool prepends).
        ldr r0, =0xE000ED08
        ldr r1, =0x34180400
        str r1, [r0]
        dsb sy
        isb

        // MSP relocation to top of _SECURE_KERNEL_DATA_MEMORY_.
        // Boot ROM set initial MSP from vector table to NS-aliased
        // AXISRAM1; we relocate to the Secure-region stack. Must happen
        // here (no Rust frame yet) since changing SP mid-function would
        // break the compiler's local-variable layout.
        movs r0, #0
        msr msplim, r0
        ldr r0, =0x341CC3FC
        msr msp, r0
        isb

        // Copy .data (no-op when VMA==LMA, which is the case on N657)
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

        bl secure_boot
