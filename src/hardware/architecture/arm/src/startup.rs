
//////////////////////////////////////////////////////////////////////
//                                                                  //
// Author: Stefano Mercogliano <stefano.mercogliano@unina.it>       //
//                                                                  //
// Description:                                                     //
//      This file contains the startup code for ARM-based MCUs.     //
//      Currently, the vector table, handlers, and startup code     // 
//      are all defined within a single global_asm macro function.  //
//                                                                  //    
//////////////////////////////////////////////////////////////////////


use core::arch::global_asm;

// Basic startup code 
#[cfg(all(target_arch = "arm", target_os = "none"))]
extern "C" {
    pub fn _umb_start();
}
#[cfg(all(target_arch = "arm", target_os = "none"))]
global_asm!(
    "
    .global _umb_start              // Define the entry point
    .global _umb_Reset_Handler      // Main reset handler
    .global _umb_Default_Handler    // Default handler for undefined interrupts
    .extern _umb_estack
    
    // Vector Table - must be at the beginning of the Flash
    // The reason for it is that ARM first initialized its stack and then jumps
    // to the reset handler
    .section ._umb_vectors, \"a\"    // Marked as 'a' for allocation in memory
    
        .word _umb_estack               // Initial stack pointer
        .word _umb_Reset_Handler        // Reset vector
        .word _umb_NMI_Handler          // Non-maskable interrupt handler
        .word _umb_HardFault_Handler    // Hard Fault handler
        .word _umb_MemManage_Handler    // Memory Management fault handler
        .word _umb_BusFault_Handler     // Bus Fault handler
        .word _umb_UsageFault_Handler   // Usage Fault handler
        .word 0                         // Reserved
        .word 0                         // Reserved
        .word 0                         // Reserved
        .word 0                         // Reserved
        .word _umb_SVC_Handler          // SVCall handler
        .word _umb_DebugMon_Handler     // Debug Monitor handler
        .word 0                         // Reserved
        .word _umb_PendSV_Handler       // PendSV handler
        .word _umb_SysTick_Handler      // SysTick handler
    
    // Define Handlers for exceptions
    .section ._umb_handlers, \"a\"
    _umb_Reset_Handler:
        bl _umb_start                   // Call main (Rust function, typically defined in main.rs)
        b .
    
    // .section .text.Default_Handler
    _umb_Default_Handler:
        b .                             // Infinite loop (hangs here if an undefined interrupt occurs)
    
    // Basic Handlers (redirect to Default_Handler if not defined)
    _umb_NMI_Handler:          b _umb_Default_Handler
    _umb_HardFault_Handler:    b _umb_Default_Handler
    _umb_MemManage_Handler:    b _umb_Default_Handler
    _umb_BusFault_Handler:     b _umb_Default_Handler
    _umb_UsageFault_Handler:   b _umb_Default_Handler
    _umb_SVC_Handler:          b _umb_Default_Handler
    _umb_DebugMon_Handler:     b _umb_Default_Handler
    _umb_PendSV_Handler:       b _umb_Default_Handler
    _umb_SysTick_Handler:      b _umb_Default_Handler

    .section .text._umb_start
    // .type _start, %function
    
    _umb_start:
        //ldr r0, =0x20000000   // Load address 0x2000F000 into r0
        //ldr r1, =0xFFFFF000   // Load value 0xFFFFFFFF into r1
        //str r1, [r0]          // Store the value in memory at the address in r0
        //ldr r1, [r0]
        //ldr r0, =0x08045000   // Load address 0x2000F000 into r0
        //str r1, [r0]
        bl secure_boot                    // Branch to main

    "
);


