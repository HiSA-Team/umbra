///////////////////////////////////////////////////////////////////////
// Author: Stefano Mercogliano <stefano.mercogliano@unina.it>
// Description:
//      This is a simple startup assembly file for an arm-based host.
//                                      
///////////////////////////////////////////////////////////////////////

    .global _host_start                 // Define the entry point
    .global _host_Reset_Handler         // Main reset handler
    .global _host_Default_Handler       // Default handler for undefined interrupts
    .extern _host_estack
    .extern _sdata
    .extern _edata
    .extern _sidata
    .extern _sbss
    .extern _ebss
    
    .section ._host_start
    
    // Vector Table Section
    .section ._host_vectors, "a"        // Marked as 'a' for allocation in memory
    
        .word _host_estack              // Initial stack pointer
        .word _host_Reset_Handler       // Reset vector
        .word _host_NMI_Handler         // Non-maskable interrupt handler
        .word _host_HardFault_Handler   // Hard Fault handler
        .word _host_MemManage_Handler   // Memory Management fault handler
        .word _host_BusFault_Handler    // Bus Fault handler
        .word _host_UsageFault_Handler  // Usage Fault handler
        .word 0                         // Reserved
        .word 0                         // Reserved
        .word 0                         // Reserved
        .word 0                         // Reserved
        .word _host_SVC_Handler         // SVCall handler
        .word _host_DebugMon_Handler    // Debug Monitor handler
        .word 0                         // Reserved
        .word _host_PendSV_Handler      // PendSV handler
        .word _host_SysTick_Handler     // SysTick handler
    
    // Define Handlers for exceptions
    .thumb
    .syntax unified
    .section ._host_handlers, "a"
        _host_Reset_Handler:
            ldr sp, =_host_estack       // Load the stack pointer with the address of the top of the stack

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

            /* Here we need to setup the vector table base address */
            bl main                     // Call main
        
        _host_Default_Handler:
            b .                         // Infinite loop (hangs here if an undefined interrupt occurs)

        _host_HardFault_Handler:
            ldr r0, =0xDEADC0DE  
            b .
    
        _host_MemManage_Handler:
            ldr r0, =0xDEADBEEF 
            b .
        
        _host_BusFault_Handler:
            ldr r0, =0xBAADF00D  
            b .
        
        _host_UsageFault_Handler:
            ldr r0, =0xCAFEBABE  
            b .
    
        // Basic Handlers (redirect to Default_Handler if not defined)
        _host_NMI_Handler:          b _host_Default_Handler
        _host_SVC_Handler:          b _host_Default_Handler
        _host_DebugMon_Handler:     b _host_Default_Handler
        _host_PendSV_Handler:       b _host_Default_Handler
        _host_SysTick_Handler:      b _host_Default_Handler
