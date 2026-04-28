    .syntax unified
    .cpu cortex-m33
    .thumb

    .section .text
    .global trampoline_to_ns
    .extern _host_entry_point

    .thumb_func
    trampoline_to_ns:
        ldr r0, =0x20020000
        msr MSP_NS, r0
        ldr r0, =_host_entry_point      // Load the address of ns_fn
        movs r1, #1
        bics r0, r1                     // Clear bit 0 of address in r0
        blxns r0                        // Branch to the non-secure function
