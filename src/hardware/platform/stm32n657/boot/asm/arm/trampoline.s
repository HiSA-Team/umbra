    .syntax unified
    // .cpu is controlled by the build.rs -mcpu flag
    .thumb

    .section .text
    .global trampoline_to_ns
    .extern _host_entry_point

    .thumb_func
    trampoline_to_ns:
        // Load NS MSP from vector[0] of the host vector table at 0x24000000
        // (the host startup.s places _host_estack there). Auto-adapts when
        // the host memory.ld changes its AXISRAM3_NS length — earlier we
        // hardcoded 0x240FFFFC and silently corrupted NS pushes after the
        // memory.ld shrink moved the real top to 0x240E0000.
        ldr r0, =0x24000000
        ldr r0, [r0]
        msr MSP_NS, r0
        // Load host entry point, clear Thumb bit for BLXNS
        ldr r0, =_host_entry_point
        movs r1, #1
        bics r0, r1
        blxns r0
