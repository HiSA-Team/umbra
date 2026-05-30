    .syntax unified
    // .cpu is controlled by the build.rs -mcpu flag per platform
    .thumb

    // NSC veneer section — SG entry points callable from Non-Secure world
    .section .umbra_nsc_api, "a"

    .global umbra_enclave_create
    .extern umbra_enclave_create_imp

    .thumb_func
    umbra_enclave_create:
        sg
        push {r4, lr}
        bl umbra_enclave_create_imp
        pop {r4, lr}
        bxns lr

    .global umbra_debug_print
    .extern umbra_debug_print_imp

    .thumb_func
    umbra_debug_print:
        sg
        push {r4, lr}
        bl umbra_debug_print_imp
        pop {r4, lr}
        bxns lr

    .global umbra_enclave_enter
    .extern umbra_enclave_enter_imp

    .thumb_func
    umbra_enclave_enter:
        sg
        push {r4, lr}
        bl umbra_enclave_enter_imp
        pop {r4, lr}
        bxns lr

    .global umbra_enclave_exit
    .extern umbra_enclave_exit_imp

    .thumb_func
    umbra_enclave_exit:
        sg
        push {r4, lr}
        bl umbra_enclave_exit_imp
        pop {r4, lr}
        bxns lr

    .global umbra_enclave_status
    .extern umbra_enclave_status_imp

    .thumb_func
    umbra_enclave_status:
        sg
        push {r4, lr}
        bl umbra_enclave_status_imp
        pop {r4, lr}
        bxns lr

    // NS host calls this once at end-of-bench between [EVAL_DUMP_BEGIN]/[EVAL_DUMP_END] sentinels
    // Always emitted regardless of the bench-eval cfg — the Secure-side imp is a no-op stub 
    // when the feature is off, so the link succeeds in every build and the production overhead per
    // call is one SVC + bxns (the Secure-side dump body is empty).
    //
    // `.align 4` (= 2^4 = 16 byte alignment in GAS) places this veneer at
    // slot 5 = NSC_BASE + 0x50 to match the 16-byte-per-slot convention
    // observed by the Tock layout.ld PROVIDE statements. Without this
    // the bench_dump symbol would land at NSC_BASE + 14*5 = 0x46
    // (Thumb-aligned but slot-misaligned) and the layout.ld PROVIDE
    // address would point at the wrong byte stream.
    .align 4
    .global umbra_bench_dump
    .extern umbra_bench_dump_imp

    .thumb_func
    umbra_bench_dump:
        sg
        push {r4, lr}
        bl umbra_bench_dump_imp
        pop {r4, lr}
        bxns lr

    // "Null SVC" — bxns lr immediately after the SG, no work done Secure-side. 
    // Used by the NS host to measure the TrustZone round-trip fixed cost
    // (SG + push + ... + bxns + return). The switch plot normalizes
    // every (slot, cache, spec) cell against this baseline value.
    .align 4
    .global umbra_null_call

    .thumb_func
    umbra_null_call:
        sg
        bxns lr

    // API implementation section — implementations live in the boot crate
    .section .umbra_api_implementation, "a"
