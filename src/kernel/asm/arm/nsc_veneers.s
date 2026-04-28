    .syntax unified
    .cpu cortex-m33
    .thumb

    // NSC veneer section — SG entry points callable from Non-Secure world
    .section .umbra_nsc_api, "a"

    .global umbra_tee_create
    .extern umbra_tee_create_imp

    .thumb_func
    umbra_tee_create:
        sg
        push {r4, lr}
        bl umbra_tee_create_imp
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

    // API implementation section — implementations live in the boot crate
    .section .umbra_api_implementation, "a"
