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

    // Remote attestation: r0 = NS ptr to 16-byte nonce, r1 = NS ptr to a
    // 115-byte quote buffer. Returns 0 on success, 0xFFFF_FFF* on error.
    // `.align 4` forces slot 7 (NSC_BASE + 0x70): the preceding `umbra_null_call`
    // is only 8 bytes, so without this the veneer lands at 0x68 and diverges from
    // the 16-byte-slot PROVIDE addresses in the host sections.ld.
    .align 4
    .global umbra_attest_quote
    .extern umbra_attest_quote_imp

    .thumb_func
    umbra_attest_quote:
        sg
        push {r4, lr}
        bl umbra_attest_quote_imp
        pop {r4, lr}
        bxns lr

    // Secure enclave update: r0 = NS ptr to the update package, r1 = package
    // length. Returns 0 on success, 0xFFFF_FF2* on error. 16 bytes → naturally
    // lands at slot 8 (NSC_BASE + 0x80) after the aligned attest veneer.
    .align 4
    .global umbra_enclave_update
    .extern umbra_enclave_update_imp

    .thumb_func
    umbra_enclave_update:
        sg
        push {r4, lr}
        bl umbra_enclave_update_imp
        pop {r4, lr}
        bxns lr

    // Secure UART bridge (USART1 is Secure-only; the NS relay does raw byte I/O here).
    // r0 = NS buffer ptr, r1 = length. slot 9 (NSC_BASE + 0x90).
    .align 4
    .global umbra_uart_read
    .extern umbra_uart_read_imp

    .thumb_func
    umbra_uart_read:
        sg
        push {r4, lr}
        bl umbra_uart_read_imp
        pop {r4, lr}
        bxns lr

    // slot 10 (NSC_BASE + 0xA0).
    .align 4
    .global umbra_uart_write
    .extern umbra_uart_write_imp

    .thumb_func
    umbra_uart_write:
        sg
        push {r4, lr}
        bl umbra_uart_write_imp
        pop {r4, lr}
        bxns lr

    // System reset (SYSRESETREQ) — relay calls it after a successful update to
    // activate the new slot without a manual reset. slot 11 (NSC_BASE + 0xB0).
    .align 4
    .global umbra_system_reset
    .extern umbra_system_reset_imp

    .thumb_func
    umbra_system_reset:
        sg
        push {r4, lr}
        bl umbra_system_reset_imp
        pop {r4, lr}
        bxns lr

    // API implementation section — implementations live in the boot crate
    .section .umbra_api_implementation, "a"
