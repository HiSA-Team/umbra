#include "fibonacci.h"

/* Demo enclave payload for the bare_metal (N657) host. Linked into
 * `.app.enclave_code` and loaded by the Secure FSBL via the EFB pipeline.
 * `fibonacci()` returns 0x72CA33A8; the `dummy_filler_*` functions exist
 * only to push the code size past one EFB block so the multi-block loader
 * and demand-paging path get exercised end-to-end. */

/* The N657 linker (sections.ld) pulls `.app.enclave_code.entry` ahead of
 * `.app.enclave_code`, so the entry symbol lands at offset 0 of the
 * enclave region regardless of GCC's intra-section ordering. */
#define ENCLAVE_ENTRY __attribute__((section(".app.enclave_code.entry")))
#define ENCLAVE_CODE  __attribute__((section(".app.enclave_code")))

/* Per-block state-continuity checkpoint. SVC #2 makes the Secure FSBL commit the
 * enclave state to flash + TAMP and return here (transparent save-and-continue), one
 * checkpoint per block boundary; a reset resumes from the last. A production tool
 * would insert these at the real EFB boundaries — here they are placed by hand. */
#define UMBRA_BLOCK_CHECKPOINT() __asm volatile("svc #2" ::: "memory")

int fibonacci(void) ENCLAVE_ENTRY;
int heavy_computation(int val) ENCLAVE_CODE;
void dummy_filler_A(int *val) ENCLAVE_CODE;
void dummy_filler_B(int *val) ENCLAVE_CODE;
void dummy_filler_C(int *val) ENCLAVE_CODE;

int heavy_computation(int val) {
    volatile int x = val;
    x = x * 1664525 + 1013904223;
    x = (x << 13) ^ x;
    x = x * 1664525 + 1013904223;
    if (x % 2 == 0)
        x += 1;
    else
        x -= 1;
    x = x * 1664525 + 1013904223;
    x = (x << 13) ^ x;
    return x;
}

void dummy_filler_A(int *val) {
    *val += 1;
    *val = heavy_computation(*val);
    *val ^= 0xAAAAAAAA;
    *val = heavy_computation(*val);
}

void dummy_filler_B(int *val) {
    *val += 2;
    *val = heavy_computation(*val);
    *val ^= 0x55555555;
    *val = heavy_computation(*val);
}

void dummy_filler_C(int *val) {
    *val += 3;
    *val = heavy_computation(*val);
    *val ^= 0xFF00FF00;
    *val = heavy_computation(*val);
}

int fibonacci(void) {
    int n = 12;
    int t1 = 0, t2 = 1;
    int nextTerm = t1 + t2;

    t1 = heavy_computation(t1);
    dummy_filler_A(&t1);
    UMBRA_BLOCK_CHECKPOINT(); /* block boundary 1 — after phase A */

    t2 = heavy_computation(t2);
    dummy_filler_B(&t2);
    UMBRA_BLOCK_CHECKPOINT(); /* block boundary 2 — after phase B */

    for (int i = 3; i <= n; ++i) {
        t1 = t2;
        t2 = nextTerm;

        dummy_filler_C(&t1);

        if (t1 > 100000)
            t1 = 0;

        nextTerm = t1 + t2;
    }
    UMBRA_BLOCK_CHECKPOINT(); /* block boundary 3 — after the loop */

    return nextTerm;
}
