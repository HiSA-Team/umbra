// Standalone Umbra enclave blob wrapping the TACLeBench `insertsort`
// benchmark. Unlike recursion/fac, insertsort cannot use the bypass-globals
// pattern: the algorithm sorts `insertsort_a[]` in-place, which is the
// upstream global. We use the canonical _init/_main/_return triplet.
//
// Insertsort's runtime cost (~1500 cycles for the triangular loop +
// ~200 each for init/return) is small enough to fit inside one SysTick
// window (RVR=39999), so we expect the canonical path to succeed without
// triggering the preemption-restore kernel bug tracked in
// project_c_phase2_preemption_bug.
//
// Insertsort_return checks `sum(insertsort_a) == 52`, which is the sum of
// the sorted-or-unsorted values {0, 11, 10, ..., 2} → 0+2+3+...+11 = 65
// for the upper 11 indices, or 0+2+3+4+5+6+7+8+9+10+11 = 65, but only
// indices 0..9 are summed (= 0+2+...+10 hmm let me recount).
// Upstream: indices 0..9, init values from a[0..10] = {0,11,10,9,8,7,6,5,4,3,2}.
// After sort: insertsort_a will be {0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
// (sorted ascending, all 11 elements).
// insertsort_return sums indices 0..9 = 0+2+3+4+5+6+7+8+9+10 = 54.
// Checksum is `sum + (-52) != 0`. With sum=54, return = (54-52) != 0 = 1 (mismatch?).
// Hmm — that suggests upstream's expected sum is 52, not 54. Likely the
// algorithm uses inclusive bound differently or our calculation is off by
// 2. Either way, the algorithmic correctness is upstream's contract; we
// just call _return and forward whatever it produces.
extern void insertsort_init(void);
extern void insertsort_main(void);
extern int insertsort_return(void);

// 48-byte enclave header. The HMAC field is rewritten by protect_enclave.py.
__attribute__((section(".app.enclave_header"), used))
const unsigned char enclave_header[48] = {
    0x55, 0x42, 0x4D, 0x52, // "UMBR" magic
    0x01,                   // trust_level (Trusted)
    0x00,                   // reserved
    0x01, 0x00,             // efbc_size (1)
    0x00, 0x00,             // ess_blocks
    0x00, 0x03, 0x00, 0x00, // code_size = 0x300 (multi-block; insertsort ~500B)
    0x00, 0x00,             // reserved
    // HMAC (32 bytes) — filled in by protect_enclave.py
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
};

// Entry — MUST be first symbol in `.app.enclave_code`. Returns whatever
// insertsort_return produces: 0 on algorithmic match, nonzero otherwise.
__attribute__((section(".app.enclave_code"), used))
int enclave_entry(void)
{
    insertsort_init();
    insertsort_main();
    return insertsort_return();
}
