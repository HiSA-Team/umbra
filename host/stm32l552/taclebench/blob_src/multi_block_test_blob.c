// Synthetic 2-block diagnostic for the multi-block chained-measurement bug.
//
// Question: does protect_enclave.py + kernel agree on the chain HMAC for ANY
// 2-block enclave, or only for insertsort? This blob has NO upstream
// dependency — just enough hand-rolled code to push the plaintext past 256
// bytes so the linker section spans 2 blocks.
//
// Expected outcomes:
//   chained-measurement OK + Enclave terminated → multi-block works,
//     insertsort failure is reachability/data specific.
//   chained-measurement FAIL → multi-block chain folding has a general bug;
//     fix needed before any benchmark larger than 1 block.
//
// The padding functions use volatile + noinline + (used) so neither LTO nor
// dead-code elimination shrinks them. Each is ~30-50 bytes of code at -O0
// targeting Thumb-2; together they push total plaintext to ~350+ bytes →
// 2 blocks of 256.

__attribute__((noinline, used, section(".app.enclave_code")))
static volatile int pad_a(volatile int x)
{
    x = x * 1664525 + 1013904223;
    x = (x << 13) ^ x;
    x = x * 22695477 + 1;
    x = x ^ 0xDEADBEEF;
    return x;
}

__attribute__((noinline, used, section(".app.enclave_code")))
static volatile int pad_b(volatile int x)
{
    x = x + 0xCAFEBABE;
    x = x ^ (x >> 7);
    x = x * 1103515245 + 12345;
    x = (x << 11) ^ x;
    return x;
}

__attribute__((noinline, used, section(".app.enclave_code")))
static volatile int pad_c(volatile int x)
{
    x = x ^ 0x55555555;
    x = (x >> 5) | (x << 27);
    x = x * 1664525 + 1013904223;
    x = x ^ 0xA5A5A5A5;
    return x;
}

__attribute__((noinline, used, section(".app.enclave_code")))
static volatile int pad_d(volatile int x)
{
    x = x + 0x12345678;
    x = (x << 9) ^ (x >> 23);
    x = x * 2654435761;
    x = x ^ 0xF0F0F0F0;
    return x;
}

// 48-byte enclave header. HMAC field rewritten by protect_enclave.py.
__attribute__((section(".app.enclave_header"), used))
const unsigned char enclave_header[48] = {
    0x55, 0x42, 0x4D, 0x52, // "UMBR" magic
    0x01,                   // trust_level (Trusted)
    0x00,                   // reserved
    0x01, 0x00,             // efbc_size (1)
    0x00, 0x00,             // ess_blocks
    0x00, 0x02, 0x00, 0x00, // code_size = 0x200 (will be patched by protect)
    0x00, 0x00,             // reserved
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
};

// Entry. Runs through all four pad_* in sequence; result is deterministic.
// Returns the chained result so the host can sanity-check actual execution
// (any R0 != 0xFFFFFFFF / 0x0 / 0xDEADBEEF strongly suggests real execution).
__attribute__((section(".app.enclave_code"), used))
int enclave_entry(void)
{
    int x = 0xCAFE;
    x = pad_a(x);
    x = pad_b(x);
    x = pad_c(x);
    x = pad_d(x);
    return x;
}
