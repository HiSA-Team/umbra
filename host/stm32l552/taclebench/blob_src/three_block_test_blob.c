// Synthetic 3-block diagnostic. Disambiguates "multi-block chain bug ≥3
// blocks" vs "insertsort-shape-specific bug". Same shape as
// multi_block_test_blob.c but with 8 pad functions instead of 4 to push
// plaintext past 512 bytes → 3 blocks of 256.
//
// Expected: chained-measurement OK + R0=deterministic hex →
//   bug is insertsort-specific (the 18 cross-block PC-rel `ldr`s from
//   block 1 to block 2 are the unique structural difference).
//
// Failure: chained-measurement FAIL → bug scales with chain length
//   (kernel HASH peripheral state or protect_enclave.py chain math).

__attribute__((noinline, used, section(".app.enclave_code")))
static volatile int p3a(volatile int x) {
    x = x * 1664525 + 1013904223;
    x = (x << 13) ^ x;
    x = x * 22695477 + 1;
    x = x ^ 0xDEADBEEF;
    return x;
}

__attribute__((noinline, used, section(".app.enclave_code")))
static volatile int p3b(volatile int x) {
    x = x + 0xCAFEBABE;
    x = x ^ (x >> 7);
    x = x * 1103515245 + 12345;
    x = (x << 11) ^ x;
    return x;
}

__attribute__((noinline, used, section(".app.enclave_code")))
static volatile int p3c(volatile int x) {
    x = x ^ 0x55555555;
    x = (x >> 5) | (x << 27);
    x = x * 1664525 + 1013904223;
    x = x ^ 0xA5A5A5A5;
    return x;
}

__attribute__((noinline, used, section(".app.enclave_code")))
static volatile int p3d(volatile int x) {
    x = x + 0x12345678;
    x = (x << 9) ^ (x >> 23);
    x = x * 2654435761;
    x = x ^ 0xF0F0F0F0;
    return x;
}

__attribute__((noinline, used, section(".app.enclave_code")))
static volatile int p3e(volatile int x) {
    x = x * 0x9E3779B1;
    x = (x ^ (x >> 16)) * 0x85EBCA6B;
    x = (x ^ (x >> 13)) * 0xC2B2AE35;
    x = x ^ (x >> 16);
    return x;
}

__attribute__((noinline, used, section(".app.enclave_code")))
static volatile int p3f(volatile int x) {
    x = x + 0x9E3779B9;
    x = (x >> 17) | (x << 15);
    x = x * 0x6C078965;
    x = x ^ 0x0F0F0F0F;
    return x;
}

__attribute__((noinline, used, section(".app.enclave_code")))
static volatile int p3g(volatile int x) {
    x = x ^ 0xAAAA5555;
    x = (x << 7) ^ (x >> 25);
    x = x * 0xACE1ACE1;
    x = x + 0x13579BDF;
    return x;
}

__attribute__((noinline, used, section(".app.enclave_code")))
static volatile int p3h(volatile int x) {
    x = x + 0xFEEDFACE;
    x = (x >> 11) | (x << 21);
    x = x * 0x5DEECE66;
    x = x ^ 0xC0FFEE15;
    return x;
}

__attribute__((section(".app.enclave_header"), used))
const unsigned char enclave_header[48] = {
    0x55, 0x42, 0x4D, 0x52, // "UMBR"
    0x01, 0x00,             // trust_level, reserved
    0x01, 0x00,             // efbc_size
    0x00, 0x00,             // ess_blocks
    0x00, 0x03, 0x00, 0x00, // code_size = 0x300 (will be patched by protect)
    0x00, 0x00,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
};

__attribute__((section(".app.enclave_code"), used))
int enclave_entry(void) {
    int x = 0xC0DE;
    x = p3a(x); x = p3b(x); x = p3c(x); x = p3d(x);
    x = p3e(x); x = p3f(x); x = p3g(x); x = p3h(x);
    return x;
}
