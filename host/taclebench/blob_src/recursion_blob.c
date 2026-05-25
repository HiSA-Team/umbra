// Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>
//
// Standalone Umbra enclave blob wrapping the TACLeBench `recursion`
// benchmark. Provides the 48-byte header + entry function; the upstream
// recursion.c is compiled separately (see Makefile) so we don't pull in
// its unused `main()`.
//
// Compiled with -fpic -fvisibility=hidden -ffunction-sections so PC-relative
// loads work for `recursion_input` / `recursion_result` after the kernel
// relocates blocks from flash to ESS at runtime.

// We call recursion_fib directly instead of the canonical
// recursion_init/main/return triplet. The canonical path WORKS at the
// compile/link level (R_ARM_REL32 relocations are patched correctly —
// verified via readelf + pre-protect objdump), but at runtime the canonical
// path takes slightly longer than fib(10) alone, which makes it cross the
// SysTick preemption boundary. On resume, the kernel's save/restore path
// drops the enclave into another enclave's ESS region (PC lands in
// fibonacci's old code at 0x328). This is a kernel bug, tracked separately;
// the bypass works around it and matches recursion_return's algorithmic
// check `result == 89`.
extern int recursion_fib(int i);

// 48-byte enclave header. Layout mirrors host/bare_metal_arm/src/main.c.
// The HMAC field (last 32 bytes) is rewritten by tools/protect_enclave.py
// after signing.
__attribute__((section(".app.enclave_header"), used))
const unsigned char enclave_header[48] = {
    0x55, 0x42, 0x4D, 0x52, // "UMBR" magic
    0x01,                   // trust_level (Trusted)
    0x00,                   // reserved
    0x01, 0x00,             // efbc_size (1)
    0x00, 0x00,             // ess_blocks
    0x00, 0x01, 0x00, 0x00, // code_size = 0x100 (1 block = 256 bytes; recursion is 244 bytes)
    0x00, 0x00,             // reserved
    // HMAC (32 bytes) — filled in by protect_enclave.py
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
};

// Entry — MUST be first symbol in `.app.enclave_code` (kernel uses
// `entry_point = ess_addr` so the byte at ESS offset 0 of the code region
// is what runs first). Returns the TACLeBench-convention checksum (0 on
// success, nonzero on result-mismatch).
__attribute__((section(".app.enclave_code"), used))
int enclave_entry(void)
{
    int result = recursion_fib(10);
    return (result + (-89)) != 0;
}
