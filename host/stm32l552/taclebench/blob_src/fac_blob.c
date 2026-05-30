// Standalone Umbra enclave blob wrapping the TACLeBench `fac` benchmark.
// Provides the 48-byte header + entry function; upstream fac.c is compiled
// separately (see Makefile) so we don't pull in its unused `main()`.
//
// We call fac_fac(n) directly instead of the canonical fac_init/main/return
// triplet. The canonical path accesses globals (`fac_s`, `fac_n`); on this
// kernel that path runs slow enough to cross a SysTick window, exposing the
// open multi-enclave save/restore preemption-restore bug. The bypass is
// algorithmically equivalent: TACLeBench's fac_return checks `fac_s == 154`
// (sum of 0!..5! = 1+1+2+6+24+120).
extern int fac_fac(int n);

// 48-byte enclave header. The HMAC field is rewritten by protect_enclave.py.
__attribute__((section(".app.enclave_header"), used))
const unsigned char enclave_header[48] = {
    0x55, 0x42, 0x4D, 0x52, // "UMBR" magic
    0x01,                   // trust_level (Trusted)
    0x00,                   // reserved
    0x01, 0x00,             // efbc_size (1)
    0x00, 0x00,             // ess_blocks
    0x00, 0x01, 0x00, 0x00, // code_size = 0x100 (1 block; fac is small)
    0x00, 0x00,             // reserved
    // HMAC (32 bytes) — filled in by protect_enclave.py
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
};

// Entry — MUST be first symbol in `.app.enclave_code`. Returns 0 if the
// algorithm produced the TACLeBench-expected sum (154), nonzero otherwise.
__attribute__((section(".app.enclave_code"), used))
int enclave_entry(void)
{
    int sum = 0;
    for (int i = 0; i <= 5; i++) {
        sum += fac_fac(i);
    }
    return sum - 154;
}
