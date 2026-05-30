// Standalone Umbra enclave blob wrapping TACLeBench `crc`.
// CRC-16 over a fixed input string — a tiny, table-lookup-bound workload.
// Filler entry for the runtime plot: small enough that the entire app
// fits in even a 1 KB EFBC with one ESS entry, useful as the "ESS-fits-
// everything" lower-bound case.
//
// Upstream crc_main returns the second computed CRC value (16-bit
// remainder), NOT 0-on-success. The wrapper forwards the raw return; the
// test harness compares the observed R0 against a golden value
// discovered on first hardware run (see expected_r0_for() in
// tools/test_taclebench.sh — entry left blank until then).
extern void crc_init(void);
extern int  crc_main(void);

__attribute__((section(".app.enclave_header"), used))
const unsigned char enclave_header[48] = {
    0x55, 0x42, 0x4D, 0x52, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x00,
    0x00, 0x03, 0x00, 0x00, // code_size = 0x300 (patched by protect)
    0x00, 0x00,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
};

__attribute__((section(".app.enclave_code"), used))
int enclave_entry(void)
{
    crc_init();
    return crc_main();
}
