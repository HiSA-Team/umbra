// Standalone Umbra enclave blob wrapping TACLeBench `md5`.
// MD5 cryptographic hash — pairs thematically with the paper's discussion
// of HW SHA/AES accelerators (here run in pure SW inside the enclave).
// Useful EFBC sweep target because the per-round constants + transform
// tables (~7 KB) are accessed uniformly across the run.
//
// Upstream md5_main returns the sum of two RandomStruct.bytesNeeded fields
// — NOT 0-on-success. The wrapper forwards the raw value verbatim; the
// test harness compares the observed R0 against the golden value
// discovered on the first hardware run (see expected_r0_for() in
// tools/test_taclebench.sh — entry left blank until then).
extern void md5_init(void);
extern int  md5_main(void);

__attribute__((section(".app.enclave_header"), used))
const unsigned char enclave_header[48] = {
    0x55, 0x42, 0x4D, 0x52, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, // code_size = 0x1000 (patched by protect)
    0x00, 0x00,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
};

__attribute__((section(".app.enclave_code"), used))
int enclave_entry(void)
{
    md5_init();
    return md5_main();
}
