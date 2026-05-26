// Standalone Umbra enclave blob wrapping TACLeBench `binarysearch`.
// Uses canonical _init/_main/_return path; this benchmark's algorithm
// is intrinsically stateful (searches a global 15-entry data array, so
// bypass-globals doesn't apply cleanly without rewriting the algorithm).
//
// Expected: _return checks `result == -1` (key 8 not found in random data).
// If chained-measurement passes, R0=0. If it fails like insertsort, we
// have a data point: the shape-specific multi-block-with-globals bug
// affects binarysearch too.
extern void binarysearch_init(void);
extern void binarysearch_main(void);
extern int binarysearch_return(void);

__attribute__((section(".app.enclave_header"), used))
const unsigned char enclave_header[48] = {
    0x55, 0x42, 0x4D, 0x52, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x00, // code_size = 0x200 (patched by protect)
    0x00, 0x00,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
};

__attribute__((section(".app.enclave_code"), used))
int enclave_entry(void)
{
    binarysearch_init();
    binarysearch_main();
    return binarysearch_return();
}
