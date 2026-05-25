// Standalone Umbra enclave blob wrapping TACLeBench `bsort`.
// Bubble-sorts 100 ints (initialized descending -1..-100). 400 bytes of
// `.bss` is intrinsic — bypass-globals not feasible without rewriting.
//
// Expected R0=0 if chained-measurement passes (bsort_return returns
// `1 - Sorted` which is 0 when the array is correctly sorted ascending).
extern void bsort_init(void);
extern void bsort_main(void);
extern int bsort_return(void);

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
    bsort_init();
    bsort_main();
    return bsort_return();
}
