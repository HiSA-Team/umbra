// Standalone Umbra enclave blob wrapping TACLeBench `huff_dec`.
// Huffman decoder — entropy-coding workload with branchy table lookups,
// a different access pattern from the linear loops in adpcm or the
// switch/case in statemate. Small enough that with sufficient EFBC the
// entire decoder fits in the cache (similar to cjpeg in the paper).
extern void huff_dec_init(void);
extern void huff_dec_main(void);
extern int  huff_dec_return(void);

__attribute__((section(".app.enclave_header"), used))
const unsigned char enclave_header[48] = {
    0x55, 0x42, 0x4D, 0x52, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x00,
    0x00, 0x08, 0x00, 0x00, // code_size = 0x800 (patched by protect)
    0x00, 0x00,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
};

__attribute__((section(".app.enclave_code"), used))
int enclave_entry(void)
{
    huff_dec_init();
    huff_dec_main();
    return huff_dec_return();
}
