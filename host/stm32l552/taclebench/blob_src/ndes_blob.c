// Standalone Umbra enclave blob wrapping TACLeBench `ndes`.
// "A lot of bit manipulation, shifts, array and matrix calculations" —
// a small symmetric-cipher benchmark with substantial fixed-size tables
// in .rodata/.data.
// Expected R0=0 if ndes_return returns 0 on success.
extern void ndes_init(void);
extern void ndes_main(void);
extern int ndes_return(void);

__attribute__((section(".app.enclave_header"), used))
const unsigned char enclave_header[48] = {
    0x55, 0x42, 0x4D, 0x52, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08,
    0x00, 0x00, // code_size = 0x800 (patched by protect)
    0x00, 0x00, 0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
};

__attribute__((section(".app.enclave_code"), used)) int enclave_entry(void) {
  ndes_init();
  ndes_main();
  return ndes_return();
}
