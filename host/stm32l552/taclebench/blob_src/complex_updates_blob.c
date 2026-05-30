// Standalone Umbra enclave blob wrapping TACLeBench `complex_updates`.
// 4 X (2X16) float arrays. Complex multiply-accumulate over N=16 elements.
// Float operations: relies on M33 FPU being enabled by the kernel's boot
// (CPACR cp10/cp11 = 0b11). If the floats fault, the enclave terminates
// with UsageFault before reaching _return.
//
// Expected R0=0 if chained-measurement passes AND FPU is enabled in the
// enclave's CONTROL state (FPCA bit). The L552 kernel currently doesn't
// grant FPU access to enclaves — likely fault or trap.
extern void complex_updates_init(void);
extern void complex_updates_main(void);
extern int complex_updates_return(void);

__attribute__((section(".app.enclave_header"), used))
const unsigned char enclave_header[48] = {
    0x55, 0x42, 0x4D, 0x52, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03,
    0x00, 0x00, // code_size = 0x300 (patched by protect)
    0x00, 0x00, 0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
};

__attribute__((section(".app.enclave_code"), used)) int enclave_entry(void) {
  complex_updates_init();
  complex_updates_main();
  return complex_updates_return();
}
