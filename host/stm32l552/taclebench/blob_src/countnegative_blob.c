// Standalone Umbra enclave blob wrapping TACLeBench `countnegative`.
// Operates on a 20X20 = 400-int (1600 byte) global matrix. Canonical
// wrapper only — bypass not feasible (stack-allocating 1600 bytes risks
// exceeding the 2KB per-enclave PSP).
//
// Expected R0=0 if chained-measurement passes (countnegative_return
// checks against a fixed expected positive/negative balance).
extern void countnegative_init(void);
extern void countnegative_main(void);
extern int countnegative_return(void);

__attribute__((section(".app.enclave_header"), used))
const unsigned char enclave_header[48] = {
    0x55, 0x42, 0x4D, 0x52, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03,
    0x00, 0x00, // code_size = 0x300 (patched by protect)
    0x00, 0x00, 0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
};

__attribute__((section(".app.enclave_code"), used)) int enclave_entry(void) {
  countnegative_init();
  countnegative_main();
  return countnegative_return();
}
