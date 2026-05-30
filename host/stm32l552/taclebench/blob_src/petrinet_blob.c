// Standalone Umbra enclave blob wrapping TACLeBench `petrinet`.
// Petri-net state simulation — sibling workload to `statemate` (both
// auto-generated finite-state-machine code) but with a different
// granularity that lets the runtime plot show how the FSM family scales
// with EFBC size.
extern void petrinet_init(void);
extern void petrinet_main(void);
extern int petrinet_return(void);

__attribute__((section(".app.enclave_header"), used))
const unsigned char enclave_header[48] = {
    0x55, 0x42, 0x4D, 0x52, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x18,
    0x00, 0x00, // code_size = 0x1800 (patched by protect)
    0x00, 0x00, 0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
};

__attribute__((section(".app.enclave_code"), used)) int enclave_entry(void) {
  petrinet_init();
  petrinet_main();
  return petrinet_return();
}
