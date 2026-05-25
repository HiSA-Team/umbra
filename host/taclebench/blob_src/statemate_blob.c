// Standalone Umbra enclave blob wrapping TACLeBench `statemate`.
// Auto-generated state-machine code for an experimental car-window-lift
// controller (~1200 LOC, single file with extensive switch/case logic).
// Mentioned in the Umbra paper as having a "uniform code access pattern"
// that benefits from larger EFBC sizes.
//
// statemate has only _init and _main entry points (no _return). The
// wrapper returns 0 unconditionally on completion — the benchmark is
// considered passing if it terminates cleanly.
extern void statemate_init(void);
extern void statemate_main(void);

__attribute__((section(".app.enclave_header"), used))
const unsigned char enclave_header[48] = {
    0x55, 0x42, 0x4D, 0x52, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x00,
    0x00, 0x18, 0x00, 0x00, // code_size = 0x1800 (patched by protect)
    0x00, 0x00,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
};

__attribute__((section(".app.enclave_code"), used))
int enclave_entry(void)
{
    statemate_init();
    statemate_main();
    return 0;
}
