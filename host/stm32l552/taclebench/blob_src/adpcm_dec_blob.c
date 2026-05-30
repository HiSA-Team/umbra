// Standalone Umbra enclave blob wrapping TACLeBench `adpcm_dec`.
// ADPCM (Adaptive Differential PCM) speech-codec decoder — an
// IoT-realistic workload with looped filter taps + lookup tables. A
// representative "codec" entry in the runtime-overhead plot, distinct in
// access pattern from the cipher-style ndes and the FSM-style statemate.
//
// Canonical TACLeBench triplet: _init/_main/_return where _return == 0
// on algorithmic match against the upstream reference checksum.
extern void adpcm_dec_init(void);
extern void adpcm_dec_main(void);
extern int  adpcm_dec_return(void);

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
    adpcm_dec_init();
    adpcm_dec_main();
    return adpcm_dec_return();
}
