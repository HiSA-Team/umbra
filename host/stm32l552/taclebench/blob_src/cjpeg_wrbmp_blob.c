// Standalone Umbra enclave blob wrapping TACLeBench `cjpeg_wrbmp`.
// JPEG-to-BMP conversion fragment (write-BMP path from the libjpeg
// `cjpeg` tool).
//
// Multi-file: cjpeg_wrbmp.c + input.c. Headers in
// lib/tacle-bench/bench/sequential/cjpeg_wrbmp/ (jpeglib.h + jconfig.h
// + 4 others). See Makefile CJPEG_WRBMP_OBJS rule with -I to add the
// include path so the per-bench .h files resolve.
extern void cjpeg_wrbmp_init(void);
extern void cjpeg_wrbmp_main(void);
extern int cjpeg_wrbmp_return(void);

__attribute__((section(".app.enclave_header"), used))
const unsigned char enclave_header[48] = {
    0x55, 0x42, 0x4D, 0x52, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14,
    0x00, 0x00, // code_size = 0x1400 (patched by protect)
    0x00, 0x00, 0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
};

__attribute__((section(".app.enclave_code"), used)) int enclave_entry(void) {
  cjpeg_wrbmp_init();
  cjpeg_wrbmp_main();
  return cjpeg_wrbmp_return();
}
