// Standalone Umbra enclave blob wrapping TACLeBench `anagram`.
// String-search benchmark with a small dictionary embedded in
// anagram_input.c.
//
// Multi-file: anagram.c + anagram_input.c + anagram_stdlib.c (custom
// libc shim with strlen/strcmp/tolower for non-libc embedded targets).
// See Makefile ANAGRAM_OBJS rule.
extern void anagram_init(void);
extern void anagram_main(void);
extern int anagram_return(void);

__attribute__((section(".app.enclave_header"), used))
const unsigned char enclave_header[48] = {
    0x55, 0x42, 0x4D, 0x52, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10,
    0x00, 0x00, // code_size = 0x1000 (patched by protect)
    0x00, 0x00, 0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
};

__attribute__((section(".app.enclave_code"), used)) int enclave_entry(void) {
  anagram_init();
  anagram_main();
  return anagram_return();
}
