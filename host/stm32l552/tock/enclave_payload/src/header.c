// Minimum source to produce a standalone enclave ELF that
// protect_enclave.py can encrypt and that Umbra Secure accepts via
// umbra_enclave_create(0x08078000).
//
// Layout in flash after link:
//   0x08078000  .app.enclave_header   48 bytes  (this file's `enclave_header`)
//   0x08078030  .app.enclave_code   ≤ 1024 bytes (fibonacci.c, pulled from
//                                                 host/stm32l552/bare_metal/app/)
//
// protect_enclave.py encrypts ._enclave_code, patches the header HMAC in
// place, and writes the result back into the ELF.

#include <stdint.h>

__attribute__((section(".app.enclave_header")))
const uint8_t enclave_header[48] = {
    0x55, 0x42, 0x4D, 0x52, // Magic: "UMBR" (little-endian)
    0x01,                   // Trust_level (Trusted)
    0x00,                   // reserved
    0x01, 0x00,             // efbc_size (1)
    0x00, 0x00,             // ess_blocks
    0x00, 0x04, 0x00, 0x00, // code_size (0x400 = 1024 bytes)
    0x00, 0x00,             // reserved
    // HMAC (32 bytes). Placeholder rewritten by protect_enclave.py against
    // the freshly-rotated master_key.bin on every ./rebuild_all.sh.
    0x37, 0x49, 0x09, 0xC7, 0x44, 0xB8, 0xD9, 0xA6, 0x9E, 0x8C, 0x2C, 0xF3,
    0x41, 0x64, 0x0E, 0x57, 0x55, 0x32, 0xC0, 0xB7, 0xDF, 0x49, 0x83, 0x98,
    0xCC, 0xC8, 0x30, 0x59, 0x03, 0xCC, 0xD9, 0x36
};
