/*
 * Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>
 *
 * STANDALONE-blob header for the vendored TACLeBench "ndes" (DES) enclave.
 *
 * This TU carries ONLY the 48-byte `.app.enclave_header` (UmbraEnclaveHeader).
 * The enclave code + its entry live in obj/enclave_combined_ndes.o
 * (partial-linked from ndes/ndes_enclave/ndes_libc with the enclave PIC
 * flags). See blob_src/ammunition_header.c for the field layout notes.
 */

__attribute__((section(".app.enclave_header"), used))
const unsigned char enclave_header[48] = {
    0x55, 0x42, 0x4D, 0x52, /* magic = 0x524D4255 ("UMBR" little-endian) */
    0x01,                   /* trust_level = 1 (Trusted) */
    0x00,                   /* reserved0 */
    0x02, 0x00,             /* efbc_size (placeholder) */
    0x00, 0x00,             /* ess_blocks */
    0x00, 0x00, 0x00, 0x00, /* code_size (patched by protect_enclave.py) */
    0x00, 0x00,             /* reserved1 / reloc_count */
    /* hmac (32 bytes) — patched by protect_enclave.py */
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
};
