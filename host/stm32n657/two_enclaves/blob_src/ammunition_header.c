/*
 * Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>
 *
 * STANDALONE-blob header for the vendored TACLeBench "ammunition" enclave.
 *
 * This TU carries ONLY the 48-byte `.app.enclave_header` (UmbraEnclaveHeader).
 * The enclave code + its entry live in obj/enclave_combined_ammunition.o
 * (partial-linked from arithm/ammunition/bits/ammunition_libc/
 * ammunition_enclave with the enclave PIC flags). linker/enclave_blob.ld
 * places this header at VMA 0 and the code right after, so the flat .bin is
 * `[header | protected blocks]` — the shape umbra_enclave_create() expects.
 *
 * protect_enclave.py post-link patches:
 *   - hmac (32 bytes)          -> the chained-measurement final value
 *   - code_size (offset 10)    -> len of the protected-blocks region
 * The other fields stay as set here (magic, trust_level=1). Mirrors the L552
 * blob_src/*_blob.c header and the two_enclaves src/main.c header.
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
