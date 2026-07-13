/*
 * Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>
 *
 * STM32N657 two_enclaves host — REAL TACLeBench "ndes" enclave (DES cipher).
 *
 * ndes is the DES symmetric-cipher benchmark from
 * tacle-bench/bench/sequential/ndes. Its single source file (ndes.c) is
 * vendored verbatim into app/ and is NOT modified. The Makefile compiles it
 * with the enclave PIC flags (-fpic -mpic-data-is-text-relative, cortex-m33)
 * and then partial-links it (ld -r --gc-sections -e enclave_entry,
 * linker/enclave_partial.ld) so the reachable code + its fixed-size DES tables
 * (.rodata) + its writable globals (.data/.bss) all land inside the single
 * .app.enclave_code / .app.enclave_bss pair, i.e. inside the EFBC window.
 *
 * ndes.c also defines its own main(); that main() is unreachable from
 * enclave_entry, so --gc-sections drops it and there is no collision with the
 * host src/main.c.
 *
 * This wrapper is the single .app.enclave_code.entry symbol. sections.ld pulls
 * .app.enclave_code.entry to offset 0 of the enclave region, so enclave_entry
 * is the address the Secure FSBL jumps to. It runs the same sequence as ndes's
 * own main() (mirrors the L552 blob_src/ndes_blob.c wrapper):
 *
 *     ndes_init();     // load DES permutation tables + fixed input/key
 *     ndes_main();     // ndes_des(...) — the DES round on the known input
 *     return ndes_return();   // (ndes_icd.r + ndes_icd.l - 8390656) != 0
 *
 * DES is deterministic and bit-exact (no UB, no toolchain-dependent behaviour),
 * so the checksum is a real FIPS-style known-answer: ndes_return() returns 0
 * on the golden result. Verified by compiling+running the vendored ndes.c
 * natively (host clang/gcc, -O0 and -O2): checksum = 0x00000000. That value is
 * returned in R0 and read back by the host via umbra_enclave_status();
 * src/main.c compares it against NDES_GOLDEN.
 */

#define ENCLAVE_ENTRY __attribute__((section(".app.enclave_code.entry")))

/* Defined in the vendored ndes.c. */
extern void ndes_init(void);
extern void ndes_main(void);
extern int  ndes_return(void);

int enclave_entry(void) ENCLAVE_ENTRY;

int enclave_entry(void)
{
    ndes_init();
    ndes_main();
    return ndes_return();
}
