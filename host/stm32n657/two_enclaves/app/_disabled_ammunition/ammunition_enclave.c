/*
 * Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>
 *
 * STM32N657 two_enclaves host — REAL TACLeBench "ammunition" enclave.
 *
 * ammunition is the arbitrary-precision integer arithmetic benchmark from
 * tacle-bench/bench/sequential/ammunition. Its .c/.h are vendored verbatim
 * into app/ (arithm.c, ammunition.c, bits.c, ammunition_libc.c + headers) and
 * are NOT modified. The Makefile compiles them with the enclave PIC flags
 * (-fpic -mpic-data-is-text-relative, cortex-m55) and then runs an
 * arm-none-eabi-objcopy pass that renames their .text/.rodata/.data.rel.ro
 * into .app.enclave_code and their .bss into .app.enclave_bss, so the whole
 * benchmark lands inside the EFBC window. ammunition.c also defines its own
 * main(); the objcopy pass redefines that symbol to ammunition_unused_main so
 * it does not collide with the host src/main.c.
 *
 * This wrapper is the single .app.enclave_code.entry symbol. sections.ld pulls
 * .app.enclave_code.entry to offset 0 of the enclave region, so enclave_entry
 * is the address the Secure FSBL jumps to. It runs the same sequence as
 * ammunition's own main():
 *
 *     ammunition_init();      // ammunition_result = 0
 *     ammunition_main();      // result |= bits_test(); result |= arithm_test();
 *     return ammunition_return();   // the checksum
 *
 * When every sub-test passes, the checksum is 0 (golden, verified natively).
 * That value is returned in R0 and read back by the host via
 * umbra_enclave_status(); src/main.c compares it against AMMUNITION_GOLDEN.
 */

#define ENCLAVE_ENTRY __attribute__((section(".app.enclave_code.entry")))

/* Defined in the vendored ammunition.c (renamed sections). */
extern void ammunition_init(void);
extern void ammunition_main(void);
extern int  ammunition_return(void);

int enclave_entry(void) ENCLAVE_ENTRY;

int enclave_entry(void)
{
    ammunition_init();
    ammunition_main();
    return ammunition_return();
}
