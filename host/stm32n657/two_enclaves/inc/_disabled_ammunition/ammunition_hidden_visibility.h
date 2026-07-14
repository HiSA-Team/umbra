/*
 * Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>
 *
 * Build helper for the vendored TACLeBench "ammunition" enclave — NOT part
 * of the ammunition sources (which are vendored verbatim and never edited).
 *
 * ammunition is compiled Position-Independent with -mpic-data-is-text-relative
 * so all global reads/writes become PC-relative (data lives in the image).
 * That works for globals whose visibility GCC can prove to be local, which
 * -fvisibility=hidden gives us for symbols DEFINED in each translation unit.
 *
 * It does NOT cover a cross-TU `extern` reference: ammunition.c reads
 * `extern int ammunition_overflow_bit;` (defined in arithm.c) via arithm.h,
 * and an extern declaration with default visibility forces GCC to route the
 * access through the GOT (R_ARM_GOT32). The N657 two_enclaves enclave model
 * has no runtime GOT relocator, so any GOT reference would fault.
 *
 * This header, force-included (-include) ahead of the ammunition sources,
 * re-declares the two cross-TU globals with hidden visibility. GCC keeps the
 * first-seen visibility, so the later default-visibility declarations in
 * arithm.h / the .c files inherit `hidden`, and the accesses become plain
 * PC-relative text-relative loads (no GOT). Verified: this drops the GOT
 * relocation count for the ammunition objects to zero.
 */
#ifndef UMBRA_N657_AMMUNITION_HIDDEN_VISIBILITY_H
#define UMBRA_N657_AMMUNITION_HIDDEN_VISIBILITY_H

extern int ammunition_overflow_bit __attribute__((visibility("hidden")));
extern int ammunition_result       __attribute__((visibility("hidden")));

#endif /* UMBRA_N657_AMMUNITION_HIDDEN_VISIBILITY_H */
