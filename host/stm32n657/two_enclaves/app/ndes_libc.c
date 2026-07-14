/*
 * Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>
 *
 * Build helper for the vendored TACLeBench "ndes" enclave — NOT part of the
 * ndes sources (ndes.c is vendored verbatim and never edited).
 *
 * ndes.c initializes several `volatile char/long` arrays with brace lists
 * (e.g. ndes_ipc1_tmp[57], the ip[65]/ipm[65] permutation tables in
 * ndes_des(), the iet[]/ipp[]/is[16][4][9] tables in ndes_cyfun()). At -Os the
 * compiler lowers those from-a-.rodata-constant copies to a call to memcpy().
 * With the enclave built -nostdlib -ffreestanding there is no libc, so memcpy
 * would be an undefined external.
 *
 * The host does have a memcpy (../../common/src/umbra_mem.c) but it is NOT in
 * this host's OBJS, and even if it were, it lives in the host .text at the
 * host VMA — the enclave runs at a dynamically-allocated ESS address with no
 * runtime relocator, so a call into host .text would jump to the wrong place.
 *
 * So we provide memcpy (and memset, in case a future -O level synthesizes it)
 * HERE, compiled with the same enclave PIC flags (-fpic
 * -mpic-data-is-text-relative -fvisibility=hidden) and partial-linked into
 * obj/enclave_combined.o. GCC's synthesized `bl memcpy` then resolves to a
 * PC-relative call to this in-image, position-independent copy that travels
 * with the enclave. --gc-sections drops whichever of the two the reachable
 * ndes code doesn't actually call. This mirrors ammunition's ammunition_libc.c
 * (which supplied ammunition_memcpy/_memset for the same reason).
 *
 * Compiled with -fno-builtin (the enclave CFLAGS), GCC does not recognize the
 * byte-copy loop as the memcpy idiom, so these definitions do not turn into a
 * self-recursive call.
 */

#include <stddef.h>

__attribute__((visibility("hidden")))
void *memcpy(void *dest, const void *src, size_t n)
{
    unsigned char       *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;
    size_t i;
    for (i = 0; i < n; i++)
        d[i] = s[i];
    return dest;
}

__attribute__((visibility("hidden")))
void *memset(void *s, int c, size_t n)
{
    unsigned char *p = (unsigned char *)s;
    size_t i;
    for (i = 0; i < n; i++)
        p[i] = (unsigned char)c;
    return s;
}
