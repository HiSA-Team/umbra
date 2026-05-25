// Minimal libc shim for TACLeBench enclave blobs.
//
// GCC silently generates calls to `memcpy`, `memset`, `memmove`, and
// `__aeabi_memcpy*` family helpers for several patterns:
//   - struct/array assignment (e.g., `volatile char ip[65] = { ... };`)
//   - copying aggregate return values
//   - block clears for stack-resident structs
//
// `-nostdlib` removes the libc that would normally provide them, so the
// linker errors out with "undefined reference to memcpy". This shim
// provides byte-level implementations of the most common ones in
// `._enclave_code` (via -ffunction-sections + the linker script's
// `*(.text.*)` glob). Unused entries get `--gc-sections`'d.
//
// Performance is irrelevant: the enclave's runtime path is dominated by
// crypto + DMA, and the chip is too small for libc anyway.
//
// CFLAGS includes `-nostdinc` (system headers off-limits), so we can't
// `#include <stddef.h>` for size_t. Define it locally — on ARMv8-M
// Cortex-M33 it's `unsigned int` (32-bit), matching the EABI.

typedef unsigned int size_t;

void *memcpy(void *dst, const void *src, size_t n)
{
    unsigned char       *d = (unsigned char       *) dst;
    const unsigned char *s = (const unsigned char *) src;
    while (n-- > 0) {
        *d++ = *s++;
    }
    return dst;
}

void *memset(void *dst, int c, size_t n)
{
    unsigned char *d = (unsigned char *) dst;
    while (n-- > 0) {
        *d++ = (unsigned char) c;
    }
    return dst;
}

void *memmove(void *dst, const void *src, size_t n)
{
    unsigned char       *d = (unsigned char       *) dst;
    const unsigned char *s = (const unsigned char *) src;
    // Forward copy is safe when dst <= src OR dst >= src + n. Backward
    // otherwise. The byte-at-a-time path matches GCC's overlap-handling
    // expectations.
    if (d < s) {
        while (n-- > 0) {
            *d++ = *s++;
        }
    } else if (d > s) {
        d += n; s += n;
        while (n-- > 0) {
            *--d = *--s;
        }
    }
    return dst;
}

// ARM EABI aliases. GCC for `-march=armv8-m.main -mthumb` emits direct
// calls to these instead of `memcpy`/`memset` for some patterns,
// particularly when the source/destination is statically known to be
// aligned. Provide them as direct passthroughs.
void __aeabi_memcpy(void *dst, const void *src, size_t n)
{
    (void) memcpy(dst, src, n);
}
void __aeabi_memcpy4(void *dst, const void *src, size_t n)
{
    (void) memcpy(dst, src, n);
}
void __aeabi_memcpy8(void *dst, const void *src, size_t n)
{
    (void) memcpy(dst, src, n);
}
void __aeabi_memmove(void *dst, const void *src, size_t n)
{
    (void) memmove(dst, src, n);
}
void __aeabi_memset(void *dst, size_t n, int c)
{
    // Note the ARM EABI argument order is (dst, n, c) — different from
    // ISO C's (dst, c, n).
    (void) memset(dst, c, n);
}
void __aeabi_memclr(void *dst, size_t n)
{
    (void) memset(dst, 0, n);
}
void __aeabi_memclr4(void *dst, size_t n)
{
    (void) memset(dst, 0, n);
}
void __aeabi_memclr8(void *dst, size_t n)
{
    (void) memset(dst, 0, n);
}
