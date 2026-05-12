/* Minimal memset/memcpy for host builds compiled with -nostdlib -fno-builtin.
 * GCC lowers struct copies into calls to these symbols, and FreeRTOS
 * tasks.c / queue.c / heap_4.c call them directly. One copy per binary
 * (linked from host/common/) replaces what was three identical per-host
 * mem.c files. */

#include <stddef.h>

void *memset(void *s, int c, size_t n) {
    unsigned char *p = s;
    while (n--)
        *p++ = (unsigned char)c;
    return s;
}

void *memcpy(void *dest, const void *src, size_t n) {
    unsigned char *d = dest;
    const unsigned char *s = src;
    while (n--)
        *d++ = *s++;
    return dest;
}
