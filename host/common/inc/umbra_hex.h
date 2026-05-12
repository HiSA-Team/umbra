#ifndef UMBRA_HOST_COMMON_HEX_H
#define UMBRA_HOST_COMMON_HEX_H

#include <stdint.h>

/* Format `val` into `buf` as the 10-char NUL-terminated string
 * "0xXXXXXXXX" and return `buf`. `buf` must have at least 11 bytes.
 * Used by every host's UART debug printer; centralises what was 4-6
 * near-identical copies. */
char *umbra_u32_to_hex(uint32_t val, char *buf);

#endif
