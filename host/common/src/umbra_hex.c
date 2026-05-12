#include "umbra_hex.h"

char *umbra_u32_to_hex(uint32_t val, char *buf) {
    static const char hex[] = "0123456789ABCDEF";
    buf[0] = '0';
    buf[1] = 'x';
    for (int i = 7; i >= 0; i--) {
        buf[2 + (7 - i)] = hex[(val >> (i * 4)) & 0xF];
    }
    buf[10] = '\0';
    return buf;
}
