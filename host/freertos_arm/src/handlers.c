/* NS fault handlers.  Defined in C (not assembly) so the linker
 * preserves the Thumb interworking bit in vector table data relocations. */

#include <stdint.h>

extern void umbra_debug_print(const char *s);

static char *u32_to_hex_h(uint32_t val, char *buf) {
    const char hex[] = "0123456789ABCDEF";
    buf[0] = '0'; buf[1] = 'x';
    for (int i = 7; i >= 0; i--)
        buf[2 + (7 - i)] = hex[(val >> (i * 4)) & 0xF];
    buf[10] = '\0';
    return buf;
}

void _host_Default_Handler(void)   { for (;;); }
void _host_NMI_Handler(void)       { for (;;); }
void _host_DebugMon_Handler(void)  { for (;;); }
void _host_HardFault_Handler(void) { for (;;); }
void _host_MemManage_Handler(void) { for (;;); }
void _host_BusFault_Handler(void)  { for (;;); }

/* Minimal — just spin. Use GDB to read:
 *   x/1xw 0xE000ED28   (NS CFSR)
 *   info reg            (stacked frame visible via PSP)  */
void _host_UsageFault_Handler(void) { for (;;); }
