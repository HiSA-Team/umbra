/* NS fault handlers.  Defined in C (not assembly) so the linker
 * preserves the Thumb interworking bit in vector table data relocations. */

#include <stdint.h>

extern void umbra_debug_print(const char *s);

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
