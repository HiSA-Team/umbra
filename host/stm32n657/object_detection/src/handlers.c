/* NS fault handlers.  Defined in C (not assembly) so the linker
 * preserves the Thumb interworking bit in vector table data relocations. */

#include <stdint.h>

#include "umbra_hex.h"

extern void umbra_debug_print(const char *s);

/* Print which fault hit and the NS CFSR (sub-type bits), then halt. */
static void halt_with_msg(const char *name) {
    char buf[12];
    uint32_t cfsr = *(volatile uint32_t *)0xE000ED28u;
    umbra_debug_print("\n[FAULT] ");
    umbra_debug_print(name);
    umbra_debug_print(" — CFSR = ");
    umbra_debug_print(umbra_u32_to_hex(cfsr, buf));
    umbra_debug_print("\n");
    for (;;) {}
}

void _host_Default_Handler(void)   { halt_with_msg("Default(unknown IRQ)"); }
void _host_NMI_Handler(void)       { halt_with_msg("NMI"); }
void _host_DebugMon_Handler(void)  { halt_with_msg("DebugMon"); }
void _host_HardFault_Handler(void) { halt_with_msg("HardFault"); }
void _host_MemManage_Handler(void) { halt_with_msg("MemManage"); }
void _host_BusFault_Handler(void)  { halt_with_msg("BusFault"); }
void _host_UsageFault_Handler(void){ halt_with_msg("UsageFault"); }
