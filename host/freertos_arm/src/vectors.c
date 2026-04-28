/* NS vector table in SRAM.
 *
 * On STM32L5, the IDAU classifies 0x08040000 (NS flash) as Secure for
 * DATA reads.  The SAU override only wins for instruction fetch.  Since
 * the Cortex-M33 vector table fetch is architecturally a data read, the
 * vector table MUST live in genuinely NS memory (SRAM_0, 0x20000000+).
 *
 * The array is non-const so it lands in .data (SRAM, initialized from
 * flash by the startup .data copy loop).  VTOR is set to its SRAM
 * address in main() before FreeRTOS starts.
 *
 * VTOR requires alignment to 2^ceil(log2(N*4)) where N = number of
 * implemented exceptions.  STM32L5 has 125 entries → 512-byte alignment. */

#include <stdint.h>

/* Linker-defined symbols */
extern uint32_t _host_estack;

/* Handlers defined in startup.s */
extern void _host_Reset_Handler(void);
extern void _host_NMI_Handler(void);
extern void _host_HardFault_Handler(void);
extern void _host_MemManage_Handler(void);
extern void _host_BusFault_Handler(void);
extern void _host_UsageFault_Handler(void);
extern void _host_DebugMon_Handler(void);

/* FreeRTOS handlers (renamed via FreeRTOSConfig.h #defines) */
extern void SVC_Handler(void);
extern void PendSV_Handler(void);
extern void SysTick_Handler(void);

/* Use void* to preserve Thumb-interworking bit (LSB=1) for function
 * addresses.  Casting to uint32_t strips the Thumb bit for assembly-
 * defined symbols, causing ARM-mode faults on exception entry. */
__attribute__((aligned(512), used))
void *__vector_table[16] = {
    (void *)&_host_estack,              /* 0x00: Initial MSP */
    (void *)_host_Reset_Handler,        /* 0x04: Reset */
    (void *)_host_NMI_Handler,          /* 0x08: NMI */
    (void *)_host_HardFault_Handler,    /* 0x0C: HardFault */
    (void *)_host_MemManage_Handler,    /* 0x10: MemManage */
    (void *)_host_BusFault_Handler,     /* 0x14: BusFault */
    (void *)_host_UsageFault_Handler,   /* 0x18: UsageFault */
    (void *)0,                          /* 0x1C: Reserved */
    (void *)0,                          /* 0x20: Reserved */
    (void *)0,                          /* 0x24: Reserved */
    (void *)0,                          /* 0x28: Reserved */
    (void *)SVC_Handler,                /* 0x2C: SVCall */
    (void *)_host_DebugMon_Handler,     /* 0x30: DebugMon */
    (void *)0,                          /* 0x34: Reserved */
    (void *)PendSV_Handler,             /* 0x38: PendSV */
    (void *)SysTick_Handler,            /* 0x3C: SysTick */
};
