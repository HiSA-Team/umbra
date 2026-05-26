/* Override FreeRTOS vStartFirstTask to avoid data-reading from the vector
 * table base address.  On STM32L5 with TrustZone, the IDAU classifies
 * 0x08040000 as Secure, so a NS data read triggers SecureFault even though
 * the SAU marks the region NS (SAU only wins for instruction fetch).
 *
 * The original port code reads VT[0] via VTOR to reset MSP.  We load the
 * initial MSP value from the linker symbol _host_estack instead. */

#include <stdint.h>

extern uint32_t _host_estack;

/* Must match the SVC number in the FreeRTOS port (portmacrocommon.h) */
#define portSVC_START_SCHEDULER    102

void vStartFirstTask( void ) __attribute__(( naked ));

void vStartFirstTask( void )
{
    __asm volatile
    (
        "   .syntax unified                                 \n"
        "                                                   \n"
        "   ldr r0, =_host_estack                           \n" /* Load initial MSP from linker symbol. */
        "   msr msp, r0                                     \n" /* Set the MSP back to the start of the stack. */
        "   cpsie i                                         \n" /* Globally enable interrupts. */
        "   cpsie f                                         \n"
        "   dsb                                             \n"
        "   isb                                             \n"
        "   svc %0                                          \n" /* System call to start the first task. */
        "   nop                                             \n"
        ::"i" ( portSVC_START_SCHEDULER ) : "memory"
    );
}
