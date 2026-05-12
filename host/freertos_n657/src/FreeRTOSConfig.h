#ifndef FREERTOS_CONFIG_H
#define FREERTOS_CONFIG_H

/* Clocks
 *
 * SysTick on Cortex-M55 is driven by the processor clock (= CPU clock, IC1 from
 * PLL1). After Phase G.0 the Umbra FSBL bumps PLL1 to 800 MHz and routes IC1 →
 * CPUCLK at 800 MHz (AXI = 400 MHz, HCLK = 200 MHz). USART1 kernel clock is
 * switched to HSI=64 MHz before the bump (insulated from PLL1).
 */
#define configCPU_CLOCK_HZ          ( 800000000UL ) /* N657 CPU clock post-G.0 */
#define configTICK_RATE_HZ          ( ( TickType_t ) 1000 )

/* Scheduler */
#define configUSE_PREEMPTION        1
#define configMAX_PRIORITIES        ( 5 )
#define configUSE_TIME_SLICING      1
#define configIDLE_SHOULD_YIELD     1

/* Memory */
#define configMINIMAL_STACK_SIZE    ( ( unsigned short ) 128 )
#define configTOTAL_HEAP_SIZE       ( ( size_t ) 32768 )
#define configMAX_TASK_NAME_LEN     ( 16 )

/* Features — keep minimal */
#define configUSE_MUTEXES           0
#define configUSE_RECURSIVE_MUTEXES 0
#define configUSE_COUNTING_SEMAPHORES 0
#define configUSE_TASK_NOTIFICATIONS 1
#define configUSE_QUEUE_SETS        0
#define configUSE_TIMERS            0
#define configUSE_CO_ROUTINES       0

/* Hooks */
#define configUSE_IDLE_HOOK         0
#define configUSE_TICK_HOOK         0
#define configUSE_MALLOC_FAILED_HOOK 0
#define configCHECK_FOR_STACK_OVERFLOW 2

/* ARMv8-M / TrustZone — NTZ port */
#define configENABLE_TRUSTZONE      0
#define configENABLE_MPU            0
#define configENABLE_FPU            0
#define configRUN_FREERTOS_SECURE_ONLY 0

/* Sizes */
#define configUSE_16_BIT_TICKS      0
#define configUSE_PORT_OPTIMISED_TASK_SELECTION 0

/* API includes */
#define INCLUDE_vTaskDelete         1
#define INCLUDE_vTaskDelay          1
#define INCLUDE_vTaskSuspend        1
#define INCLUDE_xTaskGetSchedulerState 1

/* ISR handler name mapping — these must match the names in startup.s vector table */
#define vPortSVCHandler     SVC_Handler
#define xPortPendSVHandler  PendSV_Handler
#define xPortSysTickHandler SysTick_Handler

/* Interrupt priority configuration for Cortex-M55 (ARMv8-M Main).
 * STM32N657 implements 3 priority bits (8 levels, shifted to top 5 bits).
 * __NVIC_PRIO_BITS = 3 on this platform (same as L5). */
#define configPRIO_BITS             3
#define configLIBRARY_LOWEST_INTERRUPT_PRIORITY       7
#define configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY   5
#define configKERNEL_INTERRUPT_PRIORITY        ( configLIBRARY_LOWEST_INTERRUPT_PRIORITY << ( 8 - configPRIO_BITS ) )
#define configMAX_SYSCALL_INTERRUPT_PRIORITY   ( configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY << ( 8 - configPRIO_BITS ) )

#endif /* FREERTOS_CONFIG_H */
