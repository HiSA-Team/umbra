#include "FreeRTOS.h"
#include "task.h"
#include "fibonacci.h"
#include "umbra_hex.h"
#include <stdint.h>

/* --- Enclave header (same as bare_metal (L5)) ----------------------------- */
__attribute__((section(".app.enclave_header")))
const uint8_t enclave_header[48] = {
    0x55, 0x42, 0x4D, 0x52, // Magic: "UMBR"
    0x01,                    // Trust_level (Trusted)
    0x00,                    // reserved
    0x01, 0x00,              // efbc_size (1)
    0x00, 0x00,              // ess_blocks
    0x00, 0x04, 0x00, 0x00,  // code_size (1024 bytes)
    0x00, 0x00,              // reserved
    // HMAC (32 bytes) — placeholder, overwritten by protect_enclave.py
    0x37, 0x49, 0x09, 0xC7, 0x44, 0xB8, 0xD9, 0xA6, 0x9E, 0x8C, 0x2C, 0xF3,
    0x41, 0x64, 0x0E, 0x57, 0x55, 0x32, 0xC0, 0xB7, 0xDF, 0x49, 0x83, 0x98,
    0xCC, 0xC8, 0x30, 0x59, 0x03, 0xCC, 0xD9, 0x36};

/* --- NSC veneer externs -------------------------------------------------- */
extern unsigned int umbra_enclave_create(unsigned int base_addr);
extern void umbra_debug_print(const char *s);
extern unsigned int umbra_enclave_enter(unsigned int enclave_id);
extern unsigned int umbra_enclave_status(unsigned int enclave_id);

extern uint8_t _enclave_start;

/* --- Constants ----------------------------------------------------------- */
#define NS_FLASH_END    0x08080000
#define PAGE_SIZE       0x1000
#define UMBRA_MAGIC     0x524D4255
#define MAX_ENCLAVES    4

#define STATUS_SUSPENDED  3
#define STATUS_TERMINATED 4
#define STATUS_FAULTED    5

/* --- Tick drift instrumentation (DWT-based) ----------------------------- */
typedef struct {
    uint32_t max_delta_cycles;
    uint32_t buckets[6];   /* <1.5x, <2x, <5x, <10x, <100x, >=100x EXPECTED */
    uint32_t total_ticks;
} drift_stats_t;

static drift_stats_t g_drift;

#define EXPECTED_CYC_PER_TICK 110000UL   /* 110 MHz / 1 kHz */

/* DWT MMIO — declared here (not next to SCB_VTOR below) so vApplicationTickHook
 * can reference DWT_CYCCNT. The DWT block is NS-accessible on L552. */
#define DEMCR       (*(volatile uint32_t *)0xE000EDFC)
#define DWT_CTRL    (*(volatile uint32_t *)0xE0001000)
#define DWT_CYCCNT  (*(volatile uint32_t *)0xE0001004)
#define DWT_TRCENA  (1u << 24)
#define DWT_CYCCNTENA 1u

/* --- FreeRTOS task: scan, create, and run enclaves ----------------------- */
static void vEnclaveTask(void *pvParameters) {
    (void)pvParameters;

    umbra_debug_print("[FREERTOS] Enclave task started\n");

    /* Scan NS flash for enclave headers */
    unsigned int enclave_ids[MAX_ENCLAVES];
    unsigned int enclave_count = 0;

    uint32_t scan_start =
        ((uint32_t)(uintptr_t)&_enclave_start) & ~(PAGE_SIZE - 1);

    for (uint32_t addr = scan_start;
         addr < NS_FLASH_END && enclave_count < MAX_ENCLAVES;
         addr += PAGE_SIZE) {
        uint32_t magic = *(volatile uint32_t *)(uintptr_t)addr;
        if (magic == UMBRA_MAGIC) {
            unsigned int id = umbra_enclave_create(addr);
            if (id < 0xFFFFFFF0) {
                enclave_ids[enclave_count++] = id;
                taskENTER_CRITICAL();
                umbra_debug_print("[FREERTOS] Enclave created\n");
                taskEXIT_CRITICAL();
            } else {
                taskENTER_CRITICAL();
                umbra_debug_print("[FREERTOS] Enclave creation REJECTED\n");
                taskEXIT_CRITICAL();
            }
        }
    }

    if (enclave_count == 0) {
        taskENTER_CRITICAL();
        umbra_debug_print("[FREERTOS] No enclaves found\n");
        taskEXIT_CRITICAL();
        vTaskDelete(NULL);
        return;
    }

    /* Run enclaves until all terminate or fault */
    unsigned int active = enclave_count;
    while (active > 0) {
        for (unsigned int i = 0; i < enclave_count; i++) {
            if (enclave_ids[i] == 0)
                continue;

            unsigned int ret = umbra_enclave_enter(enclave_ids[i]);
            unsigned int status = (ret >> 8) & 0xFF;
            char hex_buf[11];

            if (status == STATUS_SUSPENDED) {
                taskENTER_CRITICAL();
                umbra_debug_print("[FREERTOS] Enclave preempted (SysTick)\n");
                taskEXIT_CRITICAL();
            } else if (status == STATUS_TERMINATED) {
                taskENTER_CRITICAL();
                unsigned int full_result = umbra_enclave_status(enclave_ids[i]);
                umbra_debug_print("[FREERTOS] Enclave terminated! R0=");
                umbra_debug_print(umbra_u32_to_hex(full_result, hex_buf));
                umbra_debug_print("\n");
                taskEXIT_CRITICAL();
                enclave_ids[i] = 0;
                active--;
            } else if (status == STATUS_FAULTED) {
                taskENTER_CRITICAL();
                umbra_debug_print("[FREERTOS] Enclave faulted — ret=");
                umbra_debug_print(umbra_u32_to_hex(ret, hex_buf));
                umbra_debug_print("\n");
                taskEXIT_CRITICAL();
                enclave_ids[i] = 0;
                active--;
            }
        }
    }

    taskENTER_CRITICAL();
    umbra_debug_print("[FREERTOS] All enclaves done\n");
    taskEXIT_CRITICAL();

    /* Dump drift stats for the harness (parsed by tools/test_taclebench.sh). */
    taskENTER_CRITICAL();
    {
        char buf[11];
        umbra_debug_print("[DRIFT] max=");
        umbra_debug_print(umbra_u32_to_hex(g_drift.max_delta_cycles, buf));
        umbra_debug_print(" total=");
        umbra_debug_print(umbra_u32_to_hex(g_drift.total_ticks, buf));
        umbra_debug_print("\n[DRIFT] b0=");
        umbra_debug_print(umbra_u32_to_hex(g_drift.buckets[0], buf));
        umbra_debug_print(" b1=");
        umbra_debug_print(umbra_u32_to_hex(g_drift.buckets[1], buf));
        umbra_debug_print(" b2=");
        umbra_debug_print(umbra_u32_to_hex(g_drift.buckets[2], buf));
        umbra_debug_print(" b3=");
        umbra_debug_print(umbra_u32_to_hex(g_drift.buckets[3], buf));
        umbra_debug_print(" b4=");
        umbra_debug_print(umbra_u32_to_hex(g_drift.buckets[4], buf));
        umbra_debug_print(" b5=");
        umbra_debug_print(umbra_u32_to_hex(g_drift.buckets[5], buf));
        umbra_debug_print("\n");
    }
    taskEXIT_CRITICAL();

    vTaskDelete(NULL);
}

/* --- FreeRTOS task: visible heartbeat for composability evidence --------- */
static void vHeartbeatTask(void *pvParameters) {
    (void)pvParameters;
    char buf[11];
    /* 100 ms FreeRTOS-time → ~325 ms wall under enclave load. Effective NS
     * tick rate drops to ~250-300 Hz during enclave execution because
     * NS_SysTick is masked while in Secure code (Cortex-M33 single-pending-bit
     * coalesces missed ticks into one). */
    const TickType_t period = pdMS_TO_TICKS(100);
    for (;;) {
        TickType_t t = xTaskGetTickCount();
        umbra_debug_print("[HEARTBEAT t=");
        umbra_debug_print(umbra_u32_to_hex((unsigned int)t, buf));
        umbra_debug_print("]\n");
        vTaskDelay(period);
    }
}

/* --- FreeRTOS application tick hook (DWT drift accounting; ISR context) --- */
void vApplicationTickHook(void) {
    static uint32_t last = 0;
    uint32_t now = DWT_CYCCNT;
    uint32_t delta = now - last;          /* u32 subtraction is wraparound-safe */
    last = now;

    g_drift.total_ticks++;
    if (delta > g_drift.max_delta_cycles) g_drift.max_delta_cycles = delta;

    if      (delta < EXPECTED_CYC_PER_TICK * 3 / 2) g_drift.buckets[0]++;
    else if (delta < EXPECTED_CYC_PER_TICK * 2)     g_drift.buckets[1]++;
    else if (delta < EXPECTED_CYC_PER_TICK * 5)     g_drift.buckets[2]++;
    else if (delta < EXPECTED_CYC_PER_TICK * 10)    g_drift.buckets[3]++;
    else if (delta < EXPECTED_CYC_PER_TICK * 100)   g_drift.buckets[4]++;
    else                                            g_drift.buckets[5]++;
}

/* --- FreeRTOS stack overflow hook ---------------------------------------- */
void vApplicationStackOverflowHook(TaskHandle_t xTask, char *pcTaskName) {
    (void)xTask;
    (void)pcTaskName;
    umbra_debug_print("[FREERTOS] STACK OVERFLOW!\n");
    while (1) {}
}

/* --- Entry point --------------------------------------------------------- */

#define SCB_VTOR  (*(volatile uint32_t *)0xE000ED08)
#define SCB_SHCSR (*(volatile uint32_t *)0xE000ED24)

/* SRAM vector table — defined in vectors.c */
extern void *__vector_table[];

int main(void) {
    /* Set VTOR to SRAM vector table and enable NS fault handlers */
    SCB_VTOR = (uint32_t)(uintptr_t)__vector_table;
    SCB_SHCSR |= (1 << 16) | (1 << 17) | (1 << 18);

    /* Enable DWT.CYCCNT for vApplicationTickHook drift instrumentation.
     * DWT is NS-accessible on L552 (not gated by GTZC). */
    DEMCR     |= DWT_TRCENA;
    DWT_CYCCNT = 0;
    DWT_CTRL  |= DWT_CYCCNTENA;

    umbra_debug_print("[FREERTOS] Starting FreeRTOS demo\n");

    xTaskCreate(
        vEnclaveTask,       /* task function */
        "Enclave",          /* name (debug only) */
        512,                /* stack depth in words (2KB) */
        NULL,               /* parameters */
        1,                  /* priority (above idle) */
        NULL                /* handle (not needed) */
    );

    xTaskCreate(
        vHeartbeatTask,
        "Heartbeat",
        256,        /* stack depth in words (1 KB) */
        NULL,
        2,          /* priority 2 — higher than vEnclaveTask (1), preempts mid-run */
        NULL
    );

    vTaskStartScheduler();

    /* Should never reach here */
    umbra_debug_print("[FREERTOS] ERROR: scheduler returned\n");
    while (1) {}
    return 0;
}
