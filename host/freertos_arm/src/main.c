#include "FreeRTOS.h"
#include "task.h"
#include "fibonacci.h"
#include <stdint.h>

/* --- Minimal hex printer (no printf) ------------------------------------ */
static char *u32_to_hex(uint32_t val, char *buf) {
    const char hex[] = "0123456789ABCDEF";
    buf[0] = '0';
    buf[1] = 'x';
    for (int i = 7; i >= 0; i--) {
        buf[2 + (7 - i)] = hex[(val >> (i * 4)) & 0xF];
    }
    buf[10] = '\0';
    return buf;
}

/* --- Enclave header (same as bare_metal_arm) ----------------------------- */
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
extern unsigned int umbra_tee_create(unsigned int base_addr);
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
            unsigned int id = umbra_tee_create(addr);
            if (id < 0xFFFFFFF0) {
                enclave_ids[enclave_count++] = id;
                umbra_debug_print("[FREERTOS] Enclave created\n");
            } else {
                umbra_debug_print("[FREERTOS] Enclave creation REJECTED\n");
            }
        }
    }

    if (enclave_count == 0) {
        umbra_debug_print("[FREERTOS] No enclaves found\n");
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
                umbra_debug_print("[FREERTOS] Enclave preempted (SysTick)\n");
            } else if (status == STATUS_TERMINATED) {
                unsigned int full_result = umbra_enclave_status(enclave_ids[i]);
                umbra_debug_print("[FREERTOS] Enclave terminated! R0=");
                umbra_debug_print(u32_to_hex(full_result, hex_buf));
                umbra_debug_print("\n");
                enclave_ids[i] = 0;
                active--;
            } else if (status == STATUS_FAULTED) {
                umbra_debug_print("[FREERTOS] Enclave faulted — ret=");
                umbra_debug_print(u32_to_hex(ret, hex_buf));
                umbra_debug_print("\n");
                enclave_ids[i] = 0;
                active--;
            }
        }
    }

    umbra_debug_print("[FREERTOS] All enclaves done\n");
    vTaskDelete(NULL);
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

    umbra_debug_print("[FREERTOS] Starting FreeRTOS demo\n");

    xTaskCreate(
        vEnclaveTask,       /* task function */
        "Enclave",          /* name (debug only) */
        512,                /* stack depth in words (2KB) */
        NULL,               /* parameters */
        1,                  /* priority (above idle) */
        NULL                /* handle (not needed) */
    );

    vTaskStartScheduler();

    /* Should never reach here */
    umbra_debug_print("[FREERTOS] ERROR: scheduler returned\n");
    while (1) {}
    return 0;
}
