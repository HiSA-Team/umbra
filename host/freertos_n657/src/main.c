#include "FreeRTOS.h"
#include "task.h"
#include "fibonacci.h"
#include "umbra_hex.h"
#include <stddef.h>
#include <stdint.h>

/* --- Enclave header (same as bare_metal_n657) ---------------------------- */
__attribute__((section(".app.enclave_header")))
const uint8_t enclave_header[48] = {
    0x55, 0x42, 0x4D, 0x52, // Magic: "UMBR"
    0x01,                    // Trust_level (Trusted)
    0x00,                    // reserved
    0x02, 0x00,              // efbc_size (2 — placeholder, patched by protect_enclave.py)
    0x00, 0x00,              // ess_blocks
    0x40, 0x02, 0x00, 0x00,  // code_size (576 bytes — patched)
    0x00, 0x00,              // reserved
    // HMAC (32 bytes) — overwritten by protect_enclave.py
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
};

/* --- NSC veneer externs -------------------------------------------------- */
extern unsigned int umbra_enclave_create(unsigned int base_addr);
extern void umbra_debug_print(const char *s);
extern unsigned int umbra_enclave_enter(unsigned int enclave_id);
extern unsigned int umbra_enclave_status(unsigned int enclave_id);

extern uint8_t _enclave_start;

/* --- Constants ----------------------------------------------------------- */
/* N657 host bin lives in AXISRAM1 NS view (0x24000000-0x240E0000). The
 * enclave header is at 0x24010000 in RAM; on flash it's at the matching
 * offset 0x70090000 (= HOST_FLASH_BASE + 0x10000). Scan AXISRAM1 NS for
 * UMBR magic, but pass the FLASH address to enclave_create — the Secure FSBL
 * reads the enclave from XSPI2 directly (NS can't via RISAF12). */
#define HOST_FLASH_BASE 0x70080000u
#define HOST_RAM_BASE   0x24000000u
#define HOST_RAM_END    (HOST_RAM_BASE + 0xE0000u)
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

    /* Scan AXISRAM1 NS for enclave headers */
    unsigned int enclave_ids[MAX_ENCLAVES];
    unsigned int enclave_count = 0;

    uint32_t scan_start =
        ((uint32_t)(uintptr_t)&_enclave_start) & ~(PAGE_SIZE - 1);

    for (uint32_t addr = scan_start;
         addr < HOST_RAM_END && enclave_count < MAX_ENCLAVES;
         addr += PAGE_SIZE) {
        uint32_t magic = *(volatile uint32_t *)(uintptr_t)addr;
        if (magic == UMBRA_MAGIC) {
            /* Convert AXISRAM1 NS scan address to its XSPI2 flash twin —
             * the FSBL reads the enclave via memory-mapped XSPI2, not via
             * the NS-aliased RAM copy the host scans. */
            uint32_t flash_addr = HOST_FLASH_BASE + (addr - HOST_RAM_BASE);
            unsigned int id = umbra_enclave_create(flash_addr);
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
                umbra_debug_print(umbra_u32_to_hex(full_result, hex_buf));
                umbra_debug_print("\n");
                enclave_ids[i] = 0;
                active--;
            } else if (status == STATUS_FAULTED) {
                umbra_debug_print("[FREERTOS] Enclave faulted \xe2\x80\x94 ret=");
                umbra_debug_print(umbra_u32_to_hex(ret, hex_buf));
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

#define SCB_SHCSR (*(volatile uint32_t *)0xE000ED24)

int main(void) {
    /* VTOR_NS already set by the Secure FSBL to 0x24000000 (vector table
     * at AXISRAM1 NS base — no SCB_VTOR write needed here, unlike the L5
     * port that reads its vectors from a SRAM-located array). Enable NS
     * fault handlers (MemManage / BusFault / UsageFault). */
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
