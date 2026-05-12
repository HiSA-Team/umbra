/*
 * STM32N657 NS host — Phase E.4a real-loader test.
 *
 * The enclave (fibonacci.c) is linked into ._enclave_code by the host's
 * linker at offset 0x10000 from AXISRAM3_NS base. Its UMBR manifest
 * (.app.enclave_header below) lives just before. The whole binary is
 * flashed verbatim to XSPI2 0x70080000 — so the enclave header sits at
 * flash address 0x70090000 (outside MCE2 region 1 which starts at
 * 0x700A0000, plaintext access from Secure CPU).
 *
 * Host doesn't access XSPI2 directly (RISAF12 default-Secure blocks NS
 * reads); it computes the flash address from the linker-defined
 * _enclave_start symbol and passes it to umbra_enclave_create. The Secure
 * FSBL reads the header + blocks from XSPI2 via its own memory-mapped
 * access, so RISAF12 stays at its default config.
 *
 * Expected UART:
 *   [USER] Hello Non-Secure World!
 *   [USER] Enclave created
 *   [USER] Enclave preempted (SysTick)              ×N
 *   [ESS-MISS] block 00000001 loaded                 (when the enclave
 *                                                     spans >1 block)
 *   [USER] Enclave terminated! R0=0x72CA33A8
 *   [USER] All enclaves done
 */

#include <stdint.h>

#include "fibonacci.h"
#include "umbra_hex.h"

extern void          umbra_debug_print(const char *s);
extern unsigned int  umbra_enclave_create(unsigned int base_addr);
extern unsigned int  umbra_enclave_enter(unsigned int enclave_id);
extern unsigned int  umbra_enclave_status(unsigned int enclave_id);

#define STATUS_SUSPENDED  3
#define STATUS_TERMINATED 4
#define STATUS_FAULTED    5

#define HOST_FLASH_BASE   0x70080000u
#define HOST_RAM_BASE     0x24000000u

/* Linker-defined symbol: start of ._enclave_header section. The host's
 * linker places this at VMA 0x24010000 (offset 0x10000 from AXISRAM3_NS
 * base). The corresponding flash address is HOST_FLASH_BASE + offset.
 *
 * Path B-lite: enclave is flashed in plaintext at 0x70090000 (= header).
 * Phase E.4c MCE2 encryption is deferred (see boot crate's oracle.rs
 * doc + memory note `project_n657_mce2_is_noekeon.md`). The
 * `_enclave_ciphertext_flash_addr` linker symbol stays PROVIDE'd by
 * sections.ld but is unused. */
extern uint8_t _enclave_start;

/* UMBR header — UmbraEnclaveHeader struct laid out in
 * `.app.enclave_header`. protect_enclave.py post-link patches the HMAC
 * field with the chained-measurement final value. The other fields
 * stay as we set them here (efbc_size and code_size get re-computed by
 * protect_enclave.py based on the actual ._enclave_code size). */
__attribute__((section(".app.enclave_header")))
const uint8_t enclave_header[48] = {
    0x55, 0x42, 0x4D, 0x52, /* magic = 0x524D4255 ("UMBR" little-endian) */
    0x01,                   /* trust_level = 1 (Trusted) */
    0x00,                   /* reserved0 */
    0x02, 0x00,             /* efbc_size = 2 (placeholder) */
    0x00, 0x00,             /* ess_blocks */
    0x40, 0x02, 0x00, 0x00, /* code_size = 0x240 = 576 bytes (2 * 288) */
    0x00, 0x00,             /* reserved1 */
    /* hmac (32 bytes) — patched by protect_enclave.py */
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
};

int main(void) {
    umbra_debug_print("[USER] Hello Non-Secure World!\n");

    /* Compute the enclave header's flash address from the linker-known
     * binary offset. Equivalent to scanning XSPI2 for UMBR magic, but
     * doesn't require RISAF12 to be opened to NS. */
    uint32_t flash_offset = (uint32_t)(uintptr_t)&_enclave_start - HOST_RAM_BASE;
    uint32_t flash_addr   = HOST_FLASH_BASE + flash_offset;

    char hex_buf[11];
    unsigned int id = umbra_enclave_create(flash_addr);
    if (id >= 0xFFFFFFF0) {
        umbra_debug_print("[USER] Enclave creation REJECTED, ret=");
        umbra_debug_print(umbra_u32_to_hex(id, hex_buf));
        umbra_debug_print("\n");
        while (1) { __asm volatile("wfi"); }
    }
    umbra_debug_print("[USER] Enclave created\n");

    /* Re-entry loop until terminated/faulted. */
    for (;;) {
        unsigned int ret = umbra_enclave_enter(id);
        unsigned int status = (ret >> 8) & 0xFF;

        if (status == STATUS_SUSPENDED) {
            umbra_debug_print("[USER] Enclave preempted (SysTick)\n");
            continue;
        } else if (status == STATUS_TERMINATED) {
            unsigned int result = umbra_enclave_status(id);
            umbra_debug_print("[USER] Enclave terminated! R0=");
            umbra_debug_print(umbra_u32_to_hex(result, hex_buf));
            umbra_debug_print("\n");
            break;
        } else if (status == STATUS_FAULTED) {
            umbra_debug_print("[USER] Enclave faulted, ret=");
            umbra_debug_print(umbra_u32_to_hex(ret, hex_buf));
            umbra_debug_print("\n");
            break;
        } else {
            umbra_debug_print("[USER] Enclave unexpected status, ret=");
            umbra_debug_print(umbra_u32_to_hex(ret, hex_buf));
            umbra_debug_print("\n");
            break;
        }
    }

    umbra_debug_print("[USER] All enclaves done\n");

    while (1) {
        __asm volatile("wfi");
    }
    return 0;
}
