/*
 * Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>
 *
 * STM32N657 two_enclaves NS host — runs TWO real enclaves SEQUENTIALLY in one
 * boot (Phase 3.1, foundation for the later inter-enclave overlay).
 *
 * The two enclaves are separate standalone protected blobs flashed to XSPI2 at
 * distinct offsets (see the Makefile + tools/flash_n657.sh):
 *
 *     ammunition   TACLeBench arbitrary-precision integer arithmetic (~60 blocks)
 *                  flashed at XSPI2 0x700A0000, golden R0 = 0x00000000
 *     ndes         TACLeBench DES symmetric cipher (~20 blocks)
 *                  flashed at XSPI2 0x700C0000, golden R0 = 0x00000000
 *
 * This host is PURE host code — it embeds NO enclave. It creates + runs each
 * blob one at a time:
 *
 *     create(ammunition_flash_addr) -> enter-loop (handle STATUS_SUSPENDED
 *         re-entry) until STATUS_TERMINATED -> check R0 -> "ammunition PASS/FAIL"
 *     create(ndes_flash_addr)       -> enter-loop -> "ndes PASS/FAIL"
 *     "All enclaves done"
 *
 * Both blobs' enclaves link against the same EFBC runtime base (ORIGIN 0x0,
 * PIC) and overlay at 0x340E0000 at runtime — the kernel loads each enclave's
 * blocks to its allocated ESS window. For the two to run back-to-back inside
 * the tight 16 KB EFBC window (60 + 20 > 64 blocks), the FIRST enclave's EFBC
 * slots must be FREED when it terminates so the second `create` fits.
 *
 * The host does NOT scan XSPI2 for the UMBR magic (RISAF12 default-Secure
 * blocks NS reads of XSPI2); it passes the known flash addresses directly. The
 * Secure FSBL reads each header + blocks from XSPI2 via its own memory-mapped
 * access.
 *
 * Expected UART:
 *   [USER] Hello Non-Secure World!
 *   [USER] --- enclave 1/2: ammunition ---
 *   [USER] Enclave created
 *   [USER] Enclave preempted (SysTick)              (x N, if preempted)
 *   [USER] Enclave terminated! R0=0x00000000
 *   [USER] ammunition PASS
 *   [USER] --- enclave 2/2: ndes ---
 *   [USER] Enclave created
 *   [USER] Enclave terminated! R0=0x00000000
 *   [USER] ndes PASS
 *   [USER] All enclaves done
 */

#include <stdint.h>

#include "umbra_hex.h"

/* Golden checksums — both benches return 0 on the FIPS/known-answer result.
 * Verified natively (host clang/gcc, -O0 and -O2). */
#define AMMUNITION_GOLDEN 0x00000000u
#define NDES_GOLDEN       0x00000000u

/* Flash addresses of the two standalone blobs (XSPI2, memory-mapped at
 * 0x70000000). Must match the offsets tools/flash_n657.sh writes them to.
 * Non-overlapping: host ~71 KB at 0x70080000; ammunition ~17 KB at
 * 0x700A0000; ndes ~6 KB at 0x700C0000. All within the 1 MB flash_n657.sh
 * erases (0x70000000..0x70100000) and below the MCE2 region (0x70500000). */
#define AMMUNITION_FLASH_ADDR 0x700A0000u
#define NDES_FLASH_ADDR       0x700C0000u

#define STATUS_SUSPENDED  3
#define STATUS_TERMINATED 4
#define STATUS_FAULTED    5

extern void          umbra_debug_print(const char *s);
extern unsigned int  umbra_enclave_create(unsigned int base_addr);
extern unsigned int  umbra_enclave_enter(unsigned int enclave_id);
extern unsigned int  umbra_enclave_status(unsigned int enclave_id);

/* Create one enclave from its flash address, run it to termination (handling
 * SysTick-preemption re-entry), then compare R0 against the golden value.
 * Prints "<name> PASS" / "<name> FAIL". Returns 1 on PASS, 0 otherwise. */
static int run_enclave(const char *name, unsigned int flash_addr,
                       unsigned int golden) {
    char hex_buf[11];

    unsigned int id = umbra_enclave_create(flash_addr);
    if (id >= 0xFFFFFFF0u) {
        umbra_debug_print("[USER] Enclave creation REJECTED, ret=");
        umbra_debug_print(umbra_u32_to_hex(id, hex_buf));
        umbra_debug_print("\n");
        umbra_debug_print("[USER] ");
        umbra_debug_print(name);
        umbra_debug_print(" FAIL (create rejected)\n");
        return 0;
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
            if (result == golden) {
                umbra_debug_print("[USER] ");
                umbra_debug_print(name);
                umbra_debug_print(" PASS\n");
                return 1;
            }
            umbra_debug_print("[USER] ");
            umbra_debug_print(name);
            umbra_debug_print(" FAIL (expected R0=");
            umbra_debug_print(umbra_u32_to_hex(golden, hex_buf));
            umbra_debug_print(")\n");
            return 0;
        } else if (status == STATUS_FAULTED) {
            umbra_debug_print("[USER] Enclave faulted, ret=");
            umbra_debug_print(umbra_u32_to_hex(ret, hex_buf));
            umbra_debug_print("\n");
            umbra_debug_print("[USER] ");
            umbra_debug_print(name);
            umbra_debug_print(" FAIL (faulted)\n");
            return 0;
        } else {
            umbra_debug_print("[USER] Enclave unexpected status, ret=");
            umbra_debug_print(umbra_u32_to_hex(ret, hex_buf));
            umbra_debug_print("\n");
            umbra_debug_print("[USER] ");
            umbra_debug_print(name);
            umbra_debug_print(" FAIL (unexpected status)\n");
            return 0;
        }
    }
}

#ifdef UMBRA_OVERLAY
/* Overlay mode: create BOTH enclaves ALIVE simultaneously (the 2nd create evicts the 1st into
 * its SRAM backing), then round-robin enter them — each enter of the non-resident enclave makes
 * the boot swap the EFBC window (evict the other -> its backing, restore this one <- its
 * backing). Both time-multiplex the tight 16 KB EFBC that cannot hold both (60 + 20 > 64
 * blocks). Requires the boot `interenclave_overlay` feature (UMBRA_INTERENCLAVE_OVERLAY=1). */
static void run_overlay(void) {
    char hex_buf[11];
    unsigned int id_a = umbra_enclave_create(AMMUNITION_FLASH_ADDR);
    unsigned int id_b = umbra_enclave_create(NDES_FLASH_ADDR);
    if (id_a >= 0xFFFFFFF0u || id_b >= 0xFFFFFFF0u) {
        umbra_debug_print("[USER] overlay create REJECTED (a=");
        umbra_debug_print(umbra_u32_to_hex(id_a, hex_buf));
        umbra_debug_print(" b=");
        umbra_debug_print(umbra_u32_to_hex(id_b, hex_buf));
        umbra_debug_print(")\n");
        return;
    }
    umbra_debug_print("[USER] both enclaves created (overlay); round-robin start\n");

    int done_a = 0, done_b = 0;
    unsigned int res_a = 0xFFFFFFFFu, res_b = 0xFFFFFFFFu;
    /* Phase 4.2 — SysTick-driven: the boot round-robins A<->B on EVERY preempt (the SysTick
     * handler evicts the resident enclave -> its backing, restores the next <- its backing, and
     * resumes it). So one enter() runs MANY quanta of BOTH enclaves and returns only when SOME
     * enclave TERMINATES — which may not be the one we entered. Mark done by the RETURNED id
     * (bits 31:16 of the status), then re-enter a still-running one; the last enclave finishes
     * via the plain preempt loop (STATUS_SUSPENDED just re-enters). */
    while (!done_a || !done_b) {
        unsigned int enter_id = !done_a ? id_a : id_b;
        unsigned int ret = umbra_enclave_enter(enter_id);
        unsigned int status = (ret >> 8) & 0xFF;
        unsigned int rid = (ret >> 16) & 0xFFFF;
        if (status == STATUS_TERMINATED || status == STATUS_FAULTED) {
            if (rid == id_a) { done_a = 1; res_a = umbra_enclave_status(id_a); }
            else if (rid == id_b) { done_b = 1; res_b = umbra_enclave_status(id_b); }
        }
    }

    umbra_debug_print("[USER] ammunition R0=");
    umbra_debug_print(umbra_u32_to_hex(res_a, hex_buf));
    umbra_debug_print(res_a == AMMUNITION_GOLDEN ? " -> ammunition PASS\n" : " -> ammunition FAIL\n");
    umbra_debug_print("[USER] ndes R0=");
    umbra_debug_print(umbra_u32_to_hex(res_b, hex_buf));
    umbra_debug_print(res_b == NDES_GOLDEN ? " -> ndes PASS\n" : " -> ndes FAIL\n");
}
#endif /* UMBRA_OVERLAY */

int main(void) {
    umbra_debug_print("[USER] Hello Non-Secure World!\n");

#ifdef UMBRA_OVERLAY
    umbra_debug_print("[USER] --- inter-enclave OVERLAY: ammunition + ndes time-multiplexed ---\n");
    run_overlay();
#else
    /* Sequential: enclave 1 (ammunition) runs to termination — its EFBC slots are freed at the
     * next create — then enclave 2 (ndes). 60 + 20 > 64 blocks, so they never coexist here. */
    umbra_debug_print("[USER] --- enclave 1/2: ammunition ---\n");
    run_enclave("ammunition", AMMUNITION_FLASH_ADDR, AMMUNITION_GOLDEN);

    umbra_debug_print("[USER] --- enclave 2/2: ndes ---\n");
    run_enclave("ndes", NDES_FLASH_ADDR, NDES_GOLDEN);
#endif

    umbra_debug_print("[USER] All enclaves done\n");

    while (1) {
        __asm volatile("wfi");
    }
    return 0;
}
