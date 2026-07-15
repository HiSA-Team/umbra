/*
 * NS UART relay for Umbra remote attestation + secure enclave update.
 *
 * USART1 is Secure-only (RIFSC leaves it Secure; the Boot ROM never opens it to NS,
 * which is why NS prints go through the umbra_debug_print Secure veneer). So the relay
 * cannot poll the UART registers directly — it does raw byte I/O through two thin Secure
 * bridge veneers (umbra_uart_read / umbra_uart_write) that only move bytes to/from a
 * range-checked NS buffer. The frame parser stays here in NS, so a parser bug is at most
 * a DoS; the Secure side authenticates the quote (HMAC) and the update package (nonce +
 * HMAC), so a hostile relay cannot forge either.
 */
#include <stdint.h>

#include "attest_relay.h"

#define QUOTE_LEN 115u
/* 24 KB: bounds the largest update package (48-byte header + 64 blocks*288 +
 * framing ~= 18.6 KB) while keeping the NS host under the enclave header at
 * 0x24010000 (the whole host .text+.data+.bss must fit the first 64 KB). */
#define BUF_MAX   0x6000u

#define CMD_QUOTE_REQ   0x01
#define CMD_QUOTE_RESP  0x81
#define CMD_UPDATE_REQ  0x02
#define CMD_UPDATE_RESP 0x82

/* Secure bridge veneers (USART1 is Secure-only). */
extern unsigned int umbra_uart_read(unsigned int ptr, unsigned int len);
extern unsigned int umbra_uart_write(unsigned int ptr, unsigned int len);
extern unsigned int umbra_attest_quote(unsigned int nonce_ptr, unsigned int out_ptr);
extern unsigned int umbra_enclave_update(unsigned int pkg_ptr, unsigned int pkg_len);
extern unsigned int umbra_system_reset(void); /* never returns */

/* CRC32 (IEEE 802.3, reflected) — matches Python zlib.crc32. */
static uint32_t crc32(const uint8_t *p, uint32_t n) {
    uint32_t c = 0xFFFFFFFFu;
    for (uint32_t i = 0; i < n; i++) {
        c ^= p[i];
        for (int k = 0; k < 8; k++)
            c = (c >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(c & 1)));
    }
    return ~c;
}

/* NS AXISRAM statics — their addresses fall in the NS host window that the Secure
 * `ns_range_ok` check requires. */
static uint8_t g_buf[BUF_MAX];
static uint8_t g_nonce[16];
static uint8_t g_quote[QUOTE_LEN];
static uint8_t g_hdr[4];
static uint8_t g_crc[4];
static uint8_t g_one;
static uint8_t g_rxhdr[3];

/* umbra_uart_read returns the COUNT of bytes read within the per-byte timeout.
 * rx_exact() == 1 iff all n arrived (else the frame stalled -> caller resyncs). */
static int rx_exact(uint8_t *buf, uint32_t n) {
    return umbra_uart_read((unsigned int)(uintptr_t)buf, n) == n;
}

/* Idle-block for one byte (retry across timeouts). Only for the SOF search — waiting
 * indefinitely for the next command is correct; mid-frame reads use rx_exact so a
 * misaligned/stalled frame resyncs instead of wedging. */
static uint8_t rx_sof_byte(void) {
    for (;;) {
        if (umbra_uart_read((unsigned int)(uintptr_t)&g_one, 1) == 1)
            return g_one;
    }
}

static void send_frame(uint8_t cmd, const uint8_t *payload, uint32_t len) {
    g_hdr[0] = 0xA5;
    g_hdr[1] = cmd;
    g_hdr[2] = (uint8_t)(len & 0xFF);
    g_hdr[3] = (uint8_t)((len >> 8) & 0xFF);
    umbra_uart_write((unsigned int)(uintptr_t)g_hdr, 4);
    if (len)
        umbra_uart_write((unsigned int)(uintptr_t)payload, len);
    uint32_t crc = crc32(payload, len);
    g_crc[0] = (uint8_t)(crc & 0xFF);
    g_crc[1] = (uint8_t)((crc >> 8) & 0xFF);
    g_crc[2] = (uint8_t)((crc >> 16) & 0xFF);
    g_crc[3] = (uint8_t)((crc >> 24) & 0xFF);
    umbra_uart_write((unsigned int)(uintptr_t)g_crc, 4);
}

static void send_status(uint8_t cmd, unsigned int status) {
    uint8_t s[4] = {
        (uint8_t)status, (uint8_t)(status >> 8),
        (uint8_t)(status >> 16), (uint8_t)(status >> 24),
    };
    send_frame(cmd, s, 4);
}

void attest_relay_loop(void) {
    /* Drain any RX left over from a reboot or a premature host send (read until a
     * timeout). Without this, a boot-window overrun byte (the stale SOF held in RDR)
     * would misalign the first frame and wedge the relay on a spurious length. */
    while (umbra_uart_read((unsigned int)(uintptr_t)&g_one, 1) == 1) { }

    for (;;) {
        if (rx_sof_byte() != 0xA5)
            continue; /* resync on SOF (idle-blocks for the next command) */
        if (!rx_exact(g_rxhdr, 3))
            continue; /* cmd+len didn't complete -> resync */
        uint8_t cmd = g_rxhdr[0];
        uint32_t len = g_rxhdr[1] | ((uint32_t)g_rxhdr[2] << 8);
        if (len > BUF_MAX)
            continue; /* absurd length: drop and resync */
        if (len && !rx_exact(g_buf, len))
            continue; /* body stalled -> resync */
        if (!rx_exact(g_crc, 4))
            continue; /* crc stalled -> resync */
        uint32_t rx_crc = g_crc[0] | ((uint32_t)g_crc[1] << 8)
                        | ((uint32_t)g_crc[2] << 16) | ((uint32_t)g_crc[3] << 24);
        if (crc32(g_buf, len) != rx_crc)
            continue; /* corrupt frame */

        if (cmd == CMD_QUOTE_REQ && len == 16) {
            for (int i = 0; i < 16; i++)
                g_nonce[i] = g_buf[i];
            unsigned int r = umbra_attest_quote((unsigned int)(uintptr_t)g_nonce,
                                                (unsigned int)(uintptr_t)g_quote);
            if (r == 0)
                send_frame(CMD_QUOTE_RESP, g_quote, QUOTE_LEN);
            else
                send_status(CMD_QUOTE_RESP, r);
        } else if (cmd == CMD_UPDATE_REQ) {
            unsigned int r = umbra_enclave_update((unsigned int)(uintptr_t)g_buf, len);
            send_status(CMD_UPDATE_RESP, r);
            if (r == 0)
                umbra_system_reset(); /* activate the new slot on reboot; never returns */
        }
        /* unknown cmd: silently ignore, keep listening */
    }
}
