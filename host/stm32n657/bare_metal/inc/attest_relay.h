#ifndef ATTEST_RELAY_H
#define ATTEST_RELAY_H

/* Poll USART1 RX (NS alias) for framed attestation/update commands and answer
 * them via the NSC veneers. Never returns; call after the enclave demo.
 *
 * Frame: [SOF 0xA5][cmd u8][len u16 LE][payload][crc32 LE].
 * Commands: 0x01 QUOTE_REQ(nonce16) -> 0x81 QUOTE_RESP(quote115|status4)
 *           0x02 UPDATE_REQ(pkg)    -> 0x82 UPDATE_RESP(status4)
 */
void attest_relay_loop(void);

#endif /* ATTEST_RELAY_H */
