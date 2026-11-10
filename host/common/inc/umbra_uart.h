#ifndef UMBRA_HOST_COMMON_UART_H
#define UMBRA_HOST_COMMON_UART_H

/* Console UART for enclave code (L552/L562).
 *
 * The UART has one owner at a time. Claim it before reading or writing and
 * release it when done; an enclave that terminates or faults releases it
 * automatically. Characters typed while you own it are buffered by the
 * Secure kernel (256 bytes), so none are lost while the enclave is preempted.
 * Waiting calls yield to the host instead of spinning.
 *
 * Every function is always_inline: enclaves build at -O0, where a plain
 * `static inline` stays out of line and lands outside the enclave code
 * section (MemManage). No libc, because TACLeBench builds with -nostdinc.
 */

/* svc #3 opcodes, mirrored by `svc_uart_op` in
 * src/hardware/platform/stm32l552/boot/src/api_impl/uart_read.rs */
#define UMBRA_UART_OP_CLAIM 0u
#define UMBRA_UART_OP_RELEASE 1u
#define UMBRA_UART_OP_GETC 2u
#define UMBRA_UART_OP_PUTC 3u
#define UMBRA_UART_OP_OVERFLOW 4u
#define UMBRA_UART_NONE 0xFFFFFFFFu

#define UMBRA_UART_INLINE static inline __attribute__((always_inline))

UMBRA_UART_INLINE unsigned int umbra_uart_svc(unsigned int op,
                                              unsigned int arg) {
  register unsigned int r0 __asm("r0") = op;
  register unsigned int r1 __asm("r1") = arg;
  __asm volatile("svc #3" : "+r"(r0) : "r"(r1) : "memory");
  return r0;
}

/* Let the host run; the kernel resumes the enclave right after this. */
UMBRA_UART_INLINE void umbra_yield(void) {
  __asm volatile("svc #1" ::: "memory");
}

/* 0 on success, nonzero if another enclave owns the UART. */
UMBRA_UART_INLINE int umbra_uart_try_claim(void) {
  return umbra_uart_svc(UMBRA_UART_OP_CLAIM, 0) != 0;
}

/* Waits until no other enclave owns the UART, then takes it. */
UMBRA_UART_INLINE void umbra_uart_claim(void) {
  while (umbra_uart_try_claim())
    umbra_yield();
}

/* Gives the UART back to the host; unread characters are discarded. */
UMBRA_UART_INLINE void umbra_uart_release(void) {
  (void)umbra_uart_svc(UMBRA_UART_OP_RELEASE, 0);
}

/* Next received character; waits for one. The caller must own the UART. */
UMBRA_UART_INLINE unsigned char umbra_uart_getc(void) {
  unsigned int c;
  while ((c = umbra_uart_svc(UMBRA_UART_OP_GETC, 0)) == UMBRA_UART_NONE)
    umbra_yield();
  return (unsigned char)c;
}

/* Fills `buf` with exactly `n` characters; waits until they arrive. */
UMBRA_UART_INLINE void umbra_uart_read(unsigned char *buf, unsigned int n) {
  for (unsigned int i = 0; i < n; i++)
    buf[i] = umbra_uart_getc();
}

/* 0 when sent, nonzero if this enclave does not own the UART. */
UMBRA_UART_INLINE int umbra_uart_putc(unsigned char c) {
  return umbra_uart_svc(UMBRA_UART_OP_PUTC, c) != 0;
}

/* 0 when all `n` characters were sent, nonzero if not the owner. */
UMBRA_UART_INLINE int umbra_uart_write(const unsigned char *buf,
                                       unsigned int n) {
  for (unsigned int i = 0; i < n; i++)
    if (umbra_uart_putc(buf[i]))
      return 1;
  return 0;
}

/* Characters dropped because the buffer was full since this enclave's
 * claim, or UMBRA_UART_NONE if it does not own the UART. */
UMBRA_UART_INLINE unsigned int umbra_uart_overflow(void) {
  return umbra_uart_svc(UMBRA_UART_OP_OVERFLOW, 0);
}

#endif
