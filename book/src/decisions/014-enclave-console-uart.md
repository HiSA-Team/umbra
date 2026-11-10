# ADR 014 — Console UART for enclaves (exclusive owner, interrupt-driven reception)

**Status:** Accepted (2026-11-10) · **Platform:** STM32L552, STM32L562

## Context

Enclave code needs keyboard input from the console UART (LPUART1 on the L552
Nucleo, USART1 on the L562 Discovery). Enclaves run Secure and unprivileged
behind the MPU, so they cannot branch to an NSC veneer: the attempt faults with
`MemManage: addr outside any enclave`. The Secure kernel only ever transmitted on
this UART; reception was off, and the UART itself was left Non-Secure in the
GTZC, reachable by any host code.

A first polling design (a blocking read with a per-byte timeout inside an SVC)
lost characters whenever nobody was polling. With the 1-byte receive register, a
burst that arrived while the enclave was preempted and the host was printing
overwrote itself. Raising the timeout only moved the problem: at the workspace's
`opt-level = 0` a 2M-iteration poll held the SVC handler, and SysTick with it,
for about five seconds.

## Decision

- **The console UART is Secure.** At boot the kernel sets USART1SEC
  (`GTZC_TZSC_SECCFGR2[1]`, L562) or LPUART1SEC (`GTZC_TZSC_SECCFGR1[21]`, L552),
  and every Secure access goes through the Secure alias. Host code reaches the
  UART only through veneers; its direct reads return zero and its writes are
  dropped.
- **Reception is interrupt-driven.** The 8-byte hardware FIFO is on, `RXFNEIE`
  raises the UART IRQ (61 on L562, 66 on L552, Secure target), and the handler
  drains the FIFO into a 256-byte Secure buffer, clearing a latched overrun. A
  full buffer drops the newest byte and increments an overflow count. The buffer
  and its ownership rules live in `kernel::common::uart_rx::ConsoleUart`, a
  platform-independent module with host tests; callers in thread context mask
  interrupts around each call.
- **One owner at a time.** The host is the default owner. An enclave claims the
  UART and keeps it until it releases it, terminates or faults; a claim while
  another enclave owns it fails with *busy* and changes nothing. Every change of
  owner discards the bytes still waiting for the previous one.
- **Enclave interface: `svc #3`.** Opcode in `r0`, argument in `r1`, result in
  `r0`. The caller is always the enclave the kernel is running; no pointer
  crosses the boundary.

  | `r0` | Operation | `r1` | Result |
  |---|---|---|---|
  | 0 | claim | — | 0 ok, 1 busy |
  | 1 | release | — | 0 ok, 1 not owner |
  | 2 | try-getc | — | byte, or `0xFFFFFFFF` when empty or not owner |
  | 3 | putc | byte | 0 sent, 1 not owner |
  | 4 | overflow | — | count, or `0xFFFFFFFF` when not owner |

  Enclave authors use `host/common/inc/umbra_uart.h`. It wraps the opcodes and
  waits for a busy UART or an empty buffer by yielding (`svc #1`), so the host
  keeps running. Every function is `always_inline`, because at `-O0` an
  out-of-line copy would land outside the enclave code section.
- **Host interface: `umbra_uart_read(ptr, len)`.** A new veneer at slot 9, with
  the same ABI as the N657 relay bridge. It returns the number of bytes read,
  with a per-byte timeout. It returns 0 for a buffer outside NS SRAM, and 0 at
  once while an enclave owns the UART.
- **Transmit gate between enclaves only.** Only the owning enclave may transmit
  with `putc`. `umbra_debug_print` and kernel logs are never gated, because they
  are the diagnostic channel.

## Rationale

- **Interrupt plus buffer, not polling.** Polling cannot be made lossless: any
  stretch with nobody polling loses input, and the stretch includes every
  preemption and every host print. The buffer decouples arrival from
  consumption.
- **Exclusive owner, not broadcast or framing.** Copying every byte to every
  subscribed enclave, or routing by a PC-side frame header, would allow
  parallel readers. Both cost more than this use case needs, and framing would
  rule out a plain serial terminal. With exclusive ownership a plain terminal
  still works.
- **Flush on handover.** Without it, text typed for one enclave (a password, say)
  would reach the next owner, enclave or host.
- **Byte operations, no pointers.** An enclave-side buffer pointer would need
  validation against the calling enclave's memory. Single-byte operations need
  none; at 9600 baud one SVC per byte costs nothing that matters.
- **Yield to wait, not a new enclave state.** A "waiting for input" state would
  need every host (bare metal, FreeRTOS, Tock) to learn not to re-enter such an
  enclave. Yielding reuses the existing *Suspended* path; the price is some
  re-entries that find nothing to read.
- **Secure UART.** Ownership and flush protect nothing if host code can read the
  receive register directly.

## Consequences

- The L5 NSC surface grows from seven to eight veneers. Slots 7 and 8 stay empty
  (zero padding, not `SG`), so `umbra_uart_read` sits at slot 9 on both L5 and
  N657 and host code that calls it is portable.
- `svc #3` is a new enclave-to-kernel entry. N657 does not implement it yet; its
  `svc #2` is the block checkpoint, so the number stays free there.
- The Tock host on the L552 drives LPUART1 directly from Non-Secure code. With
  the UART Secure its console goes silent until it moves to the veneers.
- The UART IRQ shares priority 0 with SVC, SysTick and PendSV, so it waits for
  them to return. The 8-byte FIFO covers about 9.4 ms at 9600 baud, longer than
  any of those handlers.
- Host output and enclave output can interleave on the line.
- Verified on the L562: a 200-byte burst received intact while the enclave was
  preempted dozens of times; automatic release and flush when the owner faults;
  direct host access reads zero; two enclaves, where the second finds the UART
  busy and, after the first releases, sees only bytes sent after its own claim.
  The L552 build passes; there was no L552 board available for a run.

See [ADR 005](005-nsc-boundary.md) for the veneer-pair pattern and
[ADR 012](012-remote-attestation.md) for the N657 UART relay that shares slot 9.
