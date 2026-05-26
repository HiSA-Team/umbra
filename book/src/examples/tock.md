# Tock Example

The Tock host (`host/stm32l552/tock/`) runs the [Tock kernel] as an Umbra
Non-Secure host on the NUCLEO-L552ZE-Q. A libtock-rs userspace process
drives enclaves via a custom Tock capsule that wraps the NSC veneers.
Process isolation is provided by the NS-MPU regions Umbra Secure
programs during boot; Tock's own MPU layer is a no-op stub.

[Tock kernel]: https://www.tockos.org/

## How It Works

```
main()
  ├── stm32l552::vectors::init()            // VTOR + NVIC + SHCSR
  ├── heartbeat::init()                     // DWT + NS SysTick (FreeRTOS-style)
  ├── RCC: HSI16 → SYSCLK, LSE for LPUART1
  ├── LPUART1 init (PG7 TX / PG8 RX @ 9600)
  ├── Console + UmbraDriver capsules
  ├── RoundRobin scheduler + load TBF apps
  └── board_kernel.kernel_loop()            // never returns

enclave_demo (TBF app)
  ├── Scan NS flash for UMBR magic (via PROBE syscall)
  ├── command(CREATE, addr) for each enclave found
  ├── Loop: command(ENTER, id)
  │     ├── SUSPENDED  → print, re-enter
  │     ├── TERMINATED → print R0, mark done
  │     └── FAULTED    → print error, mark done
  ├── command(DUMP_DRIFT) → emits [HEARTBEAT] + [DRIFT] lines
  └── yield_wait forever
```

The capsule `host/stm32l552/tock/capsules/umbra/` exposes the four NSC
veneers as a Tock `SyscallDriver` at driver number `0xA0000`. Userspace
apps interact with it via the standard Tock `subscribe` + `command`
syscall pair: every veneer call delivers its `u32` result through
subscribe slot 0 as an upcall.

## Register Barrier

Empirically the SG/BXNS round-trip through the Umbra NSC veneers does
not preserve all callee-saved registers (r4-r11) the way Rust's
`extern "C"` ABI assumes. The capsule wraps each veneer call in an
inline-asm block that manually `push`es/`pop`s r4-r11 around the `blx`
and lists r4, r5, r8-r11 as clobbered, forcing LLVM to spill live values
out of those registers before the call. Bare-metal C and FreeRTOS hosts
on the same chip don't observe this because GCC's codegen happens to
spill differently — only rustc + LLVM keeps `&self` in r5 across the
call site and trips the bug.

## Building and Running

```bash
export MCU_VARIANT=stm32l552 HOST_APP=tock
source ./settings.sh
./rebuild_all.sh
./debug.sh
```

UART output appears at 9600 baud, line-prefixed with `[TOCK]`. The
expected trace tail when the bundled fibonacci enclave runs:

```
[TOCK] kernel up
[TOCK] init complete, entering kernel loop
[TOCK] Enclave task started
[UMBRASecureBoot] chained-measurement OK
[UMBRASecureBoot] force-load done loaded=00000000 failed=00000000
[TOCK] Enclave created
[TOCK] Enclave terminated! R0=0x72CA33A8
[HEARTBEAT t=0x00000001]
…
[DRIFT] max=0x… total=0x…
[DRIFT] b0=0x… b1=0x… b2=0x… b3=0x… b4=0x… b5=0x…
[TOCK] All enclaves done
```

## TACLeBench Harness

The Tock host integrates with `tools/test_taclebench.sh` so the same
benchmarks the FreeRTOS host runs (paper suite: `binarysearch`, `bsort`,
`countnegative`, `ndes`, `statemate`) can be driven through Tock:

```bash
HOST_APP=tock PHASE5_BENCHES=binarysearch ./tools/test_taclebench.sh
HOST_APP=tock PHASE5_BENCHES=paper ./tools/test_taclebench.sh
```

Wall-clock times match the FreeRTOS baseline within a few percent on the
PLL @ 110 MHz + T-table AES configuration — the register barrier adds no
measurable overhead.

## Heartbeat & Drift Instrumentation

The board owns NS SysTick exclusively, configured once at boot exactly
like FreeRTOS's `prvSetupTimerInterrupt`. Tock's `SchedulerTimer` is the
never-expires `()` stub so the kernel never arms/disarms SysTick — the
timer runs free and the SysTick exception updates DWT-cycle deltas on
every tick. `[HEARTBEAT]` and `[DRIFT]` lines are emitted in a single
atomic burst at end-of-run (via capsule cmd 6) rather than from the IRQ
context, so they never splice into Umbra Secure's own UART writes.

## Submodule Pins

- `host/stm32l552/tock/lib/tock` — Tock kernel @ `b35fad8` master plus a
  vendor patch on `MuxUart::do_next_op` (`3f61f85f`) that fixes a
  sync-callback ordering bug for polled LPUART drivers.
- `host/stm32l552/tock/lib/libtock-rs` — userspace runtime @ `0766d8c`.
- `rust-toolchain.toml` — `nightly-2026-05-19`.
