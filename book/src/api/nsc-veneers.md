# NSC API Reference

Umbra exposes eight Non-Secure Callable (NSC) functions on STM32L552/L562. These are the **only** way the host application can interact with the Secure World. Five are the functional enclave-lifecycle entry points, one reads the console UART, and two are baseline / instrumentation veneers used to measure or exercise the round-trip path.

Each function is implemented as an assembly veneer containing a `SG` (Secure Gateway) instruction, followed by a branch to the Rust implementation. The veneers are placed in the `.umbra_nsc_api` section at fixed addresses starting at `0x0803C000`.

## Functional veneers

`umbra_enclave_create`, `umbra_debug_print`, `umbra_enclave_enter`, `umbra_enclave_exit`, `umbra_enclave_status`, `umbra_uart_read` — documented in the sections below.

## Instrumentation veneers

`umbra_bench_dump` and `umbra_null_call` are emitted unconditionally so the round-trip cost of the NSC boundary can be measured even in production builds. They are documented at the end of this chapter.

## umbra_enclave_create

```c
uint32_t umbra_enclave_create(uint32_t base_addr);
```

Creates an enclave from a binary at `base_addr` in Non-Secure flash.

- Reads and validates the enclave header (magic `0x524D4255` = "UBMR")
- Performs chained measurement (HMAC chain over all blocks)
- Registers the enclave in the Enclave Swap Space
- **Returns**: enclave ID (bits 31:16) | status (bits 15:0). Status 0 = success.

## umbra_enclave_enter

```c
uint32_t umbra_enclave_enter(uint32_t enclave_id);
```

Enters (or resumes) an enclave. This triggers an SVC into Secure World where the kernel:

1. Restores the enclave's saved context (r4-r11, PSP, CONTROL)
2. Enables Secure SysTick for preemption (~10ms quantum)
3. Returns to the enclave via crafted EXC_RETURN

The function blocks until the enclave is preempted (SysTick), yields (SVC #1), terminates, or faults.

- **Returns**: `(enclave_id << 16) | (status << 8)` where status is one of:
  - `3` = Suspended (preempted by SysTick or voluntary yield)
  - `4` = Terminated (enclave returned normally)
  - `5` = Faulted (unrecoverable fault)

## umbra_enclave_exit

```c
uint32_t umbra_enclave_exit(uint32_t enclave_id);
```

Terminates a suspended enclave from the host side. Only valid when the enclave is in Suspended state.

- **Returns**: `(enclave_id << 16) | (status << 8)`

## umbra_enclave_status

```c
uint32_t umbra_enclave_status(uint32_t enclave_id);
```

Queries the current state of an enclave.

- **Returns**: If terminated, returns the enclave's final R0 value. Otherwise returns the status code.

## umbra_debug_print

```c
void umbra_debug_print(const char* str_ptr);
```

Prints a null-terminated string from Non-Secure memory to the Secure UART. Useful for host-side debug logging via the Secure World UART driver.

## umbra_uart_read

```c
uint32_t umbra_uart_read(uint32_t buf, uint32_t len);
```

Reads up to `len` bytes received on the console UART into the Non-Secure buffer `buf`. Reception is interrupt-driven into a Secure buffer, so bytes that arrive between calls are kept (up to 256). Slot 9 (`0x0803C091`), the same slot and ABI as the N657 UART relay.

- Waits for each byte with a timeout of about 250 ms; a short count means the input stopped.
- **Returns**: the number of bytes read. 0 if `[buf, buf+len)` is not inside NS SRAM (`0x20000000`–`0x20020000`), and 0 at once while an enclave owns the UART.
- Enclaves do not use this veneer. They include `host/common/inc/umbra_uart.h` (`umbra_uart_claim`, `umbra_uart_getc`, `umbra_uart_putc`, ...), which goes through `svc #3`. See [ADR 014](../decisions/014-enclave-console-uart.md) for the ownership rules.

## umbra_bench_dump

```c
void umbra_bench_dump(void);
```

Instrumentation veneer. Dumps the Secure-side benchmark counters (if `bench-eval` was enabled at build time) to the Secure UART. With `bench-eval` disabled the body is empty and the veneer measures only the round-trip overhead (one `SG` plus one `BXNS`).

- **Returns**: (none)

## umbra_null_call

```c
void umbra_null_call(void);
```

Baseline veneer. The body is a single `SG` followed by an immediate `BXNS`. Used by host-side benchmarks to characterise the fixed cost of an NSC round-trip on the target silicon. Production overhead is identical to any other zero-arg veneer.

- **Returns**: (none)
