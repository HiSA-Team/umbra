# NSC API Reference

Umbra exposes 5 Non-Secure Callable (NSC) functions. These are the **only** way the host application can interact with the Secure World.

Each function is implemented as an assembly veneer containing a `SG` (Secure Gateway) instruction, followed by a branch to the Rust implementation. The veneers are placed in the `.umbra_nsc_api` section at fixed addresses starting at `0x0803C000`.

## umbra_tee_create

```c
uint32_t umbra_tee_create(uint32_t base_addr);
```

Creates a TEE from an enclave binary at `base_addr` in Non-Secure flash.

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
