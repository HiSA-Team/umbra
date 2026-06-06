# ADR 007 — Panic policy for the Umbra Secure side

**Status:** Accepted (implemented)

## Context

A prior revision of the Umbra Secure side terminated panic and
unrecoverable faults with a bare `loop {}` spin. Three concrete sites
held this behaviour:

- `src/kernel/src/panic.rs` — the kernel `#[panic_handler]` ended with
  `loop {}` after flushing the panic message to UART;
- `src/hardware/platform/stm32l552/boot/src/handlers.rs` — the L552
  `panic_dump(...)` sink and the L552 `HardFault` handler both ended
  with a `loop {}` after the register dump;
- `src/hardware/platform/stm32n657/boot/src/handlers.rs` — the N657
  `HardFault` handler ended with a `loop { core::hint::spin_loop(); }`
  after dumping the Secure and Non-Secure fault registers.

The observable behaviour was: a Secure-side fault left the device
hanging forever, with the UART buffer holding the panic message and
the CPU spinning. The effect on availability was a denial-of-service
class: a single fault permanently bricked the device until the
operator power-cycled it.

The reason this was problematic enough to warrant a policy decision is
that the fault path is reachable from NS-controlled state. An NS host
that can drive an enclave through a marginal code path can use the
fault sink to take the device out of service indefinitely.

## Decision

The kernel and every platform fault handler funnel through a single
panic-policy entry point with two compile-time-selectable behaviours:

### Default (production build)

Log the panic message and register dump to UART, then raise
`SCB.AIRCR.SYSRESETREQ` to reset the system.

Reset is preferred over halt for production because:

1. **Availability matters more than post-mortem inspection in the
   field.** A reset returns the device to a usable state; a halt does
   not.
2. **The reset path goes through the Secure boot**, which
   re-validates the chained measurement on the way back up. The
   device fails secure: a fault cannot leave the device running
   on a half-configured Secure side.

### Debug build (Cargo feature `debug-halt`)

Log the panic message, then halt with `wfi`. Useful when a debugger is
attached so it can stop and inspect.

Enabled with `--features debug-halt` on the boot crate.

### Implementation contract

The policy lives in `src/kernel/src/common/panic_policy.rs` with the
following public surface:

```rust
/// Unified panic-policy entry point. The kernel `#[panic_handler]` and
/// every platform fault handler must end with a call to this function
/// (with `PanicInfo`) or `handle_fault()` (when no `PanicInfo` is
/// available — fault handlers).
///
/// Behaviour: logs `info` via UART, then either resets the system
/// (default) or halts (with `--features debug-halt`).
pub fn handle(info: &core::panic::PanicInfo<'_>) -> !;

/// No-log variant for fault handlers that have already dumped via
/// `panic_dump`. Performs only the reset/halt step.
pub fn handle_fault() -> !;
```

The reset primitive itself is an arch-specific helper in
`src/hardware/architecture/arm/src/reset.rs`:

```rust
/// Raise `SCB.AIRCR.SYSRESETREQ`. Cortex-M33 / Cortex-M55.
pub fn system_reset() -> !;
```

## Implementation status

The policy is in the codebase. The four originally-cited `loop {}`
sites now funnel through `panic_policy::handle_fault()`:

- The kernel `#[panic_handler]` delegates to
  `crate::common::panic_policy::handle(info)`;
- `panic_dump(...)` on L552 ends with
  `kernel::common::panic_policy::handle_fault()`;
- The L552 `HardFault` handler ends with the same call;
- The N657 `HardFault` handler ends with the same call after the
  Secure + Non-Secure register dump.

`handle_fault()` calls into `terminate()` which dispatches to either
`system_reset()` (production) or a `wfi` loop (under
`--features debug-halt`). No bare `loop {}` remains on any fault
path. The contributor [guardrails](../contributing/guardrails.md)
include the rule against reintroducing one.

## Alternatives considered

### Alternative A — Always halt (the status quo before this ADR)

- **Pro**: simple to debug — the device sits at the fault site until
  the operator inspects it.
- **Con**: production DoS, no recovery, no audit trail of repeat
  faults.
- **Con**: an NS attacker who can reach the fault path takes the
  device out of service permanently.

**Rejected** — violates availability for field-deployed devices.

### Alternative B — Always reset

- **Pro**: maximum availability.
- **Con**: makes interactive debugging impossible. Attaching GDB,
  triggering a fault, and watching it disappear into a reset loop
  produces no useful information for the developer.

**Rejected as a sole policy** — adopted as the production default
with a feature flag for the debug case.

### Alternative C — Watchdog-based reset (do not raise `SYSRESETREQ`; let the IWDG fire)

- **Pro**: works even if the SCB itself is faulted.
- **Con**: ~1 second worst-case latency between the fault and the
  reset, during which the UART output may be incomplete.
- **Con**: requires the IWDG to be configured and refreshed by the
  kernel, which adds a runtime dependency for the fault path.

**Rejected for now** — a future hardening can layer IWDG over the
`SYSRESETREQ` path as defence in depth without revisiting this ADR.

**Selected: B by default + A behind a feature flag.** This gives the
availability of reset for production builds and the debuggability of
halt for local development without runtime branching.

## Consequences

### Positive

1. **A Secure-side fault is no longer a permanent DoS.** The device
   resets, re-runs the chained-measurement, and either comes back up
   or fails secure.
2. **The fault path goes through one entry point.** A future
   contributor adding a new fault handler has one function to call;
   the reviewer rule is mechanical (no bare `loop {}` outside
   `debug-halt`).
3. **The debug-vs-production behaviour is selected at build time, not
   runtime.** No runtime branch in the fault path; the choice is a
   linker-time fact.

### Negative

1. **Field-deployed devices now reset on fault.** This means boot
   logs need a boot-count field to distinguish a clean cold boot from
   a reset loop. The boot-count tracking is a future hardening item
   and is not part of this ADR.
2. **Local debugging requires `cargo xtask` to be invoked with the
   debug-halt feature on**. Forgetting the flag produces a reset
   instead of a halt; the developer wonders why GDB loses the
   connection. The fix is to document the flag in the debug entry
   point.
3. **The `system_reset()` primitive is arch-specific.** Porting to a
   new MCU family means implementing a new `reset.rs` helper. This is
   one of the items in the porting guide.

## Cross-references

- The fault paths that this ADR funnels: see the boot-flow chapter for
  the per-platform handler-table layout
  ([Boot Flow](../architecture/boot-flow.md)).
- The reviewer rule that catches a re-introduced bare `loop {}`:
  NEVER_DO #5 in the [contributor guardrails](../contributing/guardrails.md).
- The threat-model invariant on availability this ADR closes:
  [ADR 000](000-threat-model.md).
