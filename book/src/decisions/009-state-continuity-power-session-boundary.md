# ADR 009 — State continuity holds only within a power session

## Status
Accepted

## Context
Rollback protection for enclave execution state is anchored in TAMP backup
registers, which are retained across a warm/software reset but cleared on a cold
power-off / POR (no VBAT coin cell on the NUCLEO-N657X0-Q). The threat model is a
software/remote attacker able to trigger warm (PIN) or software (SYSRESETREQ)
resets; a physical power-cycle is out of scope. Both were verified on hardware:
PIN and SFT resets retain the anchor; a POR clears it.

## Decision
Rollback protection is guaranteed only WITHIN a single power-on session. On a cold
boot the anchor reads empty and the current flash state is trusted as the new
baseline (COLD_WINDOW fail-open). This is explicit, logged behaviour — never a
silent fallback.

## Consequences
An attacker with physical power control is out of scope. Closing that gap requires
an OTP/BSEC monotonic epoch (finite ~32 states), gated on the irreversible
secure_boot OTP close — deferred to production bring-up.
