# ADR 000 — Umbra Threat Model (v1)

**Status:** Accepted
**Supersedes:** none (first formal threat model)

## 1. Scope

Umbra is a TrustZone-M enclave system that defends the confidentiality
and integrity of Encrypted Function Blocks (EFBs) executing inside a
Secure-side sandbox (the Enclave Swap Space) on STM32L552, STM32L562
and STM32N657. It enforces an unbroken chained-measurement boot chain
rooted in a Secure-resident master key, sandboxes per-enclave
execution behind MPCBB (L552/L562) or RIF + RISAF (N657), and exposes
a small audited NSC veneer surface as the only NS→S entry path.

Out of scope: multi-glitch fault-injection sequences, lab-grade
side-channels (electromagnetic emissions, power analysis),
production-grade debug lockdown (`DBGEN.S`), RowHammer-class memory
attacks, and NS-side denial of service caused by the host crashing
itself with malformed NSC arguments. See [§6](#6-out-of-scope-attacks)
for the full exclusion list.

## 2. Attacker model

Three concentric classes:

### A1 — Remote NS attacker

Controls the Non-Secure host application. Can invoke any NSC veneer
with any arguments. Cannot single-step the Secure side. Goal: read the
master key, alter the chained measurement, escalate to Secure
execution.

### A2 — Local NS attacker with debug interface

A1 + can attach a debugger to the NS side. Cannot attach to the Secure
side (`DBGEN.S` is disabled in production builds — see
[§5](#5-nsc-veneer-surface)).

### A3 — Local attacker with physical glitching capability

A2 + can inject single voltage or clock glitches. Cannot disassemble
the package.

## 3. Trust boundaries

1. **NS ↔ Secure.** Enforced by SAU + GTZC on L552/L562 and by
   SAU + RIFSC on N657. Crossings happen only through the NSC veneers
   in `src/kernel/src/umbra_nsc_api.rs`.
2. **EFB ↔ rest of Secure.** Enforced by MPCBB (L552/L562) or RISAF
   (N657). EFB code is only readable while loaded into the Enclave
   Swap Space.
3. **Secure ↔ external (XSPI flash on L562/N657).** On-the-fly
   decryption via OTFDEC (L562) or MCE (N657); ciphertext at rest.

## 4. Crown Jewels (CJ1–CJ4)

The four invariants the kernel is built to preserve, with the
mechanism that defends each on each platform.

| # | Invariant | L552 / L562 defence | N657 defence |
|---|---|---|---|
| CJ1 | Master key never leaves Secure storage | DHUK + software key path | DHUK + CRYP1 `KEYRx` with write-lock |
| CJ2 | Chained measurement unbroken | HW HASH peripheral (HR0–7) + `validator.rs` | SW SHA-256 path while RIFSC blocks HW HASH; HW HMAC where available |
| CJ3 | EFB confidentiality + isolation | MPCBB slot flip per ESS page | RIF + RISAF region-based isolation |
| CJ4 | NSC veneer is the only NS→S entry | SAU NSC region + `_imp` symbols | SAU NSC + RIFSC RISUP |

The Crown Jewel notation (CJ1–CJ4) is cited inline in [Error
Handling](../architecture/error-handling.md) and in the [contributor
guardrails](../contributing/guardrails.md). Each guardrail rule
references the Crown Jewel it defends.

## 5. NSC veneer surface

The NSC veneer surface is **closed** — adding a new veneer requires
landing a new ADR. The published count is seven veneers: five
functional enclave-lifecycle entry points and two instrumentation
veneers used to measure the round-trip cost.

| Veneer | Signature | NS-controlled args | Validation requirement |
|---|---|---|---|
| `umbra_enclave_create` | `fn(base_addr: u32) -> u32` | `base_addr` | Within NS flash range; page-aligned |
| `umbra_debug_print` | `fn(str_ptr: *const u8)` | `str_ptr` | Length-bounded read of NS-readable memory; reject `null`; reject crossing into Secure aliases |
| `umbra_enclave_enter` | `fn(enclave_id: u32) -> u32` | `enclave_id` | `enclave_id < MAX_EFBS`; slot in `Loaded` state |
| `umbra_enclave_exit` | `fn(enclave_id: u32) -> u32` | `enclave_id` | `enclave_id < MAX_EFBS`; slot belongs to the calling context |
| `umbra_enclave_status` | `fn(enclave_id: u32) -> u32` | `enclave_id` | `enclave_id < MAX_EFBS` |
| `umbra_bench_dump` | `fn()` | (none) | No args to validate |
| `umbra_null_call` | `fn()` | (none) | Baseline veneer; no args to validate |

The single arg-validation gate that enforces these requirements is
`arg_validation::ns_slice` plus the bounds checks at the head of each
`_imp` body. See [ADR 005](005-nsc-boundary.md) for the
`_callable` / `_imp` split that makes this enforceable.

## 6. Out-of-scope attacks

Documented explicitly so the boundary is unambiguous.

- Physical glitching attacks beyond A3 (multi-glitch sequences).
- Side-channel attacks requiring lab equipment (electromagnetic
  emissions, power analysis).
- `DBGEN.S` enabled. Development boards always have it enabled;
  production debug lockdown is a separate hardening item.
- DoS via crafted NSC arguments. The NS host can already crash itself;
  defending against self-DoS is not in scope.

## 7. Invariants checklist for PR reviewers

A copy-pasteable checklist that every PR reviewer runs:

- [ ] No new path leaks any bit of `KEYRx` register content (CJ1).
- [ ] Chained-measurement computation order unchanged or audited (CJ2).
- [ ] No new MPCBB / RIF region-config write without a `// SAFETY:`
      comment (CJ3).
- [ ] No new NSC veneer added without arg validation (CJ4).

This checklist is also part of the [contributor
guardrails](../contributing/guardrails.md).

## 8. References

- ARM TrustZone for ARMv8-M: ARM DDI 0573.
- ST RM0438 (STM32L5): §3 Security, §6 GTZC.
- ST RM0486 (STM32N6): §3 Security, §40 RIFSC.

## Cross-references

- The NSC entry-pair pattern that defends CJ4: [ADR 005](005-nsc-boundary.md).
- The error-variant taxonomy tied to the Crown Jewels: [ADR 002](002-umbra-error.md).
- The build-time master-key chain that anchors CJ1: [ADR 006](006-master-key-chain.md).
- The panic policy that closes the fault-DoS surface: [ADR 007](007-panic-policy.md).
