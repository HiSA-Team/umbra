# ADR 008 — RISC-V SPMP arbitration: keeping the M-mode monitor the sole arbiter

**Status:** Accepted. The three-ring substrate and the S-mode enclave runtime are
implemented and run on QEMU (EFB block division, chained measurement, runtime
demand-paging, preemption). PMP-dominates-SPMP is the verified hardware property;
the monitor additionally self-locks its own `.text` via ePMP. Full per-domain
enforcement — tightening the PMP grant to per-domain regions, wiring the
per-transition SPMP reset, and the two on-target negative tests below — is still
pending.

## Context

On the RISC-V RV32 target, Umbra abandons the ARM TrustZone Secure/Non-Secure
world split for a three-ring model:

- **M-mode** — the Umbra monitor (root of trust / TCB). Owns PMP, dispatches
  `ecall`, mediates every ring transition.
- **S-mode** — the enclave (trusted payload), running *above* the untrusted
  host. It manages SPMP (S-mode Physical Memory Protection) to fence or
  relinquish the host's view of a shared parameter buffer.
- **U-mode** — the host (untrusted scheduler/app).

This deliberately makes the enclave *more privileged* than the host. It also
hands the enclave a memory-protection lever — SPMP — that the host does not
have. That raises the central question for this design:

> If the S-mode enclave can program its own SPMP entries, what keeps the M-mode
> monitor the **sole arbiter** of the inter-domain boundary? What stops a buggy
> or malicious enclave from (a) fencing the host back in, (b) leaving stale SPMP
> entries that govern the host after control returns to it, or (c) reaching
> M-mode memory?

A protection lever in the hands of the payload we are containing must not be
able to widen that payload's reach. ARM TrustZone never faced this: Non-Secure
code cannot touch the SAU.

## Decision

Two mechanisms together keep the monitor the sole arbiter. Both are backed by
how the RISC-V hardware actually composes the two protection layers.

### 1. PMP dominates SPMP — SPMP can only ever restrict, never widen

On RISC-V, an S-mode or U-mode memory access must pass **both** the M-mode PMP
check **and** the S-mode SPMP check — the two are ANDed. SPMP is therefore
strictly subordinate: an entry the enclave programs can only *further restrict*
access within the region M-mode's PMP already granted that domain. It can never
grant access to an address PMP denies.

Consequence: the monitor programs PMP to define the outer inter-domain boundary
(the enclave's region, the host's region, the shared window). Whatever the
enclave does to its own SPMP, it physically cannot reach M-mode memory, the
host's private memory, or anything outside its PMP grant. The monitor remains
the sole arbiter of the outer boundary. SPMP only sub-divides *within* the
enclave's own grant — a tool for the enclave to protect itself and to expose a
shared buffer, not a way to escape its cage.

### 2. Per-transition SPMP ownership — no stale entry governs the host

The monitor resets SPMP to a known-empty baseline on every transition into the
U-mode host, and re-establishes the enclave's SPMP context only when entering
the enclave. So even though SPMP is a single S-managed entry set, a rule the
enclave left behind can never be in force while the host runs. (This applies once
the enclave is given SPMP self-management; see *Implementation status* below.)

### 3. ePMP self-lock — the monitor cannot corrupt its own code

Complementing the inter-domain fence, the monitor protects the arbiter from
within: during security init it installs a **Locked** (`L=1`) read+execute PMP
rule over its own `.text`. RISC-V binds a locked PMP rule to M-mode as well, so
even a bug in the monitor cannot overwrite its own code — a store into `.text`
faults. A sole arbiter that could rewrite its own logic would not be a root of
trust; the lock closes that gap with a single PMP entry, on stock RISC-V (no
Smepmp extension required). Full Smepmp MML (M-mode default-deny + W^X over every
M region) is deferred: the monitor reads and writes U/S memory directly to load
and decrypt enclave blocks, which MML's encodings cannot express cleanly.

### Mechanics on the target

The SPMP extension (Smspmp, spec v0.9.8) used for bring-up exposes SPMP through
*indirect* CSRs (Sscsrind), not direct `spmpcfg`/`spmpaddr` registers:

- `siselect` (`0x150`) selects entry index `ISELECT_SPMP_BASE (0x100) + i`;
- `sireg` (`0x151`) reads/writes `spmpaddr[i]`, `sireg2` (`0x152`) reads/writes
  `spmpcfg[i]`.

The entries are only reachable once the monitor delegates rules to S-mode by
writing `mpmpdeleg` (`0x316`) to a value below the maximum (at reset all rules
are reserved to M, so S-mode sees none). The monitor performs this delegation
once, during security init; the enclave never gains the ability to widen its own
PMP grant.

## Consequences

- The privilege inversion (trusted enclave above untrusted host) is sound: it
  rests on PMP dominance, a hardware property, not on trusting the enclave.
- The per-transition SPMP reset (once wired — see *Implementation status*) adds a
  small, fixed cost to each `enter`/`exit`, paid in M-mode where it is already
  mediating the transition.
- The policy is small enough to test off-target. The `SpmpModel` type in the
  `umbra-riscv-arch` crate is a host-tested mirror of the two invariants:
  `clamp(...)` enforces "restrict within the PMP window" (invariant 1) and
  `reset_to_baseline(...)` enforces "no live enclave entry for the host"
  (invariant 2).

## Implementation status

What the monitor wires today, and what remains to fully discharge the design:

- **Wired now.** Security init programs a broad outer PMP grant over RAM plus the
  locked `.text` rule (mechanism 3), then sets two SPMP regions once via the
  indirect CSRs: the enclave's region **SHARED** `R|X` (so the U-mode host can
  scan it for the header and the S-mode enclave can execute from it) and the
  host's region **UMODE** `R|W|X`. Every other address is unruled, so SPMP
  default-denies U-mode — the host cannot read the Secure ESS that holds the
  decrypted enclave blocks — while S-mode default-allows it. The S-mode enclave
  runtime (block demand-load, per-block HMAC + AES-CTR decrypt, chained
  measurement, timer preemption) runs end-to-end on this substrate.
- **Pending.** (a) Tightening the broad PMP grant into per-domain regions
  (mechanism 1 currently leans on the broad grant + SPMP for the U/S split rather
  than per-domain PMP entries). (b) Wiring `reset_to_baseline` into each
  `enter`/`exit` (mechanism 2): the current enclave does **not** program its own
  SPMP, so no stale entry can govern the host yet — the reset becomes load-bearing
  only once the enclave is given SPMP self-management. (c) The two on-target
  negative tests below.

## Proof obligations

This ADR is discharged by two on-target negative tests in the enclave-lifecycle
work, not by assertion alone:

1. A U-mode host read of enclave memory traps to the monitor — proving the PMP
   outer fence holds regardless of any SPMP the enclave set (invariant 1).
2. An S-mode enclave access outside its PMP grant traps to the monitor even when
   the enclave attempts to grant itself that region via SPMP — proving SPMP
   cannot widen past PMP (invariant 1), and that the clamp is real on hardware.

Until both tests are green, the inversion is considered *designed and modelled*
but not *proven on the target*.
