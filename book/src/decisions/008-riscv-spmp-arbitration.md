# ADR 008 — RISC-V ring model: M-mode per-world PMP+sPMP world-switch as arbiter

**Status:** Accepted. The ring flip (enclave→U, host→S, per-world PMP+sPMP context
swap) is implemented and runs on the SPMP-patched QEMU. *Corrected during QEMU
bring-up: the U-mode enclave is sPMP-denied by default, so the per-world swap must
also install the enclave's sPMP grants (a bare PMP-only swap caused `mcause 0xc`,
sPMP instruction-fetch denial, on ESS entry). The fix is in commit a41c6a3.* The
PMP→sPMP trap-and-emulate gateway and Smstateen remain a separate later slice; this
ADR covers the flipped topology and the minimal sPMP entry programming it requires.

## Context

On the RISC-V RV32 target, Umbra uses a three-ring model with the following assignment:

- **M-mode** — the Umbra monitor (TCB). Sole owner of PMP and sPMP delegation;
  dispatches `ecall`; mediates every ring transition; `.text` is ePMP-locked
  (Locked R-X at PMP slot 1 — slot 0 is the TOR base address register — world-invariant).
- **S-mode** — the untrusted host (the future RTOS), relocated from U-mode in the prior
  topology. Runs with coarse access to its own region; cannot touch PMP (the CSRs are
  M-only — an S-mode CSR access is an illegal-instruction trap to M).
- **U-mode** — the trusted enclave, relocated from S-mode. Executes from the Secure ESS
  (decrypted enclave code and stack); its PMP context fences out the host and monitor
  regions entirely.

The central isolation problem is structural, with a key RISC-V asymmetry between S and U:

- **PMP** applies to both S and U but cannot distinguish between them. No static rule
  can grant S access to its region while simultaneously denying S access to the ESS.
- **sPMP** applies to U-mode only. S-mode default-allows any address with no matching
  sPMP rule; sPMP is irrelevant to S. U-mode, by contrast, is **denied by default**
  unless a live sPMP rule grants the access.

This asymmetry determines how each domain is protected:

- The **S-mode host** is fenced purely by **PMP**: the host-world PMP context excludes
  the ESS, so any S-mode access to ESS is an unruled-and-denied PMP fault. sPMP cannot
  help or hurt here — S-mode ignores sPMP.
- The **U-mode enclave** is confined by **PMP ∧ sPMP**: PMP grants the enclave its
  code and stack envelope (and denies it the host region); sPMP must also grant the same
  envelope, because without live sPMP rules the U-mode enclave cannot execute a single
  instruction.

No single static configuration can therefore protect a trusted U-mode enclave from a
more-privileged S-mode host that might read or overwrite the Secure ESS. The per-world
swap of both PMP and sPMP, performed by M on every ring transition, is the arbiter.

## Decision

Three mechanisms together make M the sole arbiter of the inter-domain boundary.

### 1. Per-world PMP context, swapped by M on every transition

Umbra holds two per-world PMP contexts in its monitor state and rewrites the relevant
PMP entry CSRs on every ring transition:

- **Host-world context** (active while S-mode runs): grants `[0x8010_0000, 0x8020_0000)`
  RWX to S. The ESS region (`0x8020_0000` and above) has no matching PMP rule and is
  therefore denied to S.
- **Enclave-world context** (active while U-mode runs): grants ESS code R-X over
  `[0x8020_0000, 0x8021_0000)` and enclave stack R-W over `[0x8021_0000, 0x8022_0000)`
  (W^X). The host region has no matching PMP rule and is therefore denied to U.

The per-world entries occupy PMP TOR slots 3 and 5; slot 1 holds the locked `.text`
rule (slot 0 is the TOR base address register) and is untouched by any transition.

The host can never widen its own world: PMP CSRs are M-only, so any S-mode access to
them traps to M as an illegal-instruction fault. Each world runs under exactly the
context M installed for it; the other world's region is unruled and denied.

### 2. Per-world sPMP context, swapped by M on every transition

Because U-mode is sPMP-denied by default, `enter_enclave_world()` must also install
sPMP grants before returning to U:

- **Entering enclave-world:** `mpmpdeleg` is set to 32, delegating sPMP entries 32–63
  to S-mode supervision (leaving entries 0–31 under M control). M installs two U-mode
  grants in entries 0 and 1:
  - Entry 0 — ESS code region R-X (NAPOT), matching the enclave-world PMP R-X grant.
  - Entry 1 — Enclave stack region R-W (NAPOT), matching the enclave-world PMP R-W grant.
  Without these entries, the enclave faults immediately on the first instruction fetch
  (`mcause 0xc`, sPMP instruction-fetch denial) regardless of PMP state.
- **Entering host-world:** the sPMP entries are left in place. This is safe because
  the host runs in S-mode and S-mode is not gated by sPMP; the entries are inert while
  S is executing. A future slice that runs host or RTOS code in U-mode **must** reset
  the sPMP context on host entry (a `reset_to_baseline` clearing entries 0–1) before
  that U-mode guest can execute.

#### Constraint: `mpmpdeleg = 32` is doubly load-bearing

The value 32 satisfies two independent requirements simultaneously:

1. **sPMP rule coverage:** `num_deleg_rules = 64 − mpmpdeleg = 32`. Entries 0 and 1
   fall within [0, 31], so the M-installed grants are not in the delegated range and
   cannot be overwritten by S.
2. **PMP enforcement window:** `max_pmp_index = mpmpdeleg & 0x7F = 32` (the QEMU patch
   computes this directly — no minus-one). The loop checks PMP slots `0 ..< 32`, so the
   highest per-world slot used (5) and the `.text` lock (slot 1) are both inside the
   window. A value below 6 would truncate the window past slot 5 and silently disable
   the per-world PMP grants.

The combination of rules means 32 is the minimum safe value. Values 6–31 satisfy the
PMP window but expose entries 0–(63−val) to S-mode delegation (sPMP unsafe). Values
above 32 close the sPMP delegation window further but are equally safe.

The sPMP swap is implemented in `umbra-riscv-arch::pmp`, in the same
`enter_enclave_world()` function that writes the PMP context.

### 3. ePMP `.text` self-lock — the monitor cannot corrupt its own code

The monitor installs a Locked (`L=1`) read+execute PMP rule over its own `.text` at
PMP slot 1 (slot 0 holds the TOR base address) during security init. A Locked rule
applies to M-mode as well: even a bug in the monitor cannot overwrite its own code —
a store into `.text` faults.

This entry is constant in both worlds; the world-switch does not touch it.

Full Smepmp MML (M-mode default-deny + W^X over every M region) is deferred: the
monitor reads S-mode memory and writes ESS directly during enclave loading, which MML's
encodings cannot express cleanly without additional entries.

### What remains deferred to the gateway slice

sPMP *entry programming* is now part of this slice — it is required for the U-mode
enclave to execute. What remains deferred is:

- **PMP→sPMP trap-and-emulate gateway:** `mstateen0.CSRIND = 0` will force S-mode
  sPMP / indirect-CSR access (`siselect`/`sireg`/`sireg2`) to trap to M, making
  Umbra's monitor the only path to sPMP rule changes, rather than relying on the RTOS
  not knowing sPMP exists.
- **Smstateen:** wiring `mstateen0.CSRIND` to enforce the gateway trap is a prerequisite
  for the above and is also deferred.

## Proof obligations

The ADR is discharged by two classes of evidence.

### Off-target host model

The `PmpWorld` type (built via the `host_world()` / `enclave_world()` constructors)
in the `umbra-riscv-arch` crate is a host-tested mirror of the two PMP contexts.
Its assertions:

- Host-world denies the ESS region (`0x8020_0000` and above).
- Enclave-world denies the host region (`[0x8010_0000, 0x8020_0000)`) and the monitor
  region (`0x8000_0000` and above).
- A read+execute code grant does not confer write (W^X invariant).
- Region boundaries are half-open `[base, end)` — no off-by-one at the fence.

These tests run in CI as part of the host workspace (`umbra-riscv-arch`).

### On-target QEMU negative-isolation tests

Two QEMU smoke tests exercise the fence on hardware:

1. **S-mode host read of enclave ESS traps to M.** The test issues a load from the
   ESS base address (`0x8020_0000`) while the host-world PMP context is active. The
   monitor observes `mcause = load access fault` with `mtval = 0x8020_0000` and
   records the trap — proving that S-mode cannot read or corrupt enclave memory
   through any code path. Isolation here is enforced by **PMP** alone (sPMP is
   irrelevant to S-mode).
2. **U-mode enclave read of the host region traps to M.** The test issues a load
   from the host region (`0x8010_0000`) while the enclave-world PMP context is active.
   The monitor again observes a load access fault — proving that the enclave cannot
   exfiltrate or tamper with the host. Isolation here is enforced by **PMP ∧ sPMP**:
   PMP excludes the host region from the enclave's envelope, and sPMP provides no U-mode
   grant for the host region.

Until both tests are green, the model is considered *designed and modelled* but not
*proven on the target*.

## Consequences

- The enclave-in-U model requires both PMP and sPMP programming on every
  `enter_enclave_world()` call. The two mechanisms protect different directions: PMP
  fences the S-mode host away from the ESS; sPMP gates U-mode access so the enclave
  can operate at all.
- The host (S-mode) is structurally less privileged with respect to memory protection
  than under the prior topology: it cannot program PMP, and it runs under the
  host-world context M installs — any attempt to reach ESS is a hardware fault into M.
  S-mode is unaffected by sPMP, so sPMP provides no additional surface for the host.
- The per-transition swap adds a small fixed cost (~2–4 CSR writes for PMP + 3–4 for
  sPMP) to each `enter`/`exit`, paid in M-mode where the transition is already mediated.
- The policy is testable entirely off-target: the `PmpWorld` host tests cover
  all four PMP invariants and can run on any platform in CI without QEMU or hardware.
  sPMP entry correctness is validated by the on-target negative-isolation tests.
- `enter_host_world()` does not currently clear the enclave's sPMP entries (entries 0
  and 1). This is safe as long as the host runs entirely in S-mode (sPMP is inert for
  S). A future host-in-U extension must reset the sPMP context on every host entry.
- The Smstateen / PMP→sPMP gateway slice remains fully orthogonal and can be added
  without revisiting the ring assignment or the PMP+sPMP world-switch mechanism
  documented here.

## Cross-references

- [ADR 000 — Threat model](000-threat-model.md): availability and memory isolation
  invariants that this ADR closes for the RISC-V target.
- [Boot Flow](../architecture/boot-flow.md): the `_enter_smode` boot hand-off that
  places the host in S-mode before the first enclave `enter`.
- Contributor guardrails ([guardrails](../contributing/guardrails.md)): rule against
  granting S-mode any path to PMP CSRs.
