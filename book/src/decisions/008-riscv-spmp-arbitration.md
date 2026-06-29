# ADR 008 — RISC-V ring model: M-mode per-world PMP+sPMP world-switch as arbiter

**Status:** Accepted. The ring flip (enclave→U, host→S, per-world PMP+sPMP context
swap) is implemented and runs on the SPMP-patched QEMU. *Corrected during QEMU
bring-up: the U-mode enclave is sPMP-denied by default, so the per-world swap must
also install the enclave's sPMP grants (a bare PMP-only swap caused `mcause 0xc`,
sPMP instruction-fetch denial, on ESS entry). The fix is in commit a41c6a3.* The
PMP→sPMP trap-and-emulate gateway **and** the Smstateen hardening are now
implemented — see [§ Gateway + Smstateen](#gateway--smstateen) below; this ADR's
earlier "remains deferred" notes are superseded by that section.

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

## Gateway + Smstateen

The PMP→sPMP trap-and-emulate gateway and the Smstateen hardening, deferred when
this ADR was first written, are now implemented (the gateway slice). Three pieces:

### PMP→sPMP shadow (trap-and-emulate)

The S-mode guest is written as if it owns M-mode PMP. PMP CSRs are M-only, so the
guest's `pmpcfg`/`pmpaddr` accesses trap to M as illegal instructions. A fourth
trap-dispatch path, `try_handle_paravirt_csr` (after `try_handle_return` /
`try_handle_ess_miss`), decodes the trapped Zicsr instruction (a pure, host-tested
decoder in `umbra-riscv-arch::paravirt`), mirrors it in a per-guest shadow PMP
table, and for each PMP entry the guest writes programs a clamped **U-mode sPMP**
entry: guest PMP entry *i* → sPMP entry *(2 + i)*, `UMODE`, with `[base, end)`
clamped to the guest's host-world PMP grant `[HOST_REGION_BASE, HOST_WORLD_END)`.
Because every U/S access is `PMP ∧ sPMP`, the clamped `UMODE` rule can only
*restrict* within the guest's PMP world — the guest can never widen past it. The
gateway guards on `mcause == 2 && trapped_from_supervisor()`, so it never steals
the enclave's U-mode trap-fill or a genuine illegal instruction. NAPOT only in
this slice (TOR/NA4/OFF guest entries decode to "no grant" → the sPMP entry is
disabled). Proven on QEMU (`gateway_demo`): a guest grants a U-task R-X over a
region and leaves a secret ungranted; the U-task reads the granted region
(`[GW] param read OK`) then page-faults on the secret (`mcause 0xd`, sPMP deny).

### Per-transition sPMP reset (slice-1 deferral discharged)

sPMP entries are global CSRs, so the world switch now owns them fully:
`enter_host_world()` disables the enclave's sPMP entries 0/1 and reinstalls the
guest shadow entries (2+); `enter_enclave_world()` disables the guest shadow and
reinstalls entries 0/1. `mpmpdeleg = 32` is now set once at boot (it must precede
the first `enter_host_world`, which programs sPMP). This closes the gap noted
earlier ("a future host-in-U extension must reset the sPMP context"): a guest
`UMODE` rule can never govern the enclave U-task, or vice versa. The enclave still
returns `R0 = 0x72CA33A8` with the guest shadow present (no cross-leak).

### Smstateen — direct-sPMP gate

The shadow only mediates the guest's *PMP* CSRs. A guest that knows sPMP exists
could try to program it directly via the indirect-CSR mechanism (`siselect 0x150`
/ `sireg 0x151` / `sireg2 0x152`). Smstateen closes that: the monitor clears
`mstateen0` bit 60 — the indirect-select enable, named `SVSLCT` in the patched
QEMU (the architectural `CSRIND` control) — so an S-mode indirect-CSR access traps
to M, where the gateway **denies** it (`[GW] denied direct guest sPMP write`). M
always retains access (`smstateen_acc_ok` short-circuits for `priv == M`).

Two implementation subtleties, both load-bearing:

- **The CPU must have Smstateen.** A spike of the patched QEMU showed the gating
  code path is correct (bit 60 gates `siselect`/`sireg`) but is *inert* unless
  `riscv_cpu_cfg(env)->ext_smstateen` is set — and `ext_smstateen` defaults off,
  enabled neither by `spmp` nor `sscsrind`. The reference QEMU config is therefore
  `-cpu rv32,spmp=true,smstateen=true` (settings.sh). On a CPU without Smstateen
  the gate is a no-op and a guest could program sPMP directly — but even then the
  hard isolation holds: PMP dominance + the per-transition reset still fence the
  enclave and monitor; a direct guest sPMP write could only re-grant *within the
  guest's own PMP world*, affecting only the guest's own U-tasks.
- **`mstateen0` resets to 0 = deny-all-to-S.** Enabling Smstateen flips every
  `mstateen0`-gated feature (FCSR, AIA, envcfg, …) to deny-by-default for S. So the
  monitor grants S **all** `mstateen0` bits and clears **only** bit 60
  (`gate_guest_indirect_csr`), or the host would lose unrelated features.

Proven on QEMU (`gateway_evil`): a guest's direct `csrw siselect` traps and the
monitor prints the deny line; the write never takes effect.

## TockOS S-mode guest (trap-and-emulate)

Umbra runs **stock TockOS** (`qemu_rv32_virt` board) as the untrusted S-mode guest,
trap-and-emulating Tock's *machine*-mode interface on top of the PMP→sPMP gateway.
The progression below is: boot the guest to its idle loop by M-CSR emulation alone;
make it a *live* OS by virtualizing its interrupts; then have it drive the enclave.

### Boot-path M-op inventory + native feasibility

TockOS rv32 is hard-wired M-mode (no `satp`/S-mode): `arch/riscv` writes
`mscratch`/`mtvec` and ends its trap handler in `mret`; the board installs an MML
ePMP and enables interrupts via `mie`/`mstatus`. Porting it to native S-mode would
fork the upstream arch crate, so **trap-and-emulate is the chosen path**. A QEMU
`-d in_asm` trace of the stock board (M-mode) enumerated the boot-path M-ops:
`mhartid` (read), `mscratch`, `mtvec`, `mcause`, `mseccfg`, plus the gateway PMP
CSRs; running under Umbra (no MML fault) additionally surfaced `mip`. Notably the
stock trace *panics* at an MML access fault once `mseccfg` is really applied —
exactly why Umbra **shadows `mseccfg` and never applies it** (see below).

### Virtual M-CSR file (mechanism)

A monitor-side per-guest shadow of the machine CSRs Tock touches, alongside the
gateway `GuestPmp`. A trapped S-mode machine-CSR access (`mcause = 2`) is decoded by
the pure `umbra-riscv-arch::paravirt` helpers and dispatched in
`try_handle_paravirt_csr` (after the `0x150-0x152` direct-sPMP deny, before the PMP
filter):

- **RW shadow** (`MCSR_RW`): `mstatus`, `medeleg`, `mideleg`, `mie`, `mtvec`,
  `mscratch`, `mepc`, `mcause`, `mtval`, `mip`, `mcounteren`, `menvcfg`, and
  **`mseccfg` (0x747) — absorbed into the shadow and NEVER applied**, so Tock's
  Smepmp/MML write cannot alter Umbra's real PMP semantics (and the MML access-fault
  that crashes the stock kernel cannot occur). A write updates the shadow only; a
  read returns it. `mip` shadows the real machine pending bits on read (below).
- **RO constants** (`mcsr_ro_value`): `mhartid`/`mvendorid`/`marchid`/`mimpid` = 0,
  `misa` = RV32IMAC, and the performance counters (`mcycle`/`minstret`/`mhpmcounter*`
  + RV32 high halves) = 0 so Tock's panic printer completes.

The table is host-tested in `umbra-riscv-arch` (`is_mcsr` / `is_mcsr_rw` /
`mcsr_ro_value`) and is one-line-extensible — `mip` was added by reconciling the
seed against the live boot (the stock trace died at the MML fault before reaching it).

### Host-world MMIO grant + guest load

Tock drives QEMU virt MMIO directly (16550 UART, VirtIO, PLIC, CLINT), unlike the
bare-metal host which `ecall`s the monitor. `enter_host_world` therefore grants the
low-MMIO window `[0, 0x2000_0000)` (two PMP TOR entries straddling the carved CLINT
`mtimecmp` word — see the vtimer below) while S runs; it sits far below the monitor
(`0x8000_0000`) and the enclave ESS (`0x8020_0000`), and enclave-world omits it. The
board is relinked (`layout.ld` ORIGIN `0x8010_0000`, with flash/RAM kept
power-of-two and base-aligned so Tock's NAPOT ePMP specs don't panic) and loaded as
`HOST_APP=tock` via the existing `-device loader,file=` path; `debug.sh` adds
`-global virtio-mmio.force-legacy=false` so Tock's VirtIO transport accepts the virt
machine's (empty) v2 slots.

### Interrupt virtualization — the live OS

Booting to the idle loop is M-CSR-emulate-only: Tock's drivers are interrupt-driven,
and every machine interrupt (UART TX/RX via PLIC, the CLINT timer) traps to M = Umbra,
not the shadowed S-guest, so the async UART stalls after one `debug!` line and the
scheduler never ticks. The live OS reflects those interrupts into Tock and emulates
its `mret`, with a **virtualized CLINT timer** — full console output and a ticking
scheduler timer. Three monitor-side primitives, built on the shadow M-CSR file above
and pure host-tested bit-math in `umbra-riscv-arch::paravirt`:

1. **`inject_guest_irq(cause)`** — reflect a machine interrupt (timer 7 / external 11)
   into Tock by writing its shadow `mepc`/`mcause`/`mstatus` (`MPIE←MIE`, `MIE←0`,
   `MPP←S`) and redirecting `frame.mepc` to the guest's `mtvec`; the dispatch's real
   `mret` lands in S at Tock's `_start_trap`. The real source is masked until the
   guest acks (else a level-asserted UART/PLIC line re-traps every instruction).
2. **`mret` emulation** — Tock ends its handler with `mret`, which from S is an
   illegal-instruction trap (`mcause=2`) to M. An exact-opcode check (`0x30200073`)
   pops the virtual trap (`MIE←MPIE`, `MPIE←1`, real `mepc←shadow.mepc`); MPP-aware so
   a future nested-U entry can return to U unchanged.
3. **vtimer** — Umbra owns the real `mtimecmp`; Tock's `mtimecmp` word
   (`[0x0200_4000, 0x0200_4008)`) is **carved** out of its host-world MMIO grant (two
   TOR regions straddling the hole, PMP slots 4/5 + 6/7) so its writes fault into a
   per-domain virtual `mtimecmp`. The real `mtimecmp = min(domain deadlines)` — the
   `min()` is the hook for the enclave-preemption deadline. The guest's `mip` read
   returns the **real** machine pending bits (MTIP tracks `mtime≥mtimecmp`, MEIP the
   PLIC), or the guest busy-loops servicing a timer it can never clear in its view.

**Regression safety is structural:** the machinery is inert for the bare-metal host
(no PLIC/timer). Only `mie.{MTIE,MEIE}` is enabled — **never `mstatus.MIE`**, which
gates *M-mode* interrupt-taking and would let an interrupt nest inside the monitor;
while the hart runs in S/U, machine interrupts are taken regardless of it. The
enclave preemption path (`try_preempt`) is unchanged and runs *before* the new
vtimer branch. The default build still returns `R0 = 0x72CA33A8`.

**Result:** Tock boots under Umbra through full board init and prints **through**
`Entering main loop.` (+ the VirtIO lines) with no `unexpected_trap`. Reflecting RVC
`mtimecmp` accesses required decoding `c.lw`/`c.sw` and advancing `mepc` by the
instruction length (Tock is `riscv32imac`). **Out of scope (future):** interactive
console *input* — a reflected UART RX interrupt reaches Tock's driver before its
receive buffer is armed (a Tock invariant); the output side and the mechanism are
proven. Tock U-mode *processes* and their trap reflection also remain future targets.

### Tock drives the Umbra enclave

Finally, Tock becomes the **untrusted S-mode loader** of the enclave: full
three-ring coexistence (M monitor + S Tock + U enclave) in one boot. The enclave is
embedded in the relinked board (`qemu_rv32_virt_umbra`) in a dedicated `encl` flash
region (`[0x80170000, 0x80180000)`, inside the 512 KB NAPOT flash window so Tock's
ePMP is unaffected), AES-128-CTR-encrypted + chain-HMAC-signed in place by
`tools/protect_enclave.py` with the same master key the monitor embeds. At boot —
*before* Tock arms its scheduler vtimer, so the two never contend for the real
`mtimecmp` — the board `ecall`s the monitor's enclave API (`create` → loop `enter`,
re-entering on a timer-preemption suspend → `status`) and prints
`[TOCK] enclave R0=0x72CA33A8` via the monitor UART. The enclave-world PMP∧sPMP swap
fences Tock out of the ESS exactly as for the bare-metal host; the enclave runs
correctly with the full interrupt-virtualization machinery active.

## Cross-references

- [ADR 000 — Threat model](000-threat-model.md): availability and memory isolation
  invariants that this ADR closes for the RISC-V target.
- [Boot Flow](../architecture/boot-flow.md): the `_enter_smode` boot hand-off that
  places the host in S-mode before the first enclave `enter`.
- Contributor guardrails ([guardrails](../contributing/guardrails.md)): rule against
  granting S-mode any path to PMP CSRs.
