# ADR 010 — State-continuity commit: root-in-anchor

## Status
Accepted (revised 2026-07-02, superseding the version-per-sector rule)

## Context
A checkpoint writes flash state sectors AND advances the trusted anchor. A reset
landing between the two must never resume a partial or stale state. The original
rule kept a per-sector `version[]` in the anchor and compared it to a version read
from flash. A code review + verification found two correctness defects:

- **X2:** the compared version lived in **untrusted flash**; without verifying a
  keyed MAC, an attacker sets the flash version equal to the anchor's and a stale
  ciphertext is accepted. A per-sector MAC proves *integrity of a version*, not
  that it is the *latest* — an attacker replays a whole coherent OLD checkpoint
  (all sectors, valid tags, versions ≥ floor) and it passes.
- **X1:** an A/B double-buffer that flips a *global* generation per commit is
  incoherent with dirty-tracking — non-dirty sectors in the newly-active slot are
  stale, so a partial checkpoint corrupts state (false rollback / stale accept).

## Decision
The freshness truth lives **entirely in the trusted anchor as a keyed root over
the whole logical state**; flash is untrusted and holds only ciphertexts.

- **Anchor (TAMP backup registers, Secure-write-only):** `generation` (monotonic)
  + `root = HMAC(K, enclave_id ‖ state_format_version ‖ generation ‖ H(sector_0) ‖ … ‖ H(sector_{N-1}))`
  truncated to **128 bits** — field order NORMATIVE (see *Version coupling* and
  *Anchor atomicity*)
  + one **committed-slot parity bit per sector**. `H(sector_i)` is an unkeyed
  SHA-256 of sector i's committed ciphertext; the KEYED root in the trusted anchor
  is what makes it fresh and authentic.
- **Checkpoint:** stage each dirty sector into its *staging* slot (opposite its
  committed parity; the committed copy is never overwritten), flip that sector's
  parity bit, recompute the root over the resulting committed state, then commit a
  **single** new anchor `{generation+1, root, parity}`. Non-dirty sectors stay in
  place — the root covers the complete *logical* state, so dirty-tracking no longer
  touches correctness (X1 dissolved) and the wear saving is kept.
- **Restore:** recompute the root over the committed slots and **compare
  constant-time** to the anchor root. Match → resume; mismatch (rollback, replay,
  tamper, mix-and-match) → **hard reject** (X2 closed). Flash is never trusted.
- **Anchor atomicity:** the anchor spans several TAMP registers, so its write is
  not atomic. It is **double-buffered** with a valid-marker written last: a torn
  multi-register write is detected and falls back to the previous good anchor copy.
  A reset before the anchor commit ⇒ old root stands, staging ignored, last-good
  survives; a reset after ⇒ new verified state. Concretely the anchor is two
  7-register copies — `{generation, 128-bit root, per-sector parity,
  generation-echo}` — placed in the backup registers left free by the code-version
  floor; a copy is valid iff its echo (written last) confirms its generation, and
  `store` writes the STALE copy so the current newest survives until the new echo
  lands. The 128-bit root is what makes both copies fit the register budget
  (2×7 = 14 registers vs 22 at 256 bits); 2^-128 forgery resistance is ample for
  anti-rollback (the attacker must forge the keyed MAC, not find a collision).

## Version coupling: state-format, not code version

An open question was whether to fold the enclave's CODE version into the root, so a snapshot
from code v1 would be refused after an update to v2. A design-review panel rejected that:

- Under the warm-reset threat model it closes **no attack**: the code-version floor already
  refuses an old binary and the keyed root already refuses a forged state. The only v1 state
  reaching a running v2 is what a *legitimate* prior version left behind — that is continuity,
  not an attack.
- The real risk it touches is a **migration-safety** fault (v2 deserializing a v1 layout), not
  rollback. Folding the code version in would also **wipe continuity on every routine update**,
  even when the layout is unchanged.

So the root binds an author-owned **`state_format_version`** instead — bumped ONLY when the
serialized snapshot layout changes. An incompatible layout then fails closed (Reject); a
compatible update keeps its state. "Is this code recent enough?" stays with the floor; "is this
layout mine to interpret?" is the format version. The two anti-rollback controls stay
**decoupled**; cross-version state migration is the enclave's responsibility, not the kernel's.

The preimage order — `enclave_id ‖ state_format_version ‖ generation ‖ digests`, little-endian,
128-bit truncation — is **normative** and frozen here, because it is the on-anchor format:
changing it once roots are persisted is a migration event. A future per-enclave `author_id`
field or an OTP/BSEC epoch is a deliberate append, and a spare TAMP register (BKP26–31) is
reserved for an opt-in migrate-policy tag if governed cross-version re-seal is ever needed —
deferred until multi-version updates and snapshot serialization actually exist.

## Checkpoint cadence
Unchanged: not per-preemption-tick. A 4 KB NOR subsector erase takes tens–hundreds
of ms (> a tick) and the part endures ~100k cycles, so mutable state is coalesced
in RAM and flushed only at coarse boundaries (yield/suspend or a seconds timer).
Dirty-tracking bounds how many sectors each flush touches; the root keeps it
correctness-neutral.

## Cold boot (COLD_WINDOW)
On a cold power-off (no VBAT) the TAMP anchor zeroes, so there is no root to compare
against and restore must fail **open** — trust the current flash as the new baseline
(genesis). For the warm-reset threat model this is the documented boundary: cold boot
= physical power-off = out of scope (ADR 009), and the `PWR_SECCFGR.SEC5` fix closes
the software cold-equivalent path. Defending a *physical* attacker requires a durable
monotonic epoch in OTP/BSEC as the cold-boot floor — deferred (Phase 2), never silent.

## Scope (v1)
Single enclave: one `generation + root + parity`. Concurrent enclaves need a
per-enclave anchor region — a deliberately deferred extension, not silent behaviour.

## Consequences
No partial state is ever resumed and no stale state passes as fresh: freshness is a
keyed root in the trusted anchor, checked against a recomputation over untrusted
flash. Crash-atomicity is the single double-buffered anchor commit; the per-sector
A/B slots survive a torn write of an individual sector.
