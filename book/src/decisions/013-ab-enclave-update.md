# ADR 013 — Secure Enclave Update (A/B slots, nonce-bound)

**Status:** Accepted (2026-07-14) · **Platform:** STM32N657

## Context

We want to ship a new enclave to a fielded device remotely, without a cable, and
without the risk of bricking it or accepting a rolled-back image. The enclave blob
is already produced and signed offline by `protect_enclave.py` (encrypted blocks +
a measurement header bound to an author/version). The device already authenticates
that measurement and enforces anti-rollback at create time.

## Decision

Install updates into **two flash slots (A/B)** and activate by authenticated
version, gated by the attestation nonce.

> **Requires `enclave_version_bind`.** The update path's anti-rollback is the
> `version > active slot version` check, and the version is derived by
> `search_version`. With `enclave_version_bind` OFF every valid blob authenticates
> to version 0, so no update over an existing slot can ever advance — the feature is
> inert (fail-safe: it rejects, never accepts a rollback). Production/update builds
> MUST enable `enclave_version_bind` (`UMBRA_VERSION_BIND=1`). The quote path (ADR
> 012) works regardless.

- **Slots:** `ENCLAVE_SLOT_A = 0x73D0_0000`, `ENCLAVE_SLOT_B = 0x73D8_0000`
  (64 KB each, below the state-continuity region). `drivers::state_flash::
  write_enclave_slot` reuses the proven 1-1-1 SPI erase+program path.
- **Package** (`kernel::key_storage_server::enclave_update`): magic, the nonce
  from the last attestation quote, author id, version, the `protect_enclave.py`
  blob, and a `pkg_tag = HMAC(K_update, "umbra-update-v2" ‖ nonce ‖ ids ‖ blob_len
  ‖ header)`, where `header` is the blob's **entire 48-byte UMBR header**
  (`blob[0,48)`). v1 covered only `header.hmac` (`blob[16,48)`), leaving
  `trust_level`, `efbc_size`, `ess_blocks` and `reloc_count` unauthenticated —
  the format hole documented as the chain-core "residue"; v2 closes it at the
  tag. The tag authenticates the binding and the full header; the blob *body*
  is covered by the on-flash re-measurement below.
  `K_update = HMAC(MASTER_KEY, "umbra-update-key-v1")` is distinct from
  `K_attest`; quote requests therefore expose no same-key signing oracle for
  the update MAC.
- **Flow** (`umbra_enclave_update` NSC veneer): require an armed nonce that matches
  the last quote and a valid `pkg_tag` (else `ERR_NONCE`/`ERR_AUTH`); the nonce is
  consumed on every attempt. Write the blob to the **inactive** slot, then
  **re-authenticate it by reading from flash** (full measurement + version search)
  and require `version > active slot version` (else `ERR_VERIFY`/`ERR_ROLLBACK`,
  and the just-written slot is invalidated). The active slot is never touched.
- **Selection:** `umbra_enclave_create(0)` authenticates both slots and creates
  from the higher authenticated version (tie → A). No persistent "active slot"
  pointer.

## Rationale

- **A/B, not in-place.** An interrupted update or a corrupt blob leaves the active
  slot intact — never a brick. The 2× flash cost is irrelevant on a 64 MB part.
- **Re-verify from flash, not from the NS buffer.** The blob's integrity is
  established by the on-device measurement chain reading the *persisted* bytes,
  closing the TOCTOU between the NS-supplied buffer and what actually landed.
- **Nonce binding.** Tying the update to a fresh quote nonce prevents the
  untrusted relay from re-pinning a current nonce onto an old package. The nonce
  is single-use.
- **Anti-rollback is reused, not reinvented.** Version authority stays the
  existing `search_version` over the TAMP floor; the enter-time floor bump is the
  single source of truth (no duplicate bump in the update path). A package
  declaring an old version fails the `version > active` check.
- **Select-by-version, no selector.** A persistent active-slot pointer would need
  its own crash-atomic commit; deriving the active slot from the authenticated
  versions at boot avoids that entirely (TAMP dies on POR anyway).
- **DMA-free probe → coexists with `interenclave_overlay`.** The version probe
  (`authenticated_version_at`) folds the measurement by CPU-reading the
  memory-mapped flash slot directly, not by DMA-loading into the ESS window. The
  A/B slots sit outside MCE2, so the mapped bytes are the same plaintext the real
  loader would produce — the probe's measurement is byte-identical without touching
  the ESS allocator or the shared overlay window. So create-by-best-slot and the
  update handler build and run in the default (overlay-on) configuration.

## Availability: failed-boot fallback

Selecting the highest authenticated version has one liveness gap that a swap+revert
updater (MCUboot) closes and a selector-free one does not by construction: an image
that is **authentic and highest-version but crashes at runtime** passes install
re-verify *and* boot selection, then faults. On this platform an enclave fault runs
`handle_fault → SYSRESETREQ` (a *warm* reset, so TAMP survives), the FSBL re-selects
the same crashing slot, and the device warm-reset-**loops** — observed on HW as the
secure-boot LED blinking, recoverable only by a physical power-cycle + reflash.

Mitigation (the selector-free analogue of revert — a persistent *failure* counter, not
a persistent *active* pointer):

- Two spare TAMP backup registers (BKP30/BKP31) hold a per-slot **failed-boot count**
  (`drivers::tamp_store` boot-fail ops; `antirollback::BootFailCounter`). A magic tag
  in the high bits makes a POR-wiped register read as 0, so a cold boot never excludes
  a good slot.
- `create(0)` **increments** the selected slot's count *before* running the enclave;
  a clean end-of-task **clears** it (`usage_fault_terminate`, Terminated only — a
  Faulted image stays counted). A warm-reset crash therefore leaves the increment.
- After `BOOT_FAIL_THRESHOLD` (3) consecutive crashes, `create(0)` **excludes** that
  slot (passes `None` into the still-pure `select_active_slot`) and boots the other
  authenticated slot. A fresh update to a slot **clears** its count (new image, clean
  chance).
- Bound: if *both* slots exceed the threshold, `create(0)` returns `EnclaveNotFound`
  and the host halts (no loop) — a POR + re-provision is then required. Gated by
  `enclave_version_bind` (the build where A/B update lives).

## Consequences

- Create measures the chosen slot twice (probe reads flash, real create DMA-loads +
  measures). A few milliseconds — the security is worth it.
- COLD_WINDOW (ADR 009) still applies: after a POR the floor is cold and an old
  ≤ COLD_WINDOW version could be admitted locally — the attestation quote (ADR
  012) makes that window remotely visible.
- A crashing-but-authentic image no longer bricks the device: it self-recovers to the
  previous good slot after `BOOT_FAIL_THRESHOLD` warm-reset crashes (see above).
