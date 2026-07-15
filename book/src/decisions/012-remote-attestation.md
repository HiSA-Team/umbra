# ADR 012 — Remote Attestation (symmetric HMAC quote)

**Status:** Accepted (2026-07-14) · **Platform:** STM32N657

## Context

A remote verifier needs proof that the device is running the *right* enclave —
the correct measurement, an authenticated version at or above the anti-rollback
floor, and a runtime state that has not been rolled back. The existing controls
(chained block measurement `BM`, version-by-search over the TAMP floor,
state-continuity root anchor) all live *on-device*; nothing exports a signed,
fresh view of them.

## Decision

Add a **challenge-response attestation quote** signed with a symmetric key.

- **Key:** `K_attest = HMAC-SHA256(MASTER_KEY, "umbra-attest-v1")`, derived at boot
  in `init_keys` alongside the other subkeys, computed on the HW HASH engine.
- **Quote** (fixed 115-byte layout, `kernel::key_storage_server::attestation`):
  nonce, enclave id + status, `BM` (`chain_state`), author id, authenticated
  version, anti-rollback floor, state-continuity anchor generation, last restore
  decision, boot reset cause (`RCC_RSR`), HDPL, feature flags, and a trailing
  `HMAC(K_attest, preimage)` tag.
- **Transport:** the Non-Secure host relays a framed UART protocol to a new NSC
  veneer `umbra_attest_quote(nonce_ptr, out_ptr)`. The Secure side range-checks
  the NS pointers, gathers the state, signs, and writes the quote back. NS can
  only deny service.
- **Verifier:** `tools/attest_update.py` on a trusted host that already holds
  `MASTER_KEY` (it drives `protect_enclave.py`). It re-derives `K_attest`, checks
  the tag and the nonce freshness, and flags anomalies.

## Rationale

- **Symmetric, not ECDSA.** The verifier is trusted (it holds `MASTER_KEY`), so a
  shared-key MAC is sufficient and reuses the HW HASH engine with zero new
  bring-up. The quote reserves an `alg` bit in `flags` for a future ECDSA upgrade
  (PKA + RNG) when a non-trusted verifier is required — out of scope here.
- **"Wrong version" is detectable.** The quote carries the authenticated version
  and floor; the verifier rejects any version below its expectation. Because the
  version is derived by search over the measurement, a rolled-back binary is
  structurally unrepresentable on-device and cannot produce a valid higher-version
  quote.
- **COLD_WINDOW becomes visible.** After a POR the backup domain is cold and the
  anti-rollback floor / state anchor fail open (ADR 009). The quote reports the
  signed `reset_cause`, so the *remote* verifier detects the fail-open window even
  though the local device cannot close it without VBAT. Turning a silent local
  boundary into a remotely-observable event is the main security gain.

## Consequences

- The verifier can forge quotes (it holds the key). Acceptable under the trusted-
  verifier model; the ECDSA path removes it later.
- The quote is not secret: it contains only measurement/state metadata, never key
  material. It transits the untrusted NS relay safely.
- One new always-linked Secure code path (quote build + HW HMAC) in the kernel
  region.

See ADR 013 for the secure-update path that consumes the quote nonce.
