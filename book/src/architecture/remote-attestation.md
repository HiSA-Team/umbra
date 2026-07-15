# Remote Attestation & Secure Enclave Update

Two related capabilities on the STM32N657, verified on hardware:

1. **Remote attestation** — a remote verifier obtains a signed, fresh report of
   the device's internal state: the enclave measurement, the authenticated
   version, the anti-rollback floor, the state-continuity generation, and
   platform health (reset cause, HDPL). This proves the device is running the
   *right* enclave at the *right* version, and exposes fail-open windows.
2. **Secure enclave update** — a new enclave is sent from a remote host over
   UART, authenticated, written into an inactive A/B flash slot, re-verified from
   flash, and activated by version — anti-rollback enforced, never brick.

Design rationale lives in [ADR 012](../decisions/012-remote-attestation.md) and
[ADR 013](../decisions/013-ab-enclave-update.md). This page describes the feature
and how to exercise it.

## Attestation quote

A challenge-response over UART. The verifier sends a 16-byte nonce; the Secure
kernel builds a 115-byte quote and signs it with a MASTER_KEY-derived key on the
hardware HASH engine:

```text
K_attest = HMAC-SHA256(MASTER_KEY, "umbra-attest-v1")
tag      = HMAC-SHA256(K_attest, quote_fields)
```

The quote carries: nonce, enclave id + status, block measurement `bm`, author id,
authenticated version, anti-rollback floor, state-continuity anchor generation,
last restore decision, boot reset cause (`RCC_RSR`), HDPL, and feature flags. The
verifier re-derives `K_attest` (it holds `MASTER_KEY`), checks the tag and the
nonce freshness, and applies its policy — e.g. reject if the reported version is
below what it expects.

Because the version is derived by search over the measurement (not stored in the
clear), a rolled-back binary is structurally unable to produce a valid
higher-version quote.

### COLD_WINDOW visibility

The anti-rollback floor and state anchor live in the TAMP backup domain, which
survives a warm/software reset but is wiped by a power-off without a VBAT cell
(the [state-continuity power-session boundary](../decisions/009-state-continuity-power-session-boundary.md)).
The quote reports the **signed reset cause**, so the remote verifier can tell a
warm-reset-defended state from a genuine cold fail-open window — turning a local
boundary into a remotely-observable event.

## Secure update (A/B slots)

Two enclave slots on external flash (`SLOT_A = 0x73D0_0000`,
`SLOT_B = 0x73D8_0000`). `umbra_enclave_create(0)` authenticates both and runs the
higher version. An update package (built by `tools/attest_update.py`) carries the
nonce from the last quote plus a `pkg_tag` that binds the nonce to the blob:

```text
pkg_tag = HMAC-SHA256(K_attest, "umbra-update-v1" ‖ nonce ‖ author ‖ version ‖ blob_len ‖ header.hmac)
```

The Secure handler checks the armed nonce and `pkg_tag`, writes the blob to the
**inactive** slot, then **re-verifies it by reading from flash** (full measurement
+ version search) and requires the new version to strictly exceed the active one —
else `ERR_ROLLBACK`, and the just-written slot is invalidated. The active slot is
never touched, so an interrupted or malicious update never bricks the device.
Anti-rollback reuses the existing version floor; the update path requires the
`enclave_version_bind` feature.

## Transport

USART1 is Secure-only on the N657, so the Non-Secure host cannot poll it directly.
The **frame parser stays in the Non-Secure relay** (so a parser bug is at most a
denial of service), and raw byte I/O crosses to Secure through two tightly-scoped
bridge veneers:

| NSC veneer | Purpose |
|---|---|
| `umbra_attest_quote(nonce_ptr, out_ptr)` | build + sign a quote |
| `umbra_enclave_update(pkg_ptr, len)` | authenticate + install an update |
| `umbra_uart_read(ptr, len)` / `umbra_uart_write(ptr, len)` | Secure UART byte bridge |

Frame format: `[SOF 0xA5][cmd u8][len u16 LE][payload][crc32 LE]`. The CRC32 and
all byte offsets are pinned across Python and Rust by
`tools/test_attestation_guard.py`.

## Using it

Build and flash with attestation enabled. `UMBRA_KEEP_MASTER_KEY=1` keeps the
device key so the verifier CLI can check tags; `UMBRA_ATTEST_SLOTS=1` auto-provisions
`SLOT_A` from the build; `UMBRA_CREATE_BEST_SLOT=1` makes the host call `create(0)`:

```bash
export HOST_APP=bare_metal UMBRA_VERSION_BIND=1 UMBRA_KEEP_MASTER_KEY=1 \
       UMBRA_ATTEST_SLOTS=1 UMBRA_CREATE_BEST_SLOT=1
UMBRA_ENCLAVE_VERSION=2 cargo xtask flash n657
```

Request a quote (the verifier re-derives the key from `tools/master_key.bin`):

```bash
python tools/attest_update.py --port <VCP> --expect-version 2
```

Send a higher-version enclave from remote:

```bash
./tools/make_update_blob.sh 3 /tmp/slot_v3.bin
python tools/attest_update.py --port <VCP> --update-blob /tmp/slot_v3.bin --version 3
```

> Remember to `git checkout -- tools/master_key.bin src/hardware/platform/*/boot/src/master_key.rs`
> before committing — a rotated key must never be committed.

## Verified on hardware (NUCLEO-N657X0-Q)

- **Attestation quote**: `tag OK`, `nonce fresh`, correct authenticated version,
  `VERDICT TRUSTED`.
- **Wrong-version detection**: requesting a version above the reported one yields
  `UNTRUSTED`.
- **Warm vs. cold**: a warm reset (RST button) reports `reset=0x00400000` with no
  fail-open warning and the floor persists; a power-cycle reports `reset=0x00e00000`
  with the POR fail-open warning — the verifier distinguishes them.
- **Secure update**: a v3 enclave sent over UART returns `update status 0x0`
  (written to `SLOT_B`); the device then **auto-reboots** (software reset,
  `reset=0x01400000`; no manual reset) and the quote reports `version 3`,
  `floor=3`. The activate-on-reboot is the MCUboot/OTA model; the software reset
  preserves the TAMP floor.
- **Update rejections**: a below-floor rollback and a tampered blob both yield
  `ERR_VERIFY` (the enclave fails to authenticate at a version at or above the
  floor); a same-version replay yields `ERR_ROLLBACK`; an update with no armed
  nonce yields `ERR_NONCE`. Every rollback path is rejected.

## Limitations

- **Trusted verifier.** The symmetric MAC means anyone holding `MASTER_KEY` can
  forge a quote. Acceptable for a verifier provisioned with the device key; the
  quote reserves a flags bit for a future ECDSA upgrade (on-device PKA + RNG).
- **Cold durability.** Without a VBAT cell, a power-off wipes the TAMP floor/anchor
  (COLD_WINDOW). The warm/software-reset attacker is defended; physical power-cycle
  durability is a future OTP-fuse epoch. The quote makes the window remotely visible.
- **Update requires `enclave_version_bind`.** With it off, all versions collapse to
  zero and no update over an existing slot can advance (fail-safe: it rejects).
