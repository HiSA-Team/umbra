#!/usr/bin/env bash
# N657 enclave anti-rollback negative test.
# Proves the gated anti-rollback path refuses a re-presented OLDER enclave
# version (remote/software attacker). ARM builds run in the user's environment;
# this script only prints the procedure and what to look for on the UART.
#
# Requires BOTH gates enabled:
#   - offline:  UMBRA_VERSION_BIND=1  (tools/protect_enclave.py trailing fold)
#   - firmware: the N657 boot crate built with feature `enclave_version_bind`
set -euo pipefail
cat <<'STEPS'
=== N657 enclave anti-rollback negative test ===
Prereq: MCU_VARIANT=stm32n657, board powered (do NOT remove VBAT between phases),
UART @ 115200. Build the boot crate with the `enclave_version_bind` feature.

--- Phase 1: admit v2 (raises the floor to 2) ---
  export UMBRA_VERSION_BIND=1 UMBRA_AUTHOR_ID=1 UMBRA_ENCLAVE_VERSION=2
  # build N657 boot WITH --features enclave_version_bind, protect enclave @ v2
  ./rebuild_all.sh && ./debug.sh
  EXPECT: enclave runs; no "version DENIED"; (BKPSRAM floor for author 1 is now 2).

--- Phase 2: re-present v1 (must be refused) ---
  export UMBRA_VERSION_BIND=1 UMBRA_AUTHOR_ID=1 UMBRA_ENCLAVE_VERSION=1
  # re-protect the enclave blob @ v1 (same author); keep the board POWERED.
  ./debug.sh
  EXPECT: [UMBRASecureBoot] version DENIED (rollback/tamper/out-of-window)
          enclave does NOT run (v1 is below the floor 2 -> below the search start).

PASS = Phase 1 admits v2 AND Phase 2 denies v1.

NOTE (documented limitation, VBAT-trust assumption): power-cycling WITH VBAT loss
between the phases resets the floor to 0; the COLD_WINDOW (1024) scan would then
admit v1, logged as "rollback floor cold (0)". That physical-attacker gap is
closed only by the deferred OTP/BSEC fuse-counter backend. Keep the board powered
to exercise the software-attacker path this test targets.
STEPS
