#!/usr/bin/env bash
#
# Adversarial harness (gap-4): drive a counted battery of attacks at the running
# attestation/update relay and tally defended/total per attack. Non-mutating auth &
# freshness attacks run K times each; mutating attacks (tamper, downgrade) run once
# and touch only the INACTIVE A/B slot, so the device keeps booting.
#
# Prereq: board flashed + in the relay loop, same env as eval_attest.sh. A valid
# signed enclave blob is needed for tamper/downgrade (build one with make_update_blob.sh).
#
# Usage: ./tools/adversarial_attest.sh <port> [K=20] [blob] [downgrade_ver]
#   blob          : a VALID signed enclave (for tamper); optional
#   downgrade_ver : version <= active to attempt as a rollback; needs blob at that version
# NOTE: no `set -u` (settings.sh / sourced env).
set -eo pipefail

PORT="${1:?usage: adversarial_attest.sh <port> [K] [blob] [downgrade_ver]}"
K="${2:-20}"
BLOB="${3:-}"
DOWNGRADE_VER="${4:-}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY=/opt/miniconda3/bin/python
CLI="$ROOT/tools/attest_update.py"
FAIL=0

run() {  # run <attack> [extra CLI args...]
    if "$PY" "$CLI" --port "$PORT" --attack "$1" --count "$K" "${@:2}"; then :; else FAIL=1; fi
}

echo "== Adversarial harness: port=$PORT K=$K"
echo "-- non-mutating (auth + freshness), $K attempts each"
run no-quote
run replay
run wrong-key
run malformed
run stale-quote

if [ -n "$BLOB" ]; then
    echo "-- mutating (inactive slot only), 1 attempt each"
    run tamper --update-blob "$BLOB"
    run header-flip --update-blob "$BLOB"
    if [ -n "$DOWNGRADE_VER" ]; then
        run downgrade --update-blob "$BLOB" --version "$DOWNGRADE_VER"
    else
        echo "  (skip downgrade: pass a low-version blob + downgrade_ver to test rollback)"
    fi
else
    echo "-- mutating attacks SKIPPED (no blob given): tamper, header-flip, downgrade"
fi

echo "== RESULT: $([ $FAIL -eq 0 ] && echo 'ALL ATTACKS DEFENDED' || echo 'BREACH DETECTED')"
exit $FAIL
