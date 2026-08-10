#!/usr/bin/env bash
#
# Quantitative eval campaign: remote attestation + secure enclave update, STM32N657.
# Produces N quote-latency samples and N end-to-end update samples (each update
# installs a strictly-higher version into the inactive A/B slot, auto-reboots and
# waits for the device to come back ready), all appended to one CSV.
#
# Prereq — board flashed and sitting in the relay loop:
#   export HOST_APP=bare_metal UMBRA_VERSION_BIND=1 UMBRA_KEEP_MASTER_KEY=1 \
#          UMBRA_ATTEST_SLOTS=1 UMBRA_CREATE_BEST_SLOT=1
#   UMBRA_ENCLAVE_VERSION=2 cargo xtask flash n657
#
# Usage: ./tools/eval_attest.sh <port> [Nquote=30] [Nupdate=30] [app=ndes] [start_ver=3] [csv]
#   app = fib | ndes | ammunition (real TACLeBench workloads via two_enclaves blobs)
# NOTE: no `set -u` — make_update_blob.sh sources settings.sh (unbound ZSH_VERSION).
set -eo pipefail

PORT="${1:?usage: eval_attest.sh <port> [Nquote] [Nupdate] [app] [start_ver] [csv]}"
NQUOTE="${2:-30}"
NUPD="${3:-30}"
APP="${4:-ndes}"
START="${5:-3}"
CSV="${6:-/tmp/umbra_attest_bench.csv}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY=/opt/miniconda3/bin/python
BLOB=/tmp/umbra_eval_blob.bin

echo "== Umbra attest/update eval: port=$PORT quotes=$NQUOTE updates=$NUPD app=$APP versions=$START..$((START + NUPD - 1))"
echo "== CSV: $CSV"

echo "-- Phase 1: quote latency ($NQUOTE samples)"
"$PY" "$ROOT/tools/attest_update.py" --port "$PORT" --bench-quote "$NQUOTE" --csv "$CSV"

echo "-- Phase 2: update campaign ($NUPD chained updates, $APP)"
for ((v = START; v < START + NUPD; v++)); do
    echo "--- update -> v$v"
    # Always a clean blob build (~15 s): protect_enclave.py in-place re-sign is NOT
    # idempotent — a fast re-sign produced a measured-OK but crashing enclave (2026-07-19).
    "$ROOT/tools/make_update_blob.sh" "$v" "$BLOB" "$APP"
    "$PY" "$ROOT/tools/attest_update.py" --port "$PORT" \
        --update-blob "$BLOB" --version "$v" --bench --csv "$CSV" \
        || { echo "ABORT: update to v$v failed (see $CSV)"; exit 1; }
done

echo "-- Phase 3: aggregate statistics"
"$PY" "$ROOT/tools/bench_stats.py" "$CSV"
