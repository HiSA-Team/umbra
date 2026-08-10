#!/usr/bin/env bash
#
# Generate a standalone enclave UPDATE blob at a given version, signed with the
# CURRENT tools/master_key.bin (a plain `make` — NOT rebuild_all — so the key is NOT
# rotated). Use it AFTER flashing with UMBRA_KEEP_MASTER_KEY=1 so the blob is signed
# with the same key the on-chip FSBL uses, then send it with tools/attest_update.py
# --update-blob. SLOT_A itself is provisioned by `cargo xtask flash n657` when
# UMBRA_ATTEST_SLOTS=1; this only makes the higher-version blob for the remote update.
#
# Usage:  ./tools/make_update_blob.sh <version> <out.bin> [app]
#   app = fib (default, bare_metal stub) | ndes | ammunition (real TACLeBench
#         workloads, built as standalone blobs by host/stm32n657/two_enclaves).
#   e.g.  ./tools/make_update_blob.sh 3 /tmp/slot_v3.bin ndes
#
# Always a CLEAN build: protect_enclave.py patches the enclave ELF IN PLACE and is NOT
# idempotent — re-signing an already-patched ELF re-blocks [Meta|code] as code, giving a
# measurement-consistent but semantically-corrupt blob (HW-confirmed 2026-07-19: v4
# fast-resign MemManage'd at PC=0x340E05E6; clean-vs-fast diff = 2691 bytes).
# NOTE: no `set -u` — settings.sh references ZSH_VERSION (unbound under nounset).
set -eo pipefail

if [ "${UMBRA_BLOB_FAST:-0}" = "1" ]; then
    echo "WARNING: UMBRA_BLOB_FAST removed (non-idempotent re-sign corrupts the blob); clean-building."
fi

VER="${1:?usage: make_update_blob.sh <version> <out.bin> [fib|ndes|ammunition]}"
OUT="${2:?usage: make_update_blob.sh <version> <out.bin> [fib|ndes|ammunition]}"
APP="${3:-fib}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH=/opt/homebrew/bin:$PATH
case "$APP" in
    fib) export HOST_APP=bare_metal ;;
    ndes|ammunition) export HOST_APP=two_enclaves ;;
    *) echo "ERROR: unknown app '$APP' (fib|ndes|ammunition)"; exit 1 ;;
esac
# shellcheck disable=SC1091
source ./settings.sh >/dev/null          # N657 env: version_bind, numeric_fold, author (keep stderr)
export UMBRA_VERSION_BIND=1
export UMBRA_CREATE_BEST_SLOT=1

HOST_DIR="$ROOT/host/stm32n657/$HOST_APP"

if [ "$APP" = "fib" ]; then
    ELF="$HOST_DIR/bin/bare_metal.elf"
    make -C "$HOST_DIR" clean >/dev/null
    UMBRA_ENCLAVE_VERSION="$VER" make -C "$HOST_DIR" >/dev/null
    [ -f "$ELF" ] || { echo "ERROR: host ELF not built at $ELF"; exit 1; }
    arm-none-eabi-objcopy -O binary \
        --only-section=._enclave_header --only-section=._enclave_code \
        "$ELF" "$OUT"
else
    # two_enclaves already emits standalone signed blobs (header+code extracted flat).
    make -C "$HOST_DIR" clean >/dev/null
    UMBRA_ENCLAVE_VERSION="$VER" make -C "$HOST_DIR" "app/$APP.bin" >/dev/null
    if [ "${UMBRA_BLOB_CORRUPT:-0}" = "1" ]; then
        # TEST FIXTURE (failed-boot fallback only): re-sign the already-patched ELF.
        # protect_enclave.py patches in place and is NOT idempotent, so a second pass
        # re-blocks [Meta|code] as code — the header.hmac now matches the corrupted
        # blocks, so the blob is AUTHENTIC (measurement passes, install verify OK, boot
        # selects it) but the enclave CRASHES at runtime. This is exactly the v4 incident
        # (2026-07-19), reproduced deterministically to drive the fallback test.
        echo "  [CORRUPT] re-signing patched ELF -> authentic-but-crashing blob (fallback test)"
        ( cd "$HOST_DIR" && UMBRA_CHAINED=1 UMBRA_ESS_MISS_RECOVERY=0 UMBRA_NUMERIC_FOLD=1 \
            UMBRA_ENCLAVE_VERSION="$VER" python3 ../../../tools/protect_enclave.py \
            --hmac-over-plaintext "app/$APP.elf" "blob_src/${APP}_header.c" \
            ../../../tools/master_key.bin obj >/dev/null )
        arm-none-eabi-objcopy -O binary \
            --only-section=._enclave_header --only-section=._enclave_code \
            "$HOST_DIR/app/$APP.elf" "$OUT"
    else
        cp "$HOST_DIR/app/$APP.bin" "$OUT"
    fi
fi

[ -s "$OUT" ] || { echo "ERROR: blob not produced at $OUT"; exit 1; }
SZ=$(wc -c < "$OUT" | tr -d ' ')
# NS relay RX buffer is 24 KB (g_buf, attest_relay.c) minus 64 B of package framing.
[ "$SZ" -le $((24*1024 - 64)) ] || echo "WARNING: blob $SZ B exceeds the 24 KB NS relay buffer"

echo "  -> $OUT (app=$APP v$VER, $SZ bytes, magic $(xxd -l4 -p "$OUT"))"
echo "  (rebuilt at v$VER; the on-chip host is unaffected — this blob is sent over UART)"
