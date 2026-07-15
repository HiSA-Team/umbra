#!/usr/bin/env bash
#
# Generate a standalone enclave UPDATE blob at a given version, signed with the
# CURRENT tools/master_key.bin (a plain `make` — NOT rebuild_all — so the key is NOT
# rotated). Use it AFTER flashing with UMBRA_KEEP_MASTER_KEY=1 so the blob is signed
# with the same key the on-chip FSBL uses, then send it with tools/attest_update.py
# --update-blob. SLOT_A itself is provisioned by `cargo xtask flash n657` when
# UMBRA_ATTEST_SLOTS=1; this only makes the higher-version blob for the remote update.
#
# Usage:  ./tools/make_update_blob.sh <version> <out.bin>
#   e.g.  ./tools/make_update_blob.sh 3 /tmp/slot_v3.bin
# NOTE: no `set -u` — settings.sh references ZSH_VERSION (unbound under nounset).
set -eo pipefail

VER="${1:?usage: make_update_blob.sh <version> <out.bin>}"
OUT="${2:?usage: make_update_blob.sh <version> <out.bin>}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH=/opt/homebrew/bin:$PATH
export HOST_APP=bare_metal
# shellcheck disable=SC1091
source ./settings.sh >/dev/null          # N657 env: version_bind, numeric_fold, author (keep stderr)
export UMBRA_VERSION_BIND=1
export UMBRA_CREATE_BEST_SLOT=1

HOST_DIR="$ROOT/host/stm32n657/bare_metal"
ELF="$HOST_DIR/bin/bare_metal.elf"

make -C "$HOST_DIR" clean >/dev/null
UMBRA_ENCLAVE_VERSION="$VER" make -C "$HOST_DIR" >/dev/null
[ -f "$ELF" ] || { echo "ERROR: host ELF not built at $ELF"; exit 1; }
arm-none-eabi-objcopy -O binary \
    --only-section=._enclave_header --only-section=._enclave_code \
    "$ELF" "$OUT"
[ -s "$OUT" ] || { echo "ERROR: blob not produced at $OUT"; exit 1; }

echo "  -> $OUT (v$VER, $(wc -c < "$OUT" | tr -d ' ') bytes, magic $(xxd -l4 -p "$OUT"))"
echo "  (host rebuilt at v$VER; the on-chip host is unaffected — this blob is sent over UART)"
