#!/usr/bin/env bash
# Build the chained-measurement tier (issue #58).
#
#   ./build.sh          build; assumes ../update-core/proofs-coq is already built
#   ./build.sh --deps   build ../update-core/proofs-coq first, then this
#
# This project does NOT keep its own Primitives.v or AeneasLoopShim.v: both are
# loaded out of ../update-core/proofs-coq (see proofs-coq/_CoqProject), because
# Chain_Compose.v Requires Update_Crypto and two files of one logical name in a
# single load path clash. So update-core must be built first, always.
#
# The build EMITS THE ASSUMPTION AUDIT: `Print Assumptions` on the two headline
# theorems, so every run prints the sets rather than asserting them.
#   ./build.sh 2>&1 | tee assumptions.log
set -euo pipefail

cd "$(dirname "$0")"
HERE="$PWD"
UP="$HERE/../update-core/proofs-coq"
PROOFS="$HERE/proofs-coq"

COQC="${COQC:-coqc}"
command -v "$COQC" >/dev/null || {
  echo "error: coqc not on PATH (try: export PATH=\"\$HOME/.opam/default/bin:\$PATH\")" >&2
  exit 1; }

if [ "${1:-}" = "--deps" ]; then
  echo ">> building update-core first"
  ( cd "$UP" && coq_makefile -f _CoqProject -o Makefile >/dev/null && make -j4 >/dev/null )
fi

for f in Primitives AeneasLoopShim Update_Types Update_FunsExternal Update_Funs \
         Update_Safety Update_Crypto; do
  [ -f "$UP/$f.vo" ] || {
    echo "error: $UP/$f.vo missing — build update-core first (./build.sh --deps)" >&2
    exit 1; }
done

echo ">> building chain-core"
cd "$PROOFS"
coq_makefile -f _CoqProject -o Makefile >/dev/null
make -j4 >/dev/null

echo ">> assumption audit"
AUDIT="$PROOFS/Chain_Audit.v"
cat > "$AUDIT" <<'EOF'
Require Import Chain_Body.
Require Import Chain_Value.
Require Import Chain_Compose.
Require Import Chain_Residual.
Require Import Chain_Reachable.
Print Assumptions chain_accept_pins_the_blob_body.
Print Assumptions successful_blob_block_counts_agree.
Print Assumptions verified_update_pins_the_blob_body.
Print Assumptions chain_root_ignores_everything_outside_the_blocks.
Print Assumptions verdict_ignores_the_unauthenticated_header_bytes.
(* non-vacuity: the accept branch is reachable *)
Print Assumptions chain_gate_accepts_a_matching_measurement.
EOF
( cd "$PROOFS" && "$COQC" -R . Lib -R "$UP" Lib Chain_Audit.v )
rm -f "$PROOFS"/Chain_Audit.v "$PROOFS"/Chain_Audit.vo* "$PROOFS"/Chain_Audit.glob

echo "OK: $(ls "$PROOFS"/*.vo | wc -l | tr -d ' ') file(s)"
