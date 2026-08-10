#!/usr/bin/env bash
# Build the cryptographic layer of the verifiable update core.
#
#   ./build.sh              build everything (needs SSProve, see README.md)
#   ./build.sh --det-only   build only the deterministic tier (bare Coq 8.18)
#
# The deterministic tier must always build with nothing but Coq and the
# update-core chain next door. If --det-only ever needs mathcomp, that is a bug.
#
# The build EMITS THE ASSUMPTION AUDIT. `Print Assumptions` directives are
# compiled into Update_Safety.v (P3), Update_Model.v (the quarantine model) and
# Umbra_RealGame.v (both EUF-CMA bounds), so every run prints the axiom sets the
# paper quotes rather than asserting them. Redirect stdout to keep the record:
#   ./build.sh 2>&1 | tee assumptions.log
set -euo pipefail

cd "$(dirname "$0")"

COQC="${COQC:-coqc}"
command -v "$COQC" >/dev/null || {
  echo "error: $COQC not on PATH (try: eval \$(opam env --switch=default))" >&2
  exit 1
}

INCLUDES=(-R . UmbraCrypto -R ../update-core/proofs-coq Lib
          -R ../chain-core/proofs-coq Lib)

DET_FILES=(Update_Forgery.v Update_Encoding.v Umbra_Canonical.v
           Umbra_ByteSpace.v Umbra_ArrayVectors.v Umbra_DeviceLink.v
           Umbra_Wire.v Update_Converse.v Umbra_WireConverse.v
           Umbra_UnionCore.v)
GAME_FILES=(Umbra_EUFCMA.v Umbra_Reduction.v Umbra_RealGame.v Umbra_Union.v)

FILES=("${DET_FILES[@]}")
if [ "${1:-}" != "--det-only" ]; then
  for f in "${GAME_FILES[@]}"; do
    [ -f "$f" ] && FILES+=("$f")
  done
fi

# The update-core chain must already be built; it is a separate, dependency-free
# project and is never rebuilt from here.
if [ ! -f ../update-core/proofs-coq/Update_Crypto.vo ]; then
  echo "error: ../update-core/proofs-coq is not built — build it first" >&2
  exit 1
fi

# Umbra_UnionCore.v (the deterministic half of the union) is the first file
# here that consumes chain-core: it needs Chain_Body's blob-body theorem and
# Q21. chain-core is likewise a separate, dependency-free project and is never
# rebuilt from here, so the ordering is checked rather than repaired.
if [ ! -f ../chain-core/proofs-coq/Chain_Body.vo ]; then
  echo "error: ../chain-core/proofs-coq is not built — build it first" >&2
  exit 1
fi

for f in "${FILES[@]}"; do
  echo "COQC $f"
  "$COQC" "${INCLUDES[@]}" "$f"
done

echo "OK: ${#FILES[@]} file(s)"
