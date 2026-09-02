#!/usr/bin/env bash
# One-command preflight for the artifact and the accompanying manuscript.
# Use --with-extraction for the slower, submission-grade regeneration pass.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WITH_EXTRACTION=0

case "${1:-}" in
  "") ;;
  --with-extraction) WITH_EXTRACTION=1 ;;
  *) echo "usage: $0 [--with-extraction]" >&2; exit 2 ;;
esac

cd "$ROOT_DIR"

echo ">> protocol parity"
python3 tools/test_attestation_guard.py

echo ">> Rust host suites"
cargo test -p kernel -p umbra-update-core -p umbra-chain-core --locked

echo ">> N657 target check"
cargo check -p umbra-n657-boot --target thumbv8m.main-none-eabi --locked

if [ "$WITH_EXTRACTION" -eq 1 ]; then
  echo ">> regenerating extracted Rocq"
  formal/rocq/update-core/extract.sh
  formal/rocq/chain-core/extract.sh
fi

echo ">> Rocq update-core"
opam exec --switch=default -- make -C formal/rocq/update-core/proofs-coq -j4

echo ">> Rocq chain-core and assumption audit"
opam exec --switch=default -- bash formal/rocq/chain-core/build.sh

echo ">> Rocq crypto and union"
opam exec --switch=default -- bash formal/rocq/crypto/build.sh

echo ">> independent kernel check"
(
  cd formal/rocq/crypto
  opam exec --switch=default -- coqchk -silent \
    -R . UmbraCrypto \
    -R ../update-core/proofs-coq Lib \
    -R ../chain-core/proofs-coq Lib \
    UmbraCrypto.Umbra_Union
)

echo ">> frozen headline assumption set"
ASSUMPTION_BASELINE="$ROOT_DIR/formal/rocq/crypto/headline-assumptions.txt"
ASSUMPTION_ACTUAL="$(
  cd "$ROOT_DIR/formal/rocq/crypto"
  printf '%s\n' \
    'Require Import Umbra_RealGame.' \
    'Print Assumptions device_forgery_le_eufcma_at_the_real_seam.' |
    opam exec --switch=default -- coqtop -quiet \
      -R . UmbraCrypto \
      -R ../update-core/proofs-coq Lib \
      -R ../chain-core/proofs-coq Lib 2>/dev/null |
    awk '
      /^Axioms:$/ { inside=1; next }
      inside && /^Coq </ { exit }
      inside && /^[A-Za-z_][A-Za-z0-9_.]*([[:space:]]|$)/ { print $1 }
    '
)"
# The deterministic layer is axiom-free (Primitives.v defines every backend
# operation); what remains on the headline theorem is exactly what SSProve /
# mathcomp-analysis themselves introduce: 7 entries, none from this project.
ASSUMPTION_COUNT="$(printf '%s\n' "$ASSUMPTION_ACTUAL" | wc -l | tr -d ' ')"
if [ "$ASSUMPTION_COUNT" != 7 ]; then
  echo "error: headline theorem has $ASSUMPTION_COUNT assumptions, expected 7" >&2
  exit 1
fi
if printf '%s\n' "$ASSUMPTION_ACTUAL" | grep -qE '^(Primitives|Update_|Chain_|Umbra)'; then
  echo "error: a project-level assumption reached the headline theorem" >&2
  exit 1
fi
if ! diff -u "$ASSUMPTION_BASELINE" <(printf '%s\n' "$ASSUMPTION_ACTUAL"); then
  echo "error: headline assumption names differ from the frozen baseline" >&2
  exit 1
fi

echo ">> deterministic layer must declare no Axiom"
if grep -nE '^Axiom ' formal/rocq/update-core/proofs-coq/*.v formal/rocq/chain-core/proofs-coq/*.v \
     | grep -v '_Template\.v'; then
  echo "error: an Axiom is declared in the deterministic layer" >&2
  exit 1
fi

echo ">> local admit audit"
# grep, not rg (see the PDF checks below): a missing rg binary would skip
# this gate silently. formal/rocq holds no toolchain/ subtree, so no exclude
# glob is needed; the vendored toolchain lives in formal/toolchain/.
if grep -rnE 'Admitted\.|\badmit\b' formal/rocq --include='*.v'; then
  echo "error: local Rocq admit found" >&2
  exit 1
fi

echo ">> manuscript PDF"
# Venue-neutral by design: the manuscript location comes from the
# environment, so this script names no submission target. An unset
# UMBRA_PAPER_MAIN skips the paper gates LOUDLY, and the final PASS line
# says which configuration ran; the artifact copy has no manuscript and
# runs without the variable.
PAPER_MAIN="${UMBRA_PAPER_MAIN:-}"
PAPER_GATES="ran"
if [ -z "$PAPER_MAIN" ]; then
  echo "SKIP: paper gates (UMBRA_PAPER_MAIN unset)"
  PAPER_GATES="skipped"
else
  PAPER_DIR="$(cd "$(dirname "$PAPER_MAIN")" && pwd)"
  PAPER_BASE="$(basename "$PAPER_MAIN" .tex)"
  PDF="$PAPER_DIR/$PAPER_BASE.pdf"
  LOG="$PAPER_DIR/$PAPER_BASE.log"
  latexmk -pdf -interaction=nonstopmode -halt-on-error -cd "$PAPER_MAIN"

  test "$(pdfinfo "$PDF" | awk '/^Pages:/ {print $2}')" = 7
  if pdffonts "$PDF" | tail -n +3 | awk '$2 == "Type 3" {found=1} END {exit found ? 0 : 1}'; then
    echo "error: PDF contains Type-3 fonts" >&2
    exit 1
  fi
  # grep, not rg: rg is not installed everywhere, and `if rg ...` with a
  # missing binary skips the check silently (fail-open) instead of failing
  # the gate.
  if grep -nE 'Overfull|Citation .* undefined|Reference .* undefined' "$LOG"; then
    echo "error: PDF log contains a submission warning" >&2
    exit 1
  fi
  # Page 7 is references-only: its first non-blank line must be the heading
  # (pdftotext renders small caps with a space, "R EFERENCES"). Checking for a
  # spilled section title was fail-open when the title changed.
  if ! pdftotext -f 7 -l 7 "$PDF" - | grep -v '^[[:space:]]*$' | head -n 1 | \
      grep -qiE '^R ?EFERENCES'; then
    echo "error: paper body spills onto reference-only page 7" >&2
    exit 1
  fi
  test -z "$(pdfinfo "$PDF" | awk -F: '/^Author:/ {sub(/^[[:space:]]+/, "", $2); print $2}')"
fi

git diff --check
echo "PASS: preflight (paper gates $PAPER_GATES)"
