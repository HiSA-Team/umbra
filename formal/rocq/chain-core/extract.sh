#!/usr/bin/env bash
# Re-extract the umbra-chain-core Coq model end-to-end and re-apply the manual
# patches the Aeneas Coq backend needs (issue #58). Idempotent. Requires the
# vendored toolchain on PATH:
#   export PATH="$PWD/formal/toolchain/aeneas/bin:$PWD/formal/toolchain/charon/bin:$PATH"
#
# Mirrors ../update-core/extract.sh. The one structural difference: this model
# keeps NO `Primitives.v` / `AeneasLoopShim.v` of its own: both, and the generic
# backend laws (`Aeneas_Laws.v`), come from the shared library formal/rocq/lib
# (logical root AeneasLib), because the composed theorem (Chain_Compose.v)
# Requires update-core's `Update_Crypto`, and two files of the same logical name
# in the same load path would clash. `_CoqProject` therefore adds
# `-R ../../update-core/proofs-coq Lib` and `-R ../../lib AeneasLib`, and this
# script deletes the copies Aeneas drops here.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"       # repo root
HERE="$ROOT/formal/rocq/chain-core"
PROOFS="$HERE/proofs-coq"
CRATE="$ROOT/crates/umbra-chain-core"
# The proof-engineer plugin: PROOF_ENGINEER_ROOT, then CLAUDE_PLUGIN_ROOT (set when
# the agent runs this), then the newest installed copy.
PLUGIN="${PROOF_ENGINEER_ROOT:-${CLAUDE_PLUGIN_ROOT:-}}"
[ -n "$PLUGIN" ] || PLUGIN=$(ls -d "$HOME"/.claude/plugins/cache/proof-engineer/proof-engineer/*/ 2>/dev/null | sort -V | tail -1)
PLUGIN=${PLUGIN%/}
[ -x "$PLUGIN/scripts/write-extraction-record.sh" ] || { echo "error: proof-engineer plugin not found; set PROOF_ENGINEER_ROOT" >&2; exit 1; }
. "$PLUGIN/scripts/lib.sh"
PIN_CHARON=$(pe_profile "$ROOT" '.pins.charon'); PIN_AENEAS=$(pe_profile "$ROOT" '.pins.aeneas'); USIZE_BITS=$(pe_profile "$ROOT" '.target.usize_bits // 32')

mkdir -p "$PROOFS"

echo ">> [1/5] charon: Rust -> LLBC  (--cfg charon strips non-extractable derives)"
# NB: --dest-file must be ABSOLUTE — it resolves against cargo's build cwd, not the shell's.
# charon can exit non-zero while still emitting the llbc, so gate on the file, not $?.
rm -f "$HERE/chain.llbc"
( cd "$CRATE" && touch src/lib.rs && \
  charon cargo --preset=aeneas --rustc-arg=--cfg=charon --dest-file="$HERE/chain.llbc" ) || true
[ -s "$HERE/chain.llbc" ] || { echo "error: charon produced no llbc" >&2; exit 1; }

echo ">> [2/5] aeneas: LLBC -> Coq"
aeneas -backend coq "$HERE/chain.llbc" -dest "$PROOFS" -split-files

echo ">> [3/5] drop the shared support files (they live in the library, formal/rocq/lib)"
rm -f "$PROOFS/Primitives.v" "$PROOFS/AeneasLoopShim.v"
"$PLUGIN/scripts/materialize-lib.sh" --check || {
  echo "error: formal/rocq/lib does not match its manifest (re-run materialize-lib.sh)" >&2
  exit 1; }
[ -f "$ROOT/formal/rocq/lib/Primitives.v" ] || { echo "error: library Primitives.v missing" >&2; exit 1; }
[ -f "$ROOT/formal/rocq/lib/AeneasLoopShim.v" ] || { echo "error: library AeneasLoopShim.v missing" >&2; exit 1; }
[ -f "$ROOT/formal/rocq/lib/Aeneas_Laws.v" ] || { echo "error: library Aeneas_Laws.v missing" >&2; exit 1; }

echo ">> [4/5] fill the external template — by ALIASING the library's seams"
if [ -f "$PROOFS/Chain_TypesExternal_Template.v" ]; then
  sed 's/Chain_TypesExternal_Template/Chain_TypesExternal/g' \
      "$PROOFS/Chain_TypesExternal_Template.v" > "$PROOFS/Chain_TypesExternal.v"
fi
# THE POINT OF THIS STEP. Aeneas emits ONE `Axiom` per crate per opaque core
# operation, so a naive fill would give this model its OWN
# `core_slice_Slice_copy_from_slice` — a constant DISTINCT from the one the
# library's laws (Aeneas_Laws, formerly Update_Safety's quarantine) are about.
# That would force a second, parallel seam block that nothing discharges.
# Instead every opaque seam here is a transparent ALIAS of the library's
# constant (the same constant update-core's FunsExternal binds by Notation), so
# the existing laws apply verbatim and `Print Assumptions` on the theorems
# below lists no new name. `mk_array4` is likewise the library's TOTAL
# definition (never the backend's inconsistent `Primitives.mk_array`; see
# ../AENEAS_COQ_MKARRAY_BUG.md).
#
# Drift guard: the template must still declare exactly the one axiom we alias.
tmpl_axioms=$(grep -c '^Axiom ' "$PROOFS/Chain_FunsExternal_Template.v" || true)
grep -q '^Axiom core_slice_Slice_copy_from_slice :' "$PROOFS/Chain_FunsExternal_Template.v" || {
  echo "error: template no longer declares core_slice_Slice_copy_from_slice" >&2; exit 1; }
[ "$tmpl_axioms" = "1" ] || {
  echo "error: template declares $tmpl_axioms axioms; expected 1 — extraction drifted," >&2
  echo "       so the alias list below is incomplete. Update it deliberately." >&2; exit 1; }
cat > "$PROOFS/Chain_FunsExternal.v" <<'EOF'
(** Filled from the Aeneas template by ../extract.sh. NOT auto-generated
    verbatim: every opaque seam is an ALIAS of the constant of the same name in
    the shared library `Aeneas_Laws` (all DEFINITIONS there; update-core's
    FunsExternal binds the very same constants by Notation), so that the
    library's laws about them apply to this model too, and no second, parallel
    block of seams is opened.

    `mk_array4` is the library's TOTAL definition, never the Coq backend's
    `Primitives.mk_array`, which is an inconsistent axiom (it proves `False`;
    ../../AENEAS_COQ_MKARRAY_BUG.md). *)
Require Import Primitives.
Import Primitives.
Require Import Coq.ZArith.ZArith.
Require Import List.
Import ListNotations.
Local Open Scope Primitives_scope.
Require Import Chain_Types.
Include Chain_Types.
Require Import Aeneas_Laws.
Module Chain_FunsExternal.

(** [core::slice::{[T]}::copy_from_slice] — the library's seam, aliased. *)
Definition core_slice_Slice_copy_from_slice
  {T : Type} (markerCopyInst : core_marker_Copy T)
  : slice T -> slice T -> result (slice T)
  := Aeneas_Laws.core_slice_Slice_copy_from_slice markerCopyInst.

(** The byte<->u32 codecs the Coq backend has no theory for. Aliased for the
    same reason; the library's Q18/Q19 are laws about exactly these. *)
Definition core_num_U32_from_le_bytes : array u8 4%usize -> u32
  := Aeneas_Laws.core_num_U32_from_le_bytes.
Definition core_num_U32_to_le_bytes : u32 -> array u8 4%usize
  := Aeneas_Laws.core_num_U32_to_le_bytes.

(** The four-element array literal the extracted decoder builds. Total. *)
Definition mk_array4 : u8 -> u8 -> u8 -> u8 -> array u8 4%usize
  := Aeneas_Laws.mk_array4.
End Chain_FunsExternal.
EOF

echo ">> [5/5] patch generated Chain_Funs.v (the 3 documented Coq-backend frictions)"
# (a) it assumes loop/control_flow live in Primitives; they live in our shim.
perl -0pi -e 's/(Require Import Primitives\.\nImport Primitives\.\n)/$1Require Import AeneasLoopShim.\nImport AeneasLoopShim.\n/ if !$d++' "$PROOFS/Chain_Funs.v"
# (b) Coq 8.18 rejects `fun ((x, y) : T) =>`; use an irrefutable pattern binder.
# The ascribed type nests parens (`((array u8 32%usize) * u32)`), so match
# non-greedily up to the first `) =>` rather than with a paren-free class.
perl -pi -e "s/fun \(\((\w+), (\w+)\) : .*?\) =>/fun '(\$1, \$2) =>/g" "$PROOFS/Chain_Funs.v"
if grep -qE 'fun \(\(' "$PROOFS/Chain_Funs.v"; then
  echo "error: a Coq-8.18-invalid annotated tuple binder survived" >&2; exit 1; fi
# (c) every `mk_array N%usize [ x; y; … ]` literal becomes `mk_arrayN x y …`.
perl -0pi -e 's/mk_array\s+(\d+)%usize\s*\[\s*(.*?)\s*\]/"mk_array$1 " . join(" ", split(m{\s*;\s*}s, $2))/ges' "$PROOFS/Chain_Funs.v"
if grep -q 'Primitives.mk_array\|mk_array [0-9]' "$PROOFS/Chain_Funs.v"; then
  echo "error: an un-rewritten mk_array literal survived" >&2; exit 1; fi
for a in $(grep -oE 'mk_array[0-9]+' "$PROOFS/Chain_Funs.v" | sort -u); do
  grep -qE "(Definition|Notation) $a([[:space:]]|\$)" "$PROOFS/Chain_FunsExternal.v" || {
    echo "error: extracted code needs $a, which has no total constructor" >&2; exit 1; }
done

echo ">> extraction record (inputs: sources + script + pins; outputs: generated model + llbc)"
( cd "$ROOT" && "$PLUGIN/scripts/write-extraction-record.sh" \
    crates/umbra-chain-core formal/rocq/chain-core formal/rocq/chain-core/extract.sh \
    "$PIN_CHARON" "$PIN_AENEAS" "$USIZE_BITS" \
    formal/rocq/chain-core/proofs-coq/Chain_Types.v \
    formal/rocq/chain-core/proofs-coq/Chain_Funs.v \
    formal/rocq/chain-core/proofs-coq/Chain_FunsExternal.v \
    $( [ -f "$PROOFS/Chain_TypesExternal.v" ] && echo formal/rocq/chain-core/proofs-coq/Chain_TypesExternal.v ) \
    formal/rocq/chain-core/chain.llbc )

echo ">> done. Build:  cd $PROOFS && coq_makefile -f _CoqProject -o Makefile && make"
