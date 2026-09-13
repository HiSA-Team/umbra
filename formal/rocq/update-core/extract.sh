#!/usr/bin/env bash
# Re-extract the umbra-update-core Coq model end-to-end and re-apply the manual
# patches the Aeneas Coq backend needs (issue #58). Idempotent. Requires the
# vendored toolchain on PATH:
#   export PATH="$PWD/formal/toolchain/aeneas/bin:$PWD/formal/toolchain/charon/bin:$PATH"
# The backend seams (copy_from_slice, the u32 codecs, mk_array4) and the laws
# about them live in the shared library formal/rocq/lib (materialised by the
# proof-engineer plugin); this script binds the generated FunsExternal to them.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"       # repo root
HERE="$ROOT/formal/rocq/update-core"
PROOFS="$HERE/proofs-coq"
CRATE="$ROOT/crates/umbra-update-core"
# The proof-engineer plugin: PROOF_ENGINEER_ROOT, then CLAUDE_PLUGIN_ROOT (set when
# the agent runs this), then the newest installed copy.
PLUGIN="${PROOF_ENGINEER_ROOT:-${CLAUDE_PLUGIN_ROOT:-}}"
[ -n "$PLUGIN" ] || PLUGIN=$(ls -d "$HOME"/.claude/plugins/cache/proof-engineer/proof-engineer/*/ 2>/dev/null | sort -V | tail -1)
PLUGIN=${PLUGIN%/}
[ -x "$PLUGIN/scripts/write-extraction-record.sh" ] || { echo "error: proof-engineer plugin not found; set PROOF_ENGINEER_ROOT" >&2; exit 1; }
. "$PLUGIN/scripts/lib.sh"
PIN_CHARON=$(pe_profile "$ROOT" '.pins.charon'); PIN_AENEAS=$(pe_profile "$ROOT" '.pins.aeneas'); USIZE_BITS=$(pe_profile "$ROOT" '.target.usize_bits // 32')

echo ">> [1/5] charon: Rust -> LLBC  (--cfg charon strips non-extractable derives)"
# NB: --dest-file must be ABSOLUTE — it resolves against cargo's build cwd, not the shell's.
# charon can exit non-zero while still emitting the llbc, so gate on the file, not $?.
rm -f "$HERE/update.llbc"
( cd "$CRATE" && touch src/lib.rs && \
  charon cargo --preset=aeneas --rustc-arg=--cfg=charon --dest-file="$HERE/update.llbc" ) || true
[ -s "$HERE/update.llbc" ] || { echo "error: charon produced no llbc" >&2; exit 1; }

echo ">> [2/5] aeneas: LLBC -> Coq"
aeneas -backend coq "$HERE/update.llbc" -dest "$PROOFS" -split-files

echo ">> [3/5] support files: the shared library (Primitives, loop shim, backend laws)"
# Primitives.v, AeneasLoopShim.v, Aeneas_Laws.v and AeneasLoopBounds.v are NOT
# kept in proofs-coq: they are the plugin's library at formal/rocq/lib, loaded
# through `-R ../../lib AeneasLib` (see proofs-coq/_CoqProject). The library's
# Primitives.v is the axiom-free variant of the backend file (every backend
# `Axiom` given a definition, the inconsistent `mk_array` removed), so this
# step checks the materialised library against its manifest, and warns —
# loudly, but without gating — when the vendored backend Primitives.v it was
# derived from has moved.
"$PLUGIN/scripts/materialize-lib.sh" --check || {
  echo "error: formal/rocq/lib does not match its manifest (re-run materialize-lib.sh)" >&2
  exit 1; }
PRIM_UPSTREAM_SHA="a5f5677c05c3e122f9fdf604097ffb5f50fd27518087246cd37f2e62a0c33edb"
PRIM_ACTUAL_SHA="$(shasum -a 256 "$ROOT/formal/toolchain/aeneas/backends/coq/Primitives.v" | cut -d' ' -f1)"
[ "$PRIM_ACTUAL_SHA" = "$PRIM_UPSTREAM_SHA" ] || {
  echo "WARNING: vendored backend Primitives.v changed (sha256 $PRIM_ACTUAL_SHA);" >&2
  echo "         the library's Primitives.v was derived from $PRIM_UPSTREAM_SHA —" >&2
  echo "         re-derive it in the plugin and update PRIM_UPSTREAM_SHA" >&2; }
[ -f "$ROOT/formal/rocq/lib/Primitives.v" ] || { echo "error: formal/rocq/lib/Primitives.v missing" >&2; exit 1; }
if grep -q '^Axiom ' "$ROOT/formal/rocq/lib/Primitives.v"; then
  echo "error: lib/Primitives.v declares an Axiom; the library variant must not" >&2; exit 1; fi
rm -f "$PROOFS/Primitives.v" "$PROOFS/AeneasLoopShim.v"   # aeneas drops a backend copy here

echo ">> [4/5] fill the external templates (opaque seams)"
# TypesExternal only exists if extraction references an opaque core type. With the
# Debug derive cfg-gated out there is none, so aeneas emits no such template —
# handle it only when present.
if [ -f "$PROOFS/Update_TypesExternal_Template.v" ]; then
  sed 's/Update_TypesExternal_Template/Update_TypesExternal/g' \
      "$PROOFS/Update_TypesExternal_Template.v" > "$PROOFS/Update_TypesExternal.v"
fi
# FunsExternal: the template leaves copy_from_slice as an Axiom. It is BOUND,
# by Notation, to the library's DEFINITION (Aeneas_Laws.core_slice_Slice_copy_from_slice:
# Rust semantics, lengths must match, then dst holds src), so it is the very
# constant the library's laws are about; likewise the byte<->u32 codecs and
# the 4-byte array literal. Only the crate-specific 15-byte literal is defined
# here. No axiom survives in this file.
# Two steps (no pipe) so a non-zero perl under `set -e` can't silently abort.
sed 's/Update_FunsExternal_Template/Update_FunsExternal/g' \
    "$PROOFS/Update_FunsExternal_Template.v" > "$PROOFS/Update_FunsExternal.v"
perl -0pi -e 's/Axiom core_slice_Slice_copy_from_slice :\n  forall\{T : Type\} \(markerCopyInst : core_marker_Copy T\),\n        slice T -> slice T -> result \(slice T\)\n\./(* Filled by ..\/extract.sh (the template leaves it as an Axiom): bound to the\n   shared library\x27s definition (Rust panics unless the lengths match, and on\n   success dst holds src\x27s elements), so the library\x27s laws apply verbatim. *)\nNotation core_slice_Slice_copy_from_slice := Aeneas_Laws.core_slice_Slice_copy_from_slice./' \
    "$PROOFS/Update_FunsExternal.v"
grep -q '^Notation core_slice_Slice_copy_from_slice := Aeneas_Laws' "$PROOFS/Update_FunsExternal.v" || {
  echo "error: copy_from_slice Axiom in the template did not match the expected shape" >&2; exit 1; }
perl -0pi -e 's/(Require Import List\.\nImport ListNotations\.\n)/$1Require Import Aeneas_Laws.\n/' "$PROOFS/Update_FunsExternal.v"
grep -q '^Require Import Aeneas_Laws\.' "$PROOFS/Update_FunsExternal.v" || {
  echo "error: could not add the Aeneas_Laws import to Update_FunsExternal.v" >&2; exit 1; }
# … plus the codecs and the TOTAL replacements for the backend's array-literal constructor.
# `Primitives.mk_array : forall {T} (n : usize) (l : list T), array T n` is an
# UNSOUND axiom: `array T n` is `{l : list T | length l = n}`, which is EMPTY at
# `T := Empty_set, n := 4`, so the axiom proves `False` (minimal reproduction and
# `Qed`'d derivation: ../AENEAS_COQ_MKARRAY_BUG.md). It is also unnecessary here:
# the extracted body only ever builds array literals of statically known length,
# and those are definable with their own length proof. The 4-byte literal (the
# decoder's) is the library's; the 15-byte PKG_TAG_LABEL literal is this crate's.
cat > "$PROOFS/.array_lit.frag" <<'FRAG'

(* --- the byte<->u32 codecs (NOT axioms) --------------------------------- *)
(* `u32::to_le_bytes` is the base-256 digit decomposition and
   `u32::from_le_bytes` its recomposition: the shared library's definitions,
   bound here by name so the extracted body and the library's laws (Q18/Q19)
   talk about one constant. Added by ../extract.sh. *)
Notation core_num_U32_to_le_bytes := Aeneas_Laws.core_num_U32_to_le_bytes.
Notation core_num_U32_from_le_bytes := Aeneas_Laws.core_num_U32_from_le_bytes.

(* --- TOTAL array-literal constructors (NOT axioms) ---------------------- *)
(* Replacements for the Aeneas Coq backend's `mk_array`, which is an
   inconsistent `Axiom` (see ../../AENEAS_COQ_MKARRAY_BUG.md) and which the
   library's Primitives.v therefore no longer declares. `extract.sh` rewrites
   every `mk_array N%usize [ … ]` literal in generated Update_Funs.v into an
   application of one of these. Each carries its own length proof. The 4-byte
   one is the library's (Q20 is about it); the 15-byte one is crate-specific. *)
Notation mk_array4 := Aeneas_Laws.mk_array4.

Definition mk_array15
  (b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14 : u8) : array u8 15%usize :=
  exist _ [b0; b1; b2; b3; b4; b5; b6; b7; b8; b9; b10; b11; b12; b13; b14]
        eq_refl.
FRAG
awk -v frag="$PROOFS/.array_lit.frag" '
  /^End Update_FunsExternal\.$/ { while ((getline line < frag) > 0) print line; close(frag) }
  { print }' "$PROOFS/Update_FunsExternal.v" > "$PROOFS/.Update_FunsExternal.new"
mv "$PROOFS/.Update_FunsExternal.new" "$PROOFS/Update_FunsExternal.v"
rm -f "$PROOFS/.array_lit.frag"

echo ">> [5/5] patch generated Update_Funs.v (the 3 documented Coq-backend frictions)"
# (a) it assumes loop/control_flow live in Primitives; they live in our shim.
perl -0pi -e 's/(Require Import Primitives\.\nImport Primitives\.\n)/$1Require Import AeneasLoopShim.\nImport AeneasLoopShim.\n/ if !$d++' "$PROOFS/Update_Funs.v"
# (b) Coq 8.18 rejects `fun ((x, y) : T) =>`; use an irrefutable pattern binder.
perl -pi -e "s/fun \(\((\w+), (\w+)\) : \(u8 \* usize\)\) =>/fun '(\$1, \$2) =>/g" "$PROOFS/Update_Funs.v"
# (c) every `mk_array N%usize [ x; y; … ]` literal becomes `mk_arrayN x y …`,
# i.e. the total constructor added to Update_FunsExternal above. Idempotent:
# after the rewrite no `mk_array N%usize [` remains. Fails loudly if a literal of
# an arity we have no constructor for ever appears.
perl -0pi -e 's/mk_array\s+(\d+)%usize\s*\[\s*(.*?)\s*\]/"mk_array$1 " . join(" ", split(m{\s*;\s*}s, $2))/ges' "$PROOFS/Update_Funs.v"
if grep -qE 'mk_array(4|15)\b' "$PROOFS/Update_Funs.v"; then :; else
  echo "error: mk_array literal rewrite matched nothing" >&2; exit 1; fi
if grep -q 'Primitives.mk_array\|mk_array [0-9]' "$PROOFS/Update_Funs.v"; then
  echo "error: an un-rewritten mk_array literal survived" >&2; exit 1; fi
if grep -q '^Axiom ' "$PROOFS/Update_FunsExternal.v"; then
  echo "error: an Axiom survived in Update_FunsExternal.v" >&2; exit 1; fi
for a in $(grep -oE 'mk_array[0-9]+' "$PROOFS/Update_Funs.v" | sort -u); do
  grep -qE "(Definition|Notation) $a([[:space:]]|\$)" "$PROOFS/Update_FunsExternal.v" || {
    echo "error: extracted code needs $a, which has no total constructor" >&2; exit 1; }
done

echo ">> extraction record (inputs: sources + script + pins; outputs: generated model + llbc)"
( cd "$ROOT" && "$PLUGIN/scripts/write-extraction-record.sh" \
    crates/umbra-update-core formal/rocq/update-core formal/rocq/update-core/extract.sh \
    "$PIN_CHARON" "$PIN_AENEAS" "$USIZE_BITS" \
    formal/rocq/update-core/proofs-coq/Update_Types.v \
    formal/rocq/update-core/proofs-coq/Update_Funs.v \
    formal/rocq/update-core/proofs-coq/Update_FunsExternal.v \
    $( [ -f "$PROOFS/Update_TypesExternal.v" ] && echo formal/rocq/update-core/proofs-coq/Update_TypesExternal.v ) \
    formal/rocq/update-core/update.llbc )

echo ">> done. Build:  cd $PROOFS && coq_makefile -f _CoqProject -o Makefile && make"
