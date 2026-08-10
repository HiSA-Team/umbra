#!/usr/bin/env bash
# Re-extract the umbra-update-core Coq model end-to-end and re-apply the manual
# patches the Aeneas Coq backend needs (issue #58). Idempotent. Requires the
# vendored toolchain on PATH:
#   export PATH="$PWD/formal/toolchain/aeneas/bin:$PWD/formal/toolchain/charon/bin:$PATH"
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"       # repo root
HERE="$ROOT/formal/rocq/update-core"
PROOFS="$HERE/proofs-coq"
CRATE="$ROOT/crates/umbra-update-core"

echo ">> [1/5] charon: Rust -> LLBC  (--cfg charon strips non-extractable derives)"
# NB: --dest-file must be ABSOLUTE — it resolves against cargo's build cwd, not the shell's.
# charon can exit non-zero while still emitting the llbc, so gate on the file, not $?.
rm -f "$HERE/update.llbc"
( cd "$CRATE" && touch src/lib.rs && \
  charon cargo --preset=aeneas --rustc-arg=--cfg=charon --dest-file="$HERE/update.llbc" ) || true
[ -s "$HERE/update.llbc" ] || { echo "error: charon produced no llbc" >&2; exit 1; }

echo ">> [2/5] aeneas: LLBC -> Coq"
aeneas -backend coq "$HERE/update.llbc" -dest "$PROOFS" -split-files

echo ">> [3/5] support files: Primitives + reusable loop shim"
cp "$ROOT/formal/toolchain/aeneas/backends/coq/Primitives.v" "$PROOFS/"
cp "$ROOT/formal/rocq/ess-core/proofs-coq/AeneasLoopShim.v" "$PROOFS/"

echo ">> [4/5] fill the external templates (opaque seams)"
# TypesExternal only exists if extraction references an opaque core type. With the
# Debug derive cfg-gated out there is none, so aeneas emits no such template —
# handle it only when present.
if [ -f "$PROOFS/Update_TypesExternal_Template.v" ]; then
  sed 's/Update_TypesExternal_Template/Update_TypesExternal/g' \
      "$PROOFS/Update_TypesExternal_Template.v" > "$PROOFS/Update_TypesExternal.v"
fi
# FunsExternal: copy_from_slice (given by the template) + the byte<->u32 codecs
# the Coq backend has no theory for (opaque; total by their Rust return types).
# Two steps (no pipe) so a non-zero perl under `set -e` can't silently abort.
sed 's/Update_FunsExternal_Template/Update_FunsExternal/g' \
    "$PROOFS/Update_FunsExternal_Template.v" > "$PROOFS/Update_FunsExternal.v"
perl -0pi -e 's/(\nEnd Update_FunsExternal\.)/\nAxiom core_num_U32_from_le_bytes : array u8 4%usize -> u32.\nAxiom core_num_U32_to_le_bytes : u32 -> array u8 4%usize.\n$1/' \
    "$PROOFS/Update_FunsExternal.v"
# … plus the TOTAL replacements for the backend's array-literal constructor.
# `Primitives.mk_array : forall {T} (n : usize) (l : list T), array T n` is an
# UNSOUND axiom: `array T n` is `{l : list T | length l = n}`, which is EMPTY at
# `T := Empty_set, n := 4`, so the axiom proves `False` (minimal reproduction and
# `Qed`'d derivation: ../AENEAS_COQ_MKARRAY_BUG.md). It is also unnecessary here:
# the extracted body only ever builds array literals of statically known length,
# and those are definable with their own length proof. Both arities the body uses
# are covered (4-byte decoder literals AND the 15-byte PKG_TAG_LABEL).
cat > "$PROOFS/.array_lit.frag" <<'FRAG'

(* --- TOTAL array-literal constructors (NOT axioms) ---------------------- *)
(* Replacements for the Aeneas Coq backend's `Primitives.mk_array`, which is an
   inconsistent `Axiom` (see ../../AENEAS_COQ_MKARRAY_BUG.md). `extract.sh`
   rewrites every `mk_array N%usize [ … ]` literal in generated Update_Funs.v into an
   application of one of these, so no proof over the extracted body inherits the
   unsound axiom. Each carries its own length proof, so each is total and adds
   nothing to the trusted base. *)
Definition mk_array4 (b0 b1 b2 b3 : u8) : array u8 4%usize :=
  exist _ [b0; b1; b2; b3] eq_refl.

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
for a in $(grep -oE 'mk_array[0-9]+' "$PROOFS/Update_Funs.v" | sort -u); do
  grep -qE "Definition $a([[:space:]]|\$)" "$PROOFS/Update_FunsExternal.v" || {
    echo "error: extracted code needs $a, which has no total constructor" >&2; exit 1; }
done

echo ">> done. Build:  cd $PROOFS && coq_makefile -f _CoqProject -o Makefile && make"
