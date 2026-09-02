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

echo ">> [3/5] support files: Primitives (project variant, checked) + reusable loop shim"
# proofs-coq/Primitives.v is NOT the toolchain file: it is our axiom-free
# variant (same names and types; every backend `Axiom` given a definition, the
# inconsistent `mk_array` removed). It is never overwritten here. What IS
# checked is that the vendored backend file it was derived from has not moved
# under us, so an upstream change to Primitives.v is loud, not silent.
PRIM_UPSTREAM_SHA="a5f5677c05c3e122f9fdf604097ffb5f50fd27518087246cd37f2e62a0c33edb"
PRIM_ACTUAL_SHA="$(shasum -a 256 "$ROOT/formal/toolchain/aeneas/backends/coq/Primitives.v" | cut -d' ' -f1)"
[ "$PRIM_ACTUAL_SHA" = "$PRIM_UPSTREAM_SHA" ] || {
  echo "error: vendored backend Primitives.v changed (sha256 $PRIM_ACTUAL_SHA);" >&2
  echo "       re-derive proofs-coq/Primitives.v from it and update PRIM_UPSTREAM_SHA" >&2
  exit 1; }
[ -f "$PROOFS/Primitives.v" ] || { echo "error: $PROOFS/Primitives.v (project variant) missing" >&2; exit 1; }
if grep -q '^Axiom ' "$PROOFS/Primitives.v"; then
  echo "error: proofs-coq/Primitives.v declares an Axiom; the project variant must not" >&2; exit 1; fi
cp "$ROOT/formal/rocq/ess-core/proofs-coq/AeneasLoopShim.v" "$PROOFS/"

echo ">> [4/5] fill the external templates (opaque seams)"
# TypesExternal only exists if extraction references an opaque core type. With the
# Debug derive cfg-gated out there is none, so aeneas emits no such template —
# handle it only when present.
if [ -f "$PROOFS/Update_TypesExternal_Template.v" ]; then
  sed 's/Update_TypesExternal_Template/Update_TypesExternal/g' \
      "$PROOFS/Update_TypesExternal_Template.v" > "$PROOFS/Update_TypesExternal.v"
fi
# FunsExternal: the template leaves copy_from_slice as an Axiom; it becomes a
# DEFINITION (Rust semantics: lengths must match, then dst holds src), and the
# byte<->u32 codecs the Coq backend has no theory for are DEFINED as the
# base-256 digit (de)composition. No axiom survives in this file.
# Two steps (no pipe) so a non-zero perl under `set -e` can't silently abort.
sed 's/Update_FunsExternal_Template/Update_FunsExternal/g' \
    "$PROOFS/Update_FunsExternal_Template.v" > "$PROOFS/Update_FunsExternal.v"
perl -0pi -e 's/Axiom core_slice_Slice_copy_from_slice :\n  forall\{T : Type\} \(markerCopyInst : core_marker_Copy T\),\n        slice T -> slice T -> result \(slice T\)\n\./(* Filled by ..\/extract.sh (the template leaves it as an Axiom): Rust panics\n   unless the lengths match, and on success dst holds src\x27s elements. *)\nDefinition core_slice_Slice_copy_from_slice\n  {T : Type} (markerCopyInst : core_marker_Copy T) (dst src : slice T)\n  : result (slice T) :=\n  if Z.eqb (to_Z (slice_len dst)) (to_Z (slice_len src)) then Ok src else Fail_ Failure./' \
    "$PROOFS/Update_FunsExternal.v"
grep -q '^Definition core_slice_Slice_copy_from_slice' "$PROOFS/Update_FunsExternal.v" || {
  echo "error: copy_from_slice Axiom in the template did not match the expected shape" >&2; exit 1; }
perl -0pi -e 's/(Require Import List\.\nImport ListNotations\.\n)/$1Require Import Lia.\n/' "$PROOFS/Update_FunsExternal.v"
# … plus the codecs and the TOTAL replacements for the backend's array-literal constructor.
# `Primitives.mk_array : forall {T} (n : usize) (l : list T), array T n` is an
# UNSOUND axiom: `array T n` is `{l : list T | length l = n}`, which is EMPTY at
# `T := Empty_set, n := 4`, so the axiom proves `False` (minimal reproduction and
# `Qed`'d derivation: ../AENEAS_COQ_MKARRAY_BUG.md). It is also unnecessary here:
# the extracted body only ever builds array literals of statically known length,
# and those are definable with their own length proof. Both arities the body uses
# are covered (4-byte decoder literals AND the 15-byte PKG_TAG_LABEL).
cat > "$PROOFS/.array_lit.frag" <<'FRAG'

(* --- the byte<->u32 codecs (NOT axioms) --------------------------------- *)
(* `u32::to_le_bytes` is the base-256 digit decomposition and
   `u32::from_le_bytes` its recomposition. Added by ../extract.sh. *)
Local Open Scope Z_scope.

Lemma to_Z_u8_range : forall x : u8, 0 <= to_Z x < 256.
Proof. intro x. pose proof (to_Z_bounds x) as H. unfold scalar_min, scalar_max, u8_min, u8_max in H. lia. Qed.

Lemma byte_digit_bnd : forall z k : Z,
  scalar_min U8 <= (z / 256 ^ k) mod 256 <= scalar_max U8.
Proof.
  intros z k. unfold scalar_min, scalar_max, u8_min, u8_max.
  pose proof (Z.mod_pos_bound (z / 256 ^ k) 256 ltac:(lia)). lia.
Qed.

Definition byte_digit (z k : Z) : u8 :=
  mk_scalar_of_bounds U8 ((z / 256 ^ k) mod 256) (byte_digit_bnd z k).

Definition core_num_U32_to_le_bytes (x : u32) : array u8 4%usize :=
  exist _ [ byte_digit (to_Z x) 0; byte_digit (to_Z x) 1;
            byte_digit (to_Z x) 2; byte_digit (to_Z x) 3 ] eq_refl.

Definition byte_at (a : array u8 4%usize) (k : nat) : Z :=
  match nth_error (proj1_sig a) k with Some b => to_Z b | None => 0 end.

Lemma byte_at_bnd : forall a k, 0 <= byte_at a k < 256.
Proof.
  intros a k. unfold byte_at.
  destruct (nth_error (proj1_sig a) k) as [b|]; [ apply to_Z_u8_range | lia ].
Qed.

Lemma from_le_bnd : forall a : array u8 4%usize,
  scalar_min U32
  <= byte_at a 0 + 256 * byte_at a 1 + 65536 * byte_at a 2 + 16777216 * byte_at a 3
  <= scalar_max U32.
Proof.
  intros a. unfold scalar_min, scalar_max, u32_min, u32_max.
  pose proof (byte_at_bnd a 0). pose proof (byte_at_bnd a 1).
  pose proof (byte_at_bnd a 2). pose proof (byte_at_bnd a 3). lia.
Qed.

Definition core_num_U32_from_le_bytes (a : array u8 4%usize) : u32 :=
  mk_scalar_of_bounds U32
    (byte_at a 0 + 256 * byte_at a 1 + 65536 * byte_at a 2 + 16777216 * byte_at a 3)
    (from_le_bnd a).

(* --- TOTAL array-literal constructors (NOT axioms) ---------------------- *)
(* Replacements for the Aeneas Coq backend's `mk_array`, which is an
   inconsistent `Axiom` (see ../../AENEAS_COQ_MKARRAY_BUG.md) and which our
   Primitives.v therefore no longer declares. `extract.sh` rewrites every
   `mk_array N%usize [ … ]` literal in generated Update_Funs.v into an
   application of one of these. Each carries its own length proof. *)
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
if grep -q '^Axiom ' "$PROOFS/Update_FunsExternal.v"; then
  echo "error: an Axiom survived in Update_FunsExternal.v" >&2; exit 1; fi
for a in $(grep -oE 'mk_array[0-9]+' "$PROOFS/Update_Funs.v" | sort -u); do
  grep -qE "Definition $a([[:space:]]|\$)" "$PROOFS/Update_FunsExternal.v" || {
    echo "error: extracted code needs $a, which has no total constructor" >&2; exit 1; }
done

echo ">> done. Build:  cd $PROOFS && coq_makefile -f _CoqProject -o Makefile && make"
