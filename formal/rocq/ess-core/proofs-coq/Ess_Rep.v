(** LAYER 2 — the representation relation (issue #58).

    This file connects the EXTRACTED bitmap (`array u32 8`, indexed word-by-word
    and bit-by-bit exactly as the Aeneas-generated code does) to the clean model
    `Slots := nat -> bool` of Layer 1.

    It is the ONLY place the opaque primitives leak in. The Coq backend ships
    `array_index_usize`, `array_update_usize`, `scalar_and/or/shl` as bare
    `Axiom`s marked TODO (Primitives.v) — they have names but no semantics. We pin
    down exactly the semantics we use, as a small, audited axiom set:

      • array SELECT/STORE laws (the standard McCarthy theory the backend omits);
      • the bitwise `to_Z` meaning of `u32_or` / `u32_and` / `u32_shl 1` (the same
        kind of axiom `Mem_Bridge.v` introduced as `scalar_and_spec`).

    Everything else — that OR-ing in `1<<b` sets bit b and leaves the rest, that
    `w & (1<<b) = 0` iff bit b is clear — is DERIVED here from Coq's `Z.testbit`
    theory, not assumed. So Layer 3's refinement proofs reason about bit-vectors
    with zero further axioms. *)

Require Import Coq.ZArith.ZArith.
Require Import Coq.micromega.Lia.
Require Import Coq.Bool.Bool.
Require Import Primitives. Import Primitives.
Require Import Ess_Model.
Local Open Scope Z_scope.

(* ── Pure-Z bit lemmas (no Primitives; derived from ZArith) ──────────── *)

(* Setting bit b via OR makes bit b read true. *)
Lemma testbit_lor_pow2_same : forall w b, 0 <= b ->
  Z.testbit (Z.lor w (2 ^ b)) b = true.
Proof.
  intros w b Hb. rewrite Z.lor_spec, Z.pow2_bits_eqb by lia.
  rewrite Z.eqb_refl, orb_true_r. reflexivity.
Qed.

(* Setting bit b via OR leaves every other bit untouched. *)
Lemma testbit_lor_pow2_other : forall w b c, 0 <= b -> 0 <= c -> c <> b ->
  Z.testbit (Z.lor w (2 ^ b)) c = Z.testbit w c.
Proof.
  intros w b c Hb Hc Hcb. rewrite Z.lor_spec, Z.pow2_bits_eqb by lia.
  replace (b =? c) with false by (symmetry; apply Z.eqb_neq; lia).
  apply orb_false_r.
Qed.

(* The extracted free-test `w & (1<<b) = 0` reads bit b exactly. *)
Lemma land_pow2_zero_iff : forall w b, 0 <= b ->
  (Z.land w (2 ^ b) =? 0 = true) <-> Z.testbit w b = false.
Proof.
  intros w b Hb. split.
  - intro H0. apply Z.eqb_eq in H0.
    assert (Hbit : Z.testbit (Z.land w (2 ^ b)) b = false)
      by (rewrite H0; apply Z.testbit_0_l).
    rewrite Z.land_spec, Z.pow2_bits_eqb, Z.eqb_refl, andb_true_r in Hbit by lia.
    exact Hbit.
  - intro Hwb. apply Z.eqb_eq. apply Z.bits_inj_iff. intro c.
    rewrite Z.testbit_0_l, Z.land_spec.
    destruct (Z_lt_le_dec c 0) as [Hneg | Hpos].
    + rewrite (Z.testbit_neg_r w c Hneg). reflexivity.
    + rewrite Z.pow2_bits_eqb by lia.
      destruct (Z.eq_dec c b) as [->|Hne].
      * rewrite Hwb. reflexivity.
      * replace (b =? c) with false by (symmetry; apply Z.eqb_neq; lia).
        apply andb_false_r.
Qed.

(* ── Opaque-primitive axiom set (the quarantine) ─────────────────────── *)

(* Array SELECT: an in-bounds read succeeds. *)
Axiom array_index_usize_ok : forall {T} {n} (a : array T n) (i : usize),
  0 <= to_Z i < to_Z n -> exists v, array_index_usize a i = Ok v.

(* Array access is a function of the index VALUE only (not its proof term). *)
Axiom array_index_usize_ext : forall {T} {n} (a : array T n) (i j : usize),
  to_Z i = to_Z j -> array_index_usize a i = array_index_usize a j.

(* Array STORE: an in-bounds write succeeds. *)
Axiom array_update_usize_ok : forall {T} {n} (a : array T n) (i : usize) (v : T),
  0 <= to_Z i < to_Z n -> exists a', array_update_usize a i v = Ok a'.

(* McCarthy read-over-write, hit: reading any index with the just-written value
   (keyed on [to_Z], since array access depends only on the index value, not its
   in-bounds proof term) gives the stored value. *)
Axiom array_update_index_eq : forall {T} {n} (a a' : array T n) (i j : usize) (v : T),
  array_update_usize a i v = Ok a' -> to_Z j = to_Z i ->
  array_index_usize a' j = Ok v.

(* McCarthy read-over-write, miss: other indices are unchanged. *)
Axiom array_update_index_neq : forall {T} {n} (a a' : array T n) (i j : usize) (v : T),
  array_update_usize a i v = Ok a' -> to_Z i <> to_Z j ->
  array_index_usize a' j = array_index_usize a j.

(* `u32_or` / `u32_and` are the opaque `scalar_or` / `scalar_and`; their
   bit-vector meaning (what the backend left as TODO). *)
Axiom u32_or_to_Z  : forall x y : u32, to_Z (u32_or x y)  = Z.lor  (to_Z x) (to_Z y).
Axiom u32_and_to_Z : forall x y : u32, to_Z (u32_and x y) = Z.land (to_Z x) (to_Z y).

(* `1u32 << b` for b < 32 is 2^b (fits in u32, never overflows). *)
Axiom u32_shl_one_pow2 : forall (b : usize), 0 <= to_Z b < 32 ->
  exists m : u32, u32_shl 1%u32 b = Ok m /\ to_Z m = 2 ^ (to_Z b).

(* ── The representation relation ──────────────────────────────────────── *)

(* The extracted bitmap [bm] represents the model [s]: for every in-range word
   index [widx] and bit [bidx], the model slot [widx*32 + bidx] equals bit
   [bidx] of the word at [widx]. This is the bitmap ⇆ Slots correspondence both
   `mark_slots_used` and `find_free_run` operate through. *)
Definition represents (bm : array u32 8%usize) (s : Slots) : Prop :=
  forall (widx bidx : usize) (w : u32),
    0 <= to_Z widx < 8 ->
    0 <= to_Z bidx < 32 ->
    array_index_usize bm widx = Ok w ->
    s (to_Z widx * 32 + to_Z bidx) = Z.testbit (to_Z w) (to_Z bidx).

(* Well-formedness of an ESS bitmap for the allocator. The `array u32 8` type
   already pins the word count (8) and `array u32`'s length is intrinsic, so the
   "arrays have fixed length / indices in bounds" facts the representation
   relation needs are FREE from the type — there is nothing further to assert.
   We keep the predicate as the documented hook for richer invariants. *)
Definition wf_bitmap (bm : array u32 8%usize) : Prop := True.
