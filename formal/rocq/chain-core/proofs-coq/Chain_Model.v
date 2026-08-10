(** COMPANION CONSISTENCY WITNESS for the ONE axiom this development adds to
    update-core's quarantine — `Chain_Value.array_u8_ext` (Q21).

    Same discipline as `Update_Model.v`: restate the axiom as a predicate over an
    operation bundle, check that the bundle of ACTUAL opaque symbols satisfies it
    iff the axiom holds, and exhibit a concrete model that satisfies it. The model
    is update-core's own — `Update_Model.model_ops`, whose `op_array_index` is
    `nth_error` on the underlying list — so Q21 is satisfied by the SAME structure
    that satisfies Q1..Q20, not by a second, differently-shaped one.

    WHAT THE DISCHARGE COSTS. `array T n` is `{l : list T | zlen l = to_Z n}` and
    `u8` is `{z : Z | scalar_min U8 <= z <= scalar_max U8}`, so proving two of
    them equal from equal contents needs the proof components to be irrelevant.
    For the array's own component that is FREE (`Eqdep_dec.UIP_dec Z.eq_dec` — it
    is an equality in `Z`, hence a decidable type). For the scalar's it is a
    conjunction of `Z.le`s, i.e. of negations, whose irrelevance is not derivable
    in CIC; the discharge therefore uses `Coq.Logic.ProofIrrelevance`. That is a
    standard, consistent stdlib axiom about `Prop`, and it appears only in THIS
    file's `Print Assumptions` — the headline theorems list Q21 itself, not the
    means by which Q21 is shown satisfiable.

    Nothing imports this file. *)

Require Import Primitives.
Import Primitives.
Require Import Coq.ZArith.ZArith.
Require Import Coq.Lists.List.
Import ListNotations.
Require Import Lia.
Require Import Coq.Logic.Eqdep_dec.
Require Import Coq.Logic.ProofIrrelevance.
Require Import Update_Safety.
Require Import Update_Model.
Require Import Chain_Value.
Local Open Scope Z_scope.
Local Open Scope Primitives_scope.

(* ===================================================================== *)
(* Q21, as a predicate over an operation bundle.                          *)
(* ===================================================================== *)

Definition ArrayExtHolds (O : OpaqueOps) : Prop :=
  forall (n : usize) (a b : array u8 n),
    (forall i : usize, 0 <= to_Z i < to_Z n ->
       exists x y, O.(op_array_index) u8 n a i = Ok x
                /\ O.(op_array_index) u8 n b i = Ok y
                /\ to_Z x = to_Z y) ->
    a = b.

(** The bundle of the ACTUAL opaque symbols satisfies the predicate iff the axiom
    holds — Coq checks the restatement. (This lemma DOES depend on Q21; that is
    the point.) *)
Lemma array_ext_is_the_axiom : ArrayExtHolds primitives_ops.
Proof.
  unfold ArrayExtHolds; cbn [op_array_index primitives_ops].
  exact (fun n a b H => array_u8_ext n a b H).
Qed.

(* ===================================================================== *)
(* The discharge, over update-core's own list model.                      *)
(* ===================================================================== *)

(** Two `u8`s with equal values are equal. The value is `proj1_sig`; the bound
    proofs are irrelevant. *)
Lemma u8_val_eq : forall x y : u8, to_Z x = to_Z y -> x = y.
Proof.
  intros [zx Hx] [zy Hy] H. unfold to_Z in H; cbn in H. subst zy.
  f_equal. apply proof_irrelevance.
Qed.

(** Two arrays with equal underlying lists are equal: the length proof is an
    equality in `Z`, hence irrelevant by UIP for decidable types — no axiom. *)
Lemma array_sig_eq : forall (T : Type) (n : usize) (a b : array T n),
  proj1_sig a = proj1_sig b -> a = b.
Proof.
  intros T n [la Ha] [lb Hb] H. cbn in H. subst lb.
  f_equal. apply (UIP_dec Z.eq_dec).
Qed.

Theorem array_ext_has_a_model : ArrayExtHolds model_ops.
Proof.
  unfold ArrayExtHolds; cbn [op_array_index model_ops].
  intros n a b H.
  apply (array_sig_eq u8 n). apply nth_error_list_eq. intro k.
  pose proof (proj2_sig a) as Ha. pose proof (proj2_sig b) as Hb.
  unfold zlen in Ha, Hb.
  destruct (Z.lt_ge_cases (Z.of_nat k) (to_Z n)) as [Hk | Hk].
  - (* in range: the hypothesis pins both reads to equal-valued bytes *)
    assert (Hkb : scalar_min Usize <= Z.of_nat k <= scalar_max Usize).
    { pose proof (to_Z_usize_bounds n) as Hn.
      rewrite usize_min_eq, usize_max_eq. lia. }
    set (i := exist (fun x : Z => scalar_min Usize <= x <= scalar_max Usize)
                    (Z.of_nat k) Hkb : usize).
    assert (Hi : to_Z i = Z.of_nat k) by reflexivity.
    destruct (H i ltac:(lia)) as [x [y [Hx [Hy Hxy]]]].
    unfold model_array_index, opt_result in Hx, Hy.
    rewrite Hi in Hx, Hy. rewrite Nat2Z.id in Hx, Hy.
    destruct (nth_error (proj1_sig a) k) as [xa|] eqn:Ea; [| discriminate ].
    destruct (nth_error (proj1_sig b) k) as [xb|] eqn:Eb; [| discriminate ].
    injection Hx as Hx. injection Hy as Hy. subst xa xb.
    rewrite (u8_val_eq x y Hxy). reflexivity.
  - (* out of range: both lists are exhausted *)
    assert (Ea : nth_error (proj1_sig a) k = None)
      by (apply nth_error_None; lia).
    assert (Eb : nth_error (proj1_sig b) k = None)
      by (apply nth_error_None; lia).
    rewrite Ea, Eb. reflexivity.
Qed.

(** So Q21 is satisfiable — and by the SAME structure that satisfies Q1..Q20:
    `Update_Model.quarantine_has_a_model` proves `exists O, QuarantineHolds O`
    with `model_ops` as its witness (it is the first line of that proof), and
    `array_ext_has_a_model` just above proves `ArrayExtHolds` of that same
    `model_ops`. Q21 therefore does not enlarge the class of structures the
    quarantine admits; it is a further property of the one already exhibited. *)
