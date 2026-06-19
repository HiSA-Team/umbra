(** T1 — Soundness of the constant-time accept gate (issue #58).

    [umbra_rot_core::verify_measurement] decides acceptance of a measurement by:
    a length check, then folding `diff |= measured[i] XOR expected[i]` over all
    bytes, accepting iff `diff == 0`. This file models that algorithm faithfully
    over bytes (Coq `N`) and proves it is a SOUND equality gate: it accepts iff
    the tags are byte-for-byte equal. In particular the security-critical
    direction — accept ⇒ equal — holds, so no mismatched (tampered) measurement
    is ever accepted. No cryptographic assumption is used; this is pure logic. *)

Require Import Coq.NArith.NArith.
Require Import Coq.Arith.PeanoNat.
Require Import Coq.Lists.List.
Require Import Coq.Bool.Bool.
Import ListNotations.

(* The OR-fold of per-byte XORs that `verify_measurement` accumulates in `diff`. *)
Fixpoint ct_diff (m e : list N) : N :=
  match m, e with
  | a :: m', b :: e' => N.lor (N.lxor a b) (ct_diff m' e')
  | _, _ => 0%N
  end.

(* The accept decision: equal length AND zero diff (exactly verify_measurement). *)
Definition ct_eq (m e : list N) : bool :=
  andb (Nat.eqb (length m) (length e)) (N.eqb (ct_diff m e) 0).

(* Equal tags fold to a zero diff. *)
Lemma ct_diff_refl : forall l, ct_diff l l = 0%N.
Proof.
  induction l as [| a l IH]; simpl; [ reflexivity |].
  rewrite N.lxor_nilpotent. rewrite IH. reflexivity.
Qed.

(* A zero diff over equal-length tags forces the tags equal — the soundness core. *)
Lemma ct_diff_zero_eq :
  forall m e, length m = length e -> ct_diff m e = 0%N -> m = e.
Proof.
  induction m as [| a m IH]; intros e Hlen Hdiff.
  - destruct e; [ reflexivity | discriminate Hlen ].
  - destruct e as [| b e]; [ discriminate Hlen |].
    simpl in Hlen, Hdiff. injection Hlen as Hlen'.
    apply N.lor_eq_0_iff in Hdiff. destruct Hdiff as [Hxor Hrest].
    assert (Hab : a = b) by (apply N.lxor_eq_0_iff; exact Hxor).
    assert (Hme : m = e) by (apply IH; [ exact Hlen' | exact Hrest ]).
    subst. reflexivity.
Qed.

(** SOUNDNESS. The gate accepts iff the measurements are exactly equal. *)
Theorem ct_eq_correct : forall m e, ct_eq m e = true <-> m = e.
Proof.
  intros m e. unfold ct_eq. split.
  - intro H. apply andb_true_iff in H. destruct H as [Hlen Hdiff].
    apply Nat.eqb_eq in Hlen. apply N.eqb_eq in Hdiff.
    apply ct_diff_zero_eq; assumption.
  - intro H. subst e. rewrite Nat.eqb_refl. rewrite ct_diff_refl.
    rewrite N.eqb_refl. reflexivity.
Qed.

(** The security-critical corollary, stated on its own: an accepted measurement
    is the expected one — no false accept. *)
Corollary verify_no_false_accept :
  forall measured expected, ct_eq measured expected = true -> measured = expected.
Proof. intros m e H. apply ct_eq_correct. exact H. Qed.
