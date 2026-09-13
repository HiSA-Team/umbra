(* AeneasLoopModel.v — an ITree model of the Aeneas [loop_fuel] shim.
   Soundness, completeness and the measure-bound corollary, all axiom-free.
   Only Ret/Tau nodes occur (event signature [void1]), so no Vis inversion
   and hence no UIP is ever needed. *)
Require Import Primitives.
Import Primitives.
Require Import AeneasLoopShim.
Require Import AeneasLoopBounds.
From Coq Require Import Lia.
From Paco Require Import paco.
From ITree Require Import ITree ITreeFacts.
From ITree Require Import Eq.Eqit Eq.Shallow Eq.Paco2.

Import ITreeNotations.
Local Open Scope itree_scope.

Section Model.
Context {S B : Type}.

(* One step of the loop body, as a sum: [inl] continues, [inr] terminates. *)
Definition loop_step (f : S -> result (control_flow S B)) (s : S) : S + result B :=
  match f s with
  | Ok (Cont s') => inl s'
  | Ok (Done b) => inr (Ok b)
  | Fail_ e => inr (Fail_ e)
  end.

Definition loop_model (f : S -> result (control_flow S B)) : S -> itree void1 (result B) :=
  ITree.iter (fun s => Ret (loop_step f s)).

(* Observing one step of the model computes definitionally. *)
Lemma observe_loop_model (f : S -> result (control_flow S B)) (s : S) :
  observe (loop_model f s) =
  match f s with
  | Ok (Cont s') => TauF (loop_model f s')
  | Ok (Done b) => RetF (Ok b)
  | Fail_ e => RetF (Fail_ e)
  end.
Proof.
  unfold loop_model.
  rewrite (observing_observe (unfold_aloop_ _ _)).
  rewrite (observing_observe (bind_ret_ _ _)).
  unfold loop_step. destruct (f s) as [[s' | b] | e]; reflexivity.
Qed.

(* Unfolding as a [eutt] equation. *)
Lemma loop_model_unfold (f : S -> result (control_flow S B)) (s : S) :
  loop_model f s ≈
  match f s with
  | Ok (Cont s') => Tau (loop_model f s')
  | Ok (Done b) => Ret (Ok b)
  | Fail_ e => Ret (Fail_ e)
  end.
Proof.
  unfold loop_model at 1. rewrite unfold_iter. rewrite bind_ret_l.
  unfold loop_step. destruct (f s) as [[s' | b] | e]; reflexivity.
Qed.

(* (S) Soundness: any non-exhausted fuel result is the model's result. *)
Theorem loop_model_sound :
  forall (f : S -> result (control_flow S B)) (s : S) (n : nat) (r : result B),
    loop_fuel n f s = r ->
    r <> Fail_ OutOfFuel ->
    loop_model f s ≈ Ret r.
Proof.
  intros f s n. revert s.
  induction n as [| n IH]; intros s r Hrun Hne.
  - simpl in Hrun. subst r. contradiction.
  - rewrite loop_model_unfold.
    simpl in Hrun.
    destruct (f s) as [[s' | b] | e].
    + rewrite tau_eutt. apply IH; assumption.
    + subst r. reflexivity.
    + subst r. reflexivity.
Qed.

(* Inductive core of completeness: an [eqitF] derivation whose right side is
   [RetF r] and whose left side observes [loop_model f s] yields fuel for [r].
   Stated for arbitrary [vclo]/[sim] so plain [induction] applies; with
   [b2 = false] the [EqTauR] constructor is impossible ([CHECK : is_true false]
   is discriminated), and [EqTau]/[EqVis] mismatch [RetF] on the right. *)
Lemma loop_model_eqitF_complete :
  forall (f : S -> result (control_flow S B)) vclo sim
         (ot1 : itree' void1 (result B)) (ot2 : itree' void1 (result B)),
    eqitF eq true false vclo sim ot1 ot2 ->
    forall (s : S) (r : result B),
      ot2 = RetF r ->
      ot1 = observe (loop_model f s) ->
      exists n, loop_fuel n f s = r.
Proof.
  intros f vclo sim ot1 ot2 H.
  induction H; intros s r Hot2 Hot1; try discriminate.
  - (* EqRet *)
    injection Hot2 as ->.
    rewrite observe_loop_model in Hot1.
    destruct (f s) as [[s' | b] | e] eqn:Hf; try discriminate.
    + injection Hot1 as ->. exists 1. simpl. rewrite Hf. subst. reflexivity.
    + injection Hot1 as ->. exists 1. simpl. rewrite Hf. subst. reflexivity.
  - (* EqTauL *)
    rewrite observe_loop_model in Hot1.
    destruct (f s) as [[s' | b] | e] eqn:Hf; try discriminate.
    injection Hot1 as ->.
    destruct (IHeqitF s' r Hot2 eq_refl) as [n Hn].
    exists (Datatypes.S n). simpl. rewrite Hf. exact Hn.
Qed.

(* (C) Completeness: if the model returns [r], some fuel computes [r]. *)
Theorem loop_model_complete :
  forall (f : S -> result (control_flow S B)) (s : S) (r : result B),
    loop_model f s ≈ Ret r ->
    exists n, loop_fuel n f s = r.
Proof.
  intros f s r H.
  apply eutt_inv_Ret_r in H.
  punfold H. red in H. cbn in H.
  eapply loop_model_eqitF_complete; eauto.
Qed.

(* (Bc) Measure bound: under a strictly decreasing measure the model returns
   exactly the result computed with fuel [S (m s)]. *)
Theorem loop_model_bound :
  forall (f : S -> result (control_flow S B)) (m : S -> nat) (s : S),
    (forall s, f s <> Fail_ OutOfFuel) ->
    (forall s s', f s = Ok (Cont s') -> m s' < m s) ->
    loop_model f s ≈ Ret (loop_fuel (Datatypes.S (m s)) f s).
Proof.
  intros f m s Hbody Hdec.
  apply (loop_model_sound f s (Datatypes.S (m s))); [reflexivity |].
  apply loop_fuel_bound_S; assumption.
Qed.

End Model.

Print Assumptions observe_loop_model.
Print Assumptions loop_model_unfold.
Print Assumptions loop_model_sound.
Print Assumptions loop_model_eqitF_complete.
Print Assumptions loop_model_complete.
Print Assumptions loop_model_bound.
