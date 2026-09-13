(* AeneasLoopBounds.v — fuel-sufficiency, fuel-stability and measure helpers
   for the Aeneas [loop_fuel] shim.  Axiom-free; no ITree dependency. *)
Require Import Primitives.
Import Primitives.
Require Import AeneasLoopShim.
Require Import Lia.

Section Bounds.
Context {S B : Type}.

(* (a) If the body never exhausts fuel on its own and a natural-number measure
   strictly decreases on every [Cont] step, then fuel [n > m s] is enough. *)
Theorem loop_fuel_bound :
  forall (f : S -> result (control_flow S B)) (m : S -> nat) (s : S) (n : nat),
    (forall s, f s <> Fail_ OutOfFuel) ->
    (forall s s', f s = Ok (Cont s') -> m s' < m s) ->
    m s < n ->
    loop_fuel n f s <> Fail_ OutOfFuel.
Proof.
  intros f m s n Hbody Hdec.
  revert s.
  induction n as [| n IH]; intros s Hlt.
  - lia.
  - simpl.
    destruct (f s) as [[s' | b] | e] eqn:Hf.
    + apply IH. specialize (Hdec _ _ Hf). lia.
    + discriminate.
    + intros Heq. injection Heq as ->. exact (Hbody s Hf).
Qed.

(* (b) Corollary: fuel [S (m s)] is always enough. *)
Corollary loop_fuel_bound_S :
  forall (f : S -> result (control_flow S B)) (m : S -> nat) (s : S),
    (forall s, f s <> Fail_ OutOfFuel) ->
    (forall s s', f s = Ok (Cont s') -> m s' < m s) ->
    loop_fuel (Datatypes.S (m s)) f s <> Fail_ OutOfFuel.
Proof.
  intros f m s Hbody Hdec.
  apply (loop_fuel_bound f m s (Datatypes.S (m s)) Hbody Hdec). lia.
Qed.

(* (c) More fuel never changes a non-exhausted result. *)
Theorem loop_fuel_stable :
  forall (f : S -> result (control_flow S B)) (s : S) (n n' : nat) (r : result B),
    loop_fuel n f s = r ->
    r <> Fail_ OutOfFuel ->
    n <= n' ->
    loop_fuel n' f s = r.
Proof.
  intros f s n.
  revert s.
  induction n as [| n IH]; intros s n' r Hrun Hne Hle.
  - simpl in Hrun. subst r. contradiction.
  - destruct n' as [| n']; [lia |].
    simpl in Hrun. simpl.
    destruct (f s) as [[s' | b] | e] eqn:Hf.
    + apply IH; auto. lia.
    + exact Hrun.
    + exact Hrun.
Qed.

(* (d) Measure helpers. *)

(* An index that increments by one on each [Cont] step and stays below
   [bound] yields the strictly decreasing measure [bound - idx]. *)
Lemma measure_index :
  forall (idx : S -> nat) (bound : nat) (f : S -> result (control_flow S B)),
    (forall s s', f s = Ok (Cont s') -> idx s' = Datatypes.S (idx s)) ->
    (forall s s', f s = Ok (Cont s') -> idx s < bound) ->
    forall s s', f s = Ok (Cont s') -> bound - idx s' < bound - idx s.
Proof.
  intros idx bound f Hinc Hlt s s' Hf.
  specialize (Hinc _ _ Hf). specialize (Hlt _ _ Hf). lia.
Qed.

(* A strictly decreasing counter is already a measure. *)
Lemma measure_count :
  forall (cnt : S -> nat) (f : S -> result (control_flow S B)),
    (forall s s', f s = Ok (Cont s') -> cnt s' < cnt s) ->
    forall s s', f s = Ok (Cont s') -> cnt s' < cnt s.
Proof.
  intros cnt f Hdec s s' Hf. exact (Hdec _ _ Hf).
Qed.

End Bounds.

Print Assumptions loop_fuel_bound.
Print Assumptions loop_fuel_bound_S.
Print Assumptions loop_fuel_stable.
Print Assumptions measure_index.
Print Assumptions measure_count.
