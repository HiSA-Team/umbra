(** LAYER 1 — the clean ESS allocator model (issue #58).

    This is the abstraction/refinement stack's top layer. It is a pure Rocq model
    of the ESS slot allocator: NO extracted types, NO Aeneas scalars, NO opaque
    primitives. The bitmap is modelled as a predicate [Slots := Z -> bool]
    (true = the slot is in use). All the security-relevant properties of the
    first-fit allocator are proved HERE, where reasoning is clean.

    The extracted code (Layer 3) is then shown to refine this model through a
    representation relation (Layer 2), so these theorems transfer to the real
    `EnclaveSwapSpace::allocate` the firmware runs.

    Indices are [Z] (not [nat]) so the representation relation can speak directly
    in terms of `to_Z` of the extracted `usize` indices, with no conversions.

    Main property: SPATIAL ISOLATION. Two successful allocations that are live at
    the same time occupy DISJOINT slot ranges — the model-level statement of "an
    enclave's blocks can never alias another enclave's blocks", which is the whole
    point of the ESS. *)

Require Import Coq.ZArith.ZArith.
Require Import Coq.micromega.Lia.
Require Import Coq.Bool.Bool.
Local Open Scope Z_scope.

(* A slot bitmap: [s i = true] iff slot [i] is in use. *)
Definition Slots := Z -> bool.

(* A run of [n] consecutive slots starting at [start] is free. *)
Definition free_run (s : Slots) (start n : Z) : Prop :=
  forall k, 0 <= k < n -> s (start + k) = false.

(* Slot [i] lies inside the run [start, start+n). *)
Definition in_run (i start n : Z) : bool :=
  (start <=? i) && (i <? start + n).

(* The pure model of `mark_slots_used`: set every slot in [start, start+n). *)
Definition mark (s : Slots) (start n : Z) : Slots :=
  fun i => if in_run i start n then true else s i.

(* The pure model of `allocate`'s effect on the bitmap: a first-fit allocation
   marks the run it was handed. The first-fit SEARCH (which [start] is chosen) is
   modelled in Layer 3's `find_free_run_sound`; here we only need that whatever
   run is returned was free and gets marked. *)
Definition alloc (s : Slots) (start n : Z) : Slots := mark s start n.

(* ── Basic mark laws ─────────────────────────────────────────────────── *)

Lemma in_run_true : forall i start n,
  start <= i -> i < start + n -> in_run i start n = true.
Proof.
  intros i start n H1 H2. unfold in_run.
  apply andb_true_intro. split.
  - apply Z.leb_le; lia.
  - apply Z.ltb_lt; lia.
Qed.

Lemma in_run_bounds : forall i start n,
  in_run i start n = true -> start <= i /\ i < start + n.
Proof.
  intros i start n H. unfold in_run in H.
  apply andb_prop in H. destruct H as [Ha Hb].
  apply Z.leb_le in Ha. apply Z.ltb_lt in Hb. lia.
Qed.

(* mark makes every slot in the run used. *)
Theorem mark_sets : forall s start n i,
  start <= i -> i < start + n -> mark s start n i = true.
Proof.
  intros s start n i H1 H2. unfold mark.
  rewrite in_run_true by assumption. reflexivity.
Qed.

(* mark leaves every slot OUTSIDE the run untouched. *)
Theorem mark_preserves : forall s start n i,
  (i < start \/ start + n <= i) -> mark s start n i = s i.
Proof.
  intros s start n i H. unfold mark.
  destruct (in_run i start n) eqn:E; [| reflexivity].
  apply in_run_bounds in E. lia.
Qed.

(* One more slot at a time: marking [start,start+n+1) differs from [start,start+n)
   only at slot [start+n]. The step law Layer 3's loop induction rides on. *)
Theorem mark_succ : forall s start n i, 0 <= n ->
  mark s start (n + 1) i = if i =? start + n then true else mark s start n i.
Proof.
  intros s start n i Hn.
  destruct (i =? start + n) eqn:E.
  - apply Z.eqb_eq in E. subst i. apply mark_sets; lia.
  - apply Z.eqb_neq in E. unfold mark.
    destruct (in_run i start (n + 1)) eqn:E1.
    + apply in_run_bounds in E1. rewrite in_run_true by lia. reflexivity.
    + destruct (in_run i start n) eqn:E2; [| reflexivity].
      apply in_run_bounds in E2.
      rewrite in_run_true in E1 by lia. discriminate.
Qed.

(* ── THE SECURITY THEOREM: spatial isolation ─────────────────────────── *)

(* Two ranges [a, a+m) and [b, b+n) are disjoint. *)
Definition disjoint (a m b n : Z) : Prop :=
  forall i, a <= i -> i < a + m -> b <= i -> i < b + n -> False.

(** A first-fit allocator that only ever hands out FREE runs and marks them used
    keeps every live allocation on a disjoint range. Concretely: allocate run 1
    from state [s] (it was free), giving [s1]; then allocate run 2 from [s1] (it
    must be free in s1). The two runs cannot overlap, because any shared slot
    would be marked used in [s1] by the first allocation yet required free by the
    second. This is the model-level isolation guarantee. *)
Theorem alloc_isolation :
  forall s start1 n1 start2 n2,
    free_run s start1 n1 ->                    (* run 1 was free in s         *)
    free_run (alloc s start1 n1) start2 n2 ->  (* run 2 is free after alloc 1 *)
    disjoint start1 n1 start2 n2.
Proof.
  intros s start1 n1 start2 n2 _ Hfree2.
  unfold disjoint. intros i Ha1 Hb1 Ha2 Hb2.
  (* slot i is in run 1, so alloc 1 marked it used *)
  assert (Hused : alloc s start1 n1 i = true)
    by (unfold alloc; apply mark_sets; lia).
  (* but run 2 is free after alloc 1, so slot i must be free there *)
  assert (Hfree : alloc s start1 n1 i = false).
  { replace i with (start2 + (i - start2)) by lia.
    apply Hfree2. lia. }
  rewrite Hused in Hfree. discriminate.
Qed.

(* The freshly allocated run is fully used afterwards (liveness side). *)
Theorem alloc_marks_run : forall s start n i,
  start <= i -> i < start + n -> alloc s start n i = true.
Proof. intros; unfold alloc; apply mark_sets; assumption. Qed.

(* Allocation never frees a slot that was already used (no aliasing via reuse). *)
Theorem alloc_monotone : forall s start n i,
  s i = true -> alloc s start n i = true.
Proof.
  intros s start n i H. unfold alloc, mark.
  destruct (in_run i start n); [reflexivity | exact H].
Qed.
