(** THE FOLD AS A TRACE, AND THE COLLISION REDUCTION.

    Two things live here.

    (1) [chain_root_trace] — the extracted fuel loop `chain_root_loop`, when it
        returns a root, IS a finite chain of seam applications whose k-th message
        is the preimage `block_preimage` builds for block `i+k`. This is the
        refinement step: everything downstream reasons about traces, and this
        lemma is what ties a trace back to the VERBATIM extracted body.

    (2) [trace_collision] — two traces of equal length over one seam, starting
        anywhere and ending at the same root, are the same trace unless the seam
        collided; and in that case the colliding pair is EXHIBITED.

    WHY THIS SHAPE, AND NOT AN INJECTIVITY ASSUMPTION.

    The tempting statement is "HMAC is injective": `hmac k m1 = hmac k m2 -> m1 =
    m2`. It is UNSATISFIABLE for any fixed-output function on a larger domain —
    292-byte messages outnumber 32-byte tags, so a collision exists by pigeonhole
    and the hypothesis is false. Every theorem consuming it is vacuous.
    `formal/rocq/rot-core/proofs-coq/Rot_Chain.v` states exactly that hypothesis.
    This file does not.

    [trace_collision] has NO cryptographic hypothesis. It is a REDUCTION:
    tampering either fails the gate or yields a concrete HMAC collision. What
    stays outside Coq is the computational claim that finding one is infeasible —
    a statement about resources, which no inhabitant of `Prop` can express, and
    which is therefore not smuggled in here as a hypothesis that happens to be
    false.

    THE ONE LOGICAL PREMISE, AND WHY IT IS NOT AN AXIOM. The walk down two traces
    has to ask, at each step, whether the two seam inputs coincide. That decision
    is kept as an explicit `Hypothesis` in the section below, so it appears in
    [trace_collision]'s statement; [chain_trace_collision] discharges it with
    `Chain_Value.array_u8_eq_dec`, which decides equality of two byte arrays by a
    bounded enumeration of their bytes (Q21 + Q1 + `Z.eq_dec`). Constructive: no
    `classic`, no `proof_irrelevance`. It decides equality of two Coq terms and
    says nothing whatever about HMAC. *)

Require Import Primitives.
Import Primitives.
Require Import AeneasLoopShim.
Import AeneasLoopShim.
Require Import Coq.ZArith.ZArith.
Require Import Coq.Lists.List.
Import ListNotations.
Require Import Lia.
Require Import Update_Safety.
Require Import Chain_Types.
Import Chain_Types.
Require Import Chain_FunsExternal.
Import Chain_FunsExternal.
Require Import Chain_Funs.
Import Chain_Funs.
Require Import Chain_Value.
Local Open Scope Z_scope.
Local Open Scope Primitives_scope.

Definition ckey := array u8 32%usize.
Definition cmsg := array u8 292%usize.

(* ===================================================================== *)
(* Traces.                                                                *)
(* ===================================================================== *)

Section Trace.

(* The seam, as a partial keyed function; `F c m = Ok c'` is one fold step. *)
Variable F : ckey -> cmsg -> result ckey.

(** `ChainTrace c ms r`: folding the messages `ms` into the accumulator `c`, one
    successful seam application at a time, ends at `r`. *)
Inductive ChainTrace : ckey -> list cmsg -> ckey -> Prop :=
| CT_nil  : forall c, ChainTrace c [] c
| CT_cons : forall c m c' ms r,
              F c m = Ok c' -> ChainTrace c' ms r -> ChainTrace c (m :: ms) r.

(** `StepIn c ms a b`: `(a, b)` is one of the (accumulator, message) pairs the
    fold of `ms` from `c` actually applies the seam to.

    THIS IS WHAT KEEPS THE REDUCTION FROM BEING VACUOUS. "There exist two
    distinct inputs with the same tag" is TRUE of any fixed-output function by
    pigeonhole, so a disjunct saying only that would be trivially satisfiable and
    the theorem would carry no security content — the mirror image of the
    `hmac_injective` defect. `StepIn` pins the colliding pair to states the
    device REACHES while measuring the adversary's own blobs, so an unrelated
    pigeonhole collision does not discharge it. *)
Inductive StepIn : ckey -> list cmsg -> ckey -> cmsg -> Prop :=
| SI_here  : forall c m ms, StepIn c (m :: ms) c m
| SI_there : forall c m c' ms a b,
               F c m = Ok c' -> StepIn c' ms a b -> StepIn c (m :: ms) a b.

Section Collision.

Hypothesis Kem : forall x y : ckey, x = y \/ x <> y.
Hypothesis Mem : forall x y : cmsg, x = y \/ x <> y.

(** THE COLLISION REDUCTION. No hypothesis on `F`. The proof walks both traces
    from the front: the tails are handled first, and once they are known to
    coincide the two head steps have a COMMON output, so either their inputs
    coincide too — and the traces are equal — or those inputs are a collision,
    right there. *)
Lemma trace_collision :
  forall (ms1 ms2 : list cmsg) (c1 c2 r : ckey),
    ChainTrace c1 ms1 r ->
    ChainTrace c2 ms2 r ->
    length ms1 = length ms2 ->
    (c1, ms1) = (c2, ms2)
    \/ (exists (a1 : ckey) (b1 : cmsg) (a2 : ckey) (b2 : cmsg) (v : ckey),
          (a1, b1) <> (a2, b2) /\ F a1 b1 = Ok v /\ F a2 b2 = Ok v
          /\ StepIn c1 ms1 a1 b1 /\ StepIn c2 ms2 a2 b2).
Proof.
  induction ms1 as [| m1 t1 IH]; intros ms2 c1 c2 r H1 H2 Hlen.
  - destruct ms2 as [| m2 t2]; [| cbn in Hlen; discriminate ].
    inversion H1; subst. inversion H2; subst. left. reflexivity.
  - destruct ms2 as [| m2 t2]; [ cbn in Hlen; discriminate |].
    cbn in Hlen. injection Hlen as Hlen.
    inversion H1 as [| ca ma d1 msa ra Hstep1 Hrest1 Ea ]; subst.
    inversion H2 as [| cb mb d2 msb rb Hstep2 Hrest2 Eb ]; subst.
    destruct (IH t2 d1 d2 r Hrest1 Hrest2 Hlen) as [Heq | Hcoll].
    2:{ (* a collision further down: extend both witnesses by one step *)
        right. destruct Hcoll as [a1 [b1 [a2 [b2 [v [Hne [Hf1 [Hf2 [Hs1 Hs2]]]]]]]]].
        exists a1, b1, a2, b2, v. repeat split;
          [ exact Hne | exact Hf1 | exact Hf2
          | exact (SI_there c1 m1 d1 t1 a1 b1 Hstep1 Hs1)
          | exact (SI_there c2 m2 d2 t2 a2 b2 Hstep2 Hs2) ]. }
    injection Heq as Ed Et. subst d2 t2.
    (* the two head steps now share the output d1 *)
    destruct (Kem c1 c2) as [Ec | Nc]; destruct (Mem m1 m2) as [Em | Nm].
    + subst c2 m2. left. reflexivity.
    + right. exists c1, m1, c2, m2, d1. repeat split;
        [ intro Hc; injection Hc as _ E; exact (Nm E)
        | exact Hstep1 | exact Hstep2 | apply SI_here | apply SI_here ].
    + right. exists c1, m1, c2, m2, d1. repeat split;
        [ intro Hc; injection Hc as E _; exact (Nc E)
        | exact Hstep1 | exact Hstep2 | apply SI_here | apply SI_here ].
    + right. exists c1, m1, c2, m2, d1. repeat split;
        [ intro Hc; injection Hc as E _; exact (Nc E)
        | exact Hstep1 | exact Hstep2 | apply SI_here | apply SI_here ].
Qed.

(** Traces are deterministic in their messages: the seam is a function, so the
    same start and the same message list can only reach one root. Used by the
    residual (negative) results, where the messages are shown equal and the roots
    must then follow. No hypothesis, and no excluded middle. *)
Lemma trace_det :
  forall (ms : list cmsg) (c r1 r2 : ckey),
    ChainTrace c ms r1 -> ChainTrace c ms r2 -> r1 = r2.
Proof.
  induction ms as [| m t IH]; intros c r1 r2 H1 H2.
  - inversion H1; subst. inversion H2; subst. reflexivity.
  - inversion H1 as [| ca ma d1 msa ra S1 R1 ]; subst.
    inversion H2 as [| cb mb d2 msb rb S2 R2 ]; subst.
    assert (Ed : d1 = d2) by (rewrite S1 in S2; injection S2 as E; exact E).
    subst d2. exact (IH d1 r1 r2 R1 R2).
Qed.

End Collision.

(** The same statement with the two decidability premises discharged — by
    `Chain_Value.array_u8_eq_dec`, which enumerates the array's bytes using Q21,
    Q1 and `Z.eq_dec`. CONSTRUCTIVE: an earlier revision used
    `Classical_Prop.classic` here, and that axiom is now gone from the whole
    tier. This is the form the target theorem uses. *)
Lemma chain_trace_collision :
  forall (ms1 ms2 : list cmsg) (c1 c2 r : ckey),
    ChainTrace c1 ms1 r ->
    ChainTrace c2 ms2 r ->
    length ms1 = length ms2 ->
    (c1, ms1) = (c2, ms2)
    \/ (exists (a1 : ckey) (b1 : cmsg) (a2 : ckey) (b2 : cmsg) (v : ckey),
          (a1, b1) <> (a2, b2) /\ F a1 b1 = Ok v /\ F a2 b2 = Ok v
          /\ StepIn c1 ms1 a1 b1 /\ StepIn c2 ms2 a2 b2).
Proof.
  apply trace_collision;
    intros x y; [ exact (array_u8_eq_dec 32%usize x y)
                | exact (array_u8_eq_dec 292%usize x y) ].
Qed.

End Trace.


(* ===================================================================== *)
(* THE EXTRACTED LOOP IS A TRACE.                                         *)
(* ===================================================================== *)

(** The seam of a `ChainHmac` instance, as a partial keyed function. *)
Definition seam_of {HS : Type} (inst : ChainHmac_t HS) (h : HS) : ckey -> cmsg -> result ckey :=
  fun c p => inst.(ChainHmac_t_hmac_chain) h c p.

Lemma u32_add1_val : forall (i j : u32), u32_add i 1%u32 = Ok j -> to_Z j = to_Z i + 1.
Proof.
  intros i j H. unfold u32_add, scalar_add in H. apply mk_scalar_to_Z in H.
  rewrite H. reflexivity.
Qed.

(** `chain_root_loop`, run from `(c, i)`, returns a root exactly when it can fold
    blocks `i, i+1, …, num_blocks-1`; and then the sequence of messages it folded
    is the sequence of `block_preimage`s of those blocks, in that order. *)
Lemma chain_root_loop_trace :
  forall (fuel : nat) {HS : Type} (inst : ChainHmac_t HS) (h : HS)
         (blob : slice u8) (num_blocks : u32) (c : ckey) (i : u32) (r : ckey),
    loop_fuel fuel
      (fun '(c1, i1) => chain_root_loop_body inst h blob num_blocks c1 i1) (c, i)
      = Ok (Some r) ->
    exists ms : list cmsg,
      ChainTrace (seam_of inst h) c ms r
      /\ Z.of_nat (length ms) = Z.max 0 (to_Z num_blocks - to_Z i)
      /\ (forall k pre, nth_error ms k = Some pre ->
            exists blk : u32,
              to_Z blk = to_Z i + Z.of_nat k
              /\ block_preimage blob blk = Ok (Some pre)).
Proof.
  induction fuel as [| n IH];
    intros HS inst h blob num_blocks c i r Hloop.
  - simpl in Hloop. discriminate.
  - rewrite loop_step in Hloop. cbn beta iota in Hloop.
    unfold chain_root_loop_body in Hloop.
    destruct (i s< num_blocks) eqn:Hlt.
    + apply sltb_true in Hlt.
      destruct (block_preimage blob i) as [o|] eqn:Hpre;
        [ cbn [bind] in Hloop | cbn [bind] in Hloop; discriminate ].
      destruct o as [pre|]; [| discriminate ].
      destruct (inst.(ChainHmac_t_hmac_chain) h c pre) as [c1|] eqn:Hh;
        [ cbn [bind] in Hloop | cbn [bind] in Hloop; discriminate ].
      destruct (u32_add i 1%u32) as [i1|] eqn:Hi1;
        [ cbn [bind] in Hloop | cbn [bind] in Hloop; discriminate ].
      apply u32_add1_val in Hi1.
      destruct (IH HS inst h blob num_blocks c1 i1 r Hloop)
        as [ms [Htr [Hlen Hidx]]].
      exists (pre :: ms). repeat apply conj.
      * apply (CT_cons (seam_of inst h) c pre c1 ms r); [ exact Hh | exact Htr ].
      * cbn [length]. rewrite Nat2Z.inj_succ, Hlen. lia.
      * intros k p Hk. destruct k as [| k'].
        { cbn in Hk. injection Hk as Hk. subst p.
          exists i. split; [ lia | exact Hpre ]. }
        { cbn in Hk. destruct (Hidx k' p Hk) as [blk [Hb Hbp]].
          exists blk. split; [ rewrite Nat2Z.inj_succ; lia | exact Hbp ]. }
    + apply sltb_false in Hlt. injection Hloop as Hloop. subst r.
      exists []. repeat apply conj.
      * apply CT_nil.
      * cbn [length]. lia.
      * intros k p Hk. destruct k; cbn in Hk; discriminate.
Qed.

(** The same, for the entry point: `chain_root` folds blocks `0 .. num_blocks-1`. *)
Lemma chain_root_trace :
  forall {HS : Type} (inst : ChainHmac_t HS) (h : HS)
         (master : ckey) (blob : slice u8) (num_blocks : u32) (r : ckey),
    chain_root inst h master blob num_blocks = Ok (Some r) ->
    exists ms : list cmsg,
      ChainTrace (seam_of inst h) master ms r
      /\ Z.of_nat (length ms) = Z.max 0 (to_Z num_blocks)
      /\ (forall k pre, nth_error ms k = Some pre ->
            exists blk : u32,
              to_Z blk = Z.of_nat k
              /\ block_preimage blob blk = Ok (Some pre)).
Proof.
  intros HS inst h master blob num_blocks r H.
  unfold chain_root, chain_root_loop, loop in H.
  destruct (chain_root_loop_trace _ inst h blob num_blocks master 0%u32 r H)
    as [ms [Htr [Hlen Hidx]]].
  exists ms. repeat apply conj.
  - exact Htr.
  - rewrite Hlen. replace (to_Z 0%u32) with 0 by reflexivity.
    f_equal. lia.
  - intros k p Hk. destruct (Hidx k p Hk) as [blk [Hb Hbp]].
    exists blk. split;
      [ rewrite Hb; replace (to_Z 0%u32) with 0 by reflexivity; lia
      | exact Hbp ].
Qed.
