(** NON-VACUITY — acceptance is reachable, and reachable exactly when the
    measurement matches.

    `Chain_Body.chain_accept_pins_the_blob_body` is an implication whose
    hypotheses include `verify_blob_chain … = Ok true`. A reader is entitled to
    ask whether anything satisfies that. If the extracted gate could never return
    `Ok true` — under the quarantine, `slice_index_usize` and friends are opaque
    axioms with no defining equations, so this is not obvious — the theorem would
    be empty, and this development has been burned by exactly that shape before
    (`Rot_Chain.hmac_injective`, unsatisfiable; the `mk_array` axiom, which proves
    `False`).

    [chain_gate_accepts_a_matching_measurement] settles it in the direction that
    matters: whenever the chain reaches a root whose bytes are the blob's
    `header.hmac` window, the gate DOES accept. So the accept set is exactly the
    set of blobs whose measurement matches — no larger, by
    `Chain_Value.ct_eq32_at_sound`, and no smaller, by this file.

    WHAT THIS DOES NOT DO. It does not exhibit a concrete accepted blob. It
    cannot: the extracted body calls the backend's opaque readers, and the
    quarantine has no law letting one CONSTRUCT a slice with prescribed bytes.
    What it establishes is that the gate's `true` branch is not dead code — the
    only remaining way for the hypothesis to be unsatisfiable would be for the
    chain never to reach a matching root, which is a statement about the seam,
    and the seam is universally quantified in the theorem. Instantiate it at the
    honest signer and the hypothesis is met by construction; that is what
    `tools/protect_enclave.py` computes offline and stamps into `header.hmac`. *)

Require Import Primitives.
Import Primitives.
Require Import AeneasLoopShim.
Import AeneasLoopShim.
Require Import Coq.ZArith.ZArith.
Require Import Coq.Bool.Bool.
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
Require Import Chain_Trace.
Local Open Scope Z_scope.
Local Open Scope Primitives_scope.

Lemma cor_xor_zero_intro : forall (d x y : u8),
  to_Z d = 0 -> to_Z x = to_Z y -> to_Z (u8_or d (u8_xor x y)) = 0.
Proof.
  intros d x y Hd Hxy. rewrite u8_or_to_Z, u8_xor_to_Z, Hd, Hxy.
  rewrite Z.lxor_nilpotent. reflexivity.
Qed.

Lemma cu8_eqb_zero_intro : forall d : u8, to_Z d = 0 -> (d s= 0%u8) = true.
Proof.
  intros d H. unfold scalar_eqb. apply Z.eqb_eq. rewrite ctz0u8. exact H.
Qed.

(** The compare loop run forwards: equal bytes keep the accumulator at zero. *)
Lemma ct_eq32_at_loop_complete :
  forall (fuel : nat) (a : array u8 32%usize) (blob : slice u8) (off : usize)
         (d : u8) (i : usize),
    to_Z off + 32 <= to_Z (slice_len blob) ->
    to_Z off + 32 <= u32_max ->
    0 <= to_Z i <= 32 -> (Z.to_nat (32 - to_Z i) < fuel)%nat ->
    to_Z d = 0 ->
    (forall p q : usize, to_Z i <= to_Z p < 32 -> to_Z q = to_Z off + to_Z p ->
       forall x y, array_index_usize a p = Ok x -> slice_index_usize blob q = Ok y ->
         to_Z x = to_Z y) ->
    exists dfin,
      loop_fuel fuel (fun '(d1, i1) => ct_eq32_at_loop_body a blob off d1 i1) (d, i)
        = Ok dfin
      /\ to_Z dfin = 0.
Proof.
  induction fuel as [| n IH];
    intros a blob off d i Hlen Hoff Hi Hfuel Hd Heq;
    pose proof (to_Z_usize_bounds off) as Hoffb.
  - simpl in Hfuel. lia.
  - rewrite loop_step. cbn beta iota. unfold ct_eq32_at_loop_body.
    destruct (Z_lt_le_dec (to_Z i) 32) as [Hlt | Hge].
    + assert (Hc : (i s< 32%usize) = true) by (apply Z.ltb_lt; rewrite ctz32; lia).
      rewrite Hc.
      destruct (array_index_usize_ok a i) as [x1 Hx1]; [ rewrite ctz32; lia |].
      rewrite Hx1. cbn [bind].
      destruct (usize_add_ok off i) as [q0 [Hq0 Hq0v]]; [ lia |].
      rewrite Hq0. cbn [bind].
      destruct (slice_index_usize_ok blob q0) as [y1 Hy1]; [ lia |].
      rewrite Hy1. cbn [bind].
      destruct (usize_add_ok i 1%usize) as [i2 [Hi2 Hi2v]].
      { rewrite tz1. pose proof cu32max_big. lia. }
      rewrite tz1 in Hi2v. rewrite Hi2. cbn [bind].
      apply IH.
      * exact Hlen.
      * exact Hoff.
      * lia.
      * assert (Hlt2 : (Z.to_nat (32 - to_Z i2) < Z.to_nat (32 - to_Z i))%nat)
          by (apply Z2Nat.inj_lt; lia).
        lia.
      * apply (cor_xor_zero_intro d x1 y1 Hd).
        exact (Heq i q0 ltac:(lia) ltac:(lia) x1 y1 Hx1 Hy1).
      * intros p q Hp Hq. apply Heq; lia.
    + assert (Hc : (i s< 32%usize) = false) by (apply Z.ltb_ge; rewrite ctz32; lia).
      rewrite Hc. exists d. split; [ reflexivity | exact Hd ].
Qed.

(** COMPLETENESS OF THE ACCEPT GATE. The converse of
    `Chain_Value.ct_eq32_at_sound`: matching bytes are accepted. *)
Lemma ct_eq32_at_complete :
  forall (a : array u8 32%usize) (blob : slice u8) (off : usize),
    to_Z off + 32 <= to_Z (slice_len blob) ->
    to_Z off + 32 <= u32_max ->
    (forall p q : usize, 0 <= to_Z p < 32 -> to_Z q = to_Z off + to_Z p ->
       forall x y, array_index_usize a p = Ok x -> slice_index_usize blob q = Ok y ->
         to_Z x = to_Z y) ->
    ct_eq32_at a blob off = Ok true.
Proof.
  intros a blob off Hlen Hoff Heq. unfold ct_eq32_at.
  destruct (usize_add_ok off 32%usize) as [e [He Hev]]; [ rewrite ctz32; lia |].
  rewrite He. cbn [bind]. rewrite ctz32 in Hev.
  assert (Hc : (slice_len blob s< e) = false) by (apply Z.ltb_ge; lia).
  rewrite Hc. unfold ct_eq32_at_loop, loop.
  destruct (ct_eq32_at_loop_complete 1000000 a blob off 0%u8 0%usize Hlen Hoff)
    as [dfin [Hl Hz]].
  - rewrite ctz0. lia.
  - rewrite ctz0. apply Nat.ltb_lt. vm_compute. reflexivity.
  - exact ctz0u8.
  - intros p q Hp Hq. apply Heq. rewrite ctz0 in Hp. lia. exact Hq.
  - rewrite Hl. cbn [bind]. rewrite (cu8_eqb_zero_intro dfin Hz). reflexivity.
Qed.

(* ===================================================================== *)
(* THE GATE'S `true` BRANCH IS NOT DEAD CODE.                             *)
(* ===================================================================== *)

(** If the header parses to `n` blocks, the chain folds them to a root `r`, and
    `r`'s bytes ARE the blob's `header.hmac` window, then the gate accepts.

    Together with `Chain_Value.ct_eq32_at_sound` (the other direction) this says
    the accept set is EXACTLY the set of blobs whose recomputed measurement
    matches the stamped one — so the hypothesis of the target theorem is met by
    every honestly-signed blob, which is what `tools/protect_enclave.py` produces
    by computing the same chain offline. *)
Theorem chain_gate_accepts_a_matching_measurement :
  forall {HS : Type} (inst : ChainHmac_t HS) (h : HS)
         (master : ckey) (blob : slice u8) (n : u32) (r : ckey),
    blob_block_count blob = Ok (Some n) ->
    chain_root inst h master blob n = Ok (Some r) ->
    48 <= to_Z (slice_len blob) ->
    to_Z (slice_len blob) <= u32_max ->
    (forall p q : usize, 0 <= to_Z p < 32 -> to_Z q = 16 + to_Z p ->
       forall x y, array_index_usize r p = Ok x -> slice_index_usize blob q = Ok y ->
         to_Z x = to_Z y) ->
    verify_blob_chain inst h master blob = Ok true.
Proof.
  intros HS inst h master blob n r Hn Hc Hlen Hmax Heq.
  unfold verify_blob_chain. rewrite Hn. cbn [bind]. rewrite Hc. cbn [bind].
  apply ct_eq32_at_complete; rewrite c_hmoff; try lia.
  intros p q Hp Hq. apply Heq; lia.
Qed.
