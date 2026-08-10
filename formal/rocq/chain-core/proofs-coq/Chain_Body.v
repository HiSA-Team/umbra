(** THE TARGET THEOREM — the blob body is authenticated by the chain.

    `formal/rocq/crypto/Umbra_Canonical.blob_body_is_not_covered_by_pkg_tag`
    (Qed) exhibits two packages that the update package tag CANNOT tell apart
    while their blob bodies differ. That is boundary B1: the tag authenticates a
    76-byte core (pkg-tag v2) — nonce, author_id, version, blob_len and the full
    48-byte UMBR header `blob[0,48)` (which includes `header.hmac` at
    `blob[16,48)`) — and nothing of the blob BODY.

    [chain_accept_pins_the_blob_body] closes the body half of it. If two blobs
    with the same block count both pass the chained-measurement gate under one
    master key, and they agree on the 32 bytes at `blob[16,48)` — the chain root,
    a sub-window of what `Update_Crypto.accept_implies_authenticated_fields` (P2)
    pins into the tag preimage — then either they agree on EVERY byte of the
    folded region `blob[48, 48+288·n)`, or the HMAC seam collided and the
    colliding pair of inputs is produced.

    WHAT IS AND IS NOT ASSUMED. There is no assumption on the seam: not
    injectivity (unsatisfiable — see Chain_Trace), not collision resistance, not
    unforgeability, not even determinism. The infeasibility of exhibiting the
    collision is a computational claim that lives outside Coq, and is not
    smuggled in here as a hypothesis. The proof is over the VERBATIM
    Aeneas-extracted body of `umbra-chain-core`.

    THE RESIDUAL, STATED EXACTLY. The theorem takes the two block counts as
    equal. They are NOT forced to be equal by anything proved elsewhere:
    `blob_block_count` reads `blob[0,4)` (magic) and `blob[10,14)` (`code_size`),
    both of which lie in `blob[0,16)` — outside the tag's authenticated core AND
    outside every chain preimage. `Chain_Value.blob_block_count_cong` says what
    would force it (equal length plus those eight bytes), and `Chain_Residual.v`
    exhibits the bytes that remain uncovered even so. *)

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
Require Import Chain_Trace.
Local Open Scope Z_scope.
Local Open Scope Primitives_scope.

(** A collision of the seam **inside the two runs the adversary caused**: two
    distinct (chain state, preimage) pairs, each one a step the device actually
    takes while measuring the corresponding blob, carried to the same 32-byte
    value.

    WHY THE PINNING IS ESSENTIAL, AND NOT DECORATION. A disjunct saying merely
    "there exist two distinct inputs with the same tag" is TRUE of any
    fixed-output function by pigeonhole — 292-byte messages outnumber 32-byte
    tags — so `bodies agree \/ some collision exists` would be equivalent to
    `True` for every concrete seam, and the theorem would carry no security
    content at all. That is the `hmac_injective` defect in mirror image: there,
    a false hypothesis; here, a trivial conclusion.

    The two `StepIn` clauses and the two preimage clauses close it. They say the
    colliding pair consists of states reached while folding THESE blobs, with
    THESE block preimages, from THIS master key. An unrelated pigeonhole
    collision does not discharge them; producing one that does is exactly the
    work an attacker must do.

    The claim that this work is infeasible is computational, and stays outside
    the statement. *)
Definition SeamCollisionInRuns {HS : Type} (inst : ChainHmac_t HS) (h : HS)
  (master : ckey) (blob1 blob2 : slice u8) : Prop :=
  exists (ms1 ms2 : list cmsg)
         (a1 : ckey) (b1 : cmsg) (a2 : ckey) (b2 : cmsg) (v : ckey),
    (* ms1 / ms2 are the block preimages of the two blobs, in fold order *)
    (forall k pre, nth_error ms1 k = Some pre ->
       exists blk : u32, to_Z blk = Z.of_nat k
                      /\ block_preimage blob1 blk = Ok (Some pre))
    /\ (forall k pre, nth_error ms2 k = Some pre ->
       exists blk : u32, to_Z blk = Z.of_nat k
                      /\ block_preimage blob2 blk = Ok (Some pre))
    (* the colliding inputs are steps of those very folds *)
    /\ StepIn (seam_of inst h) master ms1 a1 b1
    /\ StepIn (seam_of inst h) master ms2 a2 b2
    /\ (a1, b1) <> (a2, b2)
    /\ seam_of inst h a1 b1 = Ok v
    /\ seam_of inst h a2 b2 = Ok v.

(* ===================================================================== *)
(* Acceptance, unfolded over the extracted body.                          *)
(* ===================================================================== *)

Lemma verify_blob_chain_inv :
  forall {HS : Type} (inst : ChainHmac_t HS) (h : HS)
         (master : ckey) (blob : slice u8) (n : u32),
    blob_block_count blob = Ok (Some n) ->
    verify_blob_chain inst h master blob = Ok true ->
    exists r : ckey,
      chain_root inst h master blob n = Ok (Some r)
      /\ ct_eq32_at r blob hDR_HMAC_OFF = Ok true.
Proof.
  intros HS inst h master blob n Hn Hv.
  unfold verify_blob_chain in Hv. rewrite Hn in Hv. cbn [bind] in Hv.
  destruct (chain_root inst h master blob n) as [o|] eqn:Hc;
    [ cbn [bind] in Hv | cbn [bind] in Hv; discriminate ].
  destruct o as [r|]; [| discriminate ].
  exists r. split; [ reflexivity | exact Hv ].
Qed.

(** The gate's reference value is the blob's own `header.hmac` window, so two
    accepted runs over blobs that AGREE on that window end at the same root.
    This is where Q21 (`array_u8_ext`) is used, and the only place: the gate is a
    comparison, so on its own it yields byte VALUES, and the trace argument needs
    the root as a term. *)
Lemma accepted_roots_agree :
  forall (r1 r2 : ckey) (blob1 blob2 : slice u8),
    ct_eq32_at r1 blob1 hDR_HMAC_OFF = Ok true ->
    ct_eq32_at r2 blob2 hDR_HMAC_OFF = Ok true ->
    (forall q : usize, 16 <= to_Z q < 48 ->
       slice_index_usize blob1 q = slice_index_usize blob2 q) ->
    r1 = r2.
Proof.
  intros r1 r2 blob1 blob2 H1 H2 Hhdr. pose proof cu32max_big as Hbig.
  apply (array_u8_ext 32%usize). intros p Hp. rewrite ctz32 in Hp.
  destruct (cexists_usize (16 + to_Z p) ltac:(lia)) as [q Hq].
  destruct (ct_eq32_at_sound r1 blob1 hDR_HMAC_OFF H1 p q ltac:(lia)
              ltac:(rewrite c_hmoff; lia)) as [x1 [y1 [Hx1 [Hy1 Hv1]]]].
  destruct (ct_eq32_at_sound r2 blob2 hDR_HMAC_OFF H2 p q ltac:(lia)
              ltac:(rewrite c_hmoff; lia)) as [x2 [y2 [Hx2 [Hy2 Hv2]]]].
  exists x1, x2. repeat split; [ exact Hx1 | exact Hx2 |].
  rewrite (Hhdr q ltac:(lia)) in Hy1. rewrite Hy1 in Hy2.
  injection Hy2 as Hy2. subst y2. lia.
Qed.

(* ===================================================================== *)
(* THE TARGET THEOREM.                                                    *)
(* ===================================================================== *)

Theorem chain_accept_pins_the_blob_body :
  forall {HS : Type} (inst : ChainHmac_t HS) (h : HS)
         (master : ckey) (blob1 blob2 : slice u8) (n : u32),
    (* both blobs are accepted by the chained-measurement gate, same master key *)
    verify_blob_chain inst h master blob1 = Ok true ->
    verify_blob_chain inst h master blob2 = Ok true ->
    (* … with the same block count … *)
    blob_block_count blob1 = Ok (Some n) ->
    blob_block_count blob2 = Ok (Some n) ->
    (* … and agreeing on the 32-byte `header.hmac` window blob[16,48) — the
       window P2 proves the package tag authenticates. *)
    (forall q : usize, 16 <= to_Z q < 48 ->
       slice_index_usize blob1 q = slice_index_usize blob2 q) ->
    (* THEN either they agree on EVERY byte of the folded region … *)
    (forall k : usize, 48 <= to_Z k < 48 + 288 * to_Z n ->
       slice_index_usize blob1 k = slice_index_usize blob2 k)
    (* … or the seam collided, and the colliding pair is exhibited. *)
    \/ SeamCollisionInRuns inst h master blob1 blob2.
Proof.
  intros HS inst h master blob1 blob2 n Hv1 Hv2 Hn1 Hn2 Hhdr.
  pose proof cu32max_big as Hbig. pose proof (to_Z_u32_bounds n) as Hnb.
  destruct (verify_blob_chain_inv inst h master blob1 n Hn1 Hv1) as [r1 [Hc1 Hg1]].
  destruct (verify_blob_chain_inv inst h master blob2 n Hn2 Hv2) as [r2 [Hc2 Hg2]].
  (* the two accepted runs end at the same root *)
  assert (Hr : r1 = r2)
    by exact (accepted_roots_agree r1 r2 blob1 blob2 Hg1 Hg2 Hhdr).
  subst r2.
  (* each run IS a trace of seam applications over the blocks' preimages *)
  destruct (chain_root_trace inst h master blob1 n r1 Hc1) as [ms1 [T1 [L1 I1]]].
  destruct (chain_root_trace inst h master blob2 n r1 Hc2) as [ms2 [T2 [L2 I2]]].
  assert (Hlen : length ms1 = length ms2) by (apply Nat2Z.inj; lia).
  destruct (chain_trace_collision (seam_of inst h) ms1 ms2 master master r1
              T1 T2 Hlen) as [Heq | Hcoll].
  2:{ right. destruct Hcoll as [a1 [b1 [a2 [b2 [v [Hne [Hf1 [Hf2 [Hs1 Hs2]]]]]]]]].
      exists ms1, ms2, a1, b1, a2, b2, v. repeat split;
        [ exact I1 | exact I2 | exact Hs1 | exact Hs2
        | exact Hne | exact Hf1 | exact Hf2 ]. }
  injection Heq as Hms. subst ms2.
  (* the two traces coincide, so block by block the preimages coincide, and by
     coverage the blobs coincide on every byte of every block *)
  left. intros k Hk.
  set (kk := Z.to_nat ((to_Z k - 48) / 288)).
  assert (Hkk : 0 <= Z.of_nat kk < to_Z n).
  { unfold kk. rewrite Z2Nat.id by (apply Z.div_pos; lia).
    split; [ apply Z.div_pos; lia |].
    apply Z.div_lt_upper_bound; lia. }
  assert (Hlt : (kk < length ms1)%nat) by (apply Nat2Z.inj_lt; lia).
  destruct (nth_error ms1 kk) as [pre|] eqn:Hpre;
    [| exfalso; apply nth_error_None in Hpre; lia ].
  destruct (I1 kk pre Hpre) as [b1 [Hb1 Hp1]].
  destruct (I2 kk pre Hpre) as [b2 [Hb2 Hp2]].
  (* the folded region of block kk contains k *)
  assert (Hdiv : 288 * Z.of_nat kk <= to_Z k - 48 < 288 * Z.of_nat kk + 288).
  { unfold kk. rewrite Z2Nat.id by (apply Z.div_pos; lia).
    pose proof (Z.mul_div_le (to_Z k - 48) 288 ltac:(lia)) as Hle.
    pose proof (Z.mod_pos_bound (to_Z k - 48) 288 ltac:(lia)) as Hmod.
    rewrite (Z.div_mod (to_Z k - 48) 288) at 2 3 by lia. lia. }
  apply (preimage_pins_block blob1 blob2 b1 b2 pre pre Hp1 Hp2 ltac:(lia));
    [ intros j Hj; reflexivity | lia ].
Qed.
