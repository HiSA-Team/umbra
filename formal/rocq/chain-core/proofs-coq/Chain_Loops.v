(** Chain_Loops.v — ADEQUACY of the fuel shim for this crate's two loops.

    Mirrors update-core's Update_Loops.v: the shared library's
    `AeneasLoopModel.loop_model_bound` is instantiated for the extracted
    `ct_eq32_at_loop` and `chain_root_loop`, so that the fuel-free ITree model
    of each loop returns exactly what the extracted (fuel-shimmed) loop returns.

    `ct_eq32_at_loop` needs nothing: its body is a straight line of slice
    primitives (they fail only with `Failure`) and strictly decreases `32 - i`.

    `chain_root_loop` is different in one respect, stated as an explicit
    HYPOTHESIS rather than hidden: its body calls the abstract HMAC seam
    `inst.(ChainHmac_t_hmac_chain)`, a parameter of the whole development
    about which nothing is known — in particular whether it can answer
    `Fail_ OutOfFuel`. So the instance below takes, ON THE SEAM,

        forall h chain pre, inst.(ChainHmac_t_hmac_chain) h chain pre <> Fail_ OutOfFuel

    and derives the body-level premise from it (the other call in the body,
    `block_preimage`, is proved never to exhaust fuel). It also needs the loop
    to be started within the gate's own block cap (`num_blocks <= MAX_BLOCKS`),
    because a `u32` block count can exceed the shim's fuel while the model,
    being fuel-free, still terminates; `verify_blob_chain` only ever starts it
    that way (`blob_block_count` rejects larger counts).

    This file requires ITree; NOTHING in the crypto tier or elsewhere in this
    project requires this file (it is a leaf, checked by the fast gate). *)

Require Import Primitives.
Import Primitives.
Require Import AeneasLoopShim.
Import AeneasLoopShim.
Require Import Coq.ZArith.ZArith.
Require Import Coq.Bool.Sumbool.
Require Import Lia.
Require Import Update_Safety.
Require Import Chain_Types.
Import Chain_Types.
Require Import Chain_FunsExternal.
Import Chain_FunsExternal.
Require Import Chain_Funs.
Import Chain_Funs.
Require Import Chain_Value.
Require Import AeneasLoopModel.
From ITree Require Import ITree ITreeFacts.
Import ITreeNotations.
Local Open Scope Z_scope.
Local Open Scope Primitives_scope.
Local Open Scope itree_scope.

(* ===================================================================== *)
(* ct_eq32_at_loop                                                        *)
(* ===================================================================== *)

Definition ct_eq32_at_measure (s : u8 * usize) : nat := Z.to_nat (32 - to_Z (snd s)).

Theorem ct_eq32_at_loop_adequate :
  forall (a : array u8 32%usize) (blob : slice u8) (off : usize) (d : u8) (i : usize),
    loop_model (fun '(d1, i1) => ct_eq32_at_loop_body a blob off d1 i1) (d, i)
    ≈ Ret (ct_eq32_at_loop a blob off d i).
Proof.
  intros a blob off d i. rewrite ct_eq32_at_loop_bounded.
  exact (loop_model_bound _ ct_eq32_at_measure (d, i)
           (ct_eq32_at_body_no_oof a blob off) (ct_eq32_at_body_dec a blob off)).
Qed.

(* ===================================================================== *)
(* chain_root_loop                                                        *)
(* ===================================================================== *)

(* --- the remaining primitives `block_preimage` calls fail only with Failure *)

Lemma scalar_cast_not_oof : forall src tgt (x : scalar src),
  scalar_cast src tgt x <> Fail_ OutOfFuel.
Proof. intros. unfold scalar_cast. discriminate. Qed.

Lemma usize_mul_not_oof : forall a b : usize, usize_mul a b <> Fail_ OutOfFuel.
Proof. intros. unfold usize_mul, scalar_mul. apply mk_scalar_not_oof. Qed.

Lemma u32_add_not_oof : forall a b : u32, u32_add a b <> Fail_ OutOfFuel.
Proof. intros. unfold u32_add, scalar_add. apply mk_scalar_not_oof. Qed.

Lemma slice_range_get_not_oof : forall {T} (r : core_ops_range_Range usize) (s : slice T),
  slice_range_get r s <> Fail_ OutOfFuel.
Proof.
  intros T r s. unfold slice_range_get. cbv zeta.
  destruct (Z_le_dec _ _); [ destruct (Z_le_dec _ _) |]; discriminate.
Qed.

Lemma slice_index_range_not_oof : forall {T} (s : slice T) (r : core_ops_range_Range usize),
  core_slice_index_Slice_index (core_slice_index_SliceIndexRangeUsizeSliceInst T) s r
  <> Fail_ OutOfFuel.
Proof.
  intros T s r. unfold core_slice_index_Slice_index.
  cbn [core_slice_index_SliceIndex_get core_slice_index_SliceIndexRangeUsizeSliceInst].
  unfold core_slice_index_SliceIndexRangeUsizeSlice_get.
  apply bind_not_oof; [ apply slice_range_get_not_oof | intros [x|]; discriminate ].
Qed.

Lemma array_index_mut_range_not_oof :
  forall {T} {N} (arr : array T N) (r : core_ops_range_Range usize),
  core_array_Array_index_mut
    (core_ops_index_IndexMutSliceInst (core_slice_index_SliceIndexRangeUsizeSliceInst T)) arr r
  <> Fail_ OutOfFuel.
Proof.
  intros T N arr r. unfold core_array_Array_index_mut.
  cbn [core_ops_index_IndexMut_index_mut core_ops_index_IndexMutSliceInst].
  unfold core_slice_index_Slice_index_mut.
  cbn [core_slice_index_SliceIndex_index_mut core_slice_index_SliceIndexRangeUsizeSliceInst].
  unfold core_slice_index_SliceIndexRangeUsizeSlice_index_mut, slice_range_index_mut,
    slice_range_index, slice_range_get. cbv zeta.
  destruct (Z_le_dec _ _); [ destruct (Z_le_dec _ _) |]; discriminate.
Qed.

Lemma copy_from_slice_not_oof : forall {T} (m : core_marker_Copy T) (dst src : slice T),
  Aeneas_Laws.core_slice_Slice_copy_from_slice m dst src <> Fail_ OutOfFuel.
Proof.
  intros T m dst src. unfold Aeneas_Laws.core_slice_Slice_copy_from_slice.
  destruct (Z.eqb (to_Z (slice_len dst)) (to_Z (slice_len src))); discriminate.
Qed.

(* The chain model's seams are aliases of the library's (Chain_FunsExternal),
   so the same fact holds under the aliased name the extracted body uses. *)
Lemma chain_copy_from_slice_not_oof : forall {T} (m : core_marker_Copy T) (dst src : slice T),
  Chain_Funs.core_slice_Slice_copy_from_slice m dst src <> Fail_ OutOfFuel.
Proof.
  intros T m dst src. unfold Chain_Funs.core_slice_Slice_copy_from_slice.
  apply copy_from_slice_not_oof.
Qed.

Lemma block_preimage_of_block_not_oof : forall (blk : u32) (block : array u8 288%usize),
  block_preimage_of_block blk block <> Fail_ OutOfFuel.
Proof.
  intros blk block. unfold block_preimage_of_block. cbv zeta.
  apply bind_not_oof; [ apply array_index_mut_range_not_oof | intros [s back] ].
  cbv beta iota. cbv zeta.
  apply bind_not_oof; [ apply chain_copy_from_slice_not_oof | intro s2 ].
  cbv zeta.
  apply bind_not_oof; [ apply array_index_mut_range_not_oof | intros [s3 back1] ].
  cbv beta iota.
  apply bind_not_oof; [ apply slice_index_range_not_oof | intro s4 ].
  apply bind_not_oof; [ apply chain_copy_from_slice_not_oof | intro s5 ].
  cbv zeta.
  apply bind_not_oof; [ apply array_index_mut_range_not_oof | intros [s6 back2] ].
  cbv beta iota.
  apply bind_not_oof; [ apply slice_index_range_not_oof | intro s7 ].
  apply bind_not_oof; [ apply chain_copy_from_slice_not_oof | intro s8; discriminate ].
Qed.

Lemma block_preimage_not_oof : forall (blob : slice u8) (blk : u32),
  block_preimage blob blk <> Fail_ OutOfFuel.
Proof.
  intros blob blk. unfold block_preimage.
  destruct (blk s>= mAX_BLOCKS); [ discriminate |].
  apply bind_not_oof; [ apply scalar_cast_not_oof | intro i ].
  apply bind_not_oof; [ apply usize_mul_not_oof | intro i1 ].
  apply bind_not_oof; [ apply usize_add_not_oof | intro base ].
  cbv zeta.
  apply bind_not_oof; [ apply usize_add_not_oof | intro i3 ].
  destruct (slice_len blob s< i3); [ discriminate |].
  cbv zeta.
  apply bind_not_oof; [ apply array_index_mut_range_not_oof | intros [s back] ].
  cbv beta iota.
  apply bind_not_oof; [ apply slice_index_range_not_oof | intro s1 ].
  apply bind_not_oof; [ apply chain_copy_from_slice_not_oof | intro s2 ].
  cbv zeta.
  apply bind_not_oof; [ apply block_preimage_of_block_not_oof | intro a; discriminate ].
Qed.

(* --- the loop body, under the seam hypothesis ---------------------------- *)

Definition chain_root_measure (num_blocks : u32) (s : array u8 32%usize * u32) : nat :=
  Z.to_nat (to_Z num_blocks - to_Z (snd s)).

Lemma ctz1u32 : to_Z (1%u32) = 1. Proof. reflexivity. Qed.

Lemma chain_root_body_no_oof :
  forall {HS : Type} (inst : ChainHmac_t HS) (h : HS) (blob : slice u8) (num_blocks : u32),
    (forall chain pre, inst.(ChainHmac_t_hmac_chain) h chain pre <> Fail_ OutOfFuel) ->
    forall s : array u8 32%usize * u32,
      (fun '(chain1, i1) => chain_root_loop_body inst h blob num_blocks chain1 i1) s
      <> Fail_ OutOfFuel.
Proof.
  intros HS inst h blob n Hseam [chain i]. cbn beta iota. unfold chain_root_loop_body.
  destruct (i s< n); [| discriminate ].
  apply bind_not_oof; [ apply block_preimage_not_oof | intros [pre|]; [| discriminate ] ].
  apply bind_not_oof; [ apply Hseam | intro chain1 ].
  apply bind_not_oof; [ apply u32_add_not_oof | intro i1; discriminate ].
Qed.

Lemma chain_root_body_dec :
  forall {HS : Type} (inst : ChainHmac_t HS) (h : HS) (blob : slice u8) (num_blocks : u32)
         (s s' : array u8 32%usize * u32),
    (fun '(chain1, i1) => chain_root_loop_body inst h blob num_blocks chain1 i1) s
    = Ok (Cont s') ->
    (chain_root_measure num_blocks s' < chain_root_measure num_blocks s)%nat.
Proof.
  intros HS inst h blob n [chain i] [chain' i'] H. cbn beta iota in H.
  unfold chain_root_loop_body in H.
  destruct (i s< n) eqn:Hlt; [| discriminate ].
  apply sltb_true in Hlt.
  destruct (block_preimage blob i) as [o|]; cbn [Primitives.bind] in H; [| discriminate ].
  destruct o as [pre|]; cbn beta iota in H; [| discriminate ].
  destruct (inst.(ChainHmac_t_hmac_chain) h chain pre) as [chain1|];
    cbn [Primitives.bind] in H; [| discriminate ].
  destruct (u32_add i 1%u32) as [i1|] eqn:Ei; cbn [Primitives.bind] in H; [| discriminate ].
  injection H as _ <-.
  unfold u32_add, scalar_add in Ei. apply mk_scalar_to_Z in Ei. rewrite ctz1u32 in Ei.
  unfold chain_root_measure. cbn [snd].
  pose proof (to_Z_u32_bounds i). lia.
Qed.

(* The shim's `loop` on the chain body IS the run with fuel `S (n - i)`, once
   the count is within the gate's cap (so that fuel fits under the shim's). *)
Lemma chain_root_loop_bounded :
  forall {HS : Type} (inst : ChainHmac_t HS) (h : HS) (blob : slice u8) (num_blocks : u32)
         (chain : array u8 32%usize) (i : u32),
    (forall chain pre, inst.(ChainHmac_t_hmac_chain) h chain pre <> Fail_ OutOfFuel) ->
    to_Z num_blocks <= to_Z mAX_BLOCKS ->
    chain_root_loop inst h blob num_blocks chain i
    = loop_fuel (Datatypes.S (chain_root_measure num_blocks (chain, i)))
        (fun '(chain1, i1) => chain_root_loop_body inst h blob num_blocks chain1 i1)
        (chain, i).
Proof.
  intros HS inst h blob n chain i Hseam Hcap. unfold chain_root_loop, loop.
  apply loop_fuel_stable with (n := Datatypes.S (chain_root_measure n (chain, i))).
  - reflexivity.
  - exact (loop_fuel_bound_S _ (chain_root_measure n) (chain, i)
            (chain_root_body_no_oof inst h blob n Hseam)
            (chain_root_body_dec inst h blob n)).
  - unfold chain_root_measure. cbn [snd]. rewrite c_maxb in Hcap.
    pose proof (to_Z_u32_bounds i).
    apply Nat.le_trans with (m := 65%nat);
      [ lia | apply Nat.leb_le; vm_compute; reflexivity ].
Qed.

(** The chain fold: under the seam hypothesis and within the block cap, the
    ITree model returns exactly what the extracted loop returns. *)
Theorem chain_root_loop_adequate :
  forall {HS : Type} (inst : ChainHmac_t HS) (h : HS) (blob : slice u8) (num_blocks : u32)
         (chain : array u8 32%usize) (i : u32),
    (forall chain pre, inst.(ChainHmac_t_hmac_chain) h chain pre <> Fail_ OutOfFuel) ->
    to_Z num_blocks <= to_Z mAX_BLOCKS ->
    loop_model (fun '(chain1, i1) => chain_root_loop_body inst h blob num_blocks chain1 i1)
               (chain, i)
    ≈ Ret (chain_root_loop inst h blob num_blocks chain i).
Proof.
  intros HS inst h blob n chain i Hseam Hcap.
  rewrite (chain_root_loop_bounded inst h blob n chain i Hseam Hcap).
  exact (loop_model_bound _ (chain_root_measure n) (chain, i)
           (chain_root_body_no_oof inst h blob n Hseam)
           (chain_root_body_dec inst h blob n)).
Qed.

(** Without the cap: the model still agrees with SOME fuel-bounded run — the
    one with fuel `S (n - i)` — from any state, under the seam hypothesis
    alone. This is the form `loop_model_bound` gives directly. *)
Theorem chain_root_loop_model_fuel :
  forall {HS : Type} (inst : ChainHmac_t HS) (h : HS) (blob : slice u8) (num_blocks : u32)
         (chain : array u8 32%usize) (i : u32),
    (forall chain pre, inst.(ChainHmac_t_hmac_chain) h chain pre <> Fail_ OutOfFuel) ->
    loop_model (fun '(chain1, i1) => chain_root_loop_body inst h blob num_blocks chain1 i1)
               (chain, i)
    ≈ Ret (loop_fuel (Datatypes.S (chain_root_measure num_blocks (chain, i)))
             (fun '(chain1, i1) => chain_root_loop_body inst h blob num_blocks chain1 i1)
             (chain, i)).
Proof.
  intros HS inst h blob n chain i Hseam.
  exact (loop_model_bound _ (chain_root_measure n) (chain, i)
           (chain_root_body_no_oof inst h blob n Hseam)
           (chain_root_body_dec inst h blob n)).
Qed.

(* ===================================================================== *)
(* MECHANISED ASSUMPTION AUDIT: closed under the global context.           *)
(* ===================================================================== *)
Print Assumptions ct_eq32_at_loop_adequate.
Print Assumptions chain_root_loop_adequate.
Print Assumptions chain_root_loop_model_fuel.
