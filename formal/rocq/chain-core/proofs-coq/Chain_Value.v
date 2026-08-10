(** VALUE LAYER over the VERBATIM Aeneas-extracted body of umbra-chain-core
    (Chain_Funs.v). Four results, none of them cryptographic:

      [preimage_windows]      what `block_preimage` puts where — the block index
                              at [0,4), the block's CODE half at [4,260) and its
                              META half at [260,292), each pinned byte-for-byte
                              to the blob offset it was read from.
      [preimage_pins_block]   the consequence: two blobs whose block-k preimages
                              agree agree on ALL 288 bytes of block k. This is
                              what turns "the chain touches the body" into a
                              theorem rather than a slogan.
      [ct_eq32_at_sound]      the accept gate is sound: `true` forces the 32
                              compared bytes equal.
      [blob_block_count_cong] the block count depends only on the eight header
                              bytes the extracted body reads.

    ASSUMPTION DISCIPLINE. Every opaque array/slice/copy operation used here is
    pinned by `Update_Safety`'s existing 20-axiom quarantine — the SAME block, not
    a second parallel one — and that block is discharged against a concrete list
    model in `Update_Model.v`. This file introduces no axiom of its own.

    NB the extracted `block_preimage` computes `base` from `blk` ALONE (a cast, a
    multiply and an add; the blob is not consulted), so two runs at the same index
    on different blobs necessarily produce the same `base`. That is why
    [preimage_pins_block] can compare two blobs without assuming anything about
    their lengths. *)

Require Import Primitives.
Import Primitives.
Require Import AeneasLoopShim.
Import AeneasLoopShim.
Require Import Coq.ZArith.ZArith.
Require Import Coq.Bool.Bool.
Require Import Coq.Bool.Sumbool.
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
Local Open Scope Z_scope.
Local Open Scope Primitives_scope.

(* ===================================================================== *)
(* Numerals and small scalar plumbing.                                   *)
(* ===================================================================== *)

Lemma ctz0   : to_Z (0%usize)   = 0.   Proof. reflexivity. Qed.
Lemma ctz1   : to_Z (1%usize)   = 1.   Proof. reflexivity. Qed.
Lemma ctz2   : to_Z (2%usize)   = 2.   Proof. reflexivity. Qed.
Lemma ctz3   : to_Z (3%usize)   = 3.   Proof. reflexivity. Qed.
Lemma ctz4   : to_Z (4%usize)   = 4.   Proof. reflexivity. Qed.
Lemma ctz32  : to_Z (32%usize)  = 32.  Proof. reflexivity. Qed.
Lemma ctz260 : to_Z (260%usize) = 260. Proof. reflexivity. Qed.
Lemma ctz292 : to_Z (292%usize) = 292. Proof. reflexivity. Qed.

Lemma c_hdr   : to_Z hDR_LEN     = 48.  Proof. reflexivity. Qed.
Lemma c_blk   : to_Z bLOCK_LEN   = 288. Proof. reflexivity. Qed.
Lemma c_meta  : to_Z mETA_LEN    = 32.  Proof. reflexivity. Qed.
Lemma c_maxb  : to_Z mAX_BLOCKS  = 64.  Proof. reflexivity. Qed.
Lemma c_hmoff : to_Z hDR_HMAC_OFF = 16. Proof. reflexivity. Qed.
Lemma c_csoff : to_Z cODE_SIZE_OFF = 10. Proof. reflexivity. Qed.

Lemma cu32max_big : 65536 <= u32_max.
Proof. unfold u32_max. lia. Qed.

(** Every value below `u32_max` is realised by some `usize`. *)
Lemma cexists_usize : forall z, 0 <= z <= u32_max -> exists j : usize, to_Z j = z.
Proof.
  intros z Hz. destruct (mk_usize_ok z Hz) as [s [_ Hs]]. exists s. exact Hs.
Qed.

(** The same without the `u32_max` ceiling: any value a `usize` can hold. Needed
    where the index is derived from a slice LENGTH, which is only bounded by
    `usize_max`. *)
Lemma cexists_usize_full : forall z, 0 <= z <= usize_max -> exists j : usize, to_Z j = z.
Proof.
  intros z Hz.
  assert (Hb : scalar_min Usize <= z <= scalar_max Usize)
    by (rewrite usize_min_eq, usize_max_eq; lia).
  exists (exist (fun x : Z => scalar_min Usize <= x <= scalar_max Usize) z Hb).
  reflexivity.
Qed.

(** Monadic inversion (as in Update_Value): keeps the equation about the
    sub-computation, which `destruct` alone would discard. *)
Lemma cbind_ok_inv : forall {A B} (m : result A) (f : A -> result B) (v : B),
  bind m f = Ok v -> exists a, m = Ok a /\ f a = Ok v.
Proof.
  intros A B m f v H. destruct m as [a|e]; cbn [bind] in H;
    [ exists a; split; [ reflexivity | exact H ] | discriminate ].
Qed.

Ltac cstep H a Ha :=
  let Hx := fresh in
  apply cbind_ok_inv in H; destruct H as [a [Ha Hx]]; clear H; rename Hx into H.

(* Boolean scalar comparisons -> arithmetic. *)
Lemma sgeb_false : forall {ty} (x y : scalar ty), (x s>= y) = false -> to_Z x < to_Z y.
Proof.
  intros ty x y H. unfold scalar_geb in H. rewrite Z.geb_leb in H.
  destruct (Z.leb_spec (to_Z y) (to_Z x)); [ discriminate | lia ].
Qed.

Lemma sltb_false : forall {ty} (x y : scalar ty), (x s< y) = false -> to_Z y <= to_Z x.
Proof.
  intros ty x y H. unfold scalar_ltb in H.
  destruct (Z.ltb_spec (to_Z x) (to_Z y)); [ discriminate | lia ].
Qed.

Lemma sltb_true : forall {ty} (x y : scalar ty), (x s< y) = true -> to_Z x < to_Z y.
Proof.
  intros ty x y H. unfold scalar_ltb in H.
  destruct (Z.ltb_spec (to_Z x) (to_Z y)); [ lia | discriminate ].
Qed.

Lemma seqb_true : forall {ty} (x y : scalar ty), (x s= y) = true -> to_Z x = to_Z y.
Proof.
  intros ty x y H. unfold scalar_eqb in H.
  destruct (Z.eqb_spec (to_Z x) (to_Z y)); [ lia | discriminate ].
Qed.

(* ===================================================================== *)
(* THE PREIMAGE WINDOWS, walked over the extracted body.                  *)
(* ===================================================================== *)

Ltac cstep_pair Ht Hm w b :=
  lazymatch type of Ht with
  | bind ?e _ = _ => destruct e as [[w b]|] eqn:Hm; cbn [bind] in Ht;
                     try discriminate Ht
  end.
Ltac cstep_copy Ht Hc c :=
  lazymatch type of Ht with
  | bind ?e _ = _ => destruct e as [c|] eqn:Hc; cbn [bind] in Ht;
                     try discriminate Ht
  end.

(* --------------------------------------------------------------------- *)
(* THE ASSEMBLY THE FIRMWARE CALLS.                                        *)
(*                                                                         *)
(* `block_preimage_of_block` is the function the N657 Secure kernel invokes *)
(* (`stm32n657/boot/src/api_impl.rs::fold_block_from_flash`), because the   *)
(* firmware materialises the 288-byte block out of the memory-mapped XSPI2  *)
(* window with `read_volatile` and has no blob slice to pass. This lemma is  *)
(* therefore the one that lands on shipping code; `preimage_windows` below   *)
(* is derived from it, so the blob-shaped statement the rest of this         *)
(* development consumes is a COROLLARY of the block-shaped one rather than   *)
(* a parallel claim about a cousin function.                                 *)
(* --------------------------------------------------------------------- *)

(** `block_preimage_of_block blk block = Ok pre` puts the little-endian block
    index at `pre[0,4)`, the block's CODE half `block[32,288)` at `pre[4,260)`
    and its META half `block[0,32)` at `pre[260,292)` — byte for byte. Total:
    there is no `None` branch, because the block already exists. *)
Lemma preimage_of_block_windows :
  forall (blk : u32) (block : array u8 288%usize) (pre : array u8 292%usize),
    block_preimage_of_block blk block = Ok pre ->
      (* [0,4) — the little-endian block index *)
      (forall i j : usize, 0 <= to_Z i < 4 -> to_Z j = to_Z i ->
          array_index_usize pre j
          = array_index_usize (core_num_U32_to_le_bytes blk) i)
      (* [4,260) — the CODE half, block[32 .. 288) *)
      /\ (forall i j k : usize, 0 <= to_Z i < 256 ->
            to_Z j = 4 + to_Z i -> to_Z k = 32 + to_Z i ->
            array_index_usize pre j = array_index_usize block k)
      (* [260,292) — the META half, block[0 .. 32) *)
      /\ (forall i j k : usize, 0 <= to_Z i < 32 ->
            to_Z j = 260 + to_Z i -> to_Z k = to_Z i ->
            array_index_usize pre j = array_index_usize block k).
Proof.
  intros blk block pre Ht. pose proof cu32max_big as Hbig.
  pose proof c_meta as Hm. pose proof c_blk as Hbk.
  unfold block_preimage_of_block in Ht. cbv zeta in Ht.
  cstep_pair Ht M0 w0 b0. cstep_copy Ht C0 c0.
  cstep_pair Ht M1 w1 b1.
  cstep_copy Ht S4 s4. cstep_copy Ht C1 c1.
  cstep_pair Ht M2 w2 b2.
  cstep_copy Ht S7 s7. cstep_copy Ht C2 c2.
  injection Ht as Ht.
  apply copy_from_slice_val in C0. apply copy_from_slice_val in C1.
  apply copy_from_slice_val in C2. subst c0 c1 c2.
  (* the three written slices have exactly the lengths their ranges ask for *)
  assert (HL0 : to_Z (slice_len (array_to_slice (core_num_U32_to_le_bytes blk)))
                = to_Z (4%usize) - to_Z (0%usize))
    by (rewrite slice_len_array_to_slice; rewrite ctz4, ctz0; reflexivity).
  assert (HL1 : to_Z (slice_len s4) = to_Z (260%usize) - to_Z (4%usize)).
  { rewrite (slice_index_range_len _ _ _ _ S4), ctz260, ctz4. lia. }
  assert (HL2 : to_Z (slice_len s7) = to_Z (292%usize) - to_Z (260%usize)).
  { rewrite (slice_index_range_len _ _ _ _ S7), ctz292, ctz260, ctz0. lia. }
  (* OUT: a later window's write-back leaves the earlier bytes alone *)
  assert (OUT2 : forall j : usize, to_Z j < 260 ->
     array_index_usize (b2 s7) j = array_index_usize (b1 s4) j).
  { intros j Hj. apply (array_index_mut_range_val_out _ _ _ _ _ _ _ M2 HL2).
    left. rewrite ctz260. exact Hj. }
  assert (OUT1 : forall j : usize, to_Z j < 4 ->
     array_index_usize (b1 s4) j
     = array_index_usize (b0 (array_to_slice (core_num_U32_to_le_bytes blk))) j).
  { intros j Hj. apply (array_index_mut_range_val_out _ _ _ _ _ _ _ M1 HL1).
    left. rewrite ctz4. exact Hj. }
  (* IN: each window reads back the slice that was copied into it *)
  assert (IN0 : forall ia js : usize, 0 <= to_Z ia -> to_Z ia < 4 ->
     to_Z js = to_Z ia ->
     array_index_usize (b0 (array_to_slice (core_num_U32_to_le_bytes blk))) ia
     = slice_index_usize (array_to_slice (core_num_U32_to_le_bytes blk)) js).
  { intros ia js H1 H2 H3.
    apply (array_index_mut_range_val_in _ _ _ _ _ _ _ _ M0 HL0);
      [ rewrite ctz0; lia | rewrite ctz4; lia | rewrite ctz0; lia ]. }
  assert (IN1 : forall ia js : usize, 4 <= to_Z ia -> to_Z ia < 260 ->
     to_Z js = to_Z ia - 4 ->
     array_index_usize (b1 s4) ia = slice_index_usize s4 js).
  { intros ia js H1 H2 H3.
    apply (array_index_mut_range_val_in _ _ _ _ _ _ _ _ M1 HL1);
      [ rewrite ctz4; lia | rewrite ctz260; lia | rewrite ctz4; lia ]. }
  assert (IN2 : forall ia js : usize, 260 <= to_Z ia -> to_Z ia < 292 ->
     to_Z js = to_Z ia - 260 ->
     array_index_usize (b2 s7) ia = slice_index_usize s7 js).
  { intros ia js H1 H2 H3.
    apply (array_index_mut_range_val_in _ _ _ _ _ _ _ _ M2 HL2);
      [ rewrite ctz260; lia | rewrite ctz292; lia | rewrite ctz260; lia ]. }
  subst pre. repeat apply conj.
  - (* [0,4) *)
    intros i j Hi Hj.
    rewrite (OUT2 j ltac:(lia)), (OUT1 j ltac:(lia)).
    rewrite (IN0 j i ltac:(lia) ltac:(lia) ltac:(lia)).
    apply slice_index_array_to_slice.
  - (* [4,260) — the code half, read out of the BLOCK *)
    intros i j k Hi Hj Hk.
    rewrite (OUT2 j ltac:(lia)).
    destruct (cexists_usize (to_Z i) ltac:(lia)) as [il Hil].
    rewrite (IN1 j il ltac:(lia) ltac:(lia) ltac:(lia)).
    rewrite (slice_index_range_val _ s4 mETA_LEN bLOCK_LEN il k S4
               ltac:(lia) ltac:(lia) ltac:(lia)).
    apply slice_index_array_to_slice.
  - (* [260,292) — the meta half, read out of the BLOCK *)
    intros i j k Hi Hj Hk.
    destruct (cexists_usize (to_Z i) ltac:(lia)) as [il Hil].
    rewrite (IN2 j il ltac:(lia) ltac:(lia) ltac:(lia)).
    rewrite (slice_index_range_val _ s7 0%usize mETA_LEN il k S7
               ltac:(lia) ltac:(rewrite ctz0; lia) ltac:(rewrite ctz0; lia)).
    apply slice_index_array_to_slice.
Qed.

(** THE COVERAGE STATEMENT, stated where the firmware is. Two blocks whose
    preimages agree byte for byte agree on ALL 288 of their own bytes: the code
    window `[4,260)` and the meta window `[260,292)` partition the block, so no
    byte of it escapes into the seam unobserved. This is
    [preimage_pins_block]'s content, but about `block_preimage_of_block` — the
    function `fold_block_from_flash` calls — with no blob and no materialisation
    step in the statement at all. *)
Lemma preimage_of_block_pins_block :
  forall (blk1 blk2 : u32) (block1 block2 : array u8 288%usize)
         (pre1 pre2 : array u8 292%usize),
    block_preimage_of_block blk1 block1 = Ok pre1 ->
    block_preimage_of_block blk2 block2 = Ok pre2 ->
    (forall j : usize, 0 <= to_Z j < 292 ->
       array_index_usize pre1 j = array_index_usize pre2 j) ->
    forall k : usize, 0 <= to_Z k < 288 ->
      array_index_usize block1 k = array_index_usize block2 k.
Proof.
  intros blk1 blk2 block1 block2 pre1 pre2 H1 H2 Hag k Hk.
  pose proof cu32max_big as Hbig.
  destruct (preimage_of_block_windows blk1 block1 pre1 H1) as [_ [C1 M1]].
  destruct (preimage_of_block_windows blk2 block2 pre2 H2) as [_ [C2 M2]].
  destruct (Z.lt_ge_cases (to_Z k) 32) as [Hlo|Hhi].
  - (* meta half: block[0,32) sits at pre[260,292) *)
    destruct (cexists_usize (to_Z k) ltac:(lia)) as [i Hi].
    destruct (cexists_usize (260 + to_Z i) ltac:(lia)) as [j Hj].
    rewrite <- (M1 i j k ltac:(lia) ltac:(lia) ltac:(lia)).
    rewrite <- (M2 i j k ltac:(lia) ltac:(lia) ltac:(lia)).
    apply Hag. lia.
  - (* code half: block[32,288) sits at pre[4,260) *)
    destruct (cexists_usize (to_Z k - 32) ltac:(lia)) as [i Hi].
    destruct (cexists_usize (4 + to_Z i) ltac:(lia)) as [j Hj].
    rewrite <- (C1 i j k ltac:(lia) ltac:(lia) ltac:(lia)).
    rewrite <- (C2 i j k ltac:(lia) ltac:(lia) ltac:(lia)).
    apply Hag. lia.
Qed.

(** THE FACTORISATION. `block_preimage` no longer assembles anything: it applies
    the two guards, materialises the block out of `blob[base, base+288)`, and
    calls `block_preimage_of_block`. This lemma is that sentence, proved over the
    extracted body — and it is what makes the firmware's call site and this
    development's theorems the same function rather than two functions someone
    checked against each other. *)
Lemma preimage_factors_through_block :
  forall (blob : slice u8) (blk : u32) (pre : array u8 292%usize),
    block_preimage blob blk = Ok (Some pre) ->
    exists (base : usize) (block : array u8 288%usize),
      to_Z base = 48 + 288 * to_Z blk
      /\ to_Z base + 288 <= to_Z (slice_len blob)
      (* the materialised block IS blob[base, base+288), byte for byte *)
      /\ (forall i k : usize, 0 <= to_Z i < 288 -> to_Z k = to_Z base + to_Z i ->
            array_index_usize block i = slice_index_usize blob k)
      (* and the preimage is the firmware's function of it *)
      /\ block_preimage_of_block blk block = Ok pre.
Proof.
  intros blob blk pre Ht. pose proof cu32max_big as Hbig.
  pose proof c_blk as Hbk.
  unfold block_preimage in Ht.
  destruct (blk s>= mAX_BLOCKS) eqn:Hg; [ discriminate |].
  apply sgeb_false in Hg. rewrite c_maxb in Hg.
  pose proof (to_Z_u32_bounds blk) as Hblk.
  cstep Ht ic Hic. cstep Ht i1 Hi1. cstep Ht base Hbase.
  cbv zeta in Ht. cstep Ht i3 Hi3.
  destruct (slice_len blob s< i3) eqn:Hlen; [ discriminate |].
  apply sltb_false in Hlen.
  unfold scalar_cast in Hic. apply mk_scalar_to_Z in Hic.
  unfold usize_mul, scalar_mul in Hi1. apply mk_scalar_to_Z in Hi1.
  unfold usize_add, scalar_add in Hbase. apply mk_scalar_to_Z in Hbase.
  unfold usize_add, scalar_add in Hi3. apply mk_scalar_to_Z in Hi3.
  rewrite c_blk in Hi1. rewrite c_hdr, Hi1, Hic in Hbase.
  rewrite c_blk, Hbase in Hi3.
  cbv zeta in Ht.
  cstep_pair Ht M0 w0 b0.
  cstep_copy Ht S1 s1. cstep_copy Ht C0 c0.
  cbv zeta in Ht. cstep Ht a Ha.
  injection Ht as Ht.
  apply copy_from_slice_val in C0. subst c0.
  assert (HL : to_Z (slice_len s1) = to_Z bLOCK_LEN - to_Z (0%usize)).
  { rewrite (slice_index_range_len _ _ _ _ S1), ctz0. lia. }
  exists base, (b0 s1). repeat apply conj.
  - lia.
  - lia.
  - intros i k Hi Hk.
    assert (INm : array_index_usize (b0 s1) i = slice_index_usize s1 i).
    { apply (array_index_mut_range_val_in _ _ _ _ _ _ _ _ M0 HL);
        [ rewrite ctz0; lia | lia | rewrite ctz0; lia ]. }
    rewrite INm.
    apply (slice_index_range_val blob s1 base i3 i k S1); lia.
  - subst pre. exact Ha.
Qed.

(** `block_preimage blob blk = Ok (Some pre)` forces a `base` at
    `48 + 288·blk`, a blob long enough to hold that whole block, and the three
    windows of `pre` holding — byte for byte — the block index and the block's
    two halves, at the blob offsets the firmware reads them from.

    Now a COROLLARY of [preimage_of_block_windows] and
    [preimage_factors_through_block]: the windows are established once, about
    the function the firmware calls, and transported through the materialisation
    to blob offsets. The statement is unchanged, so everything downstream
    (`preimage_pins_block`, `Chain_Residual`) consumes it exactly as before. *)
Lemma preimage_windows :
  forall (blob : slice u8) (blk : u32) (pre : array u8 292%usize),
    block_preimage blob blk = Ok (Some pre) ->
    exists base : usize,
      to_Z base = 48 + 288 * to_Z blk
      /\ to_Z base + 288 <= to_Z (slice_len blob)
      (* [0,4) — the little-endian block index *)
      /\ (forall i j : usize, 0 <= to_Z i < 4 -> to_Z j = to_Z i ->
            array_index_usize pre j
            = array_index_usize (core_num_U32_to_le_bytes blk) i)
      (* [4,260) — the CODE half, blob[base+32 .. base+288) *)
      /\ (forall i j k : usize, 0 <= to_Z i < 256 ->
            to_Z j = 4 + to_Z i -> to_Z k = to_Z base + 32 + to_Z i ->
            array_index_usize pre j = slice_index_usize blob k)
      (* [260,292) — the META half, blob[base .. base+32) *)
      /\ (forall i j k : usize, 0 <= to_Z i < 32 ->
            to_Z j = 260 + to_Z i -> to_Z k = to_Z base + to_Z i ->
            array_index_usize pre j = slice_index_usize blob k).
Proof.
  intros blob blk pre Ht. pose proof cu32max_big as Hbig.
  destruct (preimage_factors_through_block blob blk pre Ht)
    as [base [block [Hbase [Hlen [Hmat Hpre]]]]].
  destruct (preimage_of_block_windows blk block pre Hpre) as [W0 [W1 W2]].
  exists base. repeat apply conj.
  - exact Hbase.
  - exact Hlen.
  - exact W0.
  - intros i j k Hi Hj Hk.
    destruct (cexists_usize (32 + to_Z i) ltac:(lia)) as [kb Hkb].
    rewrite (W1 i j kb ltac:(lia) ltac:(lia) ltac:(lia)).
    apply (Hmat kb k); lia.
  - intros i j k Hi Hj Hk.
    destruct (cexists_usize (to_Z i) ltac:(lia)) as [kb Hkb].
    rewrite (W2 i j kb ltac:(lia) ltac:(lia) ltac:(lia)).
    apply (Hmat kb k); lia.
Qed.

(** THE COVERAGE STATEMENT. Two blobs whose block-`blk` preimages agree byte for
    byte agree on the WHOLE 288-byte block: the two windows partition it, meta at
    [base, base+32) and code at [base+32, base+288). No byte of the block escapes
    the preimage — which is exactly what the package tag could not say about the
    body (`Umbra_Canonical.blob_body_is_not_covered_by_pkg_tag`). *)
Lemma preimage_pins_block :
  forall (blob1 blob2 : slice u8) (blk1 blk2 : u32) (pre1 pre2 : array u8 292%usize),
    block_preimage blob1 blk1 = Ok (Some pre1) ->
    block_preimage blob2 blk2 = Ok (Some pre2) ->
    to_Z blk1 = to_Z blk2 ->
    (forall j : usize, 0 <= to_Z j < 292 ->
       array_index_usize pre1 j = array_index_usize pre2 j) ->
    forall k : usize,
      48 + 288 * to_Z blk1 <= to_Z k < 48 + 288 * to_Z blk1 + 288 ->
      slice_index_usize blob1 k = slice_index_usize blob2 k.
Proof.
  intros blob1 blob2 blk1 blk2 pre1 pre2 H1 H2 Hblkeq Hag k Hk.
  pose proof cu32max_big as Hbig.
  destruct (preimage_windows blob1 blk1 pre1 H1) as [b1 [Hb1 [_ [_ [C1 M1]]]]].
  destruct (preimage_windows blob2 blk2 pre2 H2) as [b2 [Hb2 [_ [_ [C2 M2]]]]].
  pose proof (to_Z_u32_bounds blk1) as Hblk.
  (* the two runs computed the same base — it is a function of `blk` alone *)
  assert (Hb : to_Z b1 = to_Z b2) by lia.
  destruct (Z.lt_ge_cases (to_Z k) (to_Z b1 + 32)) as [Hlo|Hhi].
  - (* meta half *)
    destruct (cexists_usize (to_Z k - to_Z b1) ltac:(lia)) as [i Hi].
    destruct (cexists_usize (260 + to_Z i) ltac:(lia)) as [j Hj].
    rewrite <- (M1 i j k ltac:(lia) ltac:(lia) ltac:(lia)).
    rewrite <- (M2 i j k ltac:(lia) ltac:(lia) ltac:(lia)).
    apply Hag. lia.
  - (* code half *)
    destruct (cexists_usize (to_Z k - to_Z b1 - 32) ltac:(lia)) as [i Hi].
    destruct (cexists_usize (4 + to_Z i) ltac:(lia)) as [j Hj].
    rewrite <- (C1 i j k ltac:(lia) ltac:(lia) ltac:(lia)).
    rewrite <- (C2 i j k ltac:(lia) ltac:(lia) ltac:(lia)).
    apply Hag. lia.
Qed.

(* ===================================================================== *)
(* THE ACCEPT GATE IS SOUND.                                              *)
(* ===================================================================== *)

Lemma ctz0u8 : to_Z (0%u8) = 0. Proof. reflexivity. Qed.

Lemma cu8_eqb_zero : forall d : u8, (d s= 0%u8) = true -> to_Z d = 0.
Proof. intros d H. apply seqb_true in H. rewrite ctz0u8 in H. exact H. Qed.

Lemma cor_xor_zero : forall (d x y : u8),
  to_Z (u8_or d (u8_xor x y)) = 0 -> to_Z d = 0 /\ to_Z x = to_Z y.
Proof.
  intros d x y H. rewrite u8_or_to_Z in H.
  apply (proj1 (Z.lor_eq_0_iff _ _)) in H as [Hd0 Hxor0].
  rewrite u8_xor_to_Z in Hxor0.
  apply (proj1 (Z.lxor_eq_0_iff _ _)) in Hxor0.
  split; [ exact Hd0 | exact Hxor0 ].
Qed.

(** The 32-iteration compare loop, run backwards: a zero accumulator at the end
    forces every compared pair to have been equal. Mirrors
    `Update_Value.ct_eq32_loop_sound`, over this file's own loop body. *)
Lemma ct_eq32_at_loop_sound :
  forall fuel (a : array u8 32%usize) (blob : slice u8) (off : usize) d i dfin,
    loop_fuel fuel (fun '(d1, i1) => ct_eq32_at_loop_body a blob off d1 i1) (d, i)
      = Ok dfin ->
    to_Z dfin = 0 ->
    to_Z d = 0
    /\ forall p q : usize, to_Z i <= to_Z p < 32 -> to_Z q = to_Z off + to_Z p ->
         exists x y, array_index_usize a p = Ok x
                  /\ slice_index_usize blob q = Ok y
                  /\ to_Z x = to_Z y.
Proof.
  induction fuel as [|n IH]; intros a blob off d i dfin Hloop Hz.
  - simpl in Hloop. discriminate.
  - rewrite loop_step in Hloop. cbn beta iota in Hloop.
    unfold ct_eq32_at_loop_body in Hloop.
    destruct (i s< 32%usize) eqn:Hi.
    + apply sltb_true in Hi. rewrite ctz32 in Hi.
      destruct (array_index_usize a i) as [x1|] eqn:Ea;
        [ cbn [bind] in Hloop | cbn [bind] in Hloop; discriminate ].
      destruct (usize_add off i) as [q0|] eqn:Eq;
        [ cbn [bind] in Hloop | cbn [bind] in Hloop; discriminate ].
      destruct (slice_index_usize blob q0) as [y1|] eqn:Eb;
        [ cbn [bind] in Hloop | cbn [bind] in Hloop; discriminate ].
      destruct (usize_add i 1%usize) as [i2|] eqn:Ei;
        [ cbn [bind] in Hloop | cbn [bind] in Hloop; discriminate ].
      destruct (IH a blob off (u8_or d (u8_xor x1 y1)) i2 dfin Hloop Hz)
        as [Hd1 Hrest].
      destruct (cor_xor_zero _ _ _ Hd1) as [Hd0 Hxy].
      unfold usize_add, scalar_add in Ei. apply mk_scalar_to_Z in Ei.
      unfold usize_add, scalar_add in Eq. apply mk_scalar_to_Z in Eq.
      rewrite tz1 in Ei.
      split; [ exact Hd0 |].
      intros p q Hp Hq.
      destruct (Z.eq_dec (to_Z p) (to_Z i)) as [Ep|Ep].
      * exists x1, y1. split.
        { rewrite (array_index_usize_ext a p i ltac:(lia)). exact Ea. }
        split; [| exact Hxy ].
        rewrite (slice_index_usize_ext blob q q0 ltac:(lia)). exact Eb.
      * apply Hrest; lia.
    + injection Hloop as Hloop. subst dfin.
      apply sltb_false in Hi. rewrite ctz32 in Hi.
      split; [ exact Hz |]. intros p q Hp Hq. lia.
Qed.

(** SOUNDNESS OF THE ACCEPT GATE, over the extracted body: `ct_eq32_at a blob off`
    returning `true` forces `a` and `blob[off, off+32)` equal byte for byte. *)
Lemma ct_eq32_at_sound :
  forall (a : array u8 32%usize) (blob : slice u8) (off : usize),
    ct_eq32_at a blob off = Ok true ->
    forall p q : usize, 0 <= to_Z p < 32 -> to_Z q = to_Z off + to_Z p ->
      exists x y, array_index_usize a p = Ok x
               /\ slice_index_usize blob q = Ok y
               /\ to_Z x = to_Z y.
Proof.
  intros a blob off H p q Hp Hq. unfold ct_eq32_at in H.
  destruct (usize_add off 32%usize) as [e|] eqn:Eo;
    [ cbn [bind] in H | cbn [bind] in H; discriminate ].
  destruct (slice_len blob s< e) eqn:Hl; [ discriminate |].
  destruct (ct_eq32_at_loop a blob off 0%u8 0%usize) as [dfin|] eqn:El;
    [ cbn [bind] in H | cbn [bind] in H; discriminate ].
  injection H as H. apply cu8_eqb_zero in H.
  unfold ct_eq32_at_loop, loop in El.
  destruct (ct_eq32_at_loop_sound _ a blob off 0%u8 0%usize dfin El H) as [_ Hall].
  apply Hall; [ rewrite ctz0; lia | lia ].
Qed.

(* ===================================================================== *)
(* THE BLOCK COUNT DEPENDS ONLY ON THE EIGHT HEADER BYTES IT READS.       *)
(* ===================================================================== *)

(** `blob_block_count` reads `blob[0..4)` (magic) and `blob[10..14)`
    (`code_size`) and nothing else — but it also branches on `slice_len`. So two
    blobs that agree on those eight bytes AND have equal length take the same
    path and return the same count. Pure congruence: no decoder law is needed,
    because the decoder is applied to literals built from bytes that are equal on
    the nose. *)
Lemma blob_block_count_cong :
  forall blob1 blob2 : slice u8,
    to_Z (slice_len blob1) = to_Z (slice_len blob2) ->
    (forall i : usize, 0 <= to_Z i < 4 ->
       slice_index_usize blob1 i = slice_index_usize blob2 i) ->
    (forall i : usize, 10 <= to_Z i < 14 ->
       slice_index_usize blob1 i = slice_index_usize blob2 i) ->
    blob_block_count blob1 = blob_block_count blob2.
Proof.
  intros blob1 blob2 Hlen Hmagic Hcs. pose proof cu32max_big as Hbig.
  unfold blob_block_count.
  assert (Hlb : (slice_len blob1 s< hDR_LEN) = (slice_len blob2 s< hDR_LEN)).
  { unfold scalar_ltb. rewrite Hlen. reflexivity. }
  rewrite Hlb. destruct (slice_len blob2 s< hDR_LEN); [ reflexivity |].
  rewrite (Hmagic 0%usize ltac:(rewrite ctz0; lia)).
  rewrite (Hmagic 1%usize ltac:(cbn; lia)).
  rewrite (Hmagic 2%usize ltac:(cbn; lia)).
  rewrite (Hmagic 3%usize ltac:(cbn; lia)).
  destruct (slice_index_usize blob2 0%usize); [| reflexivity ].
  destruct (slice_index_usize blob2 1%usize); [| reflexivity ].
  destruct (slice_index_usize blob2 2%usize); [| reflexivity ].
  destruct (slice_index_usize blob2 3%usize); [| reflexivity ].
  cbn [bind].
  destruct (core_num_U32_from_le_bytes _ s<> uMBR_MAGIC); [ reflexivity |].
  rewrite (Hcs cODE_SIZE_OFF ltac:(rewrite c_csoff; lia)).
  destruct (slice_index_usize blob2 cODE_SIZE_OFF); [| reflexivity ]. cbn [bind].
  destruct (usize_add cODE_SIZE_OFF 1%usize) as [k1|] eqn:E1;
    [ cbn [bind] | cbn [bind]; reflexivity ].
  unfold usize_add, scalar_add in E1. apply mk_scalar_to_Z in E1.
  rewrite c_csoff, ctz1 in E1.
  rewrite (Hcs k1 ltac:(lia)).
  destruct (slice_index_usize blob2 k1); [| reflexivity ]. cbn [bind].
  destruct (usize_add cODE_SIZE_OFF 2%usize) as [k2|] eqn:E2;
    [ cbn [bind] | cbn [bind]; reflexivity ].
  unfold usize_add, scalar_add in E2. apply mk_scalar_to_Z in E2.
  rewrite c_csoff, ctz2 in E2.
  rewrite (Hcs k2 ltac:(lia)).
  destruct (slice_index_usize blob2 k2); [| reflexivity ]. cbn [bind].
  destruct (usize_add cODE_SIZE_OFF 3%usize) as [k3|] eqn:E3;
    [ cbn [bind] | cbn [bind]; reflexivity ].
  unfold usize_add, scalar_add in E3. apply mk_scalar_to_Z in E3.
  rewrite c_csoff, ctz3 in E3.
  rewrite (Hcs k3 ltac:(lia)).
  destruct (slice_index_usize blob2 k3); reflexivity.
Qed.

(* ===================================================================== *)
(* THE ONE ADDITION TO THE QUARANTINE.                                    *)
(*                                                                        *)
(* The accept gate is a COMPARISON, so all it can establish is that the    *)
(* computed root and the blob's `header.hmac` window have equal byte       *)
(* VALUES — `to_Z x = to_Z y`, never `x = y`. Every result in update-core  *)
(* lives at that level for the same reason. But the collision reduction    *)
(* (Chain_Trace) needs the two accepted runs to end at the SAME root as a  *)
(* term, because that is what "both traces end at r" means.                *)
(*                                                                        *)
(* Q21 closes exactly that gap and nothing else: a byte array is           *)
(* determined by its bytes. It is a statement about the opaque reader      *)
(* `Primitives.array_index_usize`, in the same family as Q7/Q12/Q17, and   *)
(* it is DISCHARGED against the same concrete list model in Chain_Model.v  *)
(* (`array_ext_has_a_model`). It says nothing about HMAC, about the seam,  *)
(* or about any blob.                                                      *)
(*                                                                        *)
(* It is stated for `u8` arrays only, which is all the extracted body has. *)
(* ===================================================================== *)

Axiom array_u8_ext : forall (n : usize) (a b : array u8 n),
  (forall i : usize, 0 <= to_Z i < to_Z n ->
     exists x y, array_index_usize a i = Ok x
              /\ array_index_usize b i = Ok y
              /\ to_Z x = to_Z y) ->
  a = b.

(** The result-level form of Q21, which is what the callers actually have: a read
    that succeeds in one array and agrees as a RESULT with the other's is enough.
    Q1 (`array_index_usize_ok`) supplies the success. *)
Lemma array_u8_ext_res : forall (n : usize) (a b : array u8 n),
  (forall i : usize, 0 <= to_Z i < to_Z n ->
     array_index_usize a i = array_index_usize b i) ->
  a = b.
Proof.
  intros n a b H. apply (array_u8_ext n). intros i Hi.
  destruct (array_index_usize_ok a i Hi) as [x Hx].
  exists x, x. split; [ exact Hx |]. split; [ rewrite <- (H i Hi); exact Hx | reflexivity ].
Qed.

(** Lists agreeing at every `nth_error` are equal. *)
Lemma nth_error_list_eq : forall {A} (l1 l2 : list A),
  (forall k, nth_error l1 k = nth_error l2 k) -> l1 = l2.
Proof.
  induction l1 as [| x t1 IH]; intros l2 H.
  - destruct l2 as [| y t2]; [ reflexivity |].
    specialize (H 0%nat). cbn in H. discriminate.
  - destruct l2 as [| y t2].
    + specialize (H 0%nat). cbn in H. discriminate.
    + assert (Hx : x = y) by (specialize (H 0%nat); cbn in H; injection H; auto).
      subst y. f_equal. apply IH. intro k. exact (H (S k)).
Qed.

(** The little-endian encoder is a function of the VALUE, not of the term: two
    `u32`s with equal `to_Z` encode to the same array. Derived from Q18 (the
    digit spec) plus Q21; not assumed. Needed because the two runs of the chain
    index the same block through separately-built index terms. *)
Lemma to_le_bytes_val_cong_arr : forall x y : u32,
  to_Z x = to_Z y ->
  core_num_U32_to_le_bytes x = core_num_U32_to_le_bytes y.
Proof.
  intros x y H. apply (array_u8_ext 4%usize). intros i Hi. rewrite ctz4 in Hi.
  destruct (u32_to_le_bytes_val x i ltac:(lia)) as [bx [Hbx Hvx]].
  destruct (u32_to_le_bytes_val y i ltac:(lia)) as [by' [Hby Hvy]].
  exists bx, by'. split; [ exact Hbx |]. split; [ exact Hby |].
  rewrite Hvx, Hvy, H. reflexivity.
Qed.

(* ===================================================================== *)
(* EQUALITY OF BYTE ARRAYS IS DECIDABLE — CONSTRUCTIVELY.                 *)
(*                                                                        *)
(* An earlier revision reached for `Classical_Prop.classic` here, because *)
(* `array u8 n` is a sigma type over `scalar`, whose proof component is a *)
(* conjunction of `Z.le`s — negations — so `Eqdep_dec` does not apply and *)
(* the OBVIOUS route to decidable equality is closed.                     *)
(*                                                                        *)
(* It is not the only route. Q21 says a byte array is determined by its   *)
(* bytes, Q1 says in-bounds reads succeed, and `Z.eq_dec` decides the      *)
(* bytes. A bounded enumeration over the `n` indices therefore decides the *)
(* array. Nothing classical is needed, and after this the deterministic    *)
(* tier carries no logical axiom beyond the quarantine.                    *)
(* ===================================================================== *)

(** Enumerate the first `m` indices: either the two arrays agree on all of them,
    or a disagreeing index is EXHIBITED. *)
Lemma array_u8_agree_dec :
  forall (n : usize) (a b : array u8 n) (m : nat),
    Z.of_nat m <= to_Z n ->
    (forall i : usize, 0 <= to_Z i < Z.of_nat m ->
       exists x y, array_index_usize a i = Ok x
                /\ array_index_usize b i = Ok y
                /\ to_Z x = to_Z y)
    \/ (exists (i : usize) (x y : u8),
          array_index_usize a i = Ok x
          /\ array_index_usize b i = Ok y
          /\ to_Z x <> to_Z y).
Proof.
  intros n a b m. induction m as [| m' IH]; intros Hm.
  - left. intros i Hi. cbn in Hi. lia.
  - destruct IH as [Hall | Hdiff]; [ rewrite Nat2Z.inj_succ in Hm; lia | | right; exact Hdiff ].
    pose proof (to_Z_usize_bounds n) as Hn.
    rewrite Nat2Z.inj_succ in Hm.
    destruct (cexists_usize_full (Z.of_nat m') ltac:(lia)) as [im Him].
    destruct (array_index_usize_ok a im ltac:(lia)) as [x Hx].
    destruct (array_index_usize_ok b im ltac:(lia)) as [y Hy].
    destruct (Z.eq_dec (to_Z x) (to_Z y)) as [Heq | Hne].
    + left. intros i Hi. rewrite Nat2Z.inj_succ in Hi.
      destruct (Z_lt_le_dec (to_Z i) (Z.of_nat m')) as [Hlt | Hge].
      * apply Hall. lia.
      * exists x, y.
        rewrite (array_index_usize_ext a i im ltac:(lia)).
        rewrite (array_index_usize_ext b i im ltac:(lia)).
        split; [ exact Hx |]. split; [ exact Hy | exact Heq ].
    + right. exists im, x, y. split; [ exact Hx |]. split; [ exact Hy | exact Hne ].
Qed.

(** THE DECIDER. No `classic`, no `proof_irrelevance`. *)
Lemma array_u8_eq_dec : forall (n : usize) (a b : array u8 n), a = b \/ a <> b.
Proof.
  intros n a b. pose proof (usize_nonneg n) as Hn0.
  destruct (array_u8_agree_dec n a b (Z.to_nat (to_Z n))
              ltac:(rewrite Z2Nat.id by exact Hn0; lia))
    as [Hall | [i [x [y [Hx [Hy Hne]]]]]].
  - left. apply (array_u8_ext n). intros i Hi. apply Hall.
    rewrite Z2Nat.id by exact Hn0. exact Hi.
  - right. intro E. subst b. rewrite Hx in Hy. injection Hy as Hy. subst y.
    apply Hne. reflexivity.
Qed.
