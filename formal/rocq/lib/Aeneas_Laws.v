(* Aeneas_Laws.v — generic laws about the Aeneas Coq-backend primitives
   (scalars, arrays, slices, ranges, mutable range borrows, copy_from_slice,
   the u8 bitwise ops, the u32 little-endian codecs, the fuel loop).
   Lifted VERBATIM (statements, names, proofs) from the update-core crate's
   Update_Safety.v so that other crates can consume them without depending on
   that crate. Imports only Primitives, AeneasLoopShim and the standard
   library. Zero Axiom, zero Admitted: every lemma is closed under the global
   context (see the `Print Assumptions` audit at the end of the file).

   The backend leaves `copy_from_slice`, `u32::{to,from}_le_bytes` and the
   array-literal constructor as holes in each crate's FunsExternal template;
   the (crate-independent) definitions that fill them are reproduced here, in
   the two "backend seam" blocks, so the laws about them are self-contained.
   A crate that wants those laws aliases its own seam to the constant of the
   same name here (the way chain-core aliases update-core's). *)

Require Import Primitives.
Import Primitives.
Require Import AeneasLoopShim.
Import AeneasLoopShim.
Require Import Coq.ZArith.ZArith.
Require Import Coq.Bool.Bool.
Require Import Coq.Lists.List.
Import ListNotations.
Require Import Coq.Bool.Sumbool.
Require Import Lia.
Local Open Scope Z_scope.
Local Open Scope Primitives_scope.

(* ===================================================================== *)
(* Scalar helpers (32-bit target: usize_max = u32_max = 4294967295).      *)
(* ===================================================================== *)

Lemma usize_min_eq : scalar_min Usize = 0.        Proof. reflexivity. Qed.
Lemma usize_max_eq : scalar_max Usize = usize_max. Proof. reflexivity. Qed.
Lemma u32_min_eq : scalar_min U32 = 0.            Proof. reflexivity. Qed.
Lemma u32_max_eq : scalar_max U32 = u32_max.      Proof. reflexivity. Qed.

Lemma to_Z_usize_bounds : forall x : usize, 0 <= to_Z x <= usize_max.
Proof. intro x. exact (to_Z_bounds x). Qed.
Lemma usize_nonneg : forall x : usize, 0 <= to_Z x.
Proof. intro x. apply to_Z_usize_bounds. Qed.
Lemma to_Z_u32_bounds : forall x : u32, 0 <= to_Z x <= u32_max.
Proof. intro x. exact (to_Z_bounds x). Qed.

Lemma mk_usize_ok : forall z, 0 <= z <= u32_max ->
  exists s : usize, mk_scalar Usize z = Ok s /\ to_Z s = z.
Proof.
  intros z Hz. unfold mk_scalar.
  assert (Hb : scalar_in_bounds Usize z = true).
  { unfold scalar_in_bounds. apply andb_true_intro. split.
    - unfold scalar_ge_min. apply orb_true_iff. right.
      apply Z.leb_le. rewrite usize_min_eq. lia.
    - unfold scalar_le_max. apply orb_true_iff. right.
      apply Z.leb_le. rewrite usize_max_eq. pose proof usize_max_bound. lia. }
  destruct (sumbool_of_bool (scalar_in_bounds Usize z)) as [H|H].
  - eexists. split; [ reflexivity |]. unfold to_Z; reflexivity.
  - rewrite Hb in H. discriminate.
Qed.

Lemma mk_u32_ok : forall z, 0 <= z <= u32_max ->
  exists s : u32, mk_scalar U32 z = Ok s /\ to_Z s = z.
Proof.
  intros z Hz. unfold mk_scalar.
  assert (Hb : scalar_in_bounds U32 z = true).
  { unfold scalar_in_bounds. apply andb_true_intro. split.
    - unfold scalar_ge_min. apply orb_true_iff. right.
      apply Z.leb_le. rewrite u32_min_eq. lia.
    - unfold scalar_le_max. apply orb_true_iff. right.
      apply Z.leb_le. rewrite u32_max_eq. lia. }
  destruct (sumbool_of_bool (scalar_in_bounds U32 z)) as [H|H].
  - eexists. split; [ reflexivity |]. unfold to_Z; reflexivity.
  - rewrite Hb in H. discriminate.
Qed.

(* A successful mk_scalar returns exactly the requested value. *)
Lemma mk_scalar_to_Z : forall ty z s, mk_scalar ty z = Ok s -> to_Z s = z.
Proof.
  intros ty z s H. unfold mk_scalar in H.
  destruct (sumbool_of_bool (scalar_in_bounds ty z)) as [Hb|Hb]; [| discriminate ].
  injection H as H. subst s. reflexivity.
Qed.

Lemma usize_add_ok : forall a b : usize, to_Z a + to_Z b <= u32_max ->
  exists s, usize_add a b = Ok s /\ to_Z s = to_Z a + to_Z b.
Proof. intros a b Hab. unfold usize_add, scalar_add.
  pose proof (usize_nonneg a). pose proof (usize_nonneg b).
  apply mk_usize_ok. lia. Qed.

Lemma usize_sub_ok : forall a b : usize,
  to_Z b <= to_Z a -> to_Z a <= u32_max ->
  exists s, usize_sub a b = Ok s /\ to_Z s = to_Z a - to_Z b.
Proof. intros a b Hba Ha. unfold usize_sub, scalar_sub.
  pose proof (usize_nonneg a). pose proof (usize_nonneg b).
  apply mk_usize_ok. lia. Qed.

(* Casts: `scalar_cast` is total and wraps ([scalar_wrap]); on a value already
   in the target range the wrap is the identity ([scalar_wrap_id]). Both
   directions hold at usize_bits 32 and 64 (usize_max_bound). *)
Lemma cast_u32_usize_val : forall (x : u32) (s : usize),
  scalar_cast U32 Usize x = Ok s -> to_Z s = to_Z x.
Proof. intros x s H. apply scalar_cast_to_Z in H. rewrite H. apply scalar_wrap_id.
  pose proof (to_Z_u32_bounds x). pose proof usize_max_bound.
  rewrite usize_min_eq, usize_max_eq. lia. Qed.

Lemma cast_usize_u32_val : forall (x : usize) (s : u32),
  scalar_cast Usize U32 x = Ok s -> to_Z x <= u32_max -> to_Z s = to_Z x.
Proof. intros x s H Hx. apply scalar_cast_to_Z in H. rewrite H. apply scalar_wrap_id.
  pose proof (usize_nonneg x). rewrite u32_min_eq, u32_max_eq. lia. Qed.

Lemma cast_u32_usize_ok : forall x : u32,
  exists s : usize, scalar_cast U32 Usize x = Ok s /\ to_Z s = to_Z x.
Proof. intro x. destruct (scalar_cast U32 Usize x) as [s|] eqn:E; [| discriminate ].
  exists s. split; [ reflexivity | exact (cast_u32_usize_val x s E) ]. Qed.

Lemma cast_usize_u32_ok : forall x : usize, to_Z x <= u32_max ->
  exists s : u32, scalar_cast Usize U32 x = Ok s /\ to_Z s = to_Z x.
Proof. intros x Hx. destruct (scalar_cast Usize U32 x) as [s|] eqn:E; [| discriminate ].
  exists s. split; [ reflexivity | exact (cast_usize_u32_val x s E Hx) ]. Qed.

(* Numeric to_Z of the usize literals the extracted body mentions. *)
Lemma tz0   : to_Z (0%usize)   = 0.   Proof. reflexivity. Qed.
Lemma tz1   : to_Z (1%usize)   = 1.   Proof. reflexivity. Qed.
Lemma tz4   : to_Z (4%usize)   = 4.   Proof. reflexivity. Qed.
Lemma tz15  : to_Z (15%usize)  = 15.  Proof. reflexivity. Qed.
Lemma tz16  : to_Z (16%usize)  = 16.  Proof. reflexivity. Qed.
Lemma tz31  : to_Z (31%usize)  = 31.  Proof. reflexivity. Qed.
Lemma tz32  : to_Z (32%usize)  = 32.  Proof. reflexivity. Qed.
Lemma tz35  : to_Z (35%usize)  = 35.  Proof. reflexivity. Qed.
Lemma tz39  : to_Z (39%usize)  = 39.  Proof. reflexivity. Qed.
Lemma tz43  : to_Z (43%usize)  = 43.  Proof. reflexivity. Qed.
Lemma tz48  : to_Z (48%usize)  = 48.  Proof. reflexivity. Qed.
Lemma tz91  : to_Z (91%usize)  = 91.  Proof. reflexivity. Qed.

Lemma u32max_big : 257 <= u32_max. Proof. unfold u32_max. lia. Qed.

(* ===================================================================== *)
(* Laws about the array / slice / range / copy / codec operations. The     *)
(* Coq backend ships these operations as bare Axioms with no theory;       *)
(* Primitives.v DEFINES them (the list model is the definition), so each   *)
(* law below is a theorem about the concrete operation.                    *)
(* ===================================================================== *)

(* --- list helpers ------------------------------------------------------ *)

Lemma nth_error_in_range : forall {A} (l : list A) (k : Z),
  0 <= k < zlen l -> exists v, nth_error l (Z.to_nat k) = Some v.
Proof.
  intros A l k Hk. destruct (nth_error l (Z.to_nat k)) as [v|] eqn:E.
  - exists v; reflexivity.
  - exfalso. apply nth_error_None in E. unfold zlen in Hk. lia.
Qed.

Lemma sub_list_length : forall {T} (l : list T) (a b : usize),
  0 <= to_Z a -> to_Z a <= to_Z b -> to_Z b <= zlen l ->
  zlen (sub_list l a b) = to_Z b - to_Z a.
Proof.
  intros T l a b H1 H2 H3. unfold zlen, sub_list in *.
  rewrite firstn_length, skipn_length. lia.
Qed.

Lemma slice_sub_len : forall {T} (s : slice T) (a b : usize),
  0 <= to_Z a -> to_Z a <= to_Z b -> to_Z b <= zlen (proj1_sig s) ->
  to_Z (slice_len (slice_sub s a b)) = to_Z b - to_Z a.
Proof.
  intros T s a b H1 H2 H3.
  rewrite to_Z_slice_len. unfold slice_sub; cbn [proj1_sig].
  apply sub_list_length; assumption.
Qed.

Lemma nth_error_skipn_model : forall {A} (m : nat) (l : list A) (k : nat),
  nth_error (skipn m l) k = nth_error l (m + k).
Proof.
  induction m as [|m IH]; intros l k.
  - reflexivity.
  - destruct l as [|x l']; simpl; [ destruct k; reflexivity | apply IH ].
Qed.

Lemma nth_error_firstn_model : forall {A} (n : nat) (l : list A) (k : nat),
  (k < n)%nat -> nth_error (firstn n l) k = nth_error l k.
Proof.
  induction n as [|n IH]; intros l k Hk; [ lia |].
  destruct l as [|x l']; simpl; [ destruct k; reflexivity |].
  destruct k; simpl; [ reflexivity | apply IH; lia ].
Qed.

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

(* --- Q1/Q2: in-bounds reads succeed ------------------------------------ *)

Lemma array_index_usize_ok : forall {T} {n} (a : array T n) (i : usize),
  0 <= to_Z i < to_Z n -> exists v, array_index_usize a i = Ok v.
Proof.
  intros T n a i Hi. unfold array_index_usize.
  destruct (nth_error_in_range (proj1_sig a) (to_Z i)) as [v Hv].
  { unfold zlen. rewrite (proj2_sig a). exact Hi. }
  rewrite Hv. exists v; reflexivity.
Qed.

Lemma slice_index_usize_ok : forall {T} (s : slice T) (i : usize),
  0 <= to_Z i < to_Z (slice_len s) -> exists v, slice_index_usize s i = Ok v.
Proof.
  intros T s i Hi. unfold slice_index_usize.
  destruct (nth_error_in_range (proj1_sig s) (to_Z i)) as [v Hv].
  { rewrite <- to_Z_slice_len. exact Hi. }
  rewrite Hv. exists v; reflexivity.
Qed.

(* --- Q3: array_to_slice preserves length -------------------------------- *)

Lemma slice_len_array_to_slice : forall {T} {n} (a : array T n),
  to_Z (slice_len (array_to_slice a)) = to_Z n.
Proof.
  intros T n a. rewrite to_Z_slice_len.
  unfold array_to_slice; cbn [proj1_sig]. exact (proj2_sig a).
Qed.

Lemma zlen_array_to_slice : forall {T} {N} (arr : array T N),
  zlen (proj1_sig (array_to_slice arr)) = to_Z N.
Proof.
  intros T N arr. pose proof (slice_len_array_to_slice arr) as H.
  rewrite to_Z_slice_len in H. exact H.
Qed.

(* --- Q4: a valid Range sub-slices a slice ------------------------------- *)

Lemma slice_index_range_ok : forall {T} (s : slice T) (a b : usize),
  0 <= to_Z a -> to_Z a <= to_Z b -> to_Z b <= to_Z (slice_len s) ->
  exists sub,
    core_slice_index_Slice_index (core_slice_index_SliceIndexRangeUsizeSliceInst T) s
      {| core_ops_range_Range_start := a; core_ops_range_Range_end_ := b |} = Ok sub
    /\ to_Z (slice_len sub) = to_Z b - to_Z a.
Proof.
  intros T s a b H1 H2 H3.
  exists (slice_sub s a b). split.
  - unfold core_slice_index_Slice_index;
      cbn [core_slice_index_SliceIndex_get core_slice_index_SliceIndexRangeUsizeSliceInst].
    unfold core_slice_index_SliceIndexRangeUsizeSlice_get, slice_range_get;
      cbn [core_ops_range_Range_start core_ops_range_Range_end_].
    destruct (Z_le_dec (to_Z a) (to_Z b)) as [|Hc]; [| lia].
    destruct (Z_le_dec (to_Z b) (to_Z (slice_len s))) as [|Hc]; [| lia].
    reflexivity.
  - apply slice_sub_len; assumption.
Qed.

(* --- Q5 and the write-back laws: what a mutable range borrow of an array
       COMPUTES TO ---------------------------------------------------------- *)

Lemma index_mut_eq : forall {T} {N} (arr : array T N) (a b : usize),
  to_Z a <= to_Z b -> to_Z b <= to_Z N ->
  core_array_Array_index_mut
    (core_ops_index_IndexMutSliceInst (core_slice_index_SliceIndexRangeUsizeSliceInst T)) arr
    {| core_ops_range_Range_start := a; core_ops_range_Range_end_ := b |}
  = Ok (slice_sub (array_to_slice arr) a b,
        fun o => array_from_slice arr (slice_splice (array_to_slice arr) a b o)).
Proof.
  intros T N arr a b H1 H2.
  assert (Hget : slice_range_index
                   {| core_ops_range_Range_start := a; core_ops_range_Range_end_ := b |}
                   (array_to_slice arr)
                 = Ok (slice_sub (array_to_slice arr) a b)).
  { unfold slice_range_index, slice_range_get. cbv zeta.
    cbn [core_ops_range_Range_start core_ops_range_Range_end_].
    destruct (Z_le_dec (to_Z a) (to_Z b)) as [K1|K1]; [| lia].
    destruct (Z_le_dec (to_Z b) (to_Z (slice_len (array_to_slice arr)))) as [K2|K2].
    - reflexivity.
    - exfalso. rewrite (slice_len_array_to_slice arr) in K2. lia. }
  unfold core_array_Array_index_mut.
  cbn [core_ops_index_IndexMut_index_mut core_ops_index_IndexMutSliceInst].
  unfold core_slice_index_Slice_index_mut.
  cbn [core_slice_index_SliceIndex_index_mut core_slice_index_SliceIndexRangeUsizeSliceInst].
  unfold core_slice_index_SliceIndexRangeUsizeSlice_index_mut, slice_range_index_mut.
  rewrite Hget. reflexivity.
Qed.

Lemma index_mut_bounds : forall {T} {N} (arr : array T N)
    (a b : usize) (sub : slice T) (back : slice T -> array T N),
  core_array_Array_index_mut
    (core_ops_index_IndexMutSliceInst (core_slice_index_SliceIndexRangeUsizeSliceInst T)) arr
    {| core_ops_range_Range_start := a; core_ops_range_Range_end_ := b |} = Ok (sub, back) ->
  to_Z a <= to_Z b /\ to_Z b <= to_Z N.
Proof.
  intros T N arr a b sub back H.
  unfold core_array_Array_index_mut in H.
  cbn [core_ops_index_IndexMut_index_mut core_ops_index_IndexMutSliceInst] in H.
  unfold core_slice_index_Slice_index_mut in H.
  cbn [core_slice_index_SliceIndex_index_mut core_slice_index_SliceIndexRangeUsizeSliceInst] in H.
  unfold core_slice_index_SliceIndexRangeUsizeSlice_index_mut, slice_range_index_mut,
    slice_range_index, slice_range_get in H. cbv zeta in H.
  cbn [core_ops_range_Range_start core_ops_range_Range_end_] in H.
  destruct (Z_le_dec (to_Z a) (to_Z b)) as [K1|K1];
    [ destruct (Z_le_dec (to_Z b) (to_Z (slice_len (array_to_slice arr)))) as [K2|K2] |];
    cbv beta iota in H; try discriminate H.
  rewrite (slice_len_array_to_slice arr) in K2. split; assumption.
Qed.

Lemma array_index_mut_range_ok : forall {T} {N} (arr : array T N) (a b : usize),
  0 <= to_Z a -> to_Z a <= to_Z b -> to_Z b <= to_Z N ->
  exists sub back,
    core_array_Array_index_mut
      (core_ops_index_IndexMutSliceInst (core_slice_index_SliceIndexRangeUsizeSliceInst T)) arr
      {| core_ops_range_Range_start := a; core_ops_range_Range_end_ := b |} = Ok (sub, back)
    /\ to_Z (slice_len sub) = to_Z b - to_Z a.
Proof.
  intros T N arr a b H1 H2 H3.
  do 2 eexists. split.
  - apply index_mut_eq; assumption.
  - apply slice_sub_len; [ exact H1 | exact H2 |].
    rewrite zlen_array_to_slice. exact H3.
Qed.

(* --- backend seam: copy_from_slice (definition that fills the FunsExternal
       hole; Rust panics unless the lengths match, and on success dst holds
       src's elements) ---------------------------------------------------- *)

Definition core_slice_Slice_copy_from_slice
  {T : Type} (markerCopyInst : core_marker_Copy T) (dst src : slice T)
  : result (slice T) :=
  if Z.eqb (to_Z (slice_len dst)) (to_Z (slice_len src)) then Ok src else Fail_ Failure.

(* --- Q6: copy_from_slice succeeds on equal lengths ---------------------- *)

Lemma copy_from_slice_ok : forall {T} (m : core_marker_Copy T) (dst src : slice T),
  to_Z (slice_len dst) = to_Z (slice_len src) ->
  exists dst', core_slice_Slice_copy_from_slice m dst src = Ok dst'.
Proof.
  intros T m dst src Hlen. unfold core_slice_Slice_copy_from_slice.
  rewrite (proj2 (Z.eqb_eq _ _) Hlen). exists src; reflexivity.
Qed.

(* --- Q7/Q8: indexing depends only on the numeric value of the index ----- *)

Lemma array_index_usize_ext : forall {T} {n} (a : array T n) (i j : usize),
  to_Z i = to_Z j -> array_index_usize a i = array_index_usize a j.
Proof. intros T n a i j Hij. unfold array_index_usize. rewrite Hij. reflexivity. Qed.

Lemma slice_index_usize_ext : forall {T} (s : slice T) (i j : usize),
  to_Z i = to_Z j -> slice_index_usize s i = slice_index_usize s j.
Proof. intros T s i j Hij. unfold slice_index_usize. rewrite Hij. reflexivity. Qed.

(* --- Q9/Q10: a range sub-slice that SUCCEEDED ---------------------------- *)

Lemma range_index_inv : forall {T} (s sub : slice T) (a b : usize),
  core_slice_index_Slice_index (core_slice_index_SliceIndexRangeUsizeSliceInst T) s
    {| core_ops_range_Range_start := a; core_ops_range_Range_end_ := b |} = Ok sub ->
  to_Z a <= to_Z b /\ to_Z b <= zlen (proj1_sig s) /\ sub = slice_sub s a b.
Proof.
  intros T s sub a b H.
  unfold core_slice_index_Slice_index in H;
    cbn [core_slice_index_SliceIndex_get core_slice_index_SliceIndexRangeUsizeSliceInst] in H.
  unfold core_slice_index_SliceIndexRangeUsizeSlice_get, slice_range_get in H;
    cbn [core_ops_range_Range_start core_ops_range_Range_end_] in H.
  destruct (Z_le_dec (to_Z a) (to_Z b)) as [H1|H1];
    [ destruct (Z_le_dec (to_Z b) (to_Z (slice_len s))) as [H2|H2] |];
    cbn [bind] in H; try discriminate.
  rewrite to_Z_slice_len in H2.
  injection H as H. split; [ exact H1 | split; [ exact H2 | symmetry; exact H ] ].
Qed.

Lemma slice_index_range_len : forall {T} (s sub : slice T) (a b : usize),
  core_slice_index_Slice_index (core_slice_index_SliceIndexRangeUsizeSliceInst T) s
    {| core_ops_range_Range_start := a; core_ops_range_Range_end_ := b |} = Ok sub ->
  to_Z (slice_len sub) = to_Z b - to_Z a.
Proof.
  intros T s sub a b H. apply range_index_inv in H as [H1 [H2 H3]]. subst sub.
  apply slice_sub_len; [ apply to_Z_usize_nonneg | exact H1 | exact H2 ].
Qed.

Lemma slice_index_range_val : forall {T} (s sub : slice T) (a b i j : usize),
  core_slice_index_Slice_index (core_slice_index_SliceIndexRangeUsizeSliceInst T) s
    {| core_ops_range_Range_start := a; core_ops_range_Range_end_ := b |} = Ok sub ->
  0 <= to_Z i -> to_Z i < to_Z b - to_Z a -> to_Z j = to_Z a + to_Z i ->
  slice_index_usize sub i = slice_index_usize s j.
Proof.
  intros T s sub a b i j H Hi Hib Hj.
  apply range_index_inv in H as [H1 [H2 H3]]. subst sub.
  pose proof (to_Z_usize_nonneg a) as Ha.
  unfold slice_index_usize, slice_sub; cbn [proj1_sig]. unfold sub_list.
  rewrite nth_error_firstn_model by lia.
  rewrite nth_error_skipn_model.
  f_equal. rewrite Hj, Z2Nat.inj_add by lia. reflexivity.
Qed.

(* --- Q11: a copy that SUCCEEDED leaves the destination holding the source *)

Lemma copy_from_slice_val : forall {T} (m : core_marker_Copy T) (dst src dst' : slice T),
  core_slice_Slice_copy_from_slice m dst src = Ok dst' -> dst' = src.
Proof.
  intros T m dst src dst' H. unfold core_slice_Slice_copy_from_slice in H.
  destruct (Z.eqb (to_Z (slice_len dst)) (to_Z (slice_len src)));
    [ injection H as H; symmetry; exact H | discriminate ].
Qed.

(* --- Q12: a length-matching slice written back into an array reads like it *)

Lemma array_from_slice_val : forall {T} {n} (a : array T n) (s : slice T) (i : usize),
  to_Z (slice_len s) = to_Z n ->
  array_index_usize (array_from_slice a s) i = slice_index_usize s i.
Proof.
  intros T n a s i Hlen. rewrite to_Z_slice_len in Hlen.
  unfold array_from_slice.
  destruct (Z.eq_dec (Z.of_nat (length (proj1_sig s))) (to_Z n)) as [Hd|Hd];
    [ reflexivity | exfalso; apply Hd; exact Hlen ].
Qed.

(* --- Q13/Q14: the u8 bitwise ops are the Z bitwise ops on the values ------ *)

Lemma mk_scalar_ok : forall ty z, scalar_min ty <= z <= scalar_max ty ->
  exists s : scalar ty, mk_scalar ty z = Ok s /\ to_Z s = z.
Proof.
  intros ty z Hz. unfold mk_scalar.
  destruct (sumbool_of_bool (scalar_in_bounds ty z)) as [H|H].
  - eexists. split; reflexivity.
  - rewrite (scalar_in_bounds_complete ty z Hz) in H. discriminate.
Qed.

Lemma to_Z_u8_range : forall x : u8, 0 <= to_Z x < 256.
Proof.
  intro x. pose proof (to_Z_bounds x) as H.
  unfold scalar_min, scalar_max, u8_min, u8_max in H. lia.
Qed.

Lemma log2_lt8 : forall a, 0 <= a < 256 -> Z.log2 a < 8.
Proof.
  intros a Ha. destruct (Z.eq_dec a 0) as [->|Hne]; [ cbn; lia |].
  apply (proj1 (Z.log2_lt_pow2 a 8 ltac:(lia))). cbn. lia.
Qed.

Lemma u8_bnd_xor : forall x y : u8,
  scalar_min U8 <= Z.lxor (to_Z x) (to_Z y) <= scalar_max U8.
Proof.
  intros x y. pose proof (to_Z_u8_range x) as Hx. pose proof (to_Z_u8_range y) as Hy.
  change (scalar_min U8) with 0. change (scalar_max U8) with 255.
  assert (Hnn : 0 <= Z.lxor (to_Z x) (to_Z y)) by (apply Z.lxor_nonneg; split; lia).
  assert (Hub : Z.lxor (to_Z x) (to_Z y) < 256).
  { destruct (Z.eq_dec (Z.lxor (to_Z x) (to_Z y)) 0) as [E|E]; [ lia |].
    replace 256 with (2^8) by reflexivity.
    apply (proj2 (Z.log2_lt_pow2 (Z.lxor (to_Z x) (to_Z y)) 8 ltac:(lia))).
    eapply Z.le_lt_trans; [ apply Z.log2_lxor; lia |].
    apply Z.max_lub_lt; apply log2_lt8; lia. }
  lia.
Qed.

Lemma u8_bnd_or : forall x y : u8,
  scalar_min U8 <= Z.lor (to_Z x) (to_Z y) <= scalar_max U8.
Proof.
  intros x y. pose proof (to_Z_u8_range x) as Hx. pose proof (to_Z_u8_range y) as Hy.
  change (scalar_min U8) with 0. change (scalar_max U8) with 255.
  assert (Hnn : 0 <= Z.lor (to_Z x) (to_Z y)) by (apply Z.lor_nonneg; lia).
  assert (Hub : Z.lor (to_Z x) (to_Z y) < 256).
  { destruct (Z.eq_dec (Z.lor (to_Z x) (to_Z y)) 0) as [E|E]; [ lia |].
    replace 256 with (2^8) by reflexivity.
    apply (proj2 (Z.log2_lt_pow2 (Z.lor (to_Z x) (to_Z y)) 8 ltac:(lia))).
    rewrite Z.log2_lor by lia.
    apply Z.max_lub_lt; apply log2_lt8; lia. }
  lia.
Qed.

Lemma u8_xor_to_Z : forall x y : u8, to_Z (u8_xor x y) = Z.lxor (to_Z x) (to_Z y).
Proof.
  intros x y. unfold u8_xor, scalar_xor, scalar_or_default.
  destruct (mk_scalar_ok U8 (Z.lxor (to_Z x) (to_Z y)) (u8_bnd_xor x y)) as [s [Hs Hv]].
  rewrite Hs. exact Hv.
Qed.

Lemma u8_or_to_Z : forall x y : u8, to_Z (u8_or x y) = Z.lor (to_Z x) (to_Z y).
Proof.
  intros x y. unfold u8_or, scalar_or, scalar_or_default.
  destruct (mk_scalar_ok U8 (Z.lor (to_Z x) (to_Z y)) (u8_bnd_or x y)) as [s [Hs Hv]].
  rewrite Hs. exact Hv.
Qed.

(* --- Q15/Q16: WRITE-BACK of a mutable window ---------------------------- *)

Lemma splice_nat_facts : forall {T} (l new : list T) (a b : usize),
  to_Z a <= to_Z b -> to_Z b <= zlen l -> zlen new = to_Z b - to_Z a ->
  Z.of_nat (Z.to_nat (to_Z a)) = to_Z a
  /\ Z.of_nat (Z.to_nat (to_Z b)) = to_Z b
  /\ (Z.to_nat (to_Z a) <= Z.to_nat (to_Z b))%nat
  /\ (Z.to_nat (to_Z b) <= length l)%nat
  /\ length new = (Z.to_nat (to_Z b) - Z.to_nat (to_Z a))%nat.
Proof.
  intros T l new a b Hab Hbl Hnew.
  pose proof (to_Z_usize_nonneg a) as Ha0. pose proof (to_Z_usize_nonneg b) as Hb0.
  unfold zlen in *.
  assert (HA : Z.of_nat (Z.to_nat (to_Z a)) = to_Z a) by (apply Z2Nat.id; lia).
  assert (HB : Z.of_nat (Z.to_nat (to_Z b)) = to_Z b) by (apply Z2Nat.id; lia).
  repeat split; lia.
Qed.

Lemma splice_length : forall {T} (l new : list T) (a b : usize),
  to_Z a <= to_Z b -> to_Z b <= zlen l -> zlen new = to_Z b - to_Z a ->
  length (splice_list l a b new) = length l.
Proof.
  intros T l new a b H1 H2 H3.
  destruct (splice_nat_facts l new a b H1 H2 H3) as [HA [HB [K1 [K2 K3]]]].
  unfold splice_list. rewrite !app_length, firstn_length, skipn_length. lia.
Qed.

Lemma nth_error_splice_lt : forall {T} (l new : list T) (a b : usize) (k : nat),
  to_Z a <= to_Z b -> to_Z b <= zlen l -> zlen new = to_Z b - to_Z a ->
  (k < Z.to_nat (to_Z a))%nat ->
  nth_error (splice_list l a b new) k = nth_error l k.
Proof.
  intros T l new a b k H1 H2 H3 Hk.
  destruct (splice_nat_facts l new a b H1 H2 H3) as [HA [HB [K1 [K2 K3]]]].
  unfold splice_list.
  rewrite nth_error_app1 by (rewrite firstn_length; lia).
  apply nth_error_firstn_model. exact Hk.
Qed.

Lemma nth_error_splice_in : forall {T} (l new : list T) (a b : usize) (k : nat),
  to_Z a <= to_Z b -> to_Z b <= zlen l -> zlen new = to_Z b - to_Z a ->
  (Z.to_nat (to_Z a) <= k)%nat -> (k < Z.to_nat (to_Z b))%nat ->
  nth_error (splice_list l a b new) k = nth_error new (k - Z.to_nat (to_Z a)).
Proof.
  intros T l new a b k H1 H2 H3 Hk1 Hk2.
  destruct (splice_nat_facts l new a b H1 H2 H3) as [HA [HB [K1 [K2 K3]]]].
  unfold splice_list.
  rewrite nth_error_app2 by (rewrite firstn_length; lia).
  rewrite firstn_length.
  replace (Nat.min (Z.to_nat (to_Z a)) (length l)) with (Z.to_nat (to_Z a)) by lia.
  rewrite nth_error_app1 by lia. reflexivity.
Qed.

Lemma nth_error_splice_ge : forall {T} (l new : list T) (a b : usize) (k : nat),
  to_Z a <= to_Z b -> to_Z b <= zlen l -> zlen new = to_Z b - to_Z a ->
  (Z.to_nat (to_Z b) <= k)%nat ->
  nth_error (splice_list l a b new) k = nth_error l k.
Proof.
  intros T l new a b k H1 H2 H3 Hk.
  destruct (splice_nat_facts l new a b H1 H2 H3) as [HA [HB [K1 [K2 K3]]]].
  unfold splice_list.
  rewrite nth_error_app2 by (rewrite firstn_length; lia).
  rewrite firstn_length.
  replace (Nat.min (Z.to_nat (to_Z a)) (length l)) with (Z.to_nat (to_Z a)) by lia.
  rewrite nth_error_app2 by lia.
  replace (k - Z.to_nat (to_Z a) - length new)%nat
     with (k - Z.to_nat (to_Z b))%nat by lia.
  rewrite nth_error_skipn_model. f_equal. lia.
Qed.

Lemma proj1_slice_splice : forall {T} (s sub' : slice T) (a b : usize),
  length (splice_list (proj1_sig s) a b (proj1_sig sub')) = length (proj1_sig s) ->
  proj1_sig (slice_splice s a b sub') = splice_list (proj1_sig s) a b (proj1_sig sub').
Proof.
  intros T s sub' a b H.
  unfold slice_splice; cbn [proj1_sig]; unfold splice_or.
  rewrite (proj2 (Nat.eqb_eq _ _) H). reflexivity.
Qed.

(* The write-back always preserves the parent's length, so `array_from_slice`
   always takes its length-matching branch. *)
Lemma splice_back_len : forall {T} {N} (arr : array T N) (a b : usize) (sub' : slice T),
  to_Z (slice_len (slice_splice (array_to_slice arr) a b sub')) = to_Z N.
Proof.
  intros T N arr a b sub'.
  rewrite to_Z_slice_len. unfold zlen.
  unfold slice_splice; cbn [proj1_sig]. rewrite splice_or_length.
  exact (zlen_array_to_slice arr).
Qed.

Lemma array_index_mut_range_val_in :
  forall {T} {N} (arr : array T N) (a b : usize)
         (sub : slice T) (back : slice T -> array T N) (sub' : slice T) (i j : usize),
  core_array_Array_index_mut
    (core_ops_index_IndexMutSliceInst (core_slice_index_SliceIndexRangeUsizeSliceInst T)) arr
    {| core_ops_range_Range_start := a; core_ops_range_Range_end_ := b |} = Ok (sub, back) ->
  to_Z (slice_len sub') = to_Z b - to_Z a ->
  to_Z a <= to_Z i -> to_Z i < to_Z b -> to_Z j = to_Z i - to_Z a ->
  array_index_usize (back sub') i = slice_index_usize sub' j.
Proof.
  intros T N arr a b sub back sub' i j H Hlen Hai Hib Hj.
  destruct (index_mut_bounds arr a b sub back H) as [Hab HbN].
  rewrite (index_mut_eq arr a b Hab HbN) in H.
  injection H as _ Hback. subst back.
  rewrite to_Z_slice_len in Hlen.
  pose proof (zlen_array_to_slice arr) as HzN.
  assert (Hsl : length (splice_list (proj1_sig (array_to_slice arr)) a b (proj1_sig sub'))
                = length (proj1_sig (array_to_slice arr)))
    by (apply splice_length; [ exact Hab | rewrite HzN; exact HbN | exact Hlen ]).
  rewrite (array_from_slice_val arr _ i (splice_back_len arr a b sub')).
  unfold slice_index_usize. rewrite (proj1_slice_splice _ sub' a b Hsl).
  rewrite (nth_error_splice_in _ _ a b (Z.to_nat (to_Z i)));
    [ | exact Hab | rewrite HzN; exact HbN | exact Hlen | | ].
  - do 2 f_equal.
    assert (E1 : Z.of_nat (Z.to_nat (to_Z i)) = to_Z i)
      by (apply Z2Nat.id; apply to_Z_usize_nonneg).
    assert (E2 : Z.of_nat (Z.to_nat (to_Z a)) = to_Z a)
      by (apply Z2Nat.id; apply to_Z_usize_nonneg).
    assert (E3 : Z.of_nat (Z.to_nat (to_Z j)) = to_Z j)
      by (apply Z2Nat.id; apply to_Z_usize_nonneg).
    lia.
  - assert (E1 : Z.of_nat (Z.to_nat (to_Z i)) = to_Z i)
      by (apply Z2Nat.id; apply to_Z_usize_nonneg).
    assert (E2 : Z.of_nat (Z.to_nat (to_Z a)) = to_Z a)
      by (apply Z2Nat.id; apply to_Z_usize_nonneg).
    lia.
  - assert (E1 : Z.of_nat (Z.to_nat (to_Z i)) = to_Z i)
      by (apply Z2Nat.id; apply to_Z_usize_nonneg).
    assert (E2 : Z.of_nat (Z.to_nat (to_Z b)) = to_Z b)
      by (apply Z2Nat.id; apply to_Z_usize_nonneg).
    lia.
Qed.

Lemma array_index_mut_range_val_out :
  forall {T} {N} (arr : array T N) (a b : usize)
         (sub : slice T) (back : slice T -> array T N) (sub' : slice T) (i : usize),
  core_array_Array_index_mut
    (core_ops_index_IndexMutSliceInst (core_slice_index_SliceIndexRangeUsizeSliceInst T)) arr
    {| core_ops_range_Range_start := a; core_ops_range_Range_end_ := b |} = Ok (sub, back) ->
  to_Z (slice_len sub') = to_Z b - to_Z a ->
  (to_Z i < to_Z a \/ to_Z b <= to_Z i) ->
  array_index_usize (back sub') i = array_index_usize arr i.
Proof.
  intros T N arr a b sub back sub' i H Hlen Hout.
  destruct (index_mut_bounds arr a b sub back H) as [Hab HbN].
  rewrite (index_mut_eq arr a b Hab HbN) in H.
  injection H as _ Hback. subst back.
  rewrite to_Z_slice_len in Hlen.
  pose proof (zlen_array_to_slice arr) as HzN.
  assert (Hsl : length (splice_list (proj1_sig (array_to_slice arr)) a b (proj1_sig sub'))
                = length (proj1_sig (array_to_slice arr)))
    by (apply splice_length; [ exact Hab | rewrite HzN; exact HbN | exact Hlen ]).
  rewrite (array_from_slice_val arr _ i (splice_back_len arr a b sub')).
  unfold slice_index_usize, array_index_usize.
  rewrite (proj1_slice_splice _ sub' a b Hsl).
  assert (E1 : Z.of_nat (Z.to_nat (to_Z i)) = to_Z i)
    by (apply Z2Nat.id; apply to_Z_usize_nonneg).
  assert (E2 : Z.of_nat (Z.to_nat (to_Z a)) = to_Z a)
    by (apply Z2Nat.id; apply to_Z_usize_nonneg).
  assert (E3 : Z.of_nat (Z.to_nat (to_Z b)) = to_Z b)
    by (apply Z2Nat.id; apply to_Z_usize_nonneg).
  destruct Hout as [Hlt|Hge].
  - rewrite (nth_error_splice_lt _ _ a b (Z.to_nat (to_Z i)));
      [ reflexivity | exact Hab | rewrite HzN; exact HbN | exact Hlen | lia ].
  - rewrite (nth_error_splice_ge _ _ a b (Z.to_nat (to_Z i)));
      [ reflexivity | exact Hab | rewrite HzN; exact HbN | exact Hlen | lia ].
Qed.

(* --- Q17: array_to_slice preserves reads, not only the length ------------- *)

Lemma slice_index_array_to_slice :
  forall {T} {n} (a : array T n) (i : usize),
  slice_index_usize (array_to_slice a) i = array_index_usize a i.
Proof. reflexivity. Qed.

(* --- backend seam: the byte<->u32 codecs. `u32::to_le_bytes` is the base-256
       digit decomposition and `u32::from_le_bytes` its recomposition. ------- *)

Lemma byte_digit_bnd : forall z k : Z,
  scalar_min U8 <= (z / 256 ^ k) mod 256 <= scalar_max U8.
Proof.
  intros z k. unfold scalar_min, scalar_max, u8_min, u8_max.
  pose proof (Z.mod_pos_bound (z / 256 ^ k) 256 ltac:(lia)). lia.
Qed.

Definition byte_digit (z k : Z) : u8 :=
  mk_scalar_of_bounds U8 ((z / 256 ^ k) mod 256) (byte_digit_bnd z k).

Definition core_num_U32_to_le_bytes (x : u32) : array u8 4%usize :=
  exist _ [ byte_digit (to_Z x) 0; byte_digit (to_Z x) 1;
            byte_digit (to_Z x) 2; byte_digit (to_Z x) 3 ] eq_refl.

Definition byte_at (a : array u8 4%usize) (k : nat) : Z :=
  match nth_error (proj1_sig a) k with Some b => to_Z b | None => 0 end.

Lemma byte_at_bnd : forall a k, 0 <= byte_at a k < 256.
Proof.
  intros a k. unfold byte_at.
  destruct (nth_error (proj1_sig a) k) as [b|]; [ apply to_Z_u8_range | lia ].
Qed.

Lemma from_le_bnd : forall a : array u8 4%usize,
  scalar_min U32
  <= byte_at a 0 + 256 * byte_at a 1 + 65536 * byte_at a 2 + 16777216 * byte_at a 3
  <= scalar_max U32.
Proof.
  intros a. unfold scalar_min, scalar_max, u32_min, u32_max.
  pose proof (byte_at_bnd a 0). pose proof (byte_at_bnd a 1).
  pose proof (byte_at_bnd a 2). pose proof (byte_at_bnd a 3). lia.
Qed.

Definition core_num_U32_from_le_bytes (a : array u8 4%usize) : u32 :=
  mk_scalar_of_bounds U32
    (byte_at a 0 + 256 * byte_at a 1 + 65536 * byte_at a 2 + 16777216 * byte_at a 3)
    (from_le_bnd a).

(* --- Q18/Q19: the codecs are the base-256 digit (de)composition ----------- *)

Lemma u32_to_le_bytes_val :
  forall (x : u32) (i : usize), 0 <= to_Z i < 4 ->
  exists bv, array_index_usize (core_num_U32_to_le_bytes x) i = Ok bv
          /\ to_Z bv = (to_Z x / 256 ^ to_Z i) mod 256.
Proof.
  intros x i Hi.
  assert (Hc : to_Z i = 0 \/ to_Z i = 1 \/ to_Z i = 2 \/ to_Z i = 3) by lia.
  unfold array_index_usize, core_num_U32_to_le_bytes, opt_result; cbn [proj1_sig].
  destruct Hc as [E|[E|[E|E]]]; rewrite E; cbn [Z.to_nat nth_error];
    eexists; split; reflexivity.
Qed.

Lemma zmod_add_small : forall a k m, 0 < m -> 0 <= a < m -> (a + m * k) mod m = a.
Proof.
  intros a k m Hm Ha. replace (a + m * k) with (a + k * m) by ring.
  rewrite Z.mod_add by lia. apply Z.mod_small. exact Ha.
Qed.

Lemma zdiv_add_small : forall a k m, 0 < m -> 0 <= a < m -> (a + m * k) / m = k.
Proof.
  intros a k m Hm Ha. replace (a + m * k) with (a + k * m) by ring.
  rewrite Z.div_add by lia. rewrite (Z.div_small a m) by exact Ha. lia.
Qed.

Lemma zdiv_chain2 : forall X : Z, X / 65536 = X / 256 / 256.
Proof. intros X. rewrite Z.div_div by lia. reflexivity. Qed.

Lemma zdiv_chain3 : forall X : Z, X / 16777216 = X / 65536 / 256.
Proof. intros X. rewrite Z.div_div by lia. reflexivity. Qed.

Lemma le4_digits : forall v0 v1 v2 v3,
  0 <= v0 < 256 -> 0 <= v1 < 256 -> 0 <= v2 < 256 -> 0 <= v3 < 256 ->
  ((v0 + 256 * v1 + 65536 * v2 + 16777216 * v3) / 256 ^ 0) mod 256 = v0
  /\ ((v0 + 256 * v1 + 65536 * v2 + 16777216 * v3) / 256 ^ 1) mod 256 = v1
  /\ ((v0 + 256 * v1 + 65536 * v2 + 16777216 * v3) / 256 ^ 2) mod 256 = v2
  /\ ((v0 + 256 * v1 + 65536 * v2 + 16777216 * v3) / 256 ^ 3) mod 256 = v3.
Proof.
  intros v0 v1 v2 v3 H0 H1 H2 H3.
  assert (E0 : v0 + 256 * v1 + 65536 * v2 + 16777216 * v3
               = v0 + 256 * (v1 + 256 * v2 + 65536 * v3)) by ring.
  assert (E1 : v1 + 256 * v2 + 65536 * v3 = v1 + 256 * (v2 + 256 * v3)) by ring.
  assert (D0 : (v0 + 256 * v1 + 65536 * v2 + 16777216 * v3) mod 256 = v0)
    by (rewrite E0; apply zmod_add_small; lia).
  assert (Q1 : (v0 + 256 * v1 + 65536 * v2 + 16777216 * v3) / 256
               = v1 + 256 * v2 + 65536 * v3)
    by (rewrite E0; apply zdiv_add_small; lia).
  assert (Q2 : (v1 + 256 * v2 + 65536 * v3) / 256 = v2 + 256 * v3)
    by (rewrite E1; apply zdiv_add_small; lia).
  assert (Q3 : (v2 + 256 * v3) / 256 = v3) by (apply zdiv_add_small; lia).
  assert (P2 : (v0 + 256 * v1 + 65536 * v2 + 16777216 * v3) / 65536
               = v2 + 256 * v3).
  { rewrite zdiv_chain2, Q1. exact Q2. }
  assert (P3 : (v0 + 256 * v1 + 65536 * v2 + 16777216 * v3) / 16777216 = v3).
  { rewrite zdiv_chain3, P2. exact Q3. }
  repeat apply conj.
  - replace (256 ^ 0) with 1 by reflexivity. rewrite Z.div_1_r. exact D0.
  - replace (256 ^ 1) with 256 by reflexivity. rewrite Q1.
    rewrite E1. apply zmod_add_small; lia.
  - replace (256 ^ 2) with 65536 by reflexivity. rewrite P2.
    apply zmod_add_small; lia.
  - replace (256 ^ 3) with 16777216 by reflexivity. rewrite P3.
    apply Z.mod_small; lia.
Qed.

Lemma u32_from_le_bytes_val :
  forall (a : array u8 4%usize) (i : usize), 0 <= to_Z i < 4 ->
  exists bv, array_index_usize a i = Ok bv
          /\ (to_Z (core_num_U32_from_le_bytes a) / 256 ^ to_Z i) mod 256
             = to_Z bv.
Proof.
  intros a i Hi.
  assert (Hz : zlen (proj1_sig a) = 4)
    by (unfold zlen; rewrite (proj2_sig a); reflexivity).
  destruct (nth_error_in_range (proj1_sig a) 0 ltac:(lia)) as [c0 H0].
  destruct (nth_error_in_range (proj1_sig a) 1 ltac:(lia)) as [c1 H1].
  destruct (nth_error_in_range (proj1_sig a) 2 ltac:(lia)) as [c2 H2].
  destruct (nth_error_in_range (proj1_sig a) 3 ltac:(lia)) as [c3 H3].
  change (Z.to_nat 0) with 0%nat in H0. change (Z.to_nat 1) with 1%nat in H1.
  change (Z.to_nat 2) with 2%nat in H2. change (Z.to_nat 3) with 3%nat in H3.
  assert (B0 : byte_at a 0 = to_Z c0) by (unfold byte_at; rewrite H0; reflexivity).
  assert (B1 : byte_at a 1 = to_Z c1) by (unfold byte_at; rewrite H1; reflexivity).
  assert (B2 : byte_at a 2 = to_Z c2) by (unfold byte_at; rewrite H2; reflexivity).
  assert (B3 : byte_at a 3 = to_Z c3) by (unfold byte_at; rewrite H3; reflexivity).
  assert (Hval : to_Z (core_num_U32_from_le_bytes a)
                 = to_Z c0 + 256 * to_Z c1 + 65536 * to_Z c2 + 16777216 * to_Z c3).
  { change (to_Z (core_num_U32_from_le_bytes a))
      with (byte_at a 0 + 256 * byte_at a 1 + 65536 * byte_at a 2
            + 16777216 * byte_at a 3).
    rewrite B0, B1, B2, B3. reflexivity. }
  destruct (le4_digits (to_Z c0) (to_Z c1) (to_Z c2) (to_Z c3)
              (to_Z_u8_range c0) (to_Z_u8_range c1) (to_Z_u8_range c2)
              (to_Z_u8_range c3)) as [G0 [G1 [G2 G3]]].
  rewrite Hval.
  assert (Hc : to_Z i = 0 \/ to_Z i = 1 \/ to_Z i = 2 \/ to_Z i = 3) by lia.
  unfold array_index_usize, opt_result.
  destruct Hc as [E|[E|[E|E]]]; rewrite E.
  - change (Z.to_nat 0) with 0%nat. rewrite H0. exists c0.
    split; [ reflexivity | exact G0 ].
  - change (Z.to_nat 1) with 1%nat. rewrite H1. exists c1.
    split; [ reflexivity | exact G1 ].
  - change (Z.to_nat 2) with 2%nat. rewrite H2. exists c2.
    split; [ reflexivity | exact G2 ].
  - change (Z.to_nat 3) with 3%nat. rewrite H3. exists c3.
    split; [ reflexivity | exact G3 ].
Qed.

(* --- backend seam: the total four-element array literal (replacement for the
       backend's `mk_array`, an inconsistent Axiom) ------------------------- *)

Definition mk_array4 (b0 b1 b2 b3 : u8) : array u8 4%usize :=
  exist _ [b0; b1; b2; b3] eq_refl.

(* --- Q20: the literal reads back its elements ---------------------------- *)

Lemma mk_array4_val :
  forall b0 b1 b2 b3 : u8,
    array_index_usize (mk_array4 b0 b1 b2 b3) 0%usize = Ok b0
    /\ array_index_usize (mk_array4 b0 b1 b2 b3) 1%usize = Ok b1
    /\ array_index_usize (mk_array4 b0 b1 b2 b3) 2%usize = Ok b2
    /\ array_index_usize (mk_array4 b0 b1 b2 b3) 3%usize = Ok b3.
Proof. intros. repeat apply conj; reflexivity. Qed.

(* --- Q21 (formerly chain-core's one addition): a byte array is determined
       by its reads. General in T for term-equal reads; for u8 the reads may
       agree only in VALUE (`scalar_ext` closes the gap, no proof irrelevance). *)

Lemma array_index_ext : forall {T} {n} (a b : array T n),
  (forall i : usize, 0 <= to_Z i < to_Z n ->
     array_index_usize a i = array_index_usize b i) ->
  a = b.
Proof.
  intros T n a b H. apply array_ext. apply nth_error_list_eq. intro k.
  pose proof (proj2_sig a) as Ha. pose proof (proj2_sig b) as Hb. cbn beta in Ha, Hb.
  destruct (Z_lt_dec (Z.of_nat k) (to_Z n)) as [Hk|Hk].
  - assert (Hbnd : scalar_min Usize <= Z.of_nat k <= scalar_max Usize).
    { unfold scalar_min, scalar_max, usize_min.
      pose proof (to_Z_usize_le_max n). lia. }
    specialize (H (mk_scalar_of_bounds Usize (Z.of_nat k) Hbnd)
                  ltac:(rewrite to_Z_mk_scalar_of_bounds; lia)).
    unfold array_index_usize in H.
    rewrite to_Z_mk_scalar_of_bounds, Nat2Z.id in H.
    destruct (nth_error (proj1_sig a) k) eqn:Ea,
             (nth_error (proj1_sig b) k) eqn:Eb;
      cbn in H; try discriminate; [ injection H as -> | ]; reflexivity.
  - rewrite (proj2 (nth_error_None _ _)), (proj2 (nth_error_None _ _));
      [ reflexivity | lia | lia ].
Qed.

Lemma array_u8_ext : forall (n : usize) (a b : array u8 n),
  (forall i : usize, 0 <= to_Z i < to_Z n ->
     exists x y, array_index_usize a i = Ok x
              /\ array_index_usize b i = Ok y
              /\ to_Z x = to_Z y) ->
  a = b.
Proof.
  intros n a b H. apply array_index_ext. intros i Hi.
  destruct (H i Hi) as [x [y [Hx [Hy Hxy]]]].
  rewrite Hx, Hy. f_equal. apply scalar_ext. exact Hxy.
Qed.

(* ===================================================================== *)
(* The fuel loop: one unfolding step of `loop_fuel`.                       *)
(* ===================================================================== *)

Lemma loop_step {S B} (n : nat) (f : S -> result (control_flow S B)) (s : S) :
  loop_fuel (Datatypes.S n) f s
  = match f s with
    | Ok (Done b) => Ok b
    | Ok (Cont s') => loop_fuel n f s'
    | Fail_ e => Fail_ e
    end.
Proof. reflexivity. Qed.

(* array index_mut specialised to the fixed 91-byte buffer (concrete N avoids
   implicit-argument inference in the step tactic). *)
Lemma idx_mut91 : forall (arr : array u8 91%usize) (a b : usize),
  0 <= to_Z a -> to_Z a <= to_Z b -> to_Z b <= 91 ->
  exists sub back,
    core_array_Array_index_mut
      (core_ops_index_IndexMutSliceInst (core_slice_index_SliceIndexRangeUsizeSliceInst u8)) arr
      {| core_ops_range_Range_start := a; core_ops_range_Range_end_ := b |} = Ok (sub, back)
    /\ to_Z (slice_len sub) = to_Z b - to_Z a.
Proof.
  intros arr a b H1 H2 H3.
  apply (array_index_mut_range_ok arr a b H1 H2). rewrite tz91. exact H3.
Qed.

(* usize_max-bounded arithmetic (slice lengths can exceed u32_max in the model,
   so the u32-bounded helpers above are too weak for them). *)
Lemma mk_usize_ok' : forall z, 0 <= z <= usize_max ->
  exists s : usize, mk_scalar Usize z = Ok s /\ to_Z s = z.
Proof.
  intros z Hz. unfold mk_scalar.
  assert (Hb : scalar_in_bounds Usize z = true).
  { unfold scalar_in_bounds. apply andb_true_intro. split.
    - unfold scalar_ge_min. apply orb_true_iff. right. apply Z.leb_le. rewrite usize_min_eq. lia.
    - unfold scalar_le_max. apply orb_true_iff. right. apply Z.leb_le. rewrite usize_max_eq. lia. }
  destruct (sumbool_of_bool (scalar_in_bounds Usize z)) as [H|H].
  - eexists. split; [ reflexivity |]. unfold to_Z; reflexivity.
  - rewrite Hb in H. discriminate.
Qed.

Lemma usize_add_ok' : forall a b : usize, to_Z a + to_Z b <= usize_max ->
  exists s, usize_add a b = Ok s /\ to_Z s = to_Z a + to_Z b.
Proof. intros a b H. unfold usize_add, scalar_add.
  pose proof (usize_nonneg a). pose proof (usize_nonneg b). apply mk_usize_ok'. lia. Qed.

Lemma usize_sub_ok' : forall a b : usize, to_Z b <= to_Z a ->
  exists s, usize_sub a b = Ok s /\ to_Z s = to_Z a - to_Z b.
Proof. intros a b H. unfold usize_sub, scalar_sub.
  pose proof (usize_nonneg a). pose proof (usize_nonneg b).
  pose proof (to_Z_usize_bounds a). apply mk_usize_ok'. lia. Qed.

(* to_Z of the remaining index literals (reflexivity — the conversion checker
   handles %return; vm_compute would stick on usize_max). *)
Lemma tz2  : to_Z (2%usize)  = 2.  Proof. reflexivity. Qed.
Lemma tz3  : to_Z (3%usize)  = 3.  Proof. reflexivity. Qed.
Lemma tz20 : to_Z (20%usize) = 20. Proof. reflexivity. Qed.
Lemma tz21 : to_Z (21%usize) = 21. Proof. reflexivity. Qed.
Lemma tz22 : to_Z (22%usize) = 22. Proof. reflexivity. Qed.
Lemma tz23 : to_Z (23%usize) = 23. Proof. reflexivity. Qed.
Lemma tz24 : to_Z (24%usize) = 24. Proof. reflexivity. Qed.
Lemma tz25 : to_Z (25%usize) = 25. Proof. reflexivity. Qed.
Lemma tz26 : to_Z (26%usize) = 26. Proof. reflexivity. Qed.
Lemma tz27 : to_Z (27%usize) = 27. Proof. reflexivity. Qed.
Lemma tz28 : to_Z (28%usize) = 28. Proof. reflexivity. Qed.
Lemma tz29 : to_Z (29%usize) = 29. Proof. reflexivity. Qed.
Lemma tz30 : to_Z (30%usize) = 30. Proof. reflexivity. Qed.

(* ===================================================================== *)
(* MECHANISED ASSUMPTION AUDIT: each must be closed under the global       *)
(* context.                                                                *)
(* ===================================================================== *)
Print Assumptions array_u8_ext.
Print Assumptions loop_step.
Print Assumptions copy_from_slice_val.
