(** P3 — BOUNDS-SAFETY of parse_and_verify, proved over the REAL Aeneas-extracted
    code (Update_Funs.v). In the Aeneas `result` monad, `Fail` is the panic /
    out-of-bounds / arithmetic-overflow channel, so "no trap on hostile input" is

        forall pkg en h key,  parse_and_verify … pkg en h key  <>  Fail _.

    The single length guard `len(pkg) >= 112` discharges every fixed index and
    range; the guard `blob_len = tag_off - 32 >= MIN_BLOB(48)` discharges the one
    variable-offset access `blob[16..48]`. The array/slice/copy/codec ops the
    Coq backend ships as bare Axioms are DEFINED in our Primitives.v; the laws
    about them the proofs consume are LEMMAS, in one block below, and every
    theorem here is closed under the global context. *)

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
Require Import Update_Types.
Import Update_Types.
Require Import Update_FunsExternal.
Import Update_FunsExternal.
Require Import Update_Funs.
Import Update_Funs.
Local Open Scope Z_scope.
Local Open Scope Primitives_scope.

(* ===================================================================== *)
(* Scalar helpers — copied verbatim from ess-core/Ess_Refine.v (proved    *)
(* there; self-contained).                                                *)
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

Lemma cast_u32_usize_ok : forall x : u32,
  exists s : usize, scalar_cast U32 Usize x = Ok s /\ to_Z s = to_Z x.
Proof. intro x. unfold scalar_cast. pose proof (to_Z_u32_bounds x).
  apply mk_usize_ok. lia. Qed.

Lemma cast_usize_u32_ok : forall x : usize, to_Z x <= u32_max ->
  exists s : u32, scalar_cast Usize U32 x = Ok s /\ to_Z s = to_Z x.
Proof. intros x Hx. unfold scalar_cast. pose proof (usize_nonneg x).
  apply mk_u32_ok. lia. Qed.

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
Lemma tz_fixed : to_Z fIXED_PREFIX = 32. Proof. reflexivity. Qed.
Lemma tz_min   : to_Z mIN_BLOB    = 48. Proof. reflexivity. Qed.
Lemma tz_hdr   : to_Z hDR_LEN     = 48. Proof. reflexivity. Qed.

Lemma u32max_big : 257 <= u32_max. Proof. unfold u32_max. lia. Qed.

(* ===================================================================== *)
(* THE (FORMER) QUARANTINE — now LEMMAS.                                  *)
(*                                                                         *)
(* Earlier revisions POSTULATED the twenty-one laws below, because the     *)
(* Aeneas Coq backend shipped the array/slice/copy/codec operations as     *)
(* bare `Axiom`s with no theory, and exhibited a list model of them in a    *)
(* companion file to show the postulates consistent. Our Primitives.v now   *)
(* DEFINES every one of those operations (the list model IS the            *)
(* definition), so each law is a theorem about the concrete operation and   *)
(* nothing downstream inherits an assumption: `Print Assumptions` on every  *)
(* result of this development is closed under the global context.          *)
(*                                                                         *)
(* The statements are kept VERBATIM (names, hypotheses, conclusions), so    *)
(* every proof that consumed the axioms consumes the lemmas unchanged.      *)
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

(* --- Q20 and the label literal: the literals read back their elements ----- *)

Lemma mk_array4_val :
  forall b0 b1 b2 b3 : u8,
    array_index_usize (mk_array4 b0 b1 b2 b3) 0%usize = Ok b0
    /\ array_index_usize (mk_array4 b0 b1 b2 b3) 1%usize = Ok b1
    /\ array_index_usize (mk_array4 b0 b1 b2 b3) 2%usize = Ok b2
    /\ array_index_usize (mk_array4 b0 b1 b2 b3) 3%usize = Ok b3.
Proof. intros. repeat apply conj; reflexivity. Qed.

Lemma mk_array15_val :
  forall b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14 : u8,
    array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 0%usize = Ok b0
    /\ array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 1%usize = Ok b1
    /\ array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 2%usize = Ok b2
    /\ array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 3%usize = Ok b3
    /\ array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 4%usize = Ok b4
    /\ array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 5%usize = Ok b5
    /\ array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 6%usize = Ok b6
    /\ array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 7%usize = Ok b7
    /\ array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 8%usize = Ok b8
    /\ array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 9%usize = Ok b9
    /\ array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 10%usize = Ok b10
    /\ array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 11%usize = Ok b11
    /\ array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 12%usize = Ok b12
    /\ array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 13%usize = Ok b13
    /\ array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 14%usize = Ok b14.
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
(* ct_eq loop totality — the fixed-bound compare loops always return Ok.  *)
(* ===================================================================== *)

Lemma loop_step {S B} (n : nat) (f : S -> result (control_flow S B)) (s : S) :
  loop_fuel (Datatypes.S n) f s
  = match f s with
    | Ok (Done b) => Ok b
    | Ok (Cont s') => loop_fuel n f s'
    | Fail_ e => Fail_ e
    end.
Proof. reflexivity. Qed.

(* 16-byte / array-vs-array compare loop. *)
Lemma ct_eq16_loop_fueled : forall (fuel : nat) (a b : array u8 16%usize) (d : u8) (i : usize),
  0 <= to_Z i <= 16 -> (Z.to_nat (16 - to_Z i) < fuel)%nat ->
  exists r, loop_fuel fuel (fun '(d1, i1) => ct_eq16_loop_body a b d1 i1) (d, i) = Ok r.
Proof.
  induction fuel as [|n IH]; intros a b d i Hi Hfuel.
  - simpl in Hfuel. lia.
  - rewrite loop_step. cbn beta iota. unfold ct_eq16_loop_body.
    destruct (Z_lt_le_dec (to_Z i) 16) as [Hlt | Hge].
    + assert (Hc : (i s< 16%usize) = true) by (apply Z.ltb_lt; rewrite tz16; lia).
      rewrite Hc.
      destruct (array_index_usize_ok a i) as [x1 Hx1]; [ rewrite tz16; lia | ].
      destruct (array_index_usize_ok b i) as [x2 Hx2]; [ rewrite tz16; lia | ].
      rewrite Hx1, Hx2. cbn beta iota.
      destruct (usize_add_ok i 1%usize) as [i4 [Hi4 Hi4v]].
      { rewrite tz1. pose proof u32max_big. lia. }
      rewrite tz1 in Hi4v.
      rewrite Hi4. cbn beta iota.
      assert (Hbnd : 0 <= to_Z i4 <= 16) by lia.
      assert (Hmono : (Z.to_nat (16 - to_Z i4) < n)%nat).
      { assert (Hlt2 : (Z.to_nat (16 - to_Z i4) < Z.to_nat (16 - to_Z i))%nat)
          by (apply Z2Nat.inj_lt; lia).
        lia. }
      apply IH; assumption.
    + assert (Hc : (i s< 16%usize) = false) by (apply Z.ltb_ge; rewrite tz16; lia).
      rewrite Hc. exists d. reflexivity.
Qed.

Lemma ct_eq16_total : forall a b : array u8 16%usize, exists r, ct_eq16 a b = Ok r.
Proof.
  intros a b. unfold ct_eq16, ct_eq16_loop, loop.
  destruct (ct_eq16_loop_fueled 1000000 a b 0%u8 0%usize) as [r Hr].
  - rewrite tz0. lia.
  - rewrite tz0. apply Nat.ltb_lt. vm_compute. reflexivity.
  - rewrite Hr. cbn beta iota. exists (r s= 0%u8). reflexivity.
Qed.

(* 32-byte / array-vs-slice compare loop. Symmetric to ct_eq16, but b is a slice
   and the read is bounds-checked against its length (= 32 in the loop branch). *)
Lemma ct_eq32_loop_fueled : forall (fuel : nat) (a : array u8 32%usize) (b : slice u8) (d : u8) (i : usize),
  to_Z (slice_len b) = 32 -> 0 <= to_Z i <= 32 -> (Z.to_nat (32 - to_Z i) < fuel)%nat ->
  exists r, loop_fuel fuel (fun '(d1, i1) => ct_eq32_loop_body a b d1 i1) (d, i) = Ok r.
Proof.
  induction fuel as [|n IH]; intros a b d i Hlen Hi Hfuel.
  - simpl in Hfuel. lia.
  - rewrite loop_step. cbn beta iota. unfold ct_eq32_loop_body.
    destruct (Z_lt_le_dec (to_Z i) 32) as [Hlt | Hge].
    + assert (Hc : (i s< 32%usize) = true) by (apply Z.ltb_lt; rewrite tz32; lia).
      rewrite Hc.
      destruct (array_index_usize_ok a i) as [x1 Hx1]; [ rewrite tz32; lia | ].
      destruct (slice_index_usize_ok b i) as [x2 Hx2]; [ rewrite Hlen; lia | ].
      rewrite Hx1, Hx2. cbn beta iota.
      destruct (usize_add_ok i 1%usize) as [i4 [Hi4 Hi4v]].
      { rewrite tz1. pose proof u32max_big. lia. }
      rewrite tz1 in Hi4v.
      rewrite Hi4. cbn beta iota.
      assert (Hbnd : 0 <= to_Z i4 <= 32) by lia.
      assert (Hmono : (Z.to_nat (32 - to_Z i4) < n)%nat).
      { assert (Hlt2 : (Z.to_nat (32 - to_Z i4) < Z.to_nat (32 - to_Z i))%nat)
          by (apply Z2Nat.inj_lt; lia).
        lia. }
      apply IH; assumption.
    + assert (Hc : (i s< 32%usize) = false) by (apply Z.ltb_ge; rewrite tz32; lia).
      rewrite Hc. exists d. reflexivity.
Qed.

Lemma ct_eq32_total : forall (a : array u8 32%usize) (b : slice u8),
  exists r, ct_eq32 a b = Ok r.
Proof.
  intros a b. unfold ct_eq32.
  destruct (Z.eq_dec (to_Z (slice_len b)) 32) as [Hlen | Hne].
  - (* slice_len b = 32: the s<> guard is false, run the loop *)
    assert (Hc : (slice_len b s<> 32%usize) = false).
    { unfold scalar_neqb, scalar_eqb. apply negb_false_iff. apply Z.eqb_eq.
      rewrite tz32. exact Hlen. }
    rewrite Hc. unfold ct_eq32_loop, loop.
    destruct (ct_eq32_loop_fueled 1000000 a b 0%u8 0%usize Hlen) as [r Hr].
    + rewrite tz0. lia.
    + rewrite tz0. apply Nat.ltb_lt. vm_compute. reflexivity.
    + rewrite Hr. cbn beta iota. exists (r s= 0%u8). reflexivity.
  - (* slice_len b <> 32: returns Ok false immediately *)
    assert (Hc : (slice_len b s<> 32%usize) = true).
    { unfold scalar_neqb, scalar_eqb. apply negb_true_iff. apply Z.eqb_neq.
      rewrite tz32. exact Hne. }
    rewrite Hc. exists false. reflexivity.
Qed.

(* ===================================================================== *)
(* compute_pkg_tag totality — the fixed 91-byte preimage assembly. Every  *)
(* range and length is a compile-time constant (no attacker input); it    *)
(* traps only if the HMAC seam does, which we assume total (as T1/T2 do).  *)
(* ===================================================================== *)

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

(* Turn every `to_Z (n%usize)` into its plain number. NB: `vm_compute` cannot do
   this — it gets stuck on the opaque `usize_max` axiom inside `mk_scalar`; the
   `tzN` reflexivity-lemmas go through the conversion checker instead. *)
Ltac tzc := rewrite ?tz0, ?tz1, ?tz4, ?tz15, ?tz16, ?tz31, ?tz32, ?tz35, ?tz39, ?tz43, ?tz48, ?tz91.

(* One assembly step: an in-bounds mutable sub-slice of the 91-byte buffer, then a
   copy_from_slice whose source length matches the sub-slice. Bounds and the
   length equality are discharged inline (no floating goals / ordering issues). *)
(* NB: the range literals carry `%return` proof terms, so idx_mut91's conclusion
   is only CONVERTIBLE (not syntactically equal) to the goal's index_mut — a bare
   `rewrite He` can't key-match it. We re-state the goal's exact subterm and bridge
   it to He with `exact` (which is up to conversion), then rewrite that. *)
Ltac pkg_step :=
  match goal with
  | |- context [ core_array_Array_index_mut ?inst ?arr
        {| core_ops_range_Range_start := ?a; core_ops_range_Range_end_ := ?b |} ] =>
    let sub := fresh "sub" in let bk := fresh "bk" in
    let He := fresh "He" in let Hl := fresh "Hl" in let Hx := fresh "Hx" in
    destruct (idx_mut91 arr a b ltac:(tzc; lia) ltac:(tzc; lia)
                                 ltac:(tzc; lia)) as [sub [bk [He Hl]]];
    assert (Hx : core_array_Array_index_mut inst arr
        {| core_ops_range_Range_start := a; core_ops_range_Range_end_ := b |} = Ok (sub, bk))
      by exact He;
    rewrite Hx; clear Hx He; cbn [bind];
    match goal with
    | |- context [ core_slice_Slice_copy_from_slice ?m ?dst ?src ] =>
      let cs := fresh "cs" in let Hcs := fresh "Hcs" in
      destruct (copy_from_slice_ok m dst src
        ltac:(rewrite Hl; try unfold pKG_TAG_LABEL;
              rewrite ?slice_len_array_to_slice; tzc; lia)) as [cs Hcs];
      rewrite Hcs; cbn [bind]
    end
  end.

Lemma compute_pkg_tag_total :
  forall {H} (inst : PkgHmac_t H) (nonce : array u8 16%usize)
    (author version blob_len : u32) (hdr : array u8 48%usize) (h : H) (key : slice u8),
  (forall k p, exists t, inst.(PkgHmac_t_hmac_pkg) h k p = Ok t) ->
  exists t, compute_pkg_tag inst nonce author version blob_len hdr h key = Ok t.
Proof.
  intros HH inst nonce author version blob_len hdr h key Hmac.
  unfold compute_pkg_tag. cbv zeta.
  pkg_step. pkg_step. pkg_step. pkg_step. pkg_step. pkg_step.
  cbv zeta. apply Hmac.
Qed.

(* ===================================================================== *)
(* P3 — parse_and_verify never Fails, for ANY pkg / expected_nonce / key. *)
(* ===================================================================== *)

(* usize_max-bounded arithmetic (slice lengths can exceed u32_max in the model,
   so the u32-bounded helpers above are too weak for tag_off / i26). *)
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

Ltac tza := rewrite ?tz0, ?tz1, ?tz2, ?tz3, ?tz4, ?tz15, ?tz16, ?tz20, ?tz21, ?tz22,
  ?tz23, ?tz24, ?tz25, ?tz26, ?tz27, ?tz28, ?tz29, ?tz30, ?tz31, ?tz32, ?tz35, ?tz39,
  ?tz43, ?tz48, ?tz91, ?tz_fixed, ?tz_min, ?tz_hdr in *.

(* One in-bounds read of pkg: 0 <= to_Z k < to_Z (slice_len pkg), from Hlen. *)
Ltac pv_idx :=
  match goal with
  | |- context [ slice_index_usize ?s ?k ] =>
    let v := fresh "v" in let Hv := fresh "Hv" in
    destruct (slice_index_usize_ok s k) as [v Hv];
    [ split; tza; lia | rewrite Hv; cbn [bind] ]
  end.

(* One valid sub-slice of pkg: bridge the %return-carrying range term with exact. *)
Ltac pv_range Hlenname :=
  match goal with
  | |- context [ core_slice_index_Slice_index ?inst ?s
        {| core_ops_range_Range_start := ?a; core_ops_range_Range_end_ := ?b |} ] =>
    let sub := fresh "sub" in let Hs := fresh "Hs" in let Hx := fresh "Hx" in
    destruct (slice_index_range_ok s a b ltac:(tza; lia) ltac:(tza; lia) ltac:(tza; lia))
      as [sub [Hx Hs]];
    let E := fresh "E" in
    assert (E : core_slice_index_Slice_index inst s
        {| core_ops_range_Range_start := a; core_ops_range_Range_end_ := b |} = Ok sub)
      by exact Hx;
    rewrite E; clear E Hx; cbn [bind]; rename Hs into Hlenname
  end.

(* One copy_from_slice with a supplied length-equality proof. *)
Ltac pv_copy tac :=
  match goal with
  | |- context [ core_slice_Slice_copy_from_slice ?m ?dst ?src ] =>
    let cs := fresh "cs" in let Hcs := fresh "Hcs" in
    destruct (copy_from_slice_ok m dst src ltac:(tac)) as [cs Hcs];
    rewrite Hcs; cbn [bind]
  end.

Lemma parse_and_verify_total :
  forall {H} (inst : PkgHmac_t H) (pkg : slice u8) (en : array u8 16%usize)
    (h : H) (key : slice u8),
  (forall k p, exists t, inst.(PkgHmac_t_hmac_pkg) h k p = Ok t) ->
  exists r, parse_and_verify inst pkg en h key = Ok r.
Proof.
  intros HH inst pkg en h key Hmac.
  unfold parse_and_verify. cbv zeta.
  (* i1 = 32+48 = 80, i2 = 112 *)
  destruct (usize_add_ok' fIXED_PREFIX mIN_BLOB) as [i1 [E1 V1]];
    [ tza; pose proof usize_max_bound; unfold u32_max in *; lia | ].
  rewrite E1; cbn [bind].
  destruct (usize_add_ok' i1 32%usize) as [i2 [E2 V2]];
    [ rewrite V1; tza; pose proof usize_max_bound; unfold u32_max in *; lia | ].
  rewrite E2; cbn [bind].
  (* length guard: len < 112 -> Malformed; else len >= 112 *)
  destruct (slice_len pkg s< i2) eqn:G.
  { exists (Core_result_Result_Err UpdateError_Malformed); reflexivity. }
  assert (Hlen : 112 <= to_Z (slice_len pkg)).
  { apply Z.ltb_ge in G. rewrite V2, V1 in G. tza. lia. }
  (* magic: read pkg[0..3], branch *)
  pv_idx. pv_idx. pv_idx. pv_idx.
  match goal with |- context [ (?m0 s<> uPDATE_MAGIC) ] =>
    destruct (m0 s<> uPDATE_MAGIC) eqn:Gm end.
  { exists (Core_result_Result_Err UpdateError_BadMagic); reflexivity. }
  (* nonce := pkg[4..20] copied into a 16-byte buffer *)
  cbn [array_to_slice_mut].
  pv_range Hnonce.
  pv_copy ltac:(rewrite slice_len_array_to_slice, Hnonce; tza; lia).
  (* author (20..23), version (24..27), i21 (28..31) *)
  pv_idx. pv_idx. pv_idx. pv_idx.
  pv_idx. pv_idx. pv_idx. pv_idx.
  pv_idx. pv_idx. pv_idx. pv_idx.
  (* blob_len = cast i21 to usize; tag_off = len - 32 *)
  match goal with |- context [ scalar_cast U32 Usize ?x ] =>
    destruct (cast_u32_usize_ok x) as [bl [Ec Vc]] end.
  rewrite Ec; cbn [bind].
  destruct (usize_sub_ok' (slice_len pkg) 32%usize) as [toff [Et Vt]]; [ tza; lia | ].
  rewrite Et; cbn [bind].
  destruct (bl s< mIN_BLOB) eqn:Gmin.
  { exists (Core_result_Result_Err UpdateError_Malformed); reflexivity. }
  destruct (usize_sub_ok' toff fIXED_PREFIX) as [i23 [E23 V23]]; [ rewrite Vt; tza; lia | ].
  rewrite E23; cbn [bind].
  destruct (i23 s<> bl) eqn:G23.
  { exists (Core_result_Result_Err UpdateError_Malformed); reflexivity. }
  (* blob := pkg[32..tag_off], length = len-64 >= 48 (from Hlen) *)
  pv_range Hblob.
  match goal with |- context [ ct_eq16 ?x ?y ] =>
    destruct (ct_eq16_total x y) as [bn Hbn]; rewrite Hbn; cbn [bind] end.
  destruct bn.
  2:{ exists (Core_result_Result_Err UpdateError_NonceMismatch); reflexivity. }
  (* header := blob[0..48) — the FULL UMBR header — copied into a 48-byte buffer *)
  cbn [array_to_slice_mut].
  pv_range Hhdr.
  pv_copy ltac:(rewrite slice_len_array_to_slice, Hhdr; tza; lia).
  (* cast blob_len back to u32 (round-trip, so <= u32_max) *)
  destruct (cast_usize_u32_ok bl ltac:(rewrite Vc; apply to_Z_u32_bounds)) as [blu [Ecu Vcu]].
  rewrite Ecu; cbn [bind].
  (* compute_pkg_tag: total (Section C) *)
  match goal with |- context [ compute_pkg_tag ?I ?n ?au ?ve ?bl2 ?hh ?hh2 ?k ] =>
    destruct (compute_pkg_tag_total I n au ve bl2 hh hh2 k Hmac) as [tg Htg];
    rewrite Htg; cbn [bind] end.
  (* got := pkg[tag_off .. tag_off+32] (= pkg[..len]) *)
  destruct (usize_add_ok' toff 32%usize) as [i26 [E26 V26]];
    [ rewrite Vt; pose proof (to_Z_usize_bounds (slice_len pkg)); tza; lia | ].
  rewrite E26; cbn [bind].
  pv_range Hgot.
  match goal with |- context [ ct_eq32 ?x ?y ] =>
    destruct (ct_eq32_total x y) as [bt Hbt]; rewrite Hbt; cbn [bind] end.
  destruct bt.
  - eexists; reflexivity.
  - exists (Core_result_Result_Err UpdateError_TagInvalid); reflexivity.
Qed.

(* ===================================================================== *)
(* MECHANISED ASSUMPTION AUDIT.  The paper's central instrument is        *)
(* `Print Assumptions`; running it must therefore be part of the build,   *)
(* not a claim about a manual session.  Compiling this file emits the     *)
(* assumption set of P3 — it must be "Closed under the global context".   *)
(* ===================================================================== *)
Print Assumptions parse_and_verify_total.
