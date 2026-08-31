(** P3 — BOUNDS-SAFETY of parse_and_verify, proved over the REAL Aeneas-extracted
    code (Update_Funs.v). In the Aeneas `result` monad, `Fail` is the panic /
    out-of-bounds / arithmetic-overflow channel, so "no trap on hostile input" is

        forall pkg en h key,  parse_and_verify … pkg en h key  <>  Fail _.

    The single length guard `len(pkg) >= 112` discharges every fixed index and
    range; the guard `blob_len = tag_off - 32 >= MIN_BLOB(48)` discharges the one
    variable-offset access `blob[16..48]`. The opaque array/slice/copy ops (which
    the Coq backend ships as bare Axioms with no theory) are pinned by the same
    kind of quarantine as Ess_Rep — enumerated in one block below. *)

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
Proof. intro x. destruct x as [z Hb]. unfold to_Z; simpl.
  rewrite usize_min_eq, usize_max_eq in Hb. exact Hb. Qed.
Lemma usize_nonneg : forall x : usize, 0 <= to_Z x.
Proof. intro x. apply to_Z_usize_bounds. Qed.
Lemma to_Z_u32_bounds : forall x : u32, 0 <= to_Z x <= u32_max.
Proof. intro x. destruct x as [z Hb]. unfold to_Z; simpl.
  rewrite u32_min_eq, u32_max_eq in Hb. exact Hb. Qed.

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
(* QUARANTINE — specs for the opaque array/slice/copy operations that the *)
(* Coq backend ships as bare `Axiom`s with no theory (cf. Ess_Rep §6).    *)
(* ===================================================================== *)

(* In-bounds reads succeed. *)
Axiom array_index_usize_ok : forall {T} {n} (a : array T n) (i : usize),
  0 <= to_Z i < to_Z n -> exists v, array_index_usize a i = Ok v.
Axiom slice_index_usize_ok : forall {T} (s : slice T) (i : usize),
  0 <= to_Z i < to_Z (slice_len s) -> exists v, slice_index_usize s i = Ok v.

(* array_to_slice preserves length. *)
Axiom slice_len_array_to_slice : forall {T} {n} (a : array T n),
  to_Z (slice_len (array_to_slice a)) = to_Z n.

(* Sub-slicing a slice by a valid Range succeeds; the result has length end-start. *)
Axiom slice_index_range_ok : forall {T} (s : slice T) (a b : usize),
  0 <= to_Z a -> to_Z a <= to_Z b -> to_Z b <= to_Z (slice_len s) ->
  exists sub,
    core_slice_index_Slice_index (core_slice_index_SliceIndexRangeUsizeSliceInst T) s
      {| core_ops_range_Range_start := a; core_ops_range_Range_end_ := b |} = Ok sub
    /\ to_Z (slice_len sub) = to_Z b - to_Z a.

(* Mutable-sub-slicing an array by a Range within bounds succeeds. *)
Axiom array_index_mut_range_ok : forall {T} {N} (arr : array T N) (a b : usize),
  0 <= to_Z a -> to_Z a <= to_Z b -> to_Z b <= to_Z N ->
  exists sub back,
    core_array_Array_index_mut
      (core_ops_index_IndexMutSliceInst (core_slice_index_SliceIndexRangeUsizeSliceInst T)) arr
      {| core_ops_range_Range_start := a; core_ops_range_Range_end_ := b |} = Ok (sub, back)
    /\ to_Z (slice_len sub) = to_Z b - to_Z a.

(* copy_from_slice succeeds when source and destination have equal length. *)
Axiom copy_from_slice_ok : forall {T} (m : core_marker_Copy T) (dst src : slice T),
  to_Z (slice_len dst) = to_Z (slice_len src) ->
  exists dst', core_slice_Slice_copy_from_slice m dst src = Ok dst'.

(* --------------------------------------------------------------------- *)
(* VALUE LAWS (quarantine, part 2).                                        *)
(*                                                                         *)
(* The six laws above say the opaque ops SUCCEED. That is all P3           *)
(* (`parse_and_verify_total`) needs, and `Print Assumptions                *)
(* parse_and_verify_total` uses exactly those six and none of the fourteen *)
(* below. Pushing an ACCEPTED package's gates down to the package BYTES    *)
(* (`Update_Auth.accept_implies_nonce_equal` / `accept_implies_tag_bytes`) *)
(* additionally needs to know WHAT the ops return. Same discipline: one    *)
(* block, no assumption smeared into a theorem, and `Update_Model.v`       *)
(* exhibits ONE concrete list model that satisfies all twenty.             *)
(* --------------------------------------------------------------------- *)

(* Indexing depends only on the numeric value of the index. *)
Axiom array_index_usize_ext : forall {T} {n} (a : array T n) (i j : usize),
  to_Z i = to_Z j -> array_index_usize a i = array_index_usize a j.
Axiom slice_index_usize_ext : forall {T} (s : slice T) (i j : usize),
  to_Z i = to_Z j -> slice_index_usize s i = slice_index_usize s j.

(* A range sub-slice that SUCCEEDED has the length the range asked for … *)
Axiom slice_index_range_len : forall {T} (s sub : slice T) (a b : usize),
  core_slice_index_Slice_index (core_slice_index_SliceIndexRangeUsizeSliceInst T) s
    {| core_ops_range_Range_start := a; core_ops_range_Range_end_ := b |} = Ok sub ->
  to_Z (slice_len sub) = to_Z b - to_Z a.
(* … and reading it at i reads the parent at start + i. *)
Axiom slice_index_range_val : forall {T} (s sub : slice T) (a b i j : usize),
  core_slice_index_Slice_index (core_slice_index_SliceIndexRangeUsizeSliceInst T) s
    {| core_ops_range_Range_start := a; core_ops_range_Range_end_ := b |} = Ok sub ->
  0 <= to_Z i -> to_Z i < to_Z b - to_Z a -> to_Z j = to_Z a + to_Z i ->
  slice_index_usize sub i = slice_index_usize s j.

(* A copy that SUCCEEDED leaves the destination holding the source (Rust's
   `dst.copy_from_slice(src)`; the Aeneas write-back value is the new dst). *)
Axiom copy_from_slice_val : forall {T} (m : core_marker_Copy T) (dst src dst' : slice T),
  core_slice_Slice_copy_from_slice m dst src = Ok dst' -> dst' = src.

(* Writing a length-matching slice back into an array yields an array that
   reads like that slice. *)
Axiom array_from_slice_val : forall {T} {n} (a : array T n) (s : slice T) (i : usize),
  to_Z (slice_len s) = to_Z n ->
  array_index_usize (array_from_slice a s) i = slice_index_usize s i.

(* The u8 bitwise ops are the Z bitwise ops on the represented values
   (mirrors Ess_Rep's u32_or_to_Z / u32_and_to_Z). *)
Axiom u8_xor_to_Z : forall x y : u8, to_Z (u8_xor x y) = Z.lxor (to_Z x) (to_Z y).
Axiom u8_or_to_Z : forall x y : u8, to_Z (u8_or x y) = Z.lor (to_Z x) (to_Z y).

(* --------------------------------------------------------------------- *)
(* WRITE-BACK LAWS (quarantine, part 3).                                   *)
(*                                                                         *)
(* Parts 1 and 2 are about the FORWARD direction: which reads succeed, and *)
(* what a read returns. They say nothing about what a mutable borrow of a  *)
(* window WRITES. Aeneas compiles `&mut arr[a..b]` into a pair             *)
(* `(sub, back)`: `sub` is the window as read, and `back sub'` is the whole *)
(* array after the window has been replaced by `sub'`. Every byte that      *)
(* `compute_pkg_tag` puts into its 91-byte preimage goes through `back`, so *)
(* without a law for it the assembled preimage is formally unrelated to the *)
(* five fields written into it — which is exactly the hole that            *)
(* `Update_Crypto.v`'s deleted C2 hypothesis used to paper over. With Q15/  *)
(* Q16 the assembly becomes a THEOREM (`Update_Crypto.assembly_injective`). *)
(*                                                                         *)
(* Q17 and Q18 are the two further read laws that theorem needs: that       *)
(* `array_to_slice` preserves reads (part 1's Q3 only preserves the length) *)
(* and that `u32::to_le_bytes` really is the base-256 digit decomposition.  *)
(* Q18 is a SPEC, not an injectivity assumption: injectivity of the codec   *)
(* is derived from it in Update_Crypto (`to_le_bytes_inj`).                 *)
(*                                                                         *)
(* All four are discharged by the concrete model in `Update_Model.v`, which *)
(* now interprets the write-back as the real splice                         *)
(* `firstn a ++ sub' ++ skipn b` rather than as the identity.               *)
(* --------------------------------------------------------------------- *)

(* Inside the window: the array reads like the slice that was written back. *)
Axiom array_index_mut_range_val_in :
  forall {T} {N} (arr : array T N) (a b : usize)
         (sub : slice T) (back : slice T -> array T N) (sub' : slice T) (i j : usize),
  core_array_Array_index_mut
    (core_ops_index_IndexMutSliceInst (core_slice_index_SliceIndexRangeUsizeSliceInst T)) arr
    {| core_ops_range_Range_start := a; core_ops_range_Range_end_ := b |} = Ok (sub, back) ->
  to_Z (slice_len sub') = to_Z b - to_Z a ->
  to_Z a <= to_Z i -> to_Z i < to_Z b -> to_Z j = to_Z i - to_Z a ->
  array_index_usize (back sub') i = slice_index_usize sub' j.

(* Outside the window: the array is unchanged. *)
Axiom array_index_mut_range_val_out :
  forall {T} {N} (arr : array T N) (a b : usize)
         (sub : slice T) (back : slice T -> array T N) (sub' : slice T) (i : usize),
  core_array_Array_index_mut
    (core_ops_index_IndexMutSliceInst (core_slice_index_SliceIndexRangeUsizeSliceInst T)) arr
    {| core_ops_range_Range_start := a; core_ops_range_Range_end_ := b |} = Ok (sub, back) ->
  to_Z (slice_len sub') = to_Z b - to_Z a ->
  (to_Z i < to_Z a \/ to_Z b <= to_Z i) ->
  array_index_usize (back sub') i = array_index_usize arr i.

(* `array_to_slice` preserves reads, not only the length. *)
Axiom slice_index_array_to_slice :
  forall {T} {n} (a : array T n) (i : usize),
  slice_index_usize (array_to_slice a) i = array_index_usize a i.

(* `u32::to_le_bytes`, byte by byte: byte i is digit i of the value, base 256. *)
Axiom u32_to_le_bytes_val :
  forall (x : u32) (i : usize), 0 <= to_Z i < 4 ->
  exists bv, array_index_usize (core_num_U32_to_le_bytes x) i = Ok bv
          /\ to_Z bv = (to_Z x / 256 ^ to_Z i) mod 256.

(* --------------------------------------------------------------------- *)
(* DECODER LAWS (quarantine, part 4).                                      *)
(*                                                                         *)
(* Q18 constrains the ENCODER only. The DECODER                            *)
(* `core_num_U32_from_le_bytes` is what actually produces `author_id`,      *)
(* `version` and `blob_len` out of the attacker-supplied package bytes      *)
(* (Update_Funs.v:224/244/251/258), and it arrived with no law at all: the  *)
(* `version` that P4 compares and that P2 claims the tag covers was         *)
(* formally an ARBITRARY function of four bytes. Two laws close that.       *)
(*                                                                         *)
(* Q19 is the exact mirror of Q18 — a digit SPEC, not an injectivity        *)
(* assumption. Round-trip (`from_le_bytes ∘ to_le_bytes = id`), decoder     *)
(* injectivity and decoder congruence are all DERIVED from it in            *)
(* Update_Crypto (`from_le_bytes_to_le_bytes`, `from_le_bytes_inj`,         *)
(* `from_le_bytes_cong`, `to_le_bytes_from_le_bytes`).                      *)
(*                                                                         *)
(* Q20 is what connects the decoder to the package. The extracted body      *)
(* always applies the decoder to a four-byte array LITERAL built from four  *)
(* bytes read out of `pkg`; without a read law for that literal the four    *)
(* bytes are formally unrelated to the array that gets decoded, and Q19     *)
(* could not be applied to them.                                            *)
(*                                                                         *)
(* NB — WHAT Q20 IS NOT. It is NOT a law about the backend's `mk_array`.    *)
(* `Primitives.mk_array : forall {T} (n : usize) (l : list T), array T n`   *)
(* is an INCONSISTENT axiom (`array T n` is empty at `T := Empty_set,       *)
(* n := 4`, so it proves `False`; see ../../AENEAS_COQ_MKARRAY_BUG.md), *)
(* every result in this development used to inherit it through the          *)
(* extracted body. `extract.sh` now rewrites the two array-literal arities  *)
(* the body builds (`mk_array4`, and `mk_array15` for PKG_TAG_LABEL) into   *)
(* TOTAL definitions that carry their own length proof, so `mk_array` is    *)
(* gone from the assumption set of every theorem here. What is left in Q20  *)
(* is purely a READ law for the opaque `array_index_usize` applied to a     *)
(* CONCRETE array — the same kind of law as Q7/Q12/Q17, and unavoidable for *)
(* the same reason: `array_index_usize` itself is a bare backend axiom.     *)
(*                                                                         *)
(* Both are discharged by the concrete model in `Update_Model.v`.           *)
(* --------------------------------------------------------------------- *)

(* `u32::from_le_bytes`, byte by byte: digit i of the decoded value is byte i. *)
Axiom u32_from_le_bytes_val :
  forall (a : array u8 4%usize) (i : usize), 0 <= to_Z i < 4 ->
  exists bv, array_index_usize a i = Ok bv
          /\ (to_Z (core_num_U32_from_le_bytes a) / 256 ^ to_Z i) mod 256
             = to_Z bv.

(* The four-element array literal the parser decodes reads back its four
   elements. `mk_array4` is a total DEFINITION (Update_FunsExternal.v), so this
   constrains only `array_index_usize`. *)
Axiom mk_array4_val :
  forall b0 b1 b2 b3 : u8,
    array_index_usize (mk_array4 b0 b1 b2 b3) 0%usize = Ok b0
    /\ array_index_usize (mk_array4 b0 b1 b2 b3) 1%usize = Ok b1
    /\ array_index_usize (mk_array4 b0 b1 b2 b3) 2%usize = Ok b2
    /\ array_index_usize (mk_array4 b0 b1 b2 b3) 3%usize = Ok b3.

(* The fifteen-element literal used for the package-tag domain separator reads
   back its fifteen elements. As for Q20, `mk_array15` is total; this law only
   specifies the otherwise opaque backend index operation on that value. *)
Axiom mk_array15_val :
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
(* assumption set of P3 — it must list exactly the six SUCCESS laws above *)
(* and the backend's scalar-width parameters, and in particular must NOT  *)
(* list `mk_array` (finding F1).                                         *)
(* ===================================================================== *)
Print Assumptions parse_and_verify_total.
