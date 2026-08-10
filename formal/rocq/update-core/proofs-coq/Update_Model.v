(** MACHINE-CHECKED CONSISTENCY WITNESS for the TWENTY quarantine axioms of
    Update_Safety.v — the six SUCCESS laws P3 (bounds-safety) rests on, the
    eight VALUE laws the byte-level authentication results
    (`Update_Value.ct_eq16/32_sound`, `Update_Auth.accept_implies_nonce_equal`,
    `Update_Crypto.accept_implies_authenticated_fields`) rest on, the four
    WRITE-BACK/CODEC laws that make the 91-byte preimage assembly a theorem
    (`Update_Crypto.assembly_injective`), and the two DECODER laws that make
    the parsed `u32` fields functions of the package bytes rather than
    arbitrary (`Update_Crypto.accept_implies_version_is_package_bytes`).

    THE PROBLEM. The Aeneas Coq backend ships the slice/array/copy/bitwise
    operations as bare `Axiom`s with no theory at all (`Primitives.v` even says
    "(* TODO: finish the definitions *)"). A proof about extracted code therefore
    has to postulate what those operations do. Update_Safety.v does that in ONE
    place rather than smearing assumptions across theorems. But an axiom block is
    exactly where an unsound proof hides: postulate something contradictory and
    every theorem downstream becomes vacuous.

    WHAT THIS FILE DOES. It builds a CONCRETE interpretation of those operations
    over Coq lists (and, for the two bitwise ops, over `Z.lxor` / `Z.lor`) and
    proves, `Qed`, that all twenty statements hold of it. Two theorems:

      [quarantine_is_the_axioms]  — the record `QuarantineHolds` below, applied to
        the Primitives symbols, is DISCHARGED BY the twenty axioms of
        Update_Safety, each by `exact`. This is what makes the exercise honest:
        Coq's conversion check forces the property we model to be exactly the
        property we assumed, not a weakened restatement.

      [quarantine_has_a_model]    — `exists O, QuarantineHolds O`, proved from the
        model with NO use of the twenty axioms (check with `Print Assumptions`:
        only the backend's scalar-width parameters appear).

    WHAT THAT BUYS.
      * CONSISTENCY. `QuarantineHolds` is satisfiable in plain Coq, so the
        twenty axioms cannot, ON THEIR OWN, derive False. That bounds OUR
        axioms only — it says nothing about the backend axioms every theorem
        also inherits, and a single unsound one there defeats any quarantine
        model (as `Primitives.mk_array` did, for two revisions: see §5 and
        ../../AENEAS_COQ_MKARRAY_BUG.md). The exact mechanical claim is in §5;
        do not quote this bullet as a non-vacuity result on its own.
      * FAITHFULNESS. The witness is not some degenerate model cooked up to
        satisfy the statements: `slice`/`array` are ALREADY sigma-types over
        `list T` in Primitives.v — only the OPERATIONS are opaque — and the model
        interprets each one the way Rust does: length = list length, indexing =
        `nth_error`, range-slicing = `firstn`/`skipn`, out-of-range slicing =
        the `None` that `core_slice_index_Slice_index` turns into `Fail`,
        `copy_from_slice` = "lengths must match, then dst becomes src",
        `array_from_slice` = "a length-matching slice IS the array", the
        mutable-borrow WRITE-BACK of a window `[a,b)` = the splice
        `firstn a ++ sub' ++ skipn b` (so the array keeps its other bytes and
        takes the new ones inside the window), `u32::to_le_bytes` = the four
        base-256 digits, and the u8 bitwise ops = the `Z` bitwise ops (in
        range: proved, not assumed).

    WHAT `exists O, QuarantineHolds O` IS AN INTERPRETATION OF. The bundle is a
    record of FUNCTIONS, not a re-parameterisation that could drift away from
    the constants the extracted code runs on. Every field of `primitives_ops`
    below is either the bare `Primitives`/`Update_FunsExternal` `Axiom` itself
    (`slice_len`, `array_to_slice`, `array_index_usize`, `slice_index_usize`,
    `core_array_Array_index_mut`, `core_slice_Slice_copy_from_slice`,
    `array_from_slice`, `core_num_U32_to_le_bytes`, `core_num_U32_from_le_bytes`)
    or a `Definition` that merely applies such an axiom
    (`u8_xor`/`u8_or` = the per-width aliases of `scalar_xor`/`scalar_or`; the
    `SliceIndex`/`IndexMut` instance records). No field is a fresh opaque
    constant, and `quarantine_is_the_axioms` — which type-checks
    `QuarantineHolds primitives_ops` against Update_Safety's block by `exact`,
    conjunct for conjunct — is what forces that correspondence to be exact
    rather than merely plausible. So "the property is satisfiable" really is a
    statement about an interpretation of those constants.

    THE SIDE CONDITION, AND THAT IT HOLDS. A satisfiability argument of this
    shape is only valid if the symbols being modelled carry NO OTHER laws that
    the model would have to respect simultaneously. Otherwise a model could
    satisfy our twenty statements while contradicting some other axiom about
    the same constants, and the combined theory would still be inconsistent.
    VERIFIED for this development: in `Primitives.v`, each of
      slice_len, array_to_slice, array_from_slice, array_index_usize,
      slice_index_usize, core_array_Array_index_mut,
      core_slice_Slice_copy_from_slice,
      core_slice_index_SliceIndexRangeUsizeSlice_get/_index(_mut),
      scalar_xor, scalar_or
    occurs ONLY in its own bare `Axiom` declaration and in `Definition`s that
    merely apply it (`array_to_slice_mut`, `slice_index_mut_usize`, the
    `SliceIndex`/`IndexMut` instance records, the per-width `uN_xor`/`uN_or`
    aliases). There is no `Lemma`, no `Axiom`, and no `Hypothesis` in the file
    that states any property of any of them. (The only equational axioms in
    `Primitives.v` — `alloc_vec_Vec_index_eq`, `alloc_vec_Vec_index_mut_eq` —
    are about `alloc_vec_Vec`, which this development never touches, and the
    scalar-width axioms `usize_max`/`isize_min`/`isize_max` + their bounds are
    inherited unmodelled by both theorems alike.)

    WHAT IT DOES NOT BUY — read this before quoting the result.
      * It says NOTHING about upstream's symbols. `Primitives.array_index_usize`
        et al stay uninterpreted constants; no one can prove they behave like the
        model, because there is nothing to prove them from. Update_Safety's
        axioms must therefore REMAIN axioms; this file is a companion witness,
        not a replacement, and it is deliberately not imported by any proof.
      * The RANGE write-back is now modelled for real (the splice), which is what
        Q15/Q16 constrain. The two write-backs that no axiom mentions are still
        modelled loosely: `core_slice_index_SliceIndex_get_mut`'s (it splices when
        the option is `Some` and is the identity on `None`) and
        `array_from_slice`'s length-mismatch branch (it keeps the old array). No
        statement in the record touches either, so nothing downstream can lean on
        them; a theorem that did would need a stronger model.
      * LANDMINE in `splice_or`: its length guard makes the modelled write-back a
        SILENT NO-OP when the replacement slice has the wrong length (it returns
        the original list rather than failing). That is harmless today because
        Q15 and Q16 both carry the hypothesis `to_Z (slice_len sub') = to_Z b -
        to_Z a`, so neither can ever reach the fallback. Any FUTURE axiom about
        `back` at unconstrained lengths would be satisfied vacuously by this
        model — it must either carry the same length hypothesis or the model must
        be changed to make the mismatch case observable.
      * Q20 is stated about `mk_array4`, the four-`u8` array literal the
        extracted parser decodes. That is a total Coq DEFINITION carrying its own
        length proof (`Update_FunsExternal.v`), NOT the Aeneas backend's
        `mk_array` axiom — which is INCONSISTENT (`array T n` is empty at
        `T := Empty_set, n > 0`, so `mk_array` proves `False`; minimal
        reproduction in `../../AENEAS_COQ_MKARRAY_BUG.md`) and which `extract.sh`
        therefore rewrites out of the generated body. Q20 constrains only
        `array_index_usize`, exactly like Q7/Q12/Q17. A law at general `n` is
        still out of reach for the same shape of reason the bug has: there is no
        total constructor of `array T n` for an arbitrary `T`.
      * It is orthogonal to the Aeneas backend's remaining base axioms
        (`usize_max`, `isize_min/max` and their three bound axioms — the
        scalar-width parameters), which this file inherits and does not attempt
        to model. Those six are consistent: `Print Assumptions
        quarantine_has_a_model` reports exactly them and nothing else.

    Build position: AFTER Update_Safety.v (it imports the axioms in order to
    check them against the record). Nothing depends on this file. *)

Require Import Primitives.
Import Primitives.
Require Import Coq.ZArith.ZArith.
Require Import Coq.Lists.List.
Import ListNotations.
Require Import Lia.
Require Import Update_Types.
Import Update_Types.
Require Import Update_FunsExternal.
Import Update_FunsExternal.
Require Import Update_Safety.
Local Open Scope Z_scope.
Local Open Scope Primitives_scope.

(* ===================================================================== *)
(* 0. The twenty statements, packaged as one predicate over an            *)
(*    operation bundle. Instantiating at the Primitives symbols must give *)
(*    back EXACTLY Update_Safety's axiom block (checked in §2).           *)
(* ===================================================================== *)

Record OpaqueOps := mkOpaqueOps {
  op_slice_len : forall (T : Type), slice T -> usize;
  op_array_to_slice : forall (T : Type) (n : usize), array T n -> slice T;
  op_array_index : forall (T : Type) (n : usize), array T n -> usize -> result T;
  op_slice_index : forall (T : Type), slice T -> usize -> result T;
  op_range_inst : forall (T : Type),
    core_slice_index_SliceIndex (core_ops_range_Range usize) (slice T) (slice T);
  op_index_mut_slice_inst : forall (T Idx Output : Type),
    core_slice_index_SliceIndex Idx (slice T) Output ->
    core_ops_index_IndexMut (slice T) Idx Output;
  op_array_index_mut : forall (T Idx Output : Type) (N : usize),
    core_ops_index_IndexMut (slice T) Idx Output -> array T N -> Idx ->
    result (Output * (Output -> array T N));
  op_copy_from_slice : forall (T : Type),
    core_marker_Copy T -> slice T -> slice T -> result (slice T);
  op_array_from_slice : forall (T : Type) (n : usize), array T n -> slice T -> array T n;
  op_u8_xor : u8 -> u8 -> u8;
  op_u8_or : u8 -> u8 -> u8;
  op_u32_to_le_bytes : u32 -> array u8 4%usize;
  op_u32_from_le_bytes : array u8 4%usize -> u32;
}.

Definition mk_range (a b : usize) : core_ops_range_Range usize :=
  {| core_ops_range_Range_start := a; core_ops_range_Range_end_ := b |}.

Definition QuarantineHolds (O : OpaqueOps) : Prop :=
  (* Q1 — in-bounds array reads succeed. *)
  (forall (T : Type) (n : usize) (a : array T n) (i : usize),
     0 <= to_Z i < to_Z n -> exists v, O.(op_array_index) T n a i = Ok v)
  /\
  (* Q2 — in-bounds slice reads succeed. *)
  (forall (T : Type) (s : slice T) (i : usize),
     0 <= to_Z i < to_Z (O.(op_slice_len) T s) ->
     exists v, O.(op_slice_index) T s i = Ok v)
  /\
  (* Q3 — array_to_slice preserves length. *)
  (forall (T : Type) (n : usize) (a : array T n),
     to_Z (O.(op_slice_len) T (O.(op_array_to_slice) T n a)) = to_Z n)
  /\
  (* Q4 — a valid Range sub-slices a slice, with length end-start. *)
  (forall (T : Type) (s : slice T) (a b : usize),
     0 <= to_Z a -> to_Z a <= to_Z b -> to_Z b <= to_Z (O.(op_slice_len) T s) ->
     exists sub,
       core_slice_index_Slice_index (O.(op_range_inst) T) s (mk_range a b) = Ok sub
       /\ to_Z (O.(op_slice_len) T sub) = to_Z b - to_Z a)
  /\
  (* Q5 — a valid Range mutably sub-slices an array, with length end-start. *)
  (forall (T : Type) (N : usize) (arr : array T N) (a b : usize),
     0 <= to_Z a -> to_Z a <= to_Z b -> to_Z b <= to_Z N ->
     exists sub back,
       O.(op_array_index_mut) T (core_ops_range_Range usize) (slice T) N
         (O.(op_index_mut_slice_inst) T (core_ops_range_Range usize) (slice T)
            (O.(op_range_inst) T)) arr (mk_range a b) = Ok (sub, back)
       /\ to_Z (O.(op_slice_len) T sub) = to_Z b - to_Z a)
  /\
  (* Q6 — copy_from_slice succeeds on equal lengths. *)
  (forall (T : Type) (m : core_marker_Copy T) (dst src : slice T),
     to_Z (O.(op_slice_len) T dst) = to_Z (O.(op_slice_len) T src) ->
     exists dst', O.(op_copy_from_slice) T m dst src = Ok dst')
  /\
  (* Q7 — array indexing depends only on the numeric index. *)
  (forall (T : Type) (n : usize) (a : array T n) (i j : usize),
     to_Z i = to_Z j -> O.(op_array_index) T n a i = O.(op_array_index) T n a j)
  /\
  (* Q8 — likewise for slices. *)
  (forall (T : Type) (s : slice T) (i j : usize),
     to_Z i = to_Z j -> O.(op_slice_index) T s i = O.(op_slice_index) T s j)
  /\
  (* Q9 — a range sub-slice that SUCCEEDED has the length the range asked for. *)
  (forall (T : Type) (s sub : slice T) (a b : usize),
     core_slice_index_Slice_index (O.(op_range_inst) T) s (mk_range a b) = Ok sub ->
     to_Z (O.(op_slice_len) T sub) = to_Z b - to_Z a)
  /\
  (* Q10 — … and reading it at i reads the parent at start + i. *)
  (forall (T : Type) (s sub : slice T) (a b i j : usize),
     core_slice_index_Slice_index (O.(op_range_inst) T) s (mk_range a b) = Ok sub ->
     0 <= to_Z i -> to_Z i < to_Z b - to_Z a -> to_Z j = to_Z a + to_Z i ->
     O.(op_slice_index) T sub i = O.(op_slice_index) T s j)
  /\
  (* Q11 — a copy that SUCCEEDED leaves the destination holding the source. *)
  (forall (T : Type) (m : core_marker_Copy T) (dst src dst' : slice T),
     O.(op_copy_from_slice) T m dst src = Ok dst' -> dst' = src)
  /\
  (* Q12 — a length-matching slice written back into an array reads like it. *)
  (forall (T : Type) (n : usize) (a : array T n) (s : slice T) (i : usize),
     to_Z (O.(op_slice_len) T s) = to_Z n ->
     O.(op_array_index) T n (O.(op_array_from_slice) T n a s) i = O.(op_slice_index) T s i)
  /\
  (* Q13/Q14 — the u8 bitwise ops are the Z bitwise ops on the values. *)
  (forall x y : u8, to_Z (O.(op_u8_xor) x y) = Z.lxor (to_Z x) (to_Z y))
  /\
  (forall x y : u8, to_Z (O.(op_u8_or) x y) = Z.lor (to_Z x) (to_Z y))
  /\
  (* Q15 — WRITE-BACK, inside the window: after replacing [a,b) by sub', the
     array reads there like sub'. *)
  (forall (T : Type) (N : usize) (arr : array T N) (a b : usize)
          (sub : slice T) (back : slice T -> array T N) (sub' : slice T) (i j : usize),
     O.(op_array_index_mut) T (core_ops_range_Range usize) (slice T) N
       (O.(op_index_mut_slice_inst) T (core_ops_range_Range usize) (slice T)
          (O.(op_range_inst) T)) arr (mk_range a b) = Ok (sub, back) ->
     to_Z (O.(op_slice_len) T sub') = to_Z b - to_Z a ->
     to_Z a <= to_Z i -> to_Z i < to_Z b -> to_Z j = to_Z i - to_Z a ->
     O.(op_array_index) T N (back sub') i = O.(op_slice_index) T sub' j)
  /\
  (* Q16 — … and outside the window the array is unchanged. *)
  (forall (T : Type) (N : usize) (arr : array T N) (a b : usize)
          (sub : slice T) (back : slice T -> array T N) (sub' : slice T) (i : usize),
     O.(op_array_index_mut) T (core_ops_range_Range usize) (slice T) N
       (O.(op_index_mut_slice_inst) T (core_ops_range_Range usize) (slice T)
          (O.(op_range_inst) T)) arr (mk_range a b) = Ok (sub, back) ->
     to_Z (O.(op_slice_len) T sub') = to_Z b - to_Z a ->
     (to_Z i < to_Z a \/ to_Z b <= to_Z i) ->
     O.(op_array_index) T N (back sub') i = O.(op_array_index) T N arr i)
  /\
  (* Q17 — array_to_slice preserves reads, not only the length (Q3). *)
  (forall (T : Type) (n : usize) (a : array T n) (i : usize),
     O.(op_slice_index) T (O.(op_array_to_slice) T n a) i = O.(op_array_index) T n a i)
  /\
  (* Q18 — u32::to_le_bytes is the base-256 digit decomposition. *)
  (forall (x : u32) (i : usize), 0 <= to_Z i < 4 ->
     exists bv, O.(op_array_index) u8 4%usize (O.(op_u32_to_le_bytes) x) i = Ok bv
             /\ to_Z bv = (to_Z x / 256 ^ to_Z i) mod 256)
  /\
  (* Q19 — u32::from_le_bytes is the base-256 digit RECOMPOSITION (mirror of
     Q18: digit i of the decoded value is byte i of the array). *)
  (forall (a : array u8 4%usize) (i : usize), 0 <= to_Z i < 4 ->
     exists bv, O.(op_array_index) u8 4%usize a i = Ok bv
             /\ (to_Z (O.(op_u32_from_le_bytes) a) / 256 ^ to_Z i) mod 256
                = to_Z bv)
  /\
  (* Q20 — the four-byte array LITERAL the parser decodes reads back its four
     elements. `mk_array4` is a total Coq DEFINITION carrying its own length
     proof (Update_FunsExternal.v), not the backend's inconsistent `mk_array`
     axiom, so this constrains only `op_array_index`. *)
  (forall b0 b1 b2 b3 : u8,
     O.(op_array_index) u8 4%usize (mk_array4 b0 b1 b2 b3) 0%usize = Ok b0
     /\ O.(op_array_index) u8 4%usize (mk_array4 b0 b1 b2 b3) 1%usize = Ok b1
     /\ O.(op_array_index) u8 4%usize (mk_array4 b0 b1 b2 b3) 2%usize = Ok b2
     /\ O.(op_array_index) u8 4%usize (mk_array4 b0 b1 b2 b3) 3%usize = Ok b3).

(* ===================================================================== *)
(* 1. The bundle of the ACTUAL opaque symbols the extracted code runs on. *)
(* ===================================================================== *)

Definition primitives_ops : OpaqueOps := {|
  op_slice_len := fun T => @slice_len T;
  op_array_to_slice := fun T n => @array_to_slice T n;
  op_array_index := fun T n => @array_index_usize T n;
  op_slice_index := fun T => @slice_index_usize T;
  op_range_inst := core_slice_index_SliceIndexRangeUsizeSliceInst;
  op_index_mut_slice_inst :=
    fun T Idx Output => @core_ops_index_IndexMutSliceInst T Idx Output;
  op_array_index_mut :=
    fun T Idx Output N => @core_array_Array_index_mut T Idx Output N;
  op_copy_from_slice := fun T => @core_slice_Slice_copy_from_slice T;
  op_array_from_slice := fun T n => @array_from_slice T n;
  op_u8_xor := u8_xor;
  op_u8_or := u8_or;
  op_u32_to_le_bytes := core_num_U32_to_le_bytes;
  op_u32_from_le_bytes := core_num_U32_from_le_bytes;
|}.

(* ===================================================================== *)
(* 2. The record IS the axiom block — Coq checks the restatement.         *)
(*    (This lemma DOES depend on the twenty axioms; that is the point.)   *)
(* ===================================================================== *)

Lemma quarantine_is_the_axioms : QuarantineHolds primitives_ops.
Proof.
  unfold QuarantineHolds; cbn [op_slice_len op_array_to_slice op_array_index
    op_slice_index op_range_inst op_index_mut_slice_inst op_array_index_mut
    op_copy_from_slice op_u32_to_le_bytes op_u32_from_le_bytes
    primitives_ops].
  repeat apply conj.
  - exact (fun T n a i H => @array_index_usize_ok T n a i H).
  - exact (fun T s i H => @slice_index_usize_ok T s i H).
  - exact (fun T n a => @slice_len_array_to_slice T n a).
  - exact (fun T s a b H1 H2 H3 => @slice_index_range_ok T s a b H1 H2 H3).
  - exact (fun T N arr a b H1 H2 H3 => @array_index_mut_range_ok T N arr a b H1 H2 H3).
  - exact (fun T m dst src H => @copy_from_slice_ok T m dst src H).
  - exact (fun T n a i j H => @array_index_usize_ext T n a i j H).
  - exact (fun T s i j H => @slice_index_usize_ext T s i j H).
  - exact (fun T s sub a b H => @slice_index_range_len T s sub a b H).
  - exact (fun T s sub a b i j H H1 H2 H3 =>
             @slice_index_range_val T s sub a b i j H H1 H2 H3).
  - exact (fun T m dst src dst' H => @copy_from_slice_val T m dst src dst' H).
  - exact (fun T n a s i H => @array_from_slice_val T n a s i H).
  - exact u8_xor_to_Z.
  - exact u8_or_to_Z.
  - exact (fun T N arr a b sub back sub' i j H H1 H2 H3 H4 =>
             @array_index_mut_range_val_in T N arr a b sub back sub' i j H H1 H2 H3 H4).
  - exact (fun T N arr a b sub back sub' i H H1 H2 =>
             @array_index_mut_range_val_out T N arr a b sub back sub' i H H1 H2).
  - exact (fun T n a i => @slice_index_array_to_slice T n a i).
  - exact (fun x i H => u32_to_le_bytes_val x i H).
  - exact (fun a i H => u32_from_le_bytes_val a i H).
  - exact (fun b0 b1 b2 b3 => mk_array4_val b0 b1 b2 b3).
Qed.

(* ===================================================================== *)
(* 3. The MODEL. slice/array are already sigma-types over `list T`; we    *)
(*    give the operations their intended list semantics.                  *)
(* ===================================================================== *)

Definition zlen {T} (l : list T) : Z := Z.of_nat (length l).

(* --- lengths ---------------------------------------------------------- *)

Definition model_slice_len (T : Type) (s : slice T) : usize.
Proof.
  refine (exist _ (zlen (proj1_sig s)) _).
  pose proof (proj2_sig s) as Hs. cbn [scalar_min scalar_max].
  unfold usize_min, zlen in *. lia.
Defined.

Lemma to_Z_model_slice_len : forall (T : Type) (s : slice T),
  to_Z (model_slice_len T s) = zlen (proj1_sig s).
Proof. reflexivity. Qed.

Definition model_array_to_slice (T : Type) (n : usize) (a : array T n) : slice T.
Proof.
  refine (exist _ (proj1_sig a) _).
  pose proof (proj2_sig a) as Ha. pose proof (to_Z_usize_bounds n) as Hn.
  unfold to_Z in *. lia.
Defined.

(* --- element reads ---------------------------------------------------- *)

Definition opt_result {A} (o : option A) : result A :=
  match o with Some v => Ok v | None => Fail_ Failure end.

Definition model_array_index (T : Type) (n : usize) (a : array T n) (i : usize)
  : result T := opt_result (nth_error (proj1_sig a) (Z.to_nat (to_Z i))).

Definition model_slice_index (T : Type) (s : slice T) (i : usize)
  : result T := opt_result (nth_error (proj1_sig s) (Z.to_nat (to_Z i))).

Lemma nth_error_in_range : forall {A} (l : list A) (k : Z),
  0 <= k < zlen l -> exists v, nth_error l (Z.to_nat k) = Some v.
Proof.
  intros A l k Hk. destruct (nth_error l (Z.to_nat k)) as [v|] eqn:E.
  - exists v; reflexivity.
  - exfalso. apply nth_error_None in E. unfold zlen in Hk. lia.
Qed.

(* --- range sub-slicing ------------------------------------------------ *)

Definition sub_list {T} (l : list T) (a b : usize) : list T :=
  firstn (Z.to_nat (to_Z b - to_Z a)) (skipn (Z.to_nat (to_Z a)) l).

Lemma sub_list_zlen_le : forall {T} (l : list T) (a b : usize),
  zlen (sub_list l a b) <= zlen l.
Proof.
  intros T l a b. unfold zlen, sub_list.
  rewrite firstn_length, skipn_length. lia.
Qed.

Definition model_subslice (T : Type) (s : slice T) (a b : usize) : slice T.
Proof.
  refine (exist _ (sub_list (proj1_sig s) a b) _).
  pose proof (proj2_sig s) as Hs.
  pose proof (sub_list_zlen_le (proj1_sig s) a b) as Hle. unfold zlen in Hle.
  exact (Z.le_trans _ _ _ Hle Hs).
Defined.

Lemma sub_list_length : forall {T} (l : list T) (a b : usize),
  0 <= to_Z a -> to_Z a <= to_Z b -> to_Z b <= zlen l ->
  zlen (sub_list l a b) = to_Z b - to_Z a.
Proof.
  intros T l a b H1 H2 H3. unfold zlen, sub_list in *.
  rewrite firstn_length, skipn_length. lia.
Qed.

Lemma model_subslice_len : forall (T : Type) (s : slice T) (a b : usize),
  0 <= to_Z a -> to_Z a <= to_Z b -> to_Z b <= zlen (proj1_sig s) ->
  to_Z (model_slice_len T (model_subslice T s a b)) = to_Z b - to_Z a.
Proof.
  intros T s a b H1 H2 H3.
  rewrite to_Z_model_slice_len. unfold model_subslice; cbn [proj1_sig].
  apply sub_list_length; assumption.
Qed.

(* Rust semantics of `&s[a..b]`: in range -> the sub-slice; out of range ->
   `None`, which `core_slice_index_Slice_index` turns into a panic (`Fail`). *)
Definition model_range_get (T : Type) (r : core_ops_range_Range usize) (s : slice T)
  : result (option (slice T)) :=
  let a := r.(core_ops_range_Range_start) in
  let b := r.(core_ops_range_Range_end_) in
  match Z_le_dec (to_Z a) (to_Z b), Z_le_dec (to_Z b) (to_Z (model_slice_len T s)) with
  | left _, left _ => Ok (Some (model_subslice T s a b))
  | _, _ => Ok None
  end.

Definition model_range_index (T : Type) (r : core_ops_range_Range usize) (s : slice T)
  : result (slice T) :=
  match model_range_get T r s with
  | Ok (Some sub) => Ok sub
  | Ok None => Fail_ Failure
  | Fail_ e => Fail_ e
  end.

(* --- the WRITE-BACK of a mutable window: the real splice ---------------- *)

(* `&mut s[a..b]` handed back a new window `new`: the result keeps s's bytes
   before a and from b on, and takes `new` in between. *)
Definition splice_list {T} (l : list T) (a b : usize) (new : list T) : list T :=
  firstn (Z.to_nat (to_Z a)) l ++ new ++ skipn (Z.to_nat (to_Z b)) l.

(* A slice is a list with a length bound, so the splice is only usable as a
   slice when it does not change the length. On every path Aeneas can produce
   (the window handed back is the window that was borrowed) it does not; off
   those paths the model keeps the original, which is what makes this total. *)
Definition splice_or (T : Type) (s : slice T) (a b : usize) (new : list T) : list T :=
  if Nat.eqb (length (splice_list (proj1_sig s) a b new)) (length (proj1_sig s))
  then splice_list (proj1_sig s) a b new else proj1_sig s.

Lemma splice_or_length : forall (T : Type) (s : slice T) (a b : usize) (new : list T),
  length (splice_or T s a b new) = length (proj1_sig s).
Proof.
  intros T s a b new. unfold splice_or.
  destruct (Nat.eqb_spec (length (splice_list (proj1_sig s) a b new))
                         (length (proj1_sig s))) as [E|_];
    [ exact E | reflexivity ].
Qed.

Definition model_splice (T : Type) (s : slice T) (a b : usize) (sub' : slice T)
  : slice T.
Proof.
  refine (exist _ (splice_or T s a b (proj1_sig sub')) _).
  rewrite splice_or_length. exact (proj2_sig s).
Defined.

(* The mutable variants keep the read direction and write the new window back
   into the parent (Q15/Q16). `get_mut`'s write-back — which no statement in the
   record mentions — splices on `Some` and keeps the parent on `None`. *)
Definition model_range_inst (T : Type) :
  core_slice_index_SliceIndex (core_ops_range_Range usize) (slice T) (slice T) := {|
  core_slice_index_SliceIndex_sealedInst := tt;
  core_slice_index_SliceIndex_get := model_range_get T;
  core_slice_index_SliceIndex_get_mut :=
    fun r s => match model_range_get T r s with
               | Ok o => Ok (o, fun o' =>
                   match o' with
                   | Some sub' => model_splice T s r.(core_ops_range_Range_start)
                                                    r.(core_ops_range_Range_end_) sub'
                   | None => s
                   end)
               | Fail_ e => Fail_ e
               end;
  core_slice_index_SliceIndex_get_unchecked := fun _ _ => Fail_ Failure;
  core_slice_index_SliceIndex_get_unchecked_mut := fun _ _ => Fail_ Failure;
  core_slice_index_SliceIndex_index := model_range_index T;
  core_slice_index_SliceIndex_index_mut :=
    fun r s => match model_range_index T r s with
               | Ok sub => Ok (sub, model_splice T s r.(core_ops_range_Range_start)
                                                       r.(core_ops_range_Range_end_))
               | Fail_ e => Fail_ e
               end;
|}.

Definition model_index_mut_slice_inst (T Idx Output : Type)
  (inst : core_slice_index_SliceIndex Idx (slice T) Output)
  : core_ops_index_IndexMut (slice T) Idx Output := {|
  core_ops_index_IndexMut_indexInst := core_ops_index_IndexSliceInst inst;
  core_ops_index_IndexMut_index_mut :=
    fun s i => inst.(core_slice_index_SliceIndex_index_mut) i s;
|}.

(* --- array_from_slice: Rust's write-back of a length-matching slice ------ *)

(* `array T n` is `{l : list T | Z.of_nat (length l) = to_Z n}`, so a slice whose
   length matches IS an array; a length mismatch cannot happen on the paths the
   axioms speak about, and the model then keeps the original array. *)
Definition model_array_from_slice (T : Type) (n : usize) (a : array T n) (s : slice T)
  : array T n :=
  match Z.eq_dec (Z.of_nat (length (proj1_sig s))) (to_Z n) with
  | left Hs => exist _ (proj1_sig s) Hs
  | right _ => a
  end.

(* Rust's `impl IndexMut for [T; N]` forwards to the slice impl; so does this,
   including the write-back: the slice-level write-back is composed with
   `array_from_slice` to land back in the array type. *)
Definition model_array_index_mut (T Idx Output : Type) (N : usize)
  (inst : core_ops_index_IndexMut (slice T) Idx Output) (a : array T N) (i : Idx)
  : result (Output * (Output -> array T N)) :=
  match inst.(core_ops_index_IndexMut_index_mut) (model_array_to_slice T N a) i with
  | Ok (out, back) => Ok (out, fun o => model_array_from_slice T N a (back o))
  | Fail_ e => Fail_ e
  end.

(* --- copy_from_slice --------------------------------------------------- *)

(* Rust: panics unless the lengths match; on success dst holds src's elements. *)
Definition model_copy_from_slice (T : Type) (_ : core_marker_Copy T)
  (dst src : slice T) : result (slice T) :=
  if Z.eqb (to_Z (model_slice_len T dst)) (to_Z (model_slice_len T src))
  then Ok src else Fail_ Failure.

(* --- u8 bitwise ops ---------------------------------------------------- *)

Lemma log2_lt8 : forall a, 0 <= a < 256 -> Z.log2 a < 8.
Proof.
  intros a Ha. destruct (Z.eq_dec a 0) as [->|Hne]; [ cbn; lia |].
  apply (proj1 (Z.log2_lt_pow2 a 8 ltac:(lia))). cbn. lia.
Qed.

(* NB: destruct the sigma FIRST. Reducing `scalar_min/max` inside a hypothesis
   also reduces them inside `proj1_sig`'s implicit predicate argument, after
   which `lia` no longer recognises the goal's `to_Z x` and the hypothesis's
   `proj1_sig x` as the same atom. *)
Lemma to_Z_u8_range : forall x : u8, 0 <= to_Z x < 256.
Proof.
  intro x. destruct x as [z Hb]. unfold to_Z; simpl.
  cbv beta iota delta [scalar_min scalar_max u8_min u8_max] in Hb. lia.
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

Definition model_u8_xor (x y : u8) : u8 :=
  exist _ (Z.lxor (to_Z x) (to_Z y)) (u8_bnd_xor x y).
Definition model_u8_or (x y : u8) : u8 :=
  exist _ (Z.lor (to_Z x) (to_Z y)) (u8_bnd_or x y).

(* --- u32::to_le_bytes: the four base-256 digits ------------------------- *)

Lemma byte_digit_bnd : forall z k : Z,
  scalar_min U8 <= (z / 256 ^ k) mod 256 <= scalar_max U8.
Proof.
  intros z k. change (scalar_min U8) with 0. change (scalar_max U8) with 255.
  pose proof (Z.mod_pos_bound (z / 256 ^ k) 256 ltac:(lia)). lia.
Qed.

Definition mk_digit (z k : Z) : u8 := exist _ ((z / 256 ^ k) mod 256) (byte_digit_bnd z k).

Definition model_u32_to_le_bytes (x : u32) : array u8 4%usize.
Proof.
  refine (exist _ [ mk_digit (to_Z x) 0; mk_digit (to_Z x) 1;
                    mk_digit (to_Z x) 2; mk_digit (to_Z x) 3 ] _).
  reflexivity.
Defined.

(* --- u32::from_le_bytes: recompose the four base-256 digits ------------- *)

Definition byte_at (a : array u8 4%usize) (k : nat) : Z :=
  match nth_error (proj1_sig a) k with Some b => to_Z b | None => 0 end.

Lemma byte_at_bnd : forall a k, 0 <= byte_at a k < 256.
Proof.
  intros a k. unfold byte_at.
  destruct (nth_error (proj1_sig a) k) as [b|]; [ apply to_Z_u8_range | lia ].
Qed.

Lemma from_le_bnd : forall a : array u8 4%usize,
  scalar_min U32
  <= byte_at a 0 + 256 * byte_at a 1 + 65536 * byte_at a 2
     + 16777216 * byte_at a 3
  <= scalar_max U32.
Proof.
  intros a. change (scalar_min U32) with 0.
  change (scalar_max U32) with 4294967295.
  pose proof (byte_at_bnd a 0). pose proof (byte_at_bnd a 1).
  pose proof (byte_at_bnd a 2). pose proof (byte_at_bnd a 3). lia.
Qed.

Definition model_u32_from_le_bytes (a : array u8 4%usize) : u32 :=
  exist _ (byte_at a 0 + 256 * byte_at a 1 + 65536 * byte_at a 2
           + 16777216 * byte_at a 3) (from_le_bnd a).

(* --- base-256 digit arithmetic, for Q19 -------------------------------- *)

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
  (* digit 0 *)
  assert (D0 : (v0 + 256 * v1 + 65536 * v2 + 16777216 * v3) mod 256 = v0)
    by (rewrite E0; apply zmod_add_small; lia).
  (* the quotient by 256 drops digit 0 *)
  assert (Q1 : (v0 + 256 * v1 + 65536 * v2 + 16777216 * v3) / 256
               = v1 + 256 * v2 + 65536 * v3)
    by (rewrite E0; apply zdiv_add_small; lia).
  assert (Q2 : (v1 + 256 * v2 + 65536 * v3) / 256 = v2 + 256 * v3)
    by (rewrite E1; apply zdiv_add_small; lia).
  assert (Q3 : (v2 + 256 * v3) / 256 = v3) by (apply zdiv_add_small; lia).
  (* 256^2 and 256^3 as iterated division by 256 *)
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

(* --- list lemmas for the range-read law -------------------------------- *)

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

(* --- list lemmas for the write-back (splice) laws ----------------------- *)

(* The nat-level shape of a well-formed splice, used by all four lemmas. *)
Lemma splice_nat_facts : forall {T} (l new : list T) (a b : usize),
  to_Z a <= to_Z b -> to_Z b <= zlen l -> zlen new = to_Z b - to_Z a ->
  Z.of_nat (Z.to_nat (to_Z a)) = to_Z a
  /\ Z.of_nat (Z.to_nat (to_Z b)) = to_Z b
  /\ (Z.to_nat (to_Z a) <= Z.to_nat (to_Z b))%nat
  /\ (Z.to_nat (to_Z b) <= length l)%nat
  /\ length new = (Z.to_nat (to_Z b) - Z.to_nat (to_Z a))%nat.
Proof.
  intros T l new a b Hab Hbl Hnew.
  pose proof (usize_nonneg a) as Ha0. pose proof (usize_nonneg b) as Hb0.
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

(* --- the bundle -------------------------------------------------------- *)

Definition model_ops : OpaqueOps := {|
  op_slice_len := model_slice_len;
  op_array_to_slice := model_array_to_slice;
  op_array_index := model_array_index;
  op_slice_index := model_slice_index;
  op_range_inst := model_range_inst;
  op_index_mut_slice_inst := model_index_mut_slice_inst;
  op_array_index_mut := model_array_index_mut;
  op_copy_from_slice := model_copy_from_slice;
  op_array_from_slice := model_array_from_slice;
  op_u8_xor := model_u8_xor;
  op_u8_or := model_u8_or;
  op_u32_to_le_bytes := model_u32_to_le_bytes;
  op_u32_from_le_bytes := model_u32_from_le_bytes;
|}.

(* ===================================================================== *)
(* 4. The witness: all twenty statements hold of the model.               *)
(* ===================================================================== *)

Lemma model_Q3 : forall (T : Type) (n : usize) (a : array T n),
  to_Z (model_slice_len T (model_array_to_slice T n a)) = to_Z n.
Proof.
  intros T n a. rewrite to_Z_model_slice_len.
  unfold model_array_to_slice; cbn [proj1_sig]. exact (proj2_sig a).
Qed.

Lemma model_Q4 : forall (T : Type) (s : slice T) (a b : usize),
  0 <= to_Z a -> to_Z a <= to_Z b -> to_Z b <= to_Z (model_slice_len T s) ->
  exists sub,
    core_slice_index_Slice_index (model_range_inst T) s (mk_range a b) = Ok sub
    /\ to_Z (model_slice_len T sub) = to_Z b - to_Z a.
Proof.
  intros T s a b H1 H2 H3.
  exists (model_subslice T s a b). split.
  - unfold core_slice_index_Slice_index; cbn [core_slice_index_SliceIndex_get
      model_range_inst]. unfold model_range_get, mk_range;
      cbn [core_ops_range_Range_start core_ops_range_Range_end_].
    destruct (Z_le_dec (to_Z a) (to_Z b)) as [|Hc]; [| lia].
    destruct (Z_le_dec (to_Z b) (to_Z (model_slice_len T s))) as [|Hc]; [| lia].
    reflexivity.
  - (* H3's `to_Z (model_slice_len T s)` is convertible to `zlen (proj1_sig s)`. *)
    apply model_subslice_len; assumption.
Qed.

Lemma mk_range_start : forall a b, (mk_range a b).(core_ops_range_Range_start) = a.
Proof. reflexivity. Qed.
Lemma mk_range_end : forall a b, (mk_range a b).(core_ops_range_Range_end_) = b.
Proof. reflexivity. Qed.

(* The array-as-slice has the array's list, hence the array's length. *)
Lemma zlen_array_to_slice : forall (T : Type) (N : usize) (arr : array T N),
  zlen (proj1_sig (model_array_to_slice T N arr)) = to_Z N.
Proof.
  intros T N arr. pose proof (model_Q3 T N arr) as H.
  rewrite to_Z_model_slice_len in H. exact H.
Qed.

(* What a successful mutable range borrow of an array COMPUTES TO — window and
   write-back both. This is the fact Q5/Q15/Q16 are all read off. *)
Lemma model_index_mut_eq : forall (T : Type) (N : usize) (arr : array T N) (a b : usize),
  to_Z a <= to_Z b -> to_Z b <= to_Z N ->
  model_array_index_mut T (core_ops_range_Range usize) (slice T) N
    (model_index_mut_slice_inst T (core_ops_range_Range usize) (slice T)
       (model_range_inst T)) arr (mk_range a b)
  = Ok (model_subslice T (model_array_to_slice T N arr) a b,
        fun o => model_array_from_slice T N arr
                   (model_splice T (model_array_to_slice T N arr) a b o)).
Proof.
  intros T N arr a b H1 H2.
  assert (Hget : model_range_index T (mk_range a b) (model_array_to_slice T N arr)
                 = Ok (model_subslice T (model_array_to_slice T N arr) a b)).
  { unfold model_range_index, model_range_get. cbv zeta.
    rewrite mk_range_start, mk_range_end.
    destruct (Z_le_dec (to_Z a) (to_Z b)) as [K1|K1]; [| lia].
    destruct (Z_le_dec (to_Z b)
                (to_Z (model_slice_len T (model_array_to_slice T N arr)))) as [K2|K2].
    - reflexivity.
    - exfalso. rewrite (model_Q3 T N arr) in K2. lia. }
  unfold model_array_index_mut.
  cbn [core_ops_index_IndexMut_index_mut model_index_mut_slice_inst
       core_slice_index_SliceIndex_index_mut model_range_inst].
  rewrite Hget. reflexivity.
Qed.

Lemma model_index_mut_bounds : forall (T : Type) (N : usize) (arr : array T N)
    (a b : usize) (sub : slice T) (back : slice T -> array T N),
  model_array_index_mut T (core_ops_range_Range usize) (slice T) N
    (model_index_mut_slice_inst T (core_ops_range_Range usize) (slice T)
       (model_range_inst T)) arr (mk_range a b) = Ok (sub, back) ->
  to_Z a <= to_Z b /\ to_Z b <= to_Z N.
Proof.
  intros T N arr a b sub back H.
  unfold model_array_index_mut in H.
  cbn [core_ops_index_IndexMut_index_mut model_index_mut_slice_inst
       core_slice_index_SliceIndex_index_mut model_range_inst] in H.
  unfold model_range_index, model_range_get in H. cbv zeta in H.
  rewrite mk_range_start, mk_range_end in H.
  destruct (Z_le_dec (to_Z a) (to_Z b)) as [K1|K1];
    [ destruct (Z_le_dec (to_Z b)
        (to_Z (model_slice_len T (model_array_to_slice T N arr)))) as [K2|K2] |];
    cbv beta iota in H; try discriminate H.
  rewrite (model_Q3 T N arr) in K2. split; assumption.
Qed.

Lemma model_Q5 : forall (T : Type) (N : usize) (arr : array T N) (a b : usize),
  0 <= to_Z a -> to_Z a <= to_Z b -> to_Z b <= to_Z N ->
  exists sub back,
    model_array_index_mut T (core_ops_range_Range usize) (slice T) N
      (model_index_mut_slice_inst T (core_ops_range_Range usize) (slice T)
         (model_range_inst T)) arr (mk_range a b) = Ok (sub, back)
    /\ to_Z (model_slice_len T sub) = to_Z b - to_Z a.
Proof.
  intros T N arr a b H1 H2 H3.
  do 2 eexists. split.
  - apply model_index_mut_eq; assumption.
  - apply model_subslice_len; [ exact H1 | exact H2 |].
    rewrite zlen_array_to_slice. exact H3.
Qed.

(* Inversion for a SUCCESSFUL range index: it fixes the bounds and the result. *)
Lemma model_range_index_inv : forall (T : Type) (s sub : slice T) (a b : usize),
  core_slice_index_Slice_index (model_range_inst T) s (mk_range a b) = Ok sub ->
  to_Z a <= to_Z b /\ to_Z b <= zlen (proj1_sig s) /\ sub = model_subslice T s a b.
Proof.
  intros T s sub a b H.
  unfold core_slice_index_Slice_index in H;
    cbn [core_slice_index_SliceIndex_get model_range_inst] in H.
  unfold model_range_get, mk_range in H;
    cbn [core_ops_range_Range_start core_ops_range_Range_end_] in H.
  destruct (Z_le_dec (to_Z a) (to_Z b)) as [H1|H1];
    [ destruct (Z_le_dec (to_Z b) (to_Z (model_slice_len T s))) as [H2|H2] |];
    cbn [bind] in H; try discriminate.
  rewrite to_Z_model_slice_len in H2.
  injection H as H. split; [ exact H1 | split; [ exact H2 | symmetry; exact H ] ].
Qed.

Lemma model_Q9 : forall (T : Type) (s sub : slice T) (a b : usize),
  core_slice_index_Slice_index (model_range_inst T) s (mk_range a b) = Ok sub ->
  to_Z (model_slice_len T sub) = to_Z b - to_Z a.
Proof.
  intros T s sub a b H. apply model_range_index_inv in H as [H1 [H2 H3]]. subst sub.
  apply model_subslice_len; [ apply usize_nonneg | exact H1 | exact H2 ].
Qed.

Lemma model_Q10 : forall (T : Type) (s sub : slice T) (a b i j : usize),
  core_slice_index_Slice_index (model_range_inst T) s (mk_range a b) = Ok sub ->
  0 <= to_Z i -> to_Z i < to_Z b - to_Z a -> to_Z j = to_Z a + to_Z i ->
  model_slice_index T sub i = model_slice_index T s j.
Proof.
  intros T s sub a b i j H Hi Hib Hj.
  apply model_range_index_inv in H as [H1 [H2 H3]]. subst sub.
  pose proof (usize_nonneg a) as Ha.
  unfold model_slice_index, model_subslice; cbn [proj1_sig]. unfold sub_list.
  rewrite nth_error_firstn_model by lia.
  rewrite nth_error_skipn_model.
  f_equal. rewrite Hj, Z2Nat.inj_add by lia. reflexivity.
Qed.

Lemma model_Q12 : forall (T : Type) (n : usize) (a : array T n) (s : slice T) (i : usize),
  to_Z (model_slice_len T s) = to_Z n ->
  model_array_index T n (model_array_from_slice T n a s) i = model_slice_index T s i.
Proof.
  intros T n a s i Hlen. rewrite to_Z_model_slice_len in Hlen.
  unfold model_array_from_slice.
  destruct (Z.eq_dec (Z.of_nat (length (proj1_sig s))) (to_Z n)) as [Hd|Hd];
    [ reflexivity | exfalso; apply Hd; exact Hlen ].
Qed.

(* --- the write-back laws ------------------------------------------------ *)

Lemma proj1_model_splice : forall (T : Type) (s sub' : slice T) (a b : usize),
  length (splice_list (proj1_sig s) a b (proj1_sig sub')) = length (proj1_sig s) ->
  proj1_sig (model_splice T s a b sub') = splice_list (proj1_sig s) a b (proj1_sig sub').
Proof.
  intros T s sub' a b H.
  unfold model_splice; cbn [proj1_sig]; unfold splice_or.
  rewrite (proj2 (Nat.eqb_eq _ _) H). reflexivity.
Qed.

(* The write-back always preserves the parent's length, so `array_from_slice`
   always takes its length-matching branch. *)
Lemma model_splice_back_len : forall (T : Type) (N : usize) (arr : array T N)
    (a b : usize) (sub' : slice T),
  to_Z (model_slice_len T (model_splice T (model_array_to_slice T N arr) a b sub'))
  = to_Z N.
Proof.
  intros T N arr a b sub'.
  rewrite to_Z_model_slice_len. unfold zlen.
  unfold model_splice; cbn [proj1_sig]. rewrite splice_or_length.
  exact (zlen_array_to_slice T N arr).
Qed.

Lemma model_Q15 : forall (T : Type) (N : usize) (arr : array T N) (a b : usize)
    (sub : slice T) (back : slice T -> array T N) (sub' : slice T) (i j : usize),
  model_array_index_mut T (core_ops_range_Range usize) (slice T) N
    (model_index_mut_slice_inst T (core_ops_range_Range usize) (slice T)
       (model_range_inst T)) arr (mk_range a b) = Ok (sub, back) ->
  to_Z (model_slice_len T sub') = to_Z b - to_Z a ->
  to_Z a <= to_Z i -> to_Z i < to_Z b -> to_Z j = to_Z i - to_Z a ->
  model_array_index T N (back sub') i = model_slice_index T sub' j.
Proof.
  intros T N arr a b sub back sub' i j H Hlen Hai Hib Hj.
  destruct (model_index_mut_bounds T N arr a b sub back H) as [Hab HbN].
  rewrite (model_index_mut_eq T N arr a b Hab HbN) in H.
  injection H as _ Hback. subst back.
  rewrite to_Z_model_slice_len in Hlen.
  pose proof (zlen_array_to_slice T N arr) as HzN.
  assert (Hsl : length (splice_list (proj1_sig (model_array_to_slice T N arr)) a b
                          (proj1_sig sub'))
                = length (proj1_sig (model_array_to_slice T N arr)))
    by (apply splice_length; [ exact Hab | rewrite HzN; exact HbN | exact Hlen ]).
  rewrite (model_Q12 T N arr _ i (model_splice_back_len T N arr a b sub')).
  unfold model_slice_index. rewrite (proj1_model_splice T _ sub' a b Hsl).
  rewrite (nth_error_splice_in _ _ a b (Z.to_nat (to_Z i)));
    [ | exact Hab | rewrite HzN; exact HbN | exact Hlen | | ].
  - do 2 f_equal.
    assert (E1 : Z.of_nat (Z.to_nat (to_Z i)) = to_Z i)
      by (apply Z2Nat.id; apply usize_nonneg).
    assert (E2 : Z.of_nat (Z.to_nat (to_Z a)) = to_Z a)
      by (apply Z2Nat.id; apply usize_nonneg).
    assert (E3 : Z.of_nat (Z.to_nat (to_Z j)) = to_Z j)
      by (apply Z2Nat.id; apply usize_nonneg).
    lia.
  - assert (E1 : Z.of_nat (Z.to_nat (to_Z i)) = to_Z i)
      by (apply Z2Nat.id; apply usize_nonneg).
    assert (E2 : Z.of_nat (Z.to_nat (to_Z a)) = to_Z a)
      by (apply Z2Nat.id; apply usize_nonneg).
    lia.
  - assert (E1 : Z.of_nat (Z.to_nat (to_Z i)) = to_Z i)
      by (apply Z2Nat.id; apply usize_nonneg).
    assert (E2 : Z.of_nat (Z.to_nat (to_Z b)) = to_Z b)
      by (apply Z2Nat.id; apply usize_nonneg).
    lia.
Qed.

Lemma model_Q16 : forall (T : Type) (N : usize) (arr : array T N) (a b : usize)
    (sub : slice T) (back : slice T -> array T N) (sub' : slice T) (i : usize),
  model_array_index_mut T (core_ops_range_Range usize) (slice T) N
    (model_index_mut_slice_inst T (core_ops_range_Range usize) (slice T)
       (model_range_inst T)) arr (mk_range a b) = Ok (sub, back) ->
  to_Z (model_slice_len T sub') = to_Z b - to_Z a ->
  (to_Z i < to_Z a \/ to_Z b <= to_Z i) ->
  model_array_index T N (back sub') i = model_array_index T N arr i.
Proof.
  intros T N arr a b sub back sub' i H Hlen Hout.
  destruct (model_index_mut_bounds T N arr a b sub back H) as [Hab HbN].
  rewrite (model_index_mut_eq T N arr a b Hab HbN) in H.
  injection H as _ Hback. subst back.
  rewrite to_Z_model_slice_len in Hlen.
  pose proof (zlen_array_to_slice T N arr) as HzN.
  assert (Hsl : length (splice_list (proj1_sig (model_array_to_slice T N arr)) a b
                          (proj1_sig sub'))
                = length (proj1_sig (model_array_to_slice T N arr)))
    by (apply splice_length; [ exact Hab | rewrite HzN; exact HbN | exact Hlen ]).
  rewrite (model_Q12 T N arr _ i (model_splice_back_len T N arr a b sub')).
  unfold model_slice_index, model_array_index.
  rewrite (proj1_model_splice T _ sub' a b Hsl).
  assert (E1 : Z.of_nat (Z.to_nat (to_Z i)) = to_Z i)
    by (apply Z2Nat.id; apply usize_nonneg).
  assert (E2 : Z.of_nat (Z.to_nat (to_Z a)) = to_Z a)
    by (apply Z2Nat.id; apply usize_nonneg).
  assert (E3 : Z.of_nat (Z.to_nat (to_Z b)) = to_Z b)
    by (apply Z2Nat.id; apply usize_nonneg).
  destruct Hout as [Hlt|Hge].
  - rewrite (nth_error_splice_lt _ _ a b (Z.to_nat (to_Z i)));
      [ reflexivity | exact Hab | rewrite HzN; exact HbN | exact Hlen | lia ].
  - rewrite (nth_error_splice_ge _ _ a b (Z.to_nat (to_Z i)));
      [ reflexivity | exact Hab | rewrite HzN; exact HbN | exact Hlen | lia ].
Qed.

(* --- Q17/Q18 ------------------------------------------------------------ *)

Lemma model_Q17 : forall (T : Type) (n : usize) (a : array T n) (i : usize),
  model_slice_index T (model_array_to_slice T n a) i = model_array_index T n a i.
Proof. reflexivity. Qed.

Lemma model_Q18 : forall (x : u32) (i : usize), 0 <= to_Z i < 4 ->
  exists bv, model_array_index u8 4%usize (model_u32_to_le_bytes x) i = Ok bv
          /\ to_Z bv = (to_Z x / 256 ^ to_Z i) mod 256.
Proof.
  intros x i Hi.
  assert (Hc : to_Z i = 0 \/ to_Z i = 1 \/ to_Z i = 2 \/ to_Z i = 3) by lia.
  unfold model_array_index, model_u32_to_le_bytes, opt_result; cbn [proj1_sig].
  destruct Hc as [E|[E|[E|E]]]; rewrite E; cbn [Z.to_nat nth_error];
    eexists; split; reflexivity.
Qed.

(* --- Q19/Q20 ------------------------------------------------------------ *)

Lemma model_Q19 : forall (a : array u8 4%usize) (i : usize), 0 <= to_Z i < 4 ->
  exists bv, model_array_index u8 4%usize a i = Ok bv
          /\ (to_Z (model_u32_from_le_bytes a) / 256 ^ to_Z i) mod 256 = to_Z bv.
Proof.
  intros a i Hi.
  assert (Hz : zlen (proj1_sig a) = 4)
    by (unfold zlen; rewrite (proj2_sig a); apply tz4).
  destruct (nth_error_in_range (proj1_sig a) 0 ltac:(lia)) as [c0 H0].
  destruct (nth_error_in_range (proj1_sig a) 1 ltac:(lia)) as [c1 H1].
  destruct (nth_error_in_range (proj1_sig a) 2 ltac:(lia)) as [c2 H2].
  destruct (nth_error_in_range (proj1_sig a) 3 ltac:(lia)) as [c3 H3].
  change (Z.to_nat 0) with 0%nat in H0. change (Z.to_nat 1) with 1%nat in H1.
  change (Z.to_nat 2) with 2%nat in H2. change (Z.to_nat 3) with 3%nat in H3.
  (* the decoded value, in terms of the four bytes. NB: do NOT `unfold to_Z`
     here — it also unfolds the `to_Z 4%usize` buried in the sig predicate of
     `proj1_sig a`, after which nothing matches H0..H3 syntactically. *)
  assert (B0 : byte_at a 0 = to_Z c0) by (unfold byte_at; rewrite H0; reflexivity).
  assert (B1 : byte_at a 1 = to_Z c1) by (unfold byte_at; rewrite H1; reflexivity).
  assert (B2 : byte_at a 2 = to_Z c2) by (unfold byte_at; rewrite H2; reflexivity).
  assert (B3 : byte_at a 3 = to_Z c3) by (unfold byte_at; rewrite H3; reflexivity).
  assert (Hval : to_Z (model_u32_from_le_bytes a)
                 = to_Z c0 + 256 * to_Z c1 + 65536 * to_Z c2 + 16777216 * to_Z c3).
  { change (to_Z (model_u32_from_le_bytes a))
      with (byte_at a 0 + 256 * byte_at a 1 + 65536 * byte_at a 2
            + 16777216 * byte_at a 3).
    rewrite B0, B1, B2, B3. reflexivity. }
  destruct (le4_digits (to_Z c0) (to_Z c1) (to_Z c2) (to_Z c3)
              (to_Z_u8_range c0) (to_Z_u8_range c1) (to_Z_u8_range c2)
              (to_Z_u8_range c3)) as [G0 [G1 [G2 G3]]].
  rewrite Hval.
  assert (Hc : to_Z i = 0 \/ to_Z i = 1 \/ to_Z i = 2 \/ to_Z i = 3) by lia.
  unfold model_array_index, opt_result.
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

Lemma model_Q20 : forall b0 b1 b2 b3 : u8,
  model_array_index u8 4%usize (mk_array4 b0 b1 b2 b3) 0%usize = Ok b0
  /\ model_array_index u8 4%usize (mk_array4 b0 b1 b2 b3) 1%usize = Ok b1
  /\ model_array_index u8 4%usize (mk_array4 b0 b1 b2 b3) 2%usize = Ok b2
  /\ model_array_index u8 4%usize (mk_array4 b0 b1 b2 b3) 3%usize = Ok b3.
Proof.
  intros b0 b1 b2 b3.
  unfold model_array_index, mk_array4, opt_result; cbn [proj1_sig].
  repeat apply conj.
  - rewrite tz0. reflexivity.
  - rewrite tz1. reflexivity.
  - rewrite tz2. reflexivity.
  - rewrite tz3. reflexivity.
Qed.

Theorem quarantine_has_a_model : exists O, QuarantineHolds O.
Proof.
  exists model_ops. unfold QuarantineHolds;
    cbn [op_slice_len op_array_to_slice op_array_index op_slice_index
         op_range_inst op_index_mut_slice_inst op_array_index_mut
         op_copy_from_slice op_u32_to_le_bytes op_u32_from_le_bytes
         model_ops].
  repeat apply conj.
  - (* Q1 *) intros T n a i Hi.
    unfold model_array_index, opt_result.
    destruct (nth_error_in_range (proj1_sig a) (to_Z i)) as [v Hv].
    { unfold zlen. rewrite (proj2_sig a). exact Hi. }
    rewrite Hv. exists v; reflexivity.
  - (* Q2 *) intros T s i Hi.
    unfold model_slice_index, opt_result.
    destruct (nth_error_in_range (proj1_sig s) (to_Z i)) as [v Hv].
    { rewrite <- to_Z_model_slice_len. exact Hi. }
    rewrite Hv. exists v; reflexivity.
  - (* Q3 *) exact model_Q3.
  - (* Q4 *) exact model_Q4.
  - (* Q5 *) exact model_Q5.
  - (* Q6 *) intros T m dst src Hlen.
    unfold model_copy_from_slice. rewrite (proj2 (Z.eqb_eq _ _) Hlen).
    exists src; reflexivity.
  - (* Q7 *) intros T n a i j Hij. unfold model_array_index. rewrite Hij. reflexivity.
  - (* Q8 *) intros T s i j Hij. unfold model_slice_index. rewrite Hij. reflexivity.
  - (* Q9 *) exact model_Q9.
  - (* Q10 *) exact model_Q10.
  - (* Q11 *) intros T m dst src dst' H. unfold model_copy_from_slice in H.
    destruct (Z.eqb (to_Z (model_slice_len T dst)) (to_Z (model_slice_len T src)));
      [ injection H as H; symmetry; exact H | discriminate ].
  - (* Q12 *) exact model_Q12.
  - (* Q13 *) intros x y; reflexivity.
  - (* Q14 *) intros x y; reflexivity.
  - (* Q15 *) exact model_Q15.
  - (* Q16 *) exact model_Q16.
  - (* Q17 *) exact model_Q17.
  - (* Q18 *) exact model_Q18.
  - (* Q19 *) exact model_Q19.
  - (* Q20 *) exact model_Q20.
Qed.

(* ===================================================================== *)
(* 5. CONSISTENCY, spelled out.                                           *)
(*                                                                        *)
(*    `quarantine_has_a_model` is proved WITHOUT the twenty axioms —       *)
(*    check with `Print Assumptions quarantine_has_a_model`: only the      *)
(*    Aeneas backend's six scalar-width parameters (usize_max, isize_min,  *)
(*    isize_max and their three bound axioms) appear. Since the property   *)
(*    is satisfiable in plain Coq, no contradiction is derivable FROM THE  *)
(*    TWENTY QUARANTINE AXIOMS ALONE. The side condition (no other laws    *)
(*    about the same symbols) is checked in the header.                    *)
(*                                                                        *)
(*    `quarantine_is_the_axioms` closes the restatement loophole: the      *)
(*    modelled property, instantiated at the real symbols, is discharged   *)
(*    verbatim by Update_Safety's axiom block.                             *)
(*                                                                        *)
(*    SCOPE — read this before quoting "not vacuous".                      *)
(*                                                                        *)
(*    A model of the quarantine bounds ONLY the quarantine. Each theorem   *)
(*    also rests on whatever the Aeneas backend itself declares, and a     *)
(*    theorem is vacuous if ANY axiom in its `Print Assumptions` set is    *)
(*    inconsistent — including one this file never mentions. That is not   *)
(*    hypothetical: until this revision every headline theorem listed      *)
(*    `Primitives.mk_array`, which PROVES `False` (see                     *)
(*    ../../AENEAS_COQ_MKARRAY_BUG.md), so the non-vacuity claim made here *)
(*    was FALSE however good the model was. `extract.sh` now rewrites that *)
(*    axiom out of the extracted body.                                     *)
(*                                                                        *)
(*    WHAT IS COVERED NOW. After that change the assumption set of each of *)
(*    P3, P1, P1v, P2, P2w and P4w consists of exactly:                    *)
(*      (i)  quarantine axioms — satisfiable, by the two theorems above;   *)
(*      (ii) the six scalar-width parameters — satisfiable (take           *)
(*           usize_max := u32_max, isize_min := i32_min,                   *)
(*           isize_max := i32_max; the three bound axioms then hold);      *)
(*      (iii) the remaining backend/seam symbols, which are declared with  *)
(*           NO axiom constraining them: bare `Axiom c : A` for an         *)
(*           INHABITED `A`. Each is individually satisfiable, and each of  *)
(*           the types involved here is inhabited — `result T` by `Fail_`, *)
(*           `usize`/`u32`/`u8` by 0, `slice T` by the empty list,         *)
(*           `array T n` by … NOT always, which is precisely the           *)
(*           `mk_array` bug: `array_repeat`, `array_from_slice` and        *)
(*           `array_update` are safe because each already TAKES an         *)
(*           inhabitant of `array T n` or of `T`, whereas `mk_array`       *)
(*           manufactures one out of nothing.                              *)
(*                                                                        *)
(*    WHAT IS NOT COVERED. (iii) is an argument in this comment, not a     *)
(*    machine-checked theorem: there is no Coq artifact here exhibiting a  *)
(*    model of the WHOLE of `Primitives.v`. A second inconsistent backend  *)
(*    axiom of the same shape would not be caught by this file. What can   *)
(*    be said mechanically is weaker and worth stating exactly: `Print     *)
(*    Assumptions` on each headline theorem now lists no axiom known to be *)
(*    unsound, and the one that WAS known unsound is gone.                 *)
(* ===================================================================== *)

(* ===================================================================== *)
(* MECHANISED ASSUMPTION AUDIT (see Update_Safety.v).  The model must be  *)
(* discharged using NONE of the twenty quarantine laws: compiling this    *)
(* file emits its assumption set, which must contain only the backend's   *)
(* scalar-width constants.                                               *)
(* ===================================================================== *)
Print Assumptions quarantine_has_a_model.
