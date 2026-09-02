Require Import Lia.
Require Coq.Strings.Ascii.
Require Coq.Strings.String.
Require Import Coq.Program.Equality.
Require Import Coq.ZArith.ZArith.
Require Import Coq.ZArith.Znat.
Require Import List.
Import ListNotations.
Require Import Coq.Bool.Bool.
Require Import Coq.Logic.Eqdep_dec.

(** PROJECT VARIANT of the Aeneas Coq backend's Primitives.v (issue #58).

    The upstream file ships scalars' width parameters, the bitwise operators
    and every array/slice/vector operation as bare [Axiom]s ("TODO: finish the
    definitions"), and one of them ([mk_array]) is inconsistent. This copy keeps
    upstream's NAMES and TYPES — the extracted code is untouched — but gives
    every one of them a definition over the underlying [list]/[Z]
    representation the sigma types already carry. Consequently no theorem
    proved over the extracted code inherits a backend axiom: [Print
    Assumptions] on the deterministic layer is closed under the global context.

    The scalar carrier is a *boolean* bounds check rather than the upstream
    [Prop] conjunction, so that two scalars with the same value are equal
    ([scalar_ext]) by decidable UIP, without proof irrelevance.

    Do not overwrite with the toolchain file: ../extract.sh checks that the
    vendored backend file is the one this variant was derived from. *)

Module Primitives.

  (* TODO: use more *)
Declare Scope Primitives_scope.

(*** Result *)

Inductive error :=
  | Failure
  | OutOfFuel.

Inductive result A :=
  | Ok : A -> result A
  | Fail_ : error -> result A.

Arguments Ok {_} a.
Arguments Fail_ {_}.

Definition bind {A B} (m: result A) (f: A -> result B) : result B :=
  match m with
  | Fail_ e => Fail_ e
  | Ok x => f x
  end.

Definition return_ {A: Type} (x: A) : result A := Ok x.
Definition fail_ {A: Type} (e: error) : result A := Fail_ e.

Notation "x <- c1 ; c2" := (bind c1 (fun x => c2))
  (at level 61, c1 at next level, right associativity).

(** Monadic assert *)
Definition massert (b: bool) : result unit :=
  if b then Ok tt else Fail_ Failure.

(** Normalize and unwrap a successful result (used for globals) *)
Definition eval_result_refl {A} {x} (a: result A) (p: a = Ok x) : A :=
  match a as r return (r = Ok x -> A) with
  | Ok a' => fun _  => a'
  | Fail_ e   => fun p' =>
      False_rect _ (eq_ind (Fail_ e)
          (fun e : result A =>
          match e with
          | Ok _ => False
          | Fail_ e => True
          end)
        I (Ok x) p')
  end p.

Notation "x %global" := (eval_result_refl x eq_refl) (at level 40).
Notation "x %return" := (eval_result_refl x eq_refl) (at level 40).

(* Sanity check *)
Check (if true then Ok (1 + 2) else Fail_ Failure)%global = 3.

(*** Misc *)

Definition string := Coq.Strings.String.string.
Definition str := string.
Definition char := Coq.Strings.Ascii.ascii.
Definition char_of_byte := Coq.Strings.Ascii.ascii_of_byte.

Definition core_mem_replace {a : Type} (x : a) (y : a) : a * a := (x, x) .

Record mut_raw_ptr (T : Type) := { mut_raw_ptr_v : T }.
Record const_raw_ptr (T : Type) := { const_raw_ptr_v : T }.

(*** Scalars *)

Definition i8_min   : Z := -128%Z.
Definition i8_max   : Z := 127%Z.
Definition i16_min  : Z := -32768%Z.
Definition i16_max  : Z := 32767%Z.
Definition i32_min  : Z := -2147483648%Z.
Definition i32_max  : Z := 2147483647%Z.
Definition i64_min  : Z := -9223372036854775808%Z.
Definition i64_max  : Z := 9223372036854775807%Z.
Definition i128_min : Z := -170141183460469231731687303715884105728%Z.
Definition i128_max : Z := 170141183460469231731687303715884105727%Z.
Definition u8_min   : Z := 0%Z.
Definition u8_max   : Z := 255%Z.
Definition u16_min  : Z := 0%Z.
Definition u16_max  : Z := 65535%Z.
Definition u32_min  : Z := 0%Z.
Definition u32_max  : Z := 4294967295%Z.
Definition u64_min  : Z := 0%Z.
Definition u64_max  : Z := 18446744073709551615%Z.
Definition u128_min : Z := 0%Z.
Definition u128_max : Z := 340282366920938463463374607431768211455%Z.

(** The bounds of [isize] and [usize] are those of the 32-bit targets this
    development runs on (ARMv8-M, RV32). Definitions, not axioms. *)
Definition isize_min : Z := i32_min.
Definition isize_max : Z := i32_max.
Definition usize_min : Z := 0%Z.
Definition usize_max : Z := u32_max.

Open Scope Z_scope.

(** The bound lemmas upstream postulates; here they are proved. *)
Lemma isize_min_bound : isize_min <= i32_min.
Proof. unfold isize_min. lia. Qed.
Lemma isize_max_bound : i32_max <= isize_max.
Proof. unfold isize_max. lia. Qed.
Lemma usize_max_bound : u32_max <= usize_max.
Proof. unfold usize_max. lia. Qed.

Inductive scalar_ty :=
  | Isize
  | I8
  | I16
  | I32
  | I64
  | I128
  | Usize
  | U8
  | U16
  | U32
  | U64
  | U128
.

Definition scalar_min (ty: scalar_ty) : Z :=
  match ty with
  | Isize => isize_min
  | I8 => i8_min
  | I16 => i16_min
  | I32 => i32_min
  | I64 => i64_min
  | I128 => i128_min
  | Usize => usize_min
  | U8 => u8_min
  | U16 => u16_min
  | U32 => u32_min
  | U64 => u64_min
  | U128 => u128_min
end.

Definition scalar_max (ty: scalar_ty) : Z :=
  match ty with
  | Isize => isize_max
  | I8 => i8_max
  | I16 => i16_max
  | I32 => i32_max
  | I64 => i64_max
  | I128 => i128_max
  | Usize => usize_max
  | U8 => u8_max
  | U16 => u16_max
  | U32 => u32_max
  | U64 => u64_max
  | U128 => u128_max
end.

(** We use the following conservative bounds to make sure we can compute bound
    checks in most situations *)
Definition scalar_min_cons (ty: scalar_ty) : Z :=
  match ty with
  | Isize => i32_min
  | Usize => u32_min
  | _ => scalar_min ty
end.

Definition scalar_max_cons (ty: scalar_ty) : Z :=
  match ty with
  | Isize => i32_max
  | Usize => u32_max
  | _ => scalar_max ty
end.

Lemma scalar_min_cons_valid : forall ty, scalar_min ty <= scalar_min_cons ty .
Proof.
  destruct ty; unfold scalar_min_cons, scalar_min; try lia.
  - pose isize_min_bound; lia.
  - apply Z.le_refl.
Qed.

Lemma scalar_max_cons_valid : forall ty, scalar_max ty >= scalar_max_cons ty .
Proof.
  destruct ty; unfold scalar_max_cons, scalar_max; try lia.
  - pose isize_max_bound; lia.
  - pose usize_max_bound. lia.
Qed.

(** Bounds checks: we start by using the conservative bounds, to make sure we
    can compute in most situations, then we use the real bounds (for [isize]
    and [usize]). *)
Definition scalar_ge_min (ty: scalar_ty) (x: Z) : bool :=
  Z.leb (scalar_min_cons ty) x || Z.leb (scalar_min ty) x.

Definition scalar_le_max (ty: scalar_ty) (x: Z) : bool :=
  Z.leb x (scalar_max_cons ty) || Z.leb x (scalar_max ty).

Lemma scalar_ge_min_valid (ty: scalar_ty) (x: Z) :
  scalar_ge_min ty x = true -> scalar_min ty <= x .
Proof.
  unfold scalar_ge_min.
  pose (scalar_min_cons_valid ty).
  lia.
Qed.

Lemma scalar_le_max_valid (ty: scalar_ty) (x: Z) :
  scalar_le_max ty x = true -> x <= scalar_max ty .
Proof.
  unfold scalar_le_max.
  pose (scalar_max_cons_valid ty).
  lia.
Qed.

Definition scalar_in_bounds (ty: scalar_ty) (x: Z) : bool :=
  scalar_ge_min ty x && scalar_le_max ty x .

Lemma scalar_in_bounds_valid (ty: scalar_ty) (x: Z) :
  scalar_in_bounds ty x = true -> scalar_min ty <= x <= scalar_max ty .
Proof.
  unfold scalar_in_bounds.
  intros H.
  destruct (scalar_ge_min ty x) eqn:Hmin.
  - destruct (scalar_le_max ty x) eqn:Hmax.
    + pose (scalar_ge_min_valid ty x Hmin).
      pose (scalar_le_max_valid ty x Hmax).
      lia.
    + inversion H.
  - inversion H.
Qed.

Lemma scalar_in_bounds_complete (ty: scalar_ty) (x: Z) :
  scalar_min ty <= x <= scalar_max ty -> scalar_in_bounds ty x = true.
Proof.
  intros [H1 H2]. unfold scalar_in_bounds, scalar_ge_min, scalar_le_max.
  rewrite (proj2 (Z.leb_le _ _) H1), (proj2 (Z.leb_le _ _) H2).
  rewrite !orb_true_r. reflexivity.
Qed.

(** A scalar is a [Z] with a DECIDABLE (boolean) bounds certificate, so that
    equal values give equal scalars without proof irrelevance ([scalar_ext]). *)
Definition scalar (ty: scalar_ty) : Type :=
 { x: Z | scalar_in_bounds ty x = true }.

Definition to_Z {ty} (x: scalar ty) : Z := proj1_sig x.

Definition mk_scalar_of_bounds (ty: scalar_ty) (x: Z)
  (H : scalar_min ty <= x <= scalar_max ty) : scalar ty :=
  exist _ x (scalar_in_bounds_complete ty x H).

Lemma to_Z_mk_scalar_of_bounds : forall ty x H, to_Z (mk_scalar_of_bounds ty x H) = x.
Proof. reflexivity. Qed.

Lemma to_Z_bounds {ty} (x: scalar ty) : scalar_min ty <= to_Z x <= scalar_max ty.
Proof. exact (scalar_in_bounds_valid ty _ (proj2_sig x)). Qed.

Lemma scalar_ext {ty} (x y: scalar ty) : to_Z x = to_Z y -> x = y.
Proof.
  destruct x as [x Hx], y as [y Hy]. unfold to_Z; cbn. intros ->.
  f_equal. apply UIP_dec. apply bool_dec.
Qed.

Lemma to_Z_usize_nonneg (x: scalar Usize) : 0 <= to_Z x.
Proof. exact (proj1 (to_Z_bounds x)). Qed.

Lemma to_Z_usize_le_max (x: scalar Usize) : to_Z x <= usize_max.
Proof. exact (proj2 (to_Z_bounds x)). Qed.

Import Sumbool.

Definition mk_scalar (ty: scalar_ty) (x: Z) : result (scalar ty) :=
  match sumbool_of_bool (scalar_in_bounds ty x) with
  | left H => Ok (exist _ x H)
  | right _ => Fail_ Failure
  end.

Definition scalar_add {ty} (x y: scalar ty) : result (scalar ty) := mk_scalar ty (to_Z x + to_Z y).

Definition scalar_sub {ty} (x y: scalar ty) : result (scalar ty) := mk_scalar ty (to_Z x - to_Z y).

Definition scalar_mul {ty} (x y: scalar ty) : result (scalar ty) := mk_scalar ty (to_Z x * to_Z y).

Definition scalar_div {ty} (x y: scalar ty) : result (scalar ty) :=
  if to_Z y =? 0 then Fail_ Failure else
  mk_scalar ty (to_Z x / to_Z y).

Definition scalar_rem {ty} (x y: scalar ty) : result (scalar ty) := mk_scalar ty (Z.rem (to_Z x) (to_Z y)).
  
Definition scalar_neg {ty} (x: scalar ty) : result (scalar ty) := mk_scalar ty (-(to_Z x)).

(** Bitwise operators: the [Z] bitwise operator on the values. For every
    unsigned width the result is in range (proved where needed, e.g.
    Update_Safety.u8_xor_to_Z); the total signature upstream demands is met by
    falling back to the left operand should the check ever fail. *)
Definition scalar_or_default {ty} (r: result (scalar ty)) (d: scalar ty) : scalar ty :=
  match r with Ok s => s | Fail_ _ => d end.

Definition scalar_xor {ty} (x y: scalar ty) : scalar ty :=
  scalar_or_default (mk_scalar ty (Z.lxor (to_Z x) (to_Z y))) x.
Definition scalar_or {ty} (x y: scalar ty) : scalar ty :=
  scalar_or_default (mk_scalar ty (Z.lor (to_Z x) (to_Z y))) x.
Definition scalar_and {ty} (x y: scalar ty) : scalar ty :=
  scalar_or_default (mk_scalar ty (Z.land (to_Z x) (to_Z y))) x.
Definition scalar_shl {ty0 ty1} (x: scalar ty0) (y: scalar ty1) : result (scalar ty0) :=
  mk_scalar ty0 (Z.shiftl (to_Z x) (to_Z y)).
Definition scalar_shr {ty0 ty1} (x: scalar ty0) (y: scalar ty1) : result (scalar ty0) :=
  mk_scalar ty0 (Z.shiftr (to_Z x) (to_Z y)).
Definition scalar_signed (ty: scalar_ty) : bool :=
  match ty with Isize | I8 | I16 | I32 | I64 | I128 => true | _ => false end.
Definition scalar_not {ty} (x: scalar ty) : scalar ty :=
  scalar_or_default
    (mk_scalar ty (if scalar_signed ty then Z.lnot (to_Z x) else scalar_max ty - to_Z x)) x.

(** Cast an integer from a [src_ty] to a [tgt_ty] *)
(* TODO: check the semantics of casts in Rust *)
Definition scalar_cast (src_ty tgt_ty : scalar_ty) (x : scalar src_ty) : result (scalar tgt_ty) :=
  mk_scalar tgt_ty (to_Z x).

(* This can't fail, but for now we make all casts faillible (easier for the translation) *)
Definition scalar_cast_bool (tgt_ty : scalar_ty) (x : bool) : result (scalar tgt_ty) :=
  mk_scalar tgt_ty (if x then 1 else 0).

(** Comparisons *)
Definition scalar_leb {ty : scalar_ty} (x : scalar ty) (y : scalar ty) : bool :=
  Z.leb (to_Z x) (to_Z y) .

Definition scalar_ltb {ty : scalar_ty} (x : scalar ty) (y : scalar ty) : bool :=
  Z.ltb (to_Z x) (to_Z y) .

Definition scalar_geb {ty : scalar_ty} (x : scalar ty) (y : scalar ty) : bool :=
  Z.geb (to_Z x) (to_Z y) .

Definition scalar_gtb {ty : scalar_ty} (x : scalar ty) (y : scalar ty) : bool :=
  Z.gtb (to_Z x) (to_Z y) .

Definition scalar_eqb {ty : scalar_ty} (x : scalar ty) (y : scalar ty) : bool :=
  Z.eqb (to_Z x) (to_Z y) .

Definition scalar_neqb {ty : scalar_ty} (x : scalar ty) (y : scalar ty) : bool :=
  negb (Z.eqb (to_Z x) (to_Z y)) .

(** The scalar types *)
Definition isize := scalar Isize.
Definition i8    := scalar I8.
Definition i16   := scalar I16.
Definition i32   := scalar I32.
Definition i64   := scalar I64.
Definition i128  := scalar I128.
Definition usize := scalar Usize.
Definition u8    := scalar U8.
Definition u16   := scalar U16.
Definition u32   := scalar U32.
Definition u64   := scalar U64.
Definition u128  := scalar U128.

(** Negaion *)
Definition isize_neg := @scalar_neg Isize.
Definition i8_neg    := @scalar_neg I8.
Definition i16_neg   := @scalar_neg I16.
Definition i32_neg   := @scalar_neg I32.
Definition i64_neg   := @scalar_neg I64.
Definition i128_neg  := @scalar_neg I128.

(** Division *)
Definition isize_div := @scalar_div Isize.
Definition i8_div    := @scalar_div I8.
Definition i16_div   := @scalar_div I16.
Definition i32_div   := @scalar_div I32.
Definition i64_div   := @scalar_div I64.
Definition i128_div  := @scalar_div I128.
Definition usize_div := @scalar_div Usize.
Definition u8_div    := @scalar_div U8.
Definition u16_div   := @scalar_div U16.
Definition u32_div   := @scalar_div U32.
Definition u64_div   := @scalar_div U64.
Definition u128_div  := @scalar_div U128.

(** Remainder *)
Definition isize_rem := @scalar_rem Isize.
Definition i8_rem    := @scalar_rem I8.
Definition i16_rem   := @scalar_rem I16.
Definition i32_rem   := @scalar_rem I32.
Definition i64_rem   := @scalar_rem I64.
Definition i128_rem  := @scalar_rem I128.
Definition usize_rem := @scalar_rem Usize.
Definition u8_rem    := @scalar_rem U8.
Definition u16_rem   := @scalar_rem U16.
Definition u32_rem   := @scalar_rem U32.
Definition u64_rem   := @scalar_rem U64.
Definition u128_rem  := @scalar_rem U128.

(** Addition *)
Definition isize_add := @scalar_add Isize.
Definition i8_add    := @scalar_add I8.
Definition i16_add   := @scalar_add I16.
Definition i32_add   := @scalar_add I32.
Definition i64_add   := @scalar_add I64.
Definition i128_add  := @scalar_add I128.
Definition usize_add := @scalar_add Usize.
Definition u8_add    := @scalar_add U8.
Definition u16_add   := @scalar_add U16.
Definition u32_add   := @scalar_add U32.
Definition u64_add   := @scalar_add U64.
Definition u128_add  := @scalar_add U128.

(** Substraction *)
Definition isize_sub := @scalar_sub Isize.
Definition i8_sub    := @scalar_sub I8.
Definition i16_sub   := @scalar_sub I16.
Definition i32_sub   := @scalar_sub I32.
Definition i64_sub   := @scalar_sub I64.
Definition i128_sub  := @scalar_sub I128.
Definition usize_sub := @scalar_sub Usize.
Definition u8_sub    := @scalar_sub U8.
Definition u16_sub   := @scalar_sub U16.
Definition u32_sub   := @scalar_sub U32.
Definition u64_sub   := @scalar_sub U64.
Definition u128_sub  := @scalar_sub U128.

(** Multiplication *)
Definition isize_mul := @scalar_mul Isize.
Definition i8_mul    := @scalar_mul I8.
Definition i16_mul   := @scalar_mul I16.
Definition i32_mul   := @scalar_mul I32.
Definition i64_mul   := @scalar_mul I64.
Definition i128_mul  := @scalar_mul I128.
Definition usize_mul := @scalar_mul Usize.
Definition u8_mul    := @scalar_mul U8.
Definition u16_mul   := @scalar_mul U16.
Definition u32_mul   := @scalar_mul U32.
Definition u64_mul   := @scalar_mul U64.
Definition u128_mul  := @scalar_mul U128.

(** Xor *)
Definition u8_xor := @scalar_xor U8.
Definition u16_xor := @scalar_xor U16.
Definition u32_xor := @scalar_xor U32.
Definition u64_xor := @scalar_xor U64.
Definition u128_xor := @scalar_xor U128.
Definition usize_xor := @scalar_xor Usize.
Definition i8_xor := @scalar_xor I8.
Definition i16_xor := @scalar_xor I16.
Definition i32_xor := @scalar_xor I32.
Definition i64_xor := @scalar_xor I64.
Definition i128_xor := @scalar_xor I128.
Definition isize_xor := @scalar_xor Isize.

(** Or *)
Definition u8_or := @scalar_or U8.
Definition u16_or := @scalar_or U16.
Definition u32_or := @scalar_or U32.
Definition u64_or := @scalar_or U64.
Definition u128_or := @scalar_or U128.
Definition usize_or := @scalar_or Usize.
Definition i8_or := @scalar_or I8.
Definition i16_or := @scalar_or I16.
Definition i32_or := @scalar_or I32.
Definition i64_or := @scalar_or I64.
Definition i128_or := @scalar_or I128.
Definition isize_or := @scalar_or Isize.

(** And *)
Definition u8_and := @scalar_and U8.
Definition u16_and := @scalar_and U16.
Definition u32_and := @scalar_and U32.
Definition u64_and := @scalar_and U64.
Definition u128_and := @scalar_and U128.
Definition usize_and := @scalar_and Usize.
Definition i8_and := @scalar_and I8.
Definition i16_and := @scalar_and I16.
Definition i32_and := @scalar_and I32.
Definition i64_and := @scalar_and I64.
Definition i128_and := @scalar_and I128.
Definition isize_and := @scalar_and Isize.

(** Shift left *)
Definition u8_shl {ty} := @scalar_shl U8 ty.
Definition u16_shl {ty} := @scalar_shl U16 ty.
Definition u32_shl {ty} := @scalar_shl U32 ty.
Definition u64_shl {ty} := @scalar_shl U64 ty.
Definition u128_shl {ty} := @scalar_shl U128 ty.
Definition usize_shl {ty} := @scalar_shl Usize ty.
Definition i8_shl {ty} := @scalar_shl I8 ty.
Definition i16_shl {ty} := @scalar_shl I16 ty.
Definition i32_shl {ty} := @scalar_shl I32 ty.
Definition i64_shl {ty} := @scalar_shl I64 ty.
Definition i128_shl {ty} := @scalar_shl I128 ty.
Definition isize_shl {ty} := @scalar_shl Isize ty.

(** Shift right *)
Definition u8_shr {ty} := @scalar_shr U8 ty.
Definition u16_shr {ty} := @scalar_shr U16 ty.
Definition u32_shr {ty} := @scalar_shr U32 ty.
Definition u64_shr {ty} := @scalar_shr U64 ty.
Definition u128_shr {ty} := @scalar_shr U128 ty.
Definition usize_shr {ty} := @scalar_shr Usize ty.
Definition i8_shr {ty} := @scalar_shr I8 ty.
Definition i16_shr {ty} := @scalar_shr I16 ty.
Definition i32_shr {ty} := @scalar_shr I32 ty.
Definition i64_shr {ty} := @scalar_shr I64 ty.
Definition i128_shr {ty} := @scalar_shr I128 ty.
Definition isize_shr {ty} := @scalar_shr Isize ty.

(** Not *)
Definition u8_not := @scalar_not U8.
Definition u16_not := @scalar_not U16.
Definition u32_not := @scalar_not U32.
Definition u64_not := @scalar_not U64.
Definition u128_not := @scalar_not U128.
Definition usize_not := @scalar_not Usize.
Definition i8_not := @scalar_not I8.
Definition i16_not := @scalar_not I16.
Definition i32_not := @scalar_not I32.
Definition i64_not := @scalar_not I64.
Definition i128_not := @scalar_not I128.
Definition isize_not := @scalar_not Isize.

(** Small utility *)
Definition usize_to_nat (x: usize) : nat := Z.to_nat (to_Z x).

(** Notations *)
Notation "x %isize" := ((mk_scalar Isize x)%return) (at level 9).
Notation "x %i8"    := ((mk_scalar I8    x)%return) (at level 9).
Notation "x %i16"   := ((mk_scalar I16   x)%return) (at level 9).
Notation "x %i32"   := ((mk_scalar I32   x)%return) (at level 9).
Notation "x %i64"   := ((mk_scalar I64   x)%return) (at level 9).
Notation "x %i128"  := ((mk_scalar I128  x)%return) (at level 9).
Notation "x %usize" := ((mk_scalar Usize x)%return) (at level 9).
Notation "x %u8"    := ((mk_scalar U8    x)%return) (at level 9).
Notation "x %u16"   := ((mk_scalar U16   x)%return) (at level 9).
Notation "x %u32"   := ((mk_scalar U32   x)%return) (at level 9).
Notation "x %u64"   := ((mk_scalar U64   x)%return) (at level 9).
Notation "x %u128"  := ((mk_scalar U128  x)%return) (at level 9).

Notation "x s= y" := (scalar_eqb x y)  (at level 80) : Primitives_scope.
Notation "x s<> y" := (scalar_neqb x y) (at level 80) : Primitives_scope.
Notation "x s<= y" := (scalar_leb x y)  (at level 80) : Primitives_scope.
Notation "x s< y" := (scalar_ltb x y)  (at level 80) : Primitives_scope.
Notation "x s>= y" := (scalar_geb x y)  (at level 80) : Primitives_scope.
Notation "x s> y" := (scalar_gtb x y)  (at level 80) : Primitives_scope.

(** Constants *)
Definition core_num_U8_MIN    := u8_min %u32.
Definition core_num_U16_MIN   := u16_min %u32.
Definition core_num_U32_MIN   := u32_min %u32.
Definition core_num_U64_MIN   := u64_min %u64.
Definition core_num_U128_MIN  := u64_min %u128.
Definition core_num_Usize_MIN : usize := usize_min %usize.
Definition core_num_I8_MIN    := i8_min %i32.
Definition core_num_I16_MIN   := i16_min %i32.
Definition core_num_I32_MIN   := i32_min %i32.
Definition core_num_I64_MIN   := i64_min %i64.
Definition core_num_I128_MIN  := i128_min %i128.
Definition core_num_Isize_MIN : isize := isize_min %isize.

Definition core_num_U8_MAX    := u8_max %u32.
Definition core_num_U16_MAX   := u16_max %u32.
Definition core_num_U32_MAX   := u32_max %u32.
Definition core_num_U64_MAX   := u64_max %u64.
Definition core_num_U128_MAX  := u64_max %u128.
Definition core_num_Usize_MAX : usize := usize_max %usize.
Definition core_num_I8_MAX    := i8_max %i32.
Definition core_num_I16_MAX   := i16_max %i32.
Definition core_num_I32_MAX   := i32_max %i32.
Definition core_num_I64_MAX   := i64_max %i64.
Definition core_num_I128_MAX  := i128_max %i128.
Definition core_num_Isize_MAX : isize := isize_max %isize.

(*** core *)

(** Trait declaration: [core::clone::Clone] *)
Record core_clone_Clone (self : Type) := {
  core_clone_Clone_clone : self -> result self;
  core_clone_Clone_clone_from : self -> self -> result self
}.

Definition core_clone_impls_CloneUsize_clone (x : usize) : usize := x.
Definition core_clone_impls_CloneU8_clone (x : u8) : u8 := x.
Definition core_clone_impls_CloneU16_clone (x : u16) : u16 := x.
Definition core_clone_impls_CloneU32_clone (x : u32) : u32 := x.
Definition core_clone_impls_CloneU64_clone (x : u64) : u64 := x.
Definition core_clone_impls_CloneU128_clone (x : u128) : u128 := x.

Definition core_clone_impls_CloneIsize_clone (x : isize) : isize := x.
Definition core_clone_impls_CloneI8_clone (x : i8) : i8 := x.
Definition core_clone_impls_CloneI16_clone (x : i16) : i16 := x.
Definition core_clone_impls_CloneI32_clone (x : i32) : i32 := x.
Definition core_clone_impls_CloneI64_clone (x : i64) : i64 := x.
Definition core_clone_impls_CloneI128_clone (x : i128) : i128 := x.

Definition core_clone_impls_CloneUsize_clone_from (_ x : usize) : usize := x.
Definition core_clone_impls_CloneU8_clone_from (_ x : u8) : u8 := x.
Definition core_clone_impls_CloneU16_clone_from (_ x : u16) : u16 := x.
Definition core_clone_impls_CloneU32_clone_from (_ x : u32) : u32 := x.
Definition core_clone_impls_CloneU64_clone_from (_ x : u64) : u64 := x.
Definition core_clone_impls_CloneU128_clone_from (_ x : u128) : u128 := x.

Definition core_clone_impls_CloneIsize_clone_from (_ x : isize) : isize := x.
Definition core_clone_impls_CloneI8_clone_from (_ x : i8) : i8 := x.
Definition core_clone_impls_CloneI16_clone_from (_ x : i16) : i16 := x.
Definition core_clone_impls_CloneI32_clone_from (_ x : i32) : i32 := x.
Definition core_clone_impls_CloneI64_clone_from (_ x : i64) : i64 := x.
Definition core_clone_impls_CloneI128_clone_from (_ x : i128) : i128 := x.

Definition core_clone_CloneUsize : core_clone_Clone usize := {|
  core_clone_Clone_clone := fun x => Ok (core_clone_impls_CloneUsize_clone x);
  core_clone_Clone_clone_from := fun _ y => Ok y
|}.

Definition core_clone_CloneU8 : core_clone_Clone u8 := {|
  core_clone_Clone_clone := fun x => Ok (core_clone_impls_CloneU8_clone x);
  core_clone_Clone_clone_from := fun _ y => Ok y
|}.

Definition core_clone_CloneU16 : core_clone_Clone u16 := {|
  core_clone_Clone_clone := fun x => Ok (core_clone_impls_CloneU16_clone x);
  core_clone_Clone_clone_from := fun _ y => Ok y
|}.

Definition core_clone_CloneU32 : core_clone_Clone u32 := {|
  core_clone_Clone_clone := fun x => Ok (core_clone_impls_CloneU32_clone x);
  core_clone_Clone_clone_from := fun _ y => Ok y
|}.

Definition core_clone_CloneU64 : core_clone_Clone u64 := {|
  core_clone_Clone_clone := fun x => Ok (core_clone_impls_CloneU64_clone x);
  core_clone_Clone_clone_from := fun _ y => Ok y
|}.

Definition core_clone_CloneU128 : core_clone_Clone u128 := {|
  core_clone_Clone_clone := fun x => Ok (core_clone_impls_CloneU128_clone x);
  core_clone_Clone_clone_from := fun _ y => Ok y
|}.

Definition core_clone_CloneIsize : core_clone_Clone isize := {|
  core_clone_Clone_clone := fun x => Ok (core_clone_impls_CloneIsize_clone x);
  core_clone_Clone_clone_from := fun _ y => Ok y
|}.

Definition core_clone_CloneI8 : core_clone_Clone i8 := {|
  core_clone_Clone_clone := fun x => Ok (core_clone_impls_CloneI8_clone x);
  core_clone_Clone_clone_from := fun _ y => Ok y
|}.

Definition core_clone_CloneI16 : core_clone_Clone i16 := {|
  core_clone_Clone_clone := fun x => Ok (core_clone_impls_CloneI16_clone x);
  core_clone_Clone_clone_from := fun _ y => Ok y
|}.

Definition core_clone_CloneI32 : core_clone_Clone i32 := {|
  core_clone_Clone_clone := fun x => Ok (core_clone_impls_CloneI32_clone x);
  core_clone_Clone_clone_from := fun _ y => Ok y
|}.

Definition core_clone_CloneI64 : core_clone_Clone i64 := {|
  core_clone_Clone_clone := fun x => Ok (core_clone_impls_CloneI64_clone x);
  core_clone_Clone_clone_from := fun _ y => Ok y
|}.

Definition core_clone_CloneI128 : core_clone_Clone i128 := {|
  core_clone_Clone_clone := fun x => Ok (core_clone_impls_CloneI128_clone x);
  core_clone_Clone_clone_from := fun _ y => Ok y
|}.

Definition core_clone_impls_CloneBool_clone (b : bool) : bool := b.

Definition core_clone_CloneBool : core_clone_Clone bool := {|
  core_clone_Clone_clone := fun b => Ok (core_clone_impls_CloneBool_clone b);
  core_clone_Clone_clone_from := fun _ y => Ok y
|}.

Record core_marker_Copy (Self : Type) := mkcore_marker_Copy {
  cloneInst : core_clone_Clone Self;
}.

Arguments mkcore_marker_Copy { _ }.
Arguments cloneInst { _ } _.

Definition core_marker_CopyU8 : core_marker_Copy u8 := {|
  cloneInst := core_clone_CloneU8;
|}.

Definition core_marker_CopyU16 : core_marker_Copy u16 := {|
  cloneInst := core_clone_CloneU16;
|}.

Definition core_marker_CopyU32 : core_marker_Copy u32 := {|
  cloneInst := core_clone_CloneU32;
|}.

Definition core_marker_CopyU64 : core_marker_Copy u64 := {|
  cloneInst := core_clone_CloneU64;
|}.

Definition core_marker_CopyU128 : core_marker_Copy u128 := {|
  cloneInst := core_clone_CloneU128;
|}.

Definition core_marker_CopyUsize : core_marker_Copy usize := {|
  cloneInst := core_clone_CloneUsize;
|}.

Definition core_marker_CopyI8 : core_marker_Copy i8 := {|
  cloneInst := core_clone_CloneI8;
|}.

Definition core_marker_CopyI16 : core_marker_Copy i16 := {|
  cloneInst := core_clone_CloneI16;
|}.

Definition core_marker_CopyI32 : core_marker_Copy i32 := {|
  cloneInst := core_clone_CloneI32;
|}.

Definition core_marker_CopyI64 : core_marker_Copy i64 := {|
  cloneInst := core_clone_CloneI64;
|}.

Definition core_marker_CopyI128 : core_marker_Copy i128 := {|
  cloneInst := core_clone_CloneI128;
|}.

Definition core_marker_CopyIsize : core_marker_Copy isize := {|
  cloneInst := core_clone_CloneIsize;
|}.

(** [core::option::{core::option::Option<T>}::unwrap] *)
Definition core_option_Option_unwrap {T : Type} (x : option T) : result T :=
  match x with
  | None => Fail_ Failure
  | Some x => Ok x
  end.

(*** core::ops *)

(* Trait declaration: [core::ops::index::Index] *)
Record core_ops_index_Index (Self Idx Output : Type) := mk_core_ops_index_Index {
  core_ops_index_Index_index : Self -> Idx -> result Output;
}.
Arguments mk_core_ops_index_Index {_ _}.
Arguments core_ops_index_Index_index {_ _}.

(* Trait declaration: [core::ops::index::IndexMut] *)
Record core_ops_index_IndexMut (Self Idx Output : Type) := mk_core_ops_index_IndexMut {
  core_ops_index_IndexMut_indexInst : core_ops_index_Index Self Idx Output;
  core_ops_index_IndexMut_index_mut :
    Self ->
    Idx ->
    result (Output * (Output -> Self));
}.
Arguments mk_core_ops_index_IndexMut {_ _ _}.
Arguments core_ops_index_IndexMut_indexInst {_ _ _}.
Arguments core_ops_index_IndexMut_index_mut {_ _ _}.

(* Trait declaration [core::ops::deref::Deref] *)
Record core_ops_deref_Deref (Self Target : Type) := mk_core_ops_deref_Deref {
  core_ops_deref_Deref_deref : Self -> result Target;
}.
Arguments mk_core_ops_deref_Deref {_}.
Arguments core_ops_deref_Deref_deref {_}.

(* Trait declaration [core::ops::deref::DerefMut] *)
Record core_ops_deref_DerefMut (Self Target : Type) := mk_core_ops_deref_DerefMut {
  core_ops_deref_DerefMut_derefInst : core_ops_deref_Deref Self Target;
  core_ops_deref_DerefMut_deref_mut :
    Self ->
    result (Target * (Target -> Self));
}.
Arguments mk_core_ops_deref_DerefMut {_}.
Arguments core_ops_deref_DerefMut_derefInst {_}.
Arguments core_ops_deref_DerefMut_deref_mut {_}.

Record core_ops_range_Range (T : Type) := mk_core_ops_range_Range {
  core_ops_range_Range_start : T;
  core_ops_range_Range_end_ : T;
}.
Arguments mk_core_ops_range_Range {_}.
Arguments core_ops_range_Range_start {_}.
Arguments core_ops_range_Range_end_ {_}.

(*** [alloc] *)

Definition alloc_boxed_Box_deref {T : Type} (x : T) : T := x.
Definition alloc_boxed_Box_deref_mut {T : Type} (x : T) : T * (T -> T) :=
  (x, fun x => x).

(* Trait instance *)
Definition alloc_boxed_Box_coreopsDerefInst (Self : Type) : core_ops_deref_Deref Self Self := {|
  core_ops_deref_Deref_deref := fun x => Ok (alloc_boxed_Box_deref x);
|}.

(* Trait instance *)
Definition alloc_boxed_Box_coreopsDerefMutInst (Self : Type) : core_ops_deref_DerefMut Self Self := {|
  core_ops_deref_DerefMut_derefInst := alloc_boxed_Box_coreopsDerefInst Self;
  core_ops_deref_DerefMut_deref_mut := fun x => Ok (alloc_boxed_Box_deref_mut x);
|}.


(*** Arrays *)
Definition array T (n : usize) := { l: list T | Z.of_nat (length l) = to_Z n}.

Lemma le_0_usize_max : 0 <= usize_max.
Proof.
  pose (H := usize_max_bound).
  unfold u32_max in H.
  lia.
Qed.

Lemma eqb_imp_eq (x y : Z) : Z.eqb x y = true -> x = y.
Proof.
  lia.
Qed.

(* Helpers over the underlying lists. *)
Definition zlen {T} (l : list T) : Z := Z.of_nat (length l).

Definition opt_result {A} (o : option A) : result A :=
  match o with Some v => Ok v | None => Fail_ Failure end.

Fixpoint list_update {A} (l: list A) (n: nat) (a: A)
  : list A :=
  match l with
  | []     => []
  | x :: t => match n with
    | 0%nat => a :: t
    | S m => x :: (list_update t m a)
end end.

Lemma list_update_length : forall {A} (l : list A) (n : nat) (a : A),
  length (list_update l n a) = length l.
Proof. induction l as [|x t IH]; intros [|m] a; simpl; auto. Qed.

(* An array is determined by its list: the length certificate is an equality
   in [Z], a decidable type, so it is unique (UIP_dec — no axiom). *)
Lemma array_ext {T : Type} {n : usize} (a b : array T n) :
  proj1_sig a = proj1_sig b -> a = b.
Proof.
  destruct a as [la Ha], b as [lb Hb]; cbn. intros ->.
  f_equal. apply UIP_dec. apply Z.eq_dec.
Qed.

(* There is deliberately NO `mk_array : list T -> array T n` here: upstream's
   Axiom of that type is inconsistent (`array T n` is empty at `T := Empty_set`,
   `n > 0`). Array literals of statically known length are built with their own
   length proof (Update_FunsExternal.mk_array4 / mk_array15). *)

(* For initialization *)
Definition array_repeat {T : Type} (n : usize) (x : T) : array T n.
Proof.
  refine (exist _ (repeat x (Z.to_nat (to_Z n))) _).
  rewrite repeat_length. apply Z2Nat.id. apply to_Z_usize_nonneg.
Defined.

Definition array_index_usize {T : Type} {n : usize} (x : array T n) (i : usize) : result T :=
  opt_result (nth_error (proj1_sig x) (Z.to_nat (to_Z i))).

Definition array_update {T : Type} {n : usize} (x : array T n) (i : usize) (nx : T) : array T n :=
  exist _ (list_update (proj1_sig x) (Z.to_nat (to_Z i)) nx)
        (eq_trans (f_equal Z.of_nat (list_update_length _ _ _)) (proj2_sig x)).

Definition array_update_usize {T : Type} {n : usize} (x : array T n) (i : usize) (nx : T) : result (array T n) :=
  if Z.ltb (to_Z i) (to_Z n) then Ok (array_update x i nx) else Fail_ Failure.

Definition array_index_mut_usize {T : Type} {n : usize} (a : array T n) (i : usize) :
  result (T * (T -> array T n)) :=
  match array_index_usize a i with
  | Fail_ e => Fail_ e
  | Ok x => Ok (x, array_update a i)
  end.

(*** Slice *)
Definition slice T := { l: list T | Z.of_nat (length l) <= usize_max}.

Definition slice_len {T : Type} (s : slice T) : usize.
Proof.
  refine (exist _ (zlen (proj1_sig s)) _).
  apply scalar_in_bounds_complete. pose proof (proj2_sig s) as Hs.
  cbn [scalar_min scalar_max]. unfold usize_min, zlen in *. lia.
Defined.

Lemma to_Z_slice_len : forall {T : Type} (s : slice T), to_Z (slice_len s) = zlen (proj1_sig s).
Proof. reflexivity. Qed.

Definition slice_index_usize {T : Type} (x : slice T) (i : usize) : result T :=
  opt_result (nth_error (proj1_sig x) (Z.to_nat (to_Z i))).

Definition slice_update {T : Type} (x : slice T) (i : usize) (nx : T) : slice T.
Proof.
  refine (exist _ (list_update (proj1_sig x) (Z.to_nat (to_Z i)) nx) _).
  rewrite list_update_length. exact (proj2_sig x).
Defined.

Definition slice_update_usize {T : Type} (x : slice T) (i : usize) (nx : T) : result (slice T) :=
  if Z.ltb (to_Z i) (zlen (proj1_sig x)) then Ok (slice_update x i nx) else Fail_ Failure.

Definition slice_index_mut_usize {T : Type} (s : slice T) (i : usize) :
  result (T * (T -> slice T)) :=
  match slice_index_usize s i with
  | Fail_ e => Fail_ e
  | Ok x => Ok (x, slice_update s i)
  end.

(*** Subslices *)

Definition array_to_slice {T : Type} {n : usize} (x : array T n) : slice T.
Proof.
  refine (exist _ (proj1_sig x) _).
  rewrite (proj2_sig x). apply to_Z_usize_le_max.
Defined.

(* Rust's write-back of a length-matching slice into an array: a slice whose
   length matches IS the array. A mismatch cannot arise on any path Aeneas
   produces (the slice handed back is the one borrowed); the model then keeps
   the original array, which is what makes the operation total. *)
Definition array_from_slice {T : Type} {n : usize} (x : array T n) (s : slice T) : array T n :=
  match Z.eq_dec (Z.of_nat (length (proj1_sig s))) (to_Z n) with
  | left Hs => exist _ (proj1_sig s) Hs
  | right _ => x
  end.

Definition array_to_slice_mut {T : Type} {n : usize} (a : array T n) :
  slice T * (slice T -> array T n) :=
  (array_to_slice a, array_from_slice a)
.

(* --- range sub-slicing: Rust's `&s[a..b]` --------------------------------- *)

Definition sub_list {T} (l : list T) (a b : usize) : list T :=
  firstn (Z.to_nat (to_Z b - to_Z a)) (skipn (Z.to_nat (to_Z a)) l).

Lemma sub_list_zlen_le : forall {T} (l : list T) (a b : usize),
  zlen (sub_list l a b) <= zlen l.
Proof.
  intros T l a b. unfold zlen, sub_list.
  rewrite firstn_length, skipn_length. lia.
Qed.

Definition slice_sub {T : Type} (s : slice T) (a b : usize) : slice T.
Proof.
  refine (exist _ (sub_list (proj1_sig s) a b) _).
  pose proof (proj2_sig s) as Hs.
  pose proof (sub_list_zlen_le (proj1_sig s) a b) as Hle. unfold zlen in Hle.
  exact (Z.le_trans _ _ _ Hle Hs).
Defined.

(* In range -> the sub-slice; out of range -> `None`, which
   `core_slice_index_Slice_index` turns into a panic (`Fail`). *)
Definition slice_range_get {T : Type} (r : core_ops_range_Range usize) (s : slice T)
  : result (option (slice T)) :=
  let a := r.(core_ops_range_Range_start) in
  let b := r.(core_ops_range_Range_end_) in
  match Z_le_dec (to_Z a) (to_Z b), Z_le_dec (to_Z b) (to_Z (slice_len s)) with
  | left _, left _ => Ok (Some (slice_sub s a b))
  | _, _ => Ok None
  end.

Definition slice_range_index {T : Type} (r : core_ops_range_Range usize) (s : slice T)
  : result (slice T) :=
  match slice_range_get r s with
  | Ok (Some sub) => Ok sub
  | Ok None => Fail_ Failure
  | Fail_ e => Fail_ e
  end.

(* --- the WRITE-BACK of a mutable window: the real splice ------------------ *)

(* `&mut s[a..b]` handed back a new window `new`: the result keeps s's elements
   before a and from b on, and takes `new` in between. *)
Definition splice_list {T} (l : list T) (a b : usize) (new : list T) : list T :=
  firstn (Z.to_nat (to_Z a)) l ++ new ++ skipn (Z.to_nat (to_Z b)) l.

(* A slice is a list with a length bound, so the splice is only usable as a
   slice when it does not change the length. On every path Aeneas can produce
   (the window handed back is the window that was borrowed) it does not; off
   those paths the model keeps the original, which is what makes this total. *)
Definition splice_or {T : Type} (s : slice T) (a b : usize) (new : list T) : list T :=
  if Nat.eqb (length (splice_list (proj1_sig s) a b new)) (length (proj1_sig s))
  then splice_list (proj1_sig s) a b new else proj1_sig s.

Lemma splice_or_length : forall {T : Type} (s : slice T) (a b : usize) (new : list T),
  length (splice_or s a b new) = length (proj1_sig s).
Proof.
  intros T s a b new. unfold splice_or.
  destruct (Nat.eqb_spec (length (splice_list (proj1_sig s) a b new))
                         (length (proj1_sig s))) as [E|_];
    [ exact E | reflexivity ].
Qed.

Definition slice_splice {T : Type} (s : slice T) (a b : usize) (sub' : slice T) : slice T.
Proof.
  refine (exist _ (splice_or s a b (proj1_sig sub')) _).
  rewrite splice_or_length. exact (proj2_sig s).
Defined.

Definition slice_range_get_mut {T : Type} (r : core_ops_range_Range usize) (s : slice T)
  : result (option (slice T) * (option (slice T) -> slice T)) :=
  match slice_range_get r s with
  | Ok o => Ok (o, fun o' =>
      match o' with
      | Some sub' => slice_splice s r.(core_ops_range_Range_start)
                                   r.(core_ops_range_Range_end_) sub'
      | None => s
      end)
  | Fail_ e => Fail_ e
  end.

Definition slice_range_index_mut {T : Type} (r : core_ops_range_Range usize) (s : slice T)
  : result (slice T * (slice T -> slice T)) :=
  match slice_range_index r s with
  | Ok sub => Ok (sub, slice_splice s r.(core_ops_range_Range_start)
                                      r.(core_ops_range_Range_end_))
  | Fail_ e => Fail_ e
  end.

Definition slice_subslice {T : Type} (x : slice T) (r : core_ops_range_Range usize) : result (slice T) :=
  slice_range_index r x.
Definition slice_update_subslice {T : Type} (x : slice T) (r : core_ops_range_Range usize) (ns : slice T) : result (slice T) :=
  match slice_range_index_mut r x with
  | Ok (_, back) => Ok (back ns)
  | Fail_ e => Fail_ e
  end.
Definition array_subslice {T : Type} {n : usize} (x : array T n) (r : core_ops_range_Range usize) : result (slice T) :=
  slice_range_index r (array_to_slice x).
Definition array_update_subslice {T : Type} {n : usize} (x : array T n) (r : core_ops_range_Range usize) (ns : slice T) : result (array T n) :=
  match slice_range_index_mut r (array_to_slice x) with
  | Ok (_, back) => Ok (array_from_slice x (back ns))
  | Fail_ e => Fail_ e
  end.

(*** Vectors *)

Definition alloc_vec_Vec T := { l: list T | Z.of_nat (length l) <= usize_max }.

Definition alloc_vec_Vec_to_list {T: Type} (v: alloc_vec_Vec T) : list T := proj1_sig v.

Definition alloc_vec_Vec_length {T: Type} (v: alloc_vec_Vec T) : Z := Z.of_nat (length (alloc_vec_Vec_to_list v)).

Definition alloc_vec_Vec_new (T: Type) : alloc_vec_Vec T := (exist _ [] le_0_usize_max).

Lemma alloc_vec_Vec_len_in_usize {T} (v: alloc_vec_Vec T) : usize_min <= alloc_vec_Vec_length v <= usize_max.
Proof.
  unfold alloc_vec_Vec_length, usize_min.
  split.
  - lia.
  - apply (proj2_sig v).
Qed.

Definition alloc_vec_Vec_len {T: Type} (v: alloc_vec_Vec T) : usize :=
  mk_scalar_of_bounds Usize (alloc_vec_Vec_length v) (alloc_vec_Vec_len_in_usize v).

Definition alloc_vec_Vec_bind {A B} (v: alloc_vec_Vec A) (f: list A -> result (list B)) : result (alloc_vec_Vec B) :=
  l <- f (alloc_vec_Vec_to_list v) ;
  match sumbool_of_bool (scalar_le_max Usize (Z.of_nat (length l))) with
  | left H => Ok (exist _ l (scalar_le_max_valid _ _ H))
  | right _ => Fail_ Failure
  end.

Definition alloc_vec_Vec_push {T: Type} (v: alloc_vec_Vec T) (x: T) : result (alloc_vec_Vec T) :=
  alloc_vec_Vec_bind v (fun l => Ok (l ++ [x])).

Definition alloc_vec_Vec_insert {T: Type} (v: alloc_vec_Vec T) (i: usize) (x: T) : result (alloc_vec_Vec T) :=
  alloc_vec_Vec_bind v (fun l =>
    if to_Z i <? Z.of_nat (length l)
    then Ok (list_update l (usize_to_nat i) x)
    else Fail_ Failure).

(* `alloc_vec_Vec T` and `slice T` are the same sigma type, so the vector
   helpers ARE the slice ones. *)
Definition alloc_vec_Vec_index_usize {T : Type} (v : alloc_vec_Vec T) (i : usize) : result T :=
  slice_index_usize v i.
Definition alloc_vec_Vec_update_usize {T : Type} (v : alloc_vec_Vec T) (i : usize) (x : T) : result (alloc_vec_Vec T) :=
  slice_update_usize v i x.
Definition alloc_vec_Vec_update {T : Type} (v : alloc_vec_Vec T) (i : usize) (x : T) : alloc_vec_Vec T :=
  slice_update v i x.

Definition alloc_vec_Vec_index_mut_usize {T : Type} (v: alloc_vec_Vec T) (i: usize) :
  result (T * (T -> alloc_vec_Vec T)) :=
  match alloc_vec_Vec_index_usize v i with
  | Ok x =>
    Ok (x, alloc_vec_Vec_update v i)
  | Fail_ e => Fail_ e
  end.

(* Trait declaration: [core::slice::index::private_slice_index::Sealed] *)
Definition core_slice_index_private_slice_index_Sealed (self : Type) := unit.

(* Trait declaration: [core::slice::index::SliceIndex] *)
Record core_slice_index_SliceIndex (Self T Output : Type) := mk_core_slice_index_SliceIndex {
  core_slice_index_SliceIndex_sealedInst : core_slice_index_private_slice_index_Sealed Self;
  core_slice_index_SliceIndex_get : Self -> T -> result (option Output);
  core_slice_index_SliceIndex_get_mut :
    Self -> T -> result (option Output * (option Output -> T));
  core_slice_index_SliceIndex_get_unchecked : Self -> const_raw_ptr T -> result (const_raw_ptr Output);
  core_slice_index_SliceIndex_get_unchecked_mut : Self -> mut_raw_ptr T -> result (mut_raw_ptr Output);
  core_slice_index_SliceIndex_index : Self -> T -> result Output;
  core_slice_index_SliceIndex_index_mut :
    Self -> T -> result (Output * (Output -> T));
}.
Arguments mk_core_slice_index_SliceIndex {_ _ _}.
Arguments core_slice_index_SliceIndex_sealedInst {_ _ _}.
Arguments core_slice_index_SliceIndex_get {_ _ _}.
Arguments core_slice_index_SliceIndex_get_mut {_ _ _}.
Arguments core_slice_index_SliceIndex_get_unchecked {_ _ _}.
Arguments core_slice_index_SliceIndex_get_unchecked_mut {_ _ _}.
Arguments core_slice_index_SliceIndex_index {_ _ _}.
Arguments core_slice_index_SliceIndex_index_mut {_ _ _}.

(* [core::slice::index::[T]::index]: forward function *)
Definition core_slice_index_Slice_index
  {T Idx Output : Type} (inst : core_slice_index_SliceIndex Idx (slice T) Output)
  (s : slice T) (i : Idx) : result Output :=
  x <- inst.(core_slice_index_SliceIndex_get) i s;
  match x with
  | None => Fail_ Failure
  | Some x => Ok x
  end.

(* [core::slice::index::Range:::get]: forward function *)
Definition core_slice_index_SliceIndexRangeUsizeSlice_get {T : Type} (i : core_ops_range_Range usize) (s : slice T) : result (option (slice T)) :=
  slice_range_get i s.

(* [core::slice::index::Range::get_mut]: forward function *)
Definition core_slice_index_SliceIndexRangeUsizeSlice_get_mut
  {T : Type} :
    core_ops_range_Range usize -> slice T ->
    result (option (slice T) * (option (slice T) -> slice T)) :=
  slice_range_get_mut.

(* [core::slice::index::Range::get_unchecked]: forward function *)
Definition core_slice_index_SliceIndexRangeUsizeSlice_get_unchecked
  {T : Type} :
  core_ops_range_Range usize -> const_raw_ptr (slice T) -> result (const_raw_ptr (slice T)) :=
  (* Don't know what the model should be - for now we always fail to make
     sure code which uses it fails *)
  fun _ _ => Fail_ Failure.

(* [core::slice::index::Range::get_unchecked_mut]: forward function *)
Definition core_slice_index_SliceIndexRangeUsizeSlice_get_unchecked_mut
  {T : Type} :
  core_ops_range_Range usize -> mut_raw_ptr (slice T) -> result (mut_raw_ptr (slice T)) :=
  (* Don't know what the model should be - for now we always fail to make
    sure code which uses it fails *)
  fun _ _ => Fail_ Failure.

(* [core::slice::index::Range::index]: forward function *)
Definition core_slice_index_SliceIndexRangeUsizeSlice_index
  {T : Type} : core_ops_range_Range usize -> slice T -> result (slice T) :=
  slice_range_index.

(* [core::slice::index::Range::index_mut]: forward function *)
Definition core_slice_index_SliceIndexRangeUsizeSlice_index_mut
  {T : Type} : core_ops_range_Range usize -> slice T -> result (slice T * (slice T -> slice T)) :=
  slice_range_index_mut.

(* [core::slice::index::[T]::index_mut]: forward function *)
Definition core_slice_index_Slice_index_mut
  {T Idx Output : Type} (inst : core_slice_index_SliceIndex Idx (slice T) Output)
  (s : slice T) (i : Idx) : result (Output * (Output -> slice T)) :=
  inst.(core_slice_index_SliceIndex_index_mut) i s.

(* [core::array::[T; N]::index]: forward function. Rust's `impl Index for
   [T; N]` forwards to the slice impl. *)
Definition core_array_Array_index
  {T Idx Output : Type} {N : usize} (inst : core_ops_index_Index (slice T) Idx Output)
  (a : array T N) (i : Idx) : result Output :=
  core_ops_index_Index_index _ inst (array_to_slice a) i.

(* [core::array::[T; N]::index_mut]: forward function. Forwards to the slice
   impl, write-back included: the slice-level write-back is composed with
   `array_from_slice` to land back in the array type. *)
Definition core_array_Array_index_mut
  {T Idx Output : Type} {N : usize} (inst : core_ops_index_IndexMut (slice T) Idx Output)
  (a : array T N) (i : Idx) : result (Output * (Output -> array T N)) :=
  match inst.(core_ops_index_IndexMut_index_mut) (array_to_slice a) i with
  | Ok (out, back) => Ok (out, fun o => array_from_slice a (back o))
  | Fail_ e => Fail_ e
  end.

(* Trait implementation: [core::slice::index::private_slice_index::Range] *)
Definition core_slice_index_private_slice_index_SealedRangeUsizeInst
  : core_slice_index_private_slice_index_Sealed (core_ops_range_Range usize) := tt.

(* Trait implementation: [core::slice::index::Range] *)
Definition core_slice_index_SliceIndexRangeUsizeSliceInst (T : Type) :
  core_slice_index_SliceIndex (core_ops_range_Range usize) (slice T) (slice T) := {|
  core_slice_index_SliceIndex_sealedInst := core_slice_index_private_slice_index_SealedRangeUsizeInst;
  core_slice_index_SliceIndex_get := core_slice_index_SliceIndexRangeUsizeSlice_get;
  core_slice_index_SliceIndex_get_mut := core_slice_index_SliceIndexRangeUsizeSlice_get_mut;
  core_slice_index_SliceIndex_get_unchecked := core_slice_index_SliceIndexRangeUsizeSlice_get_unchecked;
  core_slice_index_SliceIndex_get_unchecked_mut := core_slice_index_SliceIndexRangeUsizeSlice_get_unchecked_mut;
  core_slice_index_SliceIndex_index := core_slice_index_SliceIndexRangeUsizeSlice_index;
  core_slice_index_SliceIndex_index_mut := core_slice_index_SliceIndexRangeUsizeSlice_index_mut;
|}.

(* Trait implementation: [core::slice::index::[T]] *)
Definition core_ops_index_IndexSliceInst {T Idx Output : Type}
  (inst : core_slice_index_SliceIndex Idx (slice T) Output) :
  core_ops_index_Index (slice T) Idx Output := {|
  core_ops_index_Index_index := core_slice_index_Slice_index inst;
|}.

(* Trait implementation: [core::slice::index::[T]] *)
Definition core_ops_index_IndexMutSliceInst {T Idx Output : Type}
  (inst : core_slice_index_SliceIndex Idx (slice T) Output) :
  core_ops_index_IndexMut (slice T) Idx Output := {|
  core_ops_index_IndexMut_indexInst := core_ops_index_IndexSliceInst inst;
  core_ops_index_IndexMut_index_mut := core_slice_index_Slice_index_mut inst;
|}.

(* Trait implementation: [core::array::[T; N]] *)
Definition core_ops_index_IndexArrayInst {T Idx Output : Type} (N : usize)
  (inst : core_ops_index_Index (slice T) Idx Output) :
  core_ops_index_Index (array T N) Idx Output := {|
  core_ops_index_Index_index := core_array_Array_index inst;
|}.

(* Trait implementation: [core::array::[T; N]] *)
Definition core_ops_index_IndexMutArrayInst {T Idx Output : Type} (N : usize)
  (inst : core_ops_index_IndexMut (slice T) Idx Output) :
  core_ops_index_IndexMut (array T N) Idx Output := {|
  core_ops_index_IndexMut_indexInst := core_ops_index_IndexArrayInst N inst.(core_ops_index_IndexMut_indexInst);
  core_ops_index_IndexMut_index_mut := core_array_Array_index_mut inst;
|}.

(* [core::slice::index::usize::get]: forward function *)
Definition core_slice_index_usize_get {T : Type} (i : usize) (s : slice T) : result (option T) :=
  Ok (nth_error (proj1_sig s) (Z.to_nat (to_Z i))).

(* [core::slice::index::usize::get_mut]: forward function *)
Definition core_slice_index_usize_get_mut
  {T : Type} (i : usize) (s : slice T) : result (option T * (option T -> slice T)) :=
  Ok (nth_error (proj1_sig s) (Z.to_nat (to_Z i)),
      fun o => match o with Some x => slice_update s i x | None => s end).

(* [core::slice::index::usize::get_unchecked]: forward function *)
Definition core_slice_index_usize_get_unchecked
  {T : Type} : usize -> const_raw_ptr (slice T) -> result (const_raw_ptr T) :=
  (* Don't know what the model should be - for now we always fail to make
     sure code which uses it fails *)
  fun _ _ => Fail_ Failure.

(* [core::slice::index::usize::get_unchecked_mut]: forward function *)
Definition core_slice_index_usize_get_unchecked_mut
  {T : Type} : usize -> mut_raw_ptr (slice T) -> result (mut_raw_ptr T) :=
  fun _ _ => Fail_ Failure.

(* [core::slice::index::usize::index]: forward function *)
Definition core_slice_index_usize_index {T : Type} (i : usize) (s : slice T) : result T :=
  slice_index_usize s i.

(* [core::slice::index::usize::index_mut]: forward function *)
Definition core_slice_index_usize_index_mut
  {T : Type} (i : usize) (s : slice T) : result (T * (T -> slice T)) :=
  slice_index_mut_usize s i.

(* Trait implementation: [core::slice::index::private_slice_index::usize] *)
Definition core_slice_index_private_slice_index_SealedUsizeInst
  : core_slice_index_private_slice_index_Sealed usize := tt.

(* Trait implementation: [core::slice::index::usize] *)
Definition core_slice_index_SliceIndexUsizeSliceInst (T : Type) :
  core_slice_index_SliceIndex usize (slice T) T := {|
  core_slice_index_SliceIndex_sealedInst := core_slice_index_private_slice_index_SealedUsizeInst;
  core_slice_index_SliceIndex_get := core_slice_index_usize_get;
  core_slice_index_SliceIndex_get_mut := core_slice_index_usize_get_mut;
  core_slice_index_SliceIndex_get_unchecked := core_slice_index_usize_get_unchecked;
  core_slice_index_SliceIndex_get_unchecked_mut := core_slice_index_usize_get_unchecked_mut;
  core_slice_index_SliceIndex_index := core_slice_index_usize_index;
  core_slice_index_SliceIndex_index_mut := core_slice_index_usize_index_mut;
|}.

(* [alloc::vec::Vec::index]: forward function *)
Definition alloc_vec_Vec_index {T Idx Output : Type}
  (inst : core_slice_index_SliceIndex Idx (slice T) Output)
  (Self : alloc_vec_Vec T) (i : Idx) : result Output :=
  inst.(core_slice_index_SliceIndex_index) i Self.

(* [alloc::vec::Vec::index_mut]: forward function *)
Definition alloc_vec_Vec_index_mut {T Idx Output : Type}
  (inst : core_slice_index_SliceIndex Idx (slice T) Output)
  (Self : alloc_vec_Vec T) (i : Idx) :
  result (Output * (Output -> alloc_vec_Vec T)) :=
  inst.(core_slice_index_SliceIndex_index_mut) i Self.

(* Trait implementation: [alloc::vec::Vec] *)
Definition alloc_vec_Vec_IndexInst {T Idx Output : Type}
  (inst : core_slice_index_SliceIndex Idx (slice T) Output) :
  core_ops_index_Index (alloc_vec_Vec T) Idx Output := {|
  core_ops_index_Index_index := alloc_vec_Vec_index inst;
|}.

(* Trait implementation: [alloc::vec::Vec] *)
Definition alloc_vec_Vec_IndexMutInst {T Idx Output : Type}
  (inst : core_slice_index_SliceIndex Idx (slice T) Output) :
  core_ops_index_IndexMut (alloc_vec_Vec T) Idx Output := {|
  core_ops_index_IndexMut_indexInst := alloc_vec_Vec_IndexInst inst;
  core_ops_index_IndexMut_index_mut := alloc_vec_Vec_index_mut inst;
|}.

(*** Theorems *)

Lemma alloc_vec_Vec_index_eq : forall {a : Type} (v : alloc_vec_Vec a) (i : usize) (x : a),
  alloc_vec_Vec_index (core_slice_index_SliceIndexUsizeSliceInst a) v i =
    alloc_vec_Vec_index_usize v i.
Proof. reflexivity. Qed.

Lemma alloc_vec_Vec_index_mut_eq : forall {a : Type} (v : alloc_vec_Vec a) (i : usize) (x : a),
  alloc_vec_Vec_index_mut (core_slice_index_SliceIndexUsizeSliceInst a) v i =
    alloc_vec_Vec_index_mut_usize v i.
Proof. reflexivity. Qed.

End Primitives.
