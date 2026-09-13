(* Primitives_Check.v — executable pins on the backend model's Rust semantics.

   Every [Example] below evaluates a primitive on literal scalars by
   [vm_compute] and compares the result with the value Rust computes (Rust
   Reference, "Arithmetic and Logical Binary Operators" / "Overflow"; the
   `mem::replace` and `Vec::insert` contracts of `core`/`alloc`). A change to
   Primitives.v that drifts from Rust on any of these makes this file — and so
   the library build — fail. Depends on Primitives and the standard library
   only; never imported by anything. *)

Require Import Coq.ZArith.ZArith.
Require Import Coq.Lists.List.
Import ListNotations.
Require Import Lia.
Require Import Primitives.
Import Primitives.
Local Open Scope Z_scope.

(* Bounds side condition of [mk_scalar_of_bounds] on literals: unfold every
   named bound and the target width, reduce the [Nat.eqb] gate on `usize`, and
   let lia close the arithmetic. *)
Ltac bnd :=
  unfold scalar_min, scalar_max, isize_min, isize_max, usize_min, usize_max,
         i8_min, i8_max, i16_min, i16_max, i32_min, i32_max, i64_min, i64_max,
         i128_min, i128_max, u8_min, u8_max, u16_min, u16_max, u32_min, u32_max,
         u64_min, u64_max, u128_min, u128_max, AeneasTarget.usize_bits;
  simpl; lia.

Notation "'sc' ty z" := (mk_scalar_of_bounds ty z ltac:(bnd)) (at level 10, ty at level 9, z at level 9, only parsing).

(* Observe a scalar result by its value: [Ok s ↦ Some (to_Z s)], failure ↦ None.
   Comparing raw [result (scalar ty)] terms would compare bounds proofs too. *)
Definition rZ {ty} (r : result (scalar ty)) : option Z :=
  match r with Ok s => Some (to_Z s) | Fail_ _ => None end.

Definition rL {T} (r : result (alloc_vec_Vec T)) : option (list T) :=
  match r with Ok v => Some (alloc_vec_Vec_to_list v) | Fail_ _ => None end.

(* ---- mem::replace: returns the OLD value, stores the NEW one ------------- *)
Example mem_replace_old_new : core_mem_replace 0%nat 1%nat = (0%nat, 1%nat).
Proof. reflexivity. Qed.

(* ---- Vec::insert(i, x): 0 <= i <= len inserts and shifts; i > len panics -- *)
Definition v2 : result (alloc_vec_Vec nat) :=
  v <- alloc_vec_Vec_push (alloc_vec_Vec_new nat) 10%nat; alloc_vec_Vec_push v 20%nat.

Example vec_insert_middle :
  rL (v <- v2; alloc_vec_Vec_insert v (sc Usize 1) 99%nat) = Some [10; 99; 20]%nat.
Proof. vm_compute. reflexivity. Qed.

Example vec_insert_at_len :
  rL (v <- v2; alloc_vec_Vec_insert v (sc Usize 2) 99%nat) = Some [10; 20; 99]%nat.
Proof. vm_compute. reflexivity. Qed.

Example vec_insert_beyond_len :
  rL (v <- v2; alloc_vec_Vec_insert v (sc Usize 3) 99%nat) = None.
Proof. vm_compute. reflexivity. Qed.

(* ---- `/` rounds toward zero; `x / 0` and `MIN / -1` panic ---------------- *)
Example div_neg3_2 : rZ (i8_div (sc I8 (-3)) (sc I8 2)) = Some (-1).
Proof. vm_compute. reflexivity. Qed.

Example div_7_neg2 : rZ (i8_div (sc I8 7) (sc I8 (-2))) = Some (-3).
Proof. vm_compute. reflexivity. Qed.

Example div_neg7_neg2 : rZ (i32_div (sc I32 (-7)) (sc I32 (-2))) = Some 3.
Proof. vm_compute. reflexivity. Qed.

Example div_u8_by_zero : rZ (u8_div (sc U8 7) (sc U8 0)) = None.
Proof. vm_compute. reflexivity. Qed.

Example div_i8_by_zero : rZ (i8_div (sc I8 (-7)) (sc I8 0)) = None.
Proof. vm_compute. reflexivity. Qed.

Example div_i8_min_by_neg1 : rZ (i8_div (sc I8 (-128)) (sc I8 (-1))) = None.
Proof. vm_compute. reflexivity. Qed.

Example div_i8_min_by_1 : rZ (i8_div (sc I8 (-128)) (sc I8 1)) = Some (-128).
Proof. vm_compute. reflexivity. Qed.

Example div_u8_255_2 : rZ (u8_div (sc U8 255) (sc U8 2)) = Some 127.
Proof. vm_compute. reflexivity. Qed.

(* ---- `%` has the sign of the dividend; `x % 0` and `MIN % -1` panic ------ *)
Example rem_neg3_2 : rZ (i8_rem (sc I8 (-3)) (sc I8 2)) = Some (-1).
Proof. vm_compute. reflexivity. Qed.

Example rem_3_neg2 : rZ (i8_rem (sc I8 3) (sc I8 (-2))) = Some 1.
Proof. vm_compute. reflexivity. Qed.

Example rem_neg7_neg2 : rZ (i16_rem (sc I16 (-7)) (sc I16 (-2))) = Some (-1).
Proof. vm_compute. reflexivity. Qed.

Example rem_u8_by_zero : rZ (u8_rem (sc U8 7) (sc U8 0)) = None.
Proof. vm_compute. reflexivity. Qed.

Example rem_i8_by_zero : rZ (i8_rem (sc I8 7) (sc I8 0)) = None.
Proof. vm_compute. reflexivity. Qed.

Example rem_i8_min_by_neg1 : rZ (i8_rem (sc I8 (-128)) (sc I8 (-1))) = None.
Proof. vm_compute. reflexivity. Qed.

Example rem_i8_neg127_by_neg1 : rZ (i8_rem (sc I8 (-127)) (sc I8 (-1))) = Some 0.
Proof. vm_compute. reflexivity. Qed.

Example rem_u8_255_16 : rZ (u8_rem (sc U8 255) (sc U8 16)) = Some 15.
Proof. vm_compute. reflexivity. Qed.

(* ---- `<<` truncates to the width; `n >= bits` panics --------------------- *)
Example shl_u8_128_1 : rZ (u8_shl (sc U8 128) (sc U32 1)) = Some 0.
Proof. vm_compute. reflexivity. Qed.

Example shl_u8_1_7 : rZ (u8_shl (sc U8 1) (sc U32 7)) = Some 128.
Proof. vm_compute. reflexivity. Qed.

Example shl_u8_1_8_fails : rZ (u8_shl (sc U8 1) (sc U32 8)) = None.
Proof. vm_compute. reflexivity. Qed.

Example shl_u8_255_4 : rZ (u8_shl (sc U8 255) (sc U32 4)) = Some 240.
Proof. vm_compute. reflexivity. Qed.

Example shl_i8_1_7 : rZ (i8_shl (sc I8 1) (sc U32 7)) = Some (-128).
Proof. vm_compute. reflexivity. Qed.

Example shl_i8_neg1_1 : rZ (i8_shl (sc I8 (-1)) (sc U32 1)) = Some (-2).
Proof. vm_compute. reflexivity. Qed.

Example shl_i8_64_1 : rZ (i8_shl (sc I8 64) (sc U32 1)) = Some (-128).
Proof. vm_compute. reflexivity. Qed.

Example shl_i8_neg_amount_fails : rZ (i8_shl (sc I8 1) (sc I32 (-1))) = None.
Proof. vm_compute. reflexivity. Qed.

Example shl_u32_1_31 : rZ (u32_shl (sc U32 1) (sc U32 31)) = Some 2147483648.
Proof. vm_compute. reflexivity. Qed.

Example shl_u32_1_32_fails : rZ (u32_shl (sc U32 1) (sc U32 32)) = None.
Proof. vm_compute. reflexivity. Qed.

Example shl_u128_1_127 : rZ (u128_shl (sc U128 1) (sc U32 127)) = Some (2 ^ 127).
Proof. vm_compute. reflexivity. Qed.

(* ---- `>>`: logical on unsigned, arithmetic on signed; `n >= bits` panics -- *)
Example shr_i8_neg1_1 : rZ (i8_shr (sc I8 (-1)) (sc U32 1)) = Some (-1).
Proof. vm_compute. reflexivity. Qed.

Example shr_i8_neg128_7 : rZ (i8_shr (sc I8 (-128)) (sc U32 7)) = Some (-1).
Proof. vm_compute. reflexivity. Qed.

Example shr_i8_neg3_1 : rZ (i8_shr (sc I8 (-3)) (sc U32 1)) = Some (-2).
Proof. vm_compute. reflexivity. Qed.

Example shr_u8_255_7 : rZ (u8_shr (sc U8 255) (sc U32 7)) = Some 1.
Proof. vm_compute. reflexivity. Qed.

Example shr_u8_255_8_fails : rZ (u8_shr (sc U8 255) (sc U32 8)) = None.
Proof. vm_compute. reflexivity. Qed.

Example shr_i8_neg1_8_fails : rZ (i8_shr (sc I8 (-1)) (sc U32 8)) = None.
Proof. vm_compute. reflexivity. Qed.

(* ---- pointer-sized types: width-parametric (hold at 32 and at 64) --------- *)
Example shl_usize_top_bit :
  rZ (usize_shl (sc Usize 1) (sc U32 (scalar_bits Usize - 1))) = Some (2 ^ (scalar_bits Usize - 1)).
Proof. vm_compute. reflexivity. Qed.

Example shl_usize_bits_fails :
  rZ (usize_shl (sc Usize 1) (sc U32 (scalar_bits Usize))) = None.
Proof. vm_compute. reflexivity. Qed.

Example shr_isize_neg1_1 : rZ (isize_shr (sc Isize (-1)) (sc U32 1)) = Some (-1).
Proof. vm_compute. reflexivity. Qed.

Example div_isize_neg3_2 : rZ (isize_div (sc Isize (-3)) (sc Isize 2)) = Some (-1).
Proof. vm_compute. reflexivity. Qed.

(* ---- `as` between integer types: truncate to the target width, reinterpret -- *)
Example cast_u16_256_u8 : rZ (scalar_cast U16 U8 (sc U16 256)) = Some 0.
Proof. vm_compute. reflexivity. Qed.

Example cast_u8_255_i8 : rZ (scalar_cast U8 I8 (sc U8 255)) = Some (-1).
Proof. vm_compute. reflexivity. Qed.

Example cast_i8_neg1_u8 : rZ (scalar_cast I8 U8 (sc I8 (-1))) = Some 255.
Proof. vm_compute. reflexivity. Qed.

Example cast_i8_neg1_i32 : rZ (scalar_cast I8 I32 (sc I8 (-1))) = Some (-1).
Proof. vm_compute. reflexivity. Qed.

Example cast_i32_neg1_u32 : rZ (scalar_cast I32 U32 (sc I32 (-1))) = Some 4294967295.
Proof. vm_compute. reflexivity. Qed.

Example cast_u32_max_u64 : rZ (scalar_cast U32 U64 (sc U32 4294967295)) = Some 4294967295.
Proof. vm_compute. reflexivity. Qed.

Example cast_u64_2p40_5_u32 : rZ (scalar_cast U64 U32 (sc U64 (2 ^ 40 + 5))) = Some 5.
Proof. vm_compute. reflexivity. Qed.

(* pointer-sized: identity in both directions on a value <= u32_max (32 and 64) *)
Example cast_u32_usize_id : rZ (scalar_cast U32 Usize (sc U32 4294967295)) = Some 4294967295.
Proof. vm_compute. reflexivity. Qed.

Example cast_usize_u32_id : rZ (scalar_cast Usize U32 (sc Usize 4294967295)) = Some 4294967295.
Proof. vm_compute. reflexivity. Qed.

(* `as` never panics: the cast is [Ok] for every source, target and value. *)
Lemma scalar_cast_ok : forall src tgt (x : scalar src), exists y, scalar_cast src tgt x = Ok y.
Proof. intros src tgt x. eexists. reflexivity. Qed.

(* ---- <int>::MIN / <int>::MAX at their own types ------------------------- *)
Example u8_max_val   : to_Z (core_num_U8_MAX   : u8)   = 255.
Proof. vm_compute. reflexivity. Qed.
Example u8_min_val   : to_Z (core_num_U8_MIN   : u8)   = 0.
Proof. vm_compute. reflexivity. Qed.
Example u16_max_val  : to_Z (core_num_U16_MAX  : u16)  = 65535.
Proof. vm_compute. reflexivity. Qed.
Example u32_max_val  : to_Z (core_num_U32_MAX  : u32)  = 4294967295.
Proof. vm_compute. reflexivity. Qed.
Example u64_max_val  : to_Z (core_num_U64_MAX  : u64)  = 2 ^ 64 - 1.
Proof. vm_compute. reflexivity. Qed.
Example u128_max_val : to_Z (core_num_U128_MAX : u128) = 2 ^ 128 - 1.
Proof. vm_compute. reflexivity. Qed.
Example u128_min_val : to_Z (core_num_U128_MIN : u128) = 0.
Proof. vm_compute. reflexivity. Qed.
Example i8_min_val   : to_Z (core_num_I8_MIN   : i8)   = -128.
Proof. vm_compute. reflexivity. Qed.
Example i8_max_val   : to_Z (core_num_I8_MAX   : i8)   = 127.
Proof. vm_compute. reflexivity. Qed.
Example i16_min_val  : to_Z (core_num_I16_MIN  : i16)  = -32768.
Proof. vm_compute. reflexivity. Qed.
Example i16_max_val  : to_Z (core_num_I16_MAX  : i16)  = 32767.
Proof. vm_compute. reflexivity. Qed.
Example i32_min_val  : to_Z (core_num_I32_MIN  : i32)  = -2147483648.
Proof. vm_compute. reflexivity. Qed.
Example i64_min_val  : to_Z (core_num_I64_MIN  : i64)  = - 2 ^ 63.
Proof. vm_compute. reflexivity. Qed.
Example i128_min_val : to_Z (core_num_I128_MIN : i128) = - 2 ^ 127.
Proof. vm_compute. reflexivity. Qed.
Example i128_max_val : to_Z (core_num_I128_MAX : i128) = 2 ^ 127 - 1.
Proof. vm_compute. reflexivity. Qed.
Example usize_max_val : to_Z (core_num_Usize_MAX : usize) = 2 ^ scalar_bits Usize - 1.
Proof. vm_compute. reflexivity. Qed.
Example usize_min_val : to_Z (core_num_Usize_MIN : usize) = 0.
Proof. vm_compute. reflexivity. Qed.
Example isize_min_val : to_Z (core_num_Isize_MIN : isize) = - 2 ^ (scalar_bits Isize - 1).
Proof. vm_compute. reflexivity. Qed.
Example isize_max_val : to_Z (core_num_Isize_MAX : isize) = 2 ^ (scalar_bits Isize - 1) - 1.
Proof. vm_compute. reflexivity. Qed.

(* ---- the 128-bit bound is its own type's bound, not u64's --------------- *)
Example u128_max_is_type_max : to_Z core_num_U128_MAX = scalar_max U128.
Proof. reflexivity. Qed.
Example u128_max_not_u64 : to_Z core_num_U128_MAX <> u64_max.
Proof. vm_compute. discriminate. Qed.
