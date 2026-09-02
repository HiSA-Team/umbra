(** NON-VACUITY WITNESS — the accept branch of the EXTRACTED parser is
    reachable, by computation.

    Every acceptance theorem of this development ("if `parse_and_verify`
    returns `Ok (Ok r)` then …") is conditional. This file closes the obvious
    hostile question — is the antecedent ever true? — by RUNNING the extracted
    body on one concrete package under a concrete (constant) seam and checking
    the verdict with `vm_compute`. It became possible only once the
    array/slice/copy/codec operations were DEFINED (Primitives.v): with the
    backend's bare axioms nothing about a concrete package could compute.

    The package: the crate's magic, a 16-byte nonce of 7s, author 1, version 2,
    blob_len 48, a 48-byte blob (= the full header window) of 9s, and a 32-byte
    tag of zeros. The seam returns 32 zero bytes for every input, so the tag
    gate passes; the nonce gate passes because `expected_nonce` is the same 16
    bytes. The theorem also reads the returned fields back, so the witness
    exercises the decoder, not only the verdict.

    What this is NOT: a statement about HMAC (the seam is a stub), nor about
    any package other than this one. It is exactly the antecedent of P1/P2/P4
    instantiated once. *)

Require Import Primitives.
Import Primitives.
Require Import AeneasLoopShim.
Import AeneasLoopShim.
Require Import Coq.ZArith.ZArith.
Require Import Coq.Lists.List.
Import ListNotations.
Require Import Update_Types.
Import Update_Types.
Require Import Update_FunsExternal.
Import Update_FunsExternal.
Require Import Update_Funs.
Import Update_Funs.
Local Open Scope Z_scope.
Local Open Scope Primitives_scope.

(* A seam that answers every query with 32 zero bytes. *)
Definition zero_seam : PkgHmac_t unit :=
  {| PkgHmac_t_hmac_pkg := fun _ _ _ => Ok (array_repeat 32%usize 0%u8) |}.

(* Z -> u8, clamping out-of-range values to 0 (never exercised below). *)
Definition byte (z : Z) : u8 :=
  match mk_scalar U8 z with Ok b => b | Fail_ _ => 0%u8 end.

Definition magic_bytes : list Z :=
  let m := to_Z uPDATE_MAGIC in
  [m mod 256; (m / 256) mod 256; (m / 65536) mod 256; (m / 16777216) mod 256].

Definition pkg_bytes : list Z :=
  magic_bytes                    (* the crate's UPDATE_MAGIC, little-endian *)
  ++ repeat 7 16                 (* nonce *)
  ++ [1; 0; 0; 0]                (* author_id = 1 *)
  ++ [2; 0; 0; 0]                (* version   = 2 *)
  ++ [48; 0; 0; 0]               (* blob_len  = 48 *)
  ++ repeat 9 48                 (* blob: exactly the 48-byte header window *)
  ++ repeat 0 32.                (* tag: what zero_seam answers *)

Definition witness_pkg : slice u8.
Proof. refine (exist _ (map byte pkg_bytes) _). vm_compute. discriminate. Defined.

Definition witness_nonce : array u8 16%usize.
Proof. refine (exist _ (map byte (repeat 7 16)) _). vm_compute. reflexivity. Defined.

Definition witness_key : slice u8.
Proof. refine (exist _ (map byte (repeat 3 32)) _). vm_compute. discriminate. Defined.

(* What we observe of the verdict: accepted?, and the decoded fields. *)
Definition observe (r : result (core_result_Result_t VerifiedUpdate_t UpdateError_t))
  : bool * Z * Z * list Z :=
  match r with
  | Ok (Core_result_Result_Ok v) =>
      (true, to_Z v.(verifiedUpdate_author_id), to_Z v.(verifiedUpdate_version),
       map to_Z (proj1_sig v.(verifiedUpdate_blob)))
  | _ => (false, 0, 0, [])
  end.

Theorem parse_and_verify_accepts_the_witness :
  observe (parse_and_verify zero_seam witness_pkg witness_nonce tt witness_key)
  = (true, 1, 2, repeat 9 48).
Proof. vm_compute. reflexivity. Qed.

(* Each rejection path is reachable too: flip one thing, watch the verdict. *)
Definition reject (r : result (core_result_Result_t VerifiedUpdate_t UpdateError_t))
  : option UpdateError_t :=
  match r with Ok (Core_result_Result_Err e) => Some e | _ => None end.

Definition witness_nonce_bad : array u8 16%usize.
Proof. refine (exist _ (map byte (repeat 8 16)) _). vm_compute. reflexivity. Defined.

Theorem nonce_mismatch_is_reachable :
  reject (parse_and_verify zero_seam witness_pkg witness_nonce_bad tt witness_key)
  = Some UpdateError_NonceMismatch.
Proof. vm_compute. reflexivity. Qed.

Definition one_seam : PkgHmac_t unit :=
  {| PkgHmac_t_hmac_pkg := fun _ _ _ => Ok (array_repeat 32%usize 1%u8) |}.

Theorem tag_invalid_is_reachable :
  reject (parse_and_verify one_seam witness_pkg witness_nonce tt witness_key)
  = Some UpdateError_TagInvalid.
Proof. vm_compute. reflexivity. Qed.

Print Assumptions parse_and_verify_accepts_the_witness.
