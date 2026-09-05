(** DIFFERENTIAL CHECK, hand-written half — the seams and the observation.

    The extracted `parse_and_verify` is run by `vm_compute` on the SAME bytes
    the Rust crate's host tests feed to the Rust `parse_and_verify`, and the
    two verdicts are compared. The bytes and the Rust-side verdicts live in the
    GENERATED file Update_Differential.v (written by
    `UMBRA_DUMP_DIFFERENTIAL=1 cargo test -p umbra-update-core`); this file
    holds what the generated file needs and what must stay reviewable by hand:

    - `mock_seam`: the Rocq reimplementation of the Rust test `MockHmac`
      (crates/umbra-update-core/src/lib_tests.rs). It is NOT a MAC; it is a
      deterministic fold, so both sides compute the tag from the bytes alone
      and the comparison exercises the whole parser, tag gate included.
    - `table_seam`: for packages signed with a real HMAC-SHA-256 (the Python
      producer, tools/attest_update.py, and the Rust `RealHmac` KAT agree on
      them). Rocq has no SHA-256 here, so the seam answers with the RECORDED
      tag when handed the RECORDED (key, 91-byte preimage) and 32 zero bytes
      otherwise — a lookup, nothing more. The device corpus (packages the
      host sent to the N657 during the campaign, recorded by
      tools/attest_update.py --dump) shares one table under a dummy key, so
      the lookup is by preimage and the device key never leaves the signer.
    - `verdict_of`: what is compared. It reads the verdict AND the returned
      fields back, but as plain `Z`/`list Z` — a `slice u8` carries a
      `Z.le` certificate, and two certificates for the same list need not be
      syntactically equal, so a raw `=` on the result would compare proof
      terms. Nothing observable is lost: author, version, the exact blob
      bytes, or the error constructor.

    Nothing here is an axiom: the whole layer is definitional and computes. *)

Require Import Primitives.
Import Primitives.
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

(* Z -> u8, clamping out-of-range values to 0. Never exercised on generated
   data: the generated file proves every emitted value is in [0,256) first. *)
Definition byte (z : Z) : u8 :=
  match mk_scalar U8 z with Ok b => b | Fail_ _ => 0%u8 end.

Definition in_byte_range (z : Z) : bool := andb (0 <=? z) (z <? 256).

(* ---------------------------------------------------------------------- *)
(* mock_seam — the Rust test MockHmac, line for line:                     *)
(*                                                                        *)
(*   let mut acc = [0u8; 32]; let mut n = 0usize;                         *)
(*   for &b in key       { acc[n % 32] = acc[n % 32].wrapping_add(b)      *)
(*                                                   .wrapping_add(1);    *)
(*                         n += 1; }                                      *)
(*   for &b in pre.iter(){ acc[n % 32] = acc[n % 32].wrapping_add(b)      *)
(*                                                   .wrapping_add(2);    *)
(*                         n += 1; }                                      *)
(*                                                                        *)
(* Two u8 wrapping adds are one addition modulo 256; `n` keeps counting   *)
(* across the two loops, so the preimage bytes land at offsets shifted by *)
(* the key length.                                                        *)
(* ---------------------------------------------------------------------- *)

Definition mock_step (delta : Z) (st : list Z * Z) (b : Z) : list Z * Z :=
  let '(acc, n) := st in
  let i := Z.to_nat (n mod 32) in
  (list_update acc i ((nth i acc 0 + b + delta) mod 256), n + 1).

Definition mock_fold (key pre : list Z) : list Z :=
  fst (fold_left (mock_step 2) pre (fold_left (mock_step 1) key (repeat 0 32, 0))).

Lemma mock_step_length : forall d st b,
  length (fst (mock_step d st b)) = length (fst st).
Proof. intros d [acc n] b. simpl. apply list_update_length. Qed.

Lemma fold_mock_step_length : forall d l st,
  length (fst (fold_left (mock_step d) l st)) = length (fst st).
Proof.
  induction l as [|b l IH]; intros st; simpl; [reflexivity |].
  rewrite IH. apply mock_step_length.
Qed.

Lemma mock_fold_length : forall key pre, length (mock_fold key pre) = 32%nat.
Proof.
  intros key pre. unfold mock_fold. rewrite !fold_mock_step_length.
  apply repeat_length.
Qed.

Definition mock_hmac (key : slice u8) (pre : array u8 91%usize) : array u8 32%usize.
Proof.
  refine (exist _ (map byte (mock_fold (map to_Z (proj1_sig key))
                                       (map to_Z (proj1_sig pre)))) _).
  rewrite map_length, mock_fold_length. reflexivity.
Defined.

Definition mock_seam : PkgHmac_t unit :=
  {| PkgHmac_t_hmac_pkg := fun _ key pre => Ok (mock_hmac key pre) |}.

(* ---------------------------------------------------------------------- *)
(* table_seam — recorded (key, preimage, tag) triples; zeros otherwise.   *)
(* ---------------------------------------------------------------------- *)

Fixpoint zlist_eqb (a b : list Z) : bool :=
  match a, b with
  | [], [] => true
  | x :: a', y :: b' => andb (x =? y) (zlist_eqb a' b')
  | _, _ => false
  end.

Definition table_entry := (list Z * list Z * list Z)%type.  (* key, pre, tag *)

Fixpoint table_lookup (t : list table_entry) (key pre : list Z) : option (list Z) :=
  match t with
  | [] => None
  | (k, p, tag) :: t' =>
      if andb (zlist_eqb k key) (zlist_eqb p pre) then Some tag else table_lookup t' key pre
  end.

(* A recorded tag is an array only if it really has 32 bytes; anything else
   falls back to zeros, which can only make a vector REJECT (never accept). *)
Definition arr32_of (l : list Z) : array u8 32%usize :=
  match Z.eq_dec (Z.of_nat (length (map byte l))) (to_Z 32%usize) with
  | left H => exist _ (map byte l) H
  | right _ => array_repeat 32%usize 0%u8
  end.

Definition table_hmac (t : list table_entry) (key : slice u8) (pre : array u8 91%usize)
  : array u8 32%usize :=
  match table_lookup t (map to_Z (proj1_sig key)) (map to_Z (proj1_sig pre)) with
  | Some tag => arr32_of tag
  | None => array_repeat 32%usize 0%u8
  end.

Definition table_seam (t : list table_entry) : PkgHmac_t unit :=
  {| PkgHmac_t_hmac_pkg := fun _ key pre => Ok (table_hmac t key pre) |}.

(* ---------------------------------------------------------------------- *)
(* The observation.                                                       *)
(* ---------------------------------------------------------------------- *)

Inductive verdict :=
| V_Ok : Z -> Z -> list Z -> verdict          (* author_id, version, blob *)
| V_Err : UpdateError_t -> verdict
| V_Fail : verdict.                            (* backend Fail_: never expected *)

Definition verdict_of
  (r : result (core_result_Result_t VerifiedUpdate_t UpdateError_t)) : verdict :=
  match r with
  | Ok (Core_result_Result_Ok v) =>
      V_Ok (to_Z v.(verifiedUpdate_author_id)) (to_Z v.(verifiedUpdate_version))
           (map to_Z (proj1_sig v.(verifiedUpdate_blob)))
  | Ok (Core_result_Result_Err e) => V_Err e
  | Fail_ _ => V_Fail
  end.

(* The selector's verdict, likewise read back as plain data. *)
Definition slot_of (r : result (option usize)) : option Z :=
  match r with
  | Ok (Some s) => Some (to_Z s)
  | Ok None => None
  | Fail_ _ => Some (-1)
  end.

(* Sanity: the mock, run on the Rust KAT-shaped inputs, is total (never Fail_)
   and 32 bytes long — the seam cannot itself abort a vector. *)
Lemma mock_seam_total : forall key pre,
  exists t, mock_seam.(PkgHmac_t_hmac_pkg) tt key pre = Ok t.
Proof. intros key pre. eexists. reflexivity. Qed.
