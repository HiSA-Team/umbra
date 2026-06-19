(** T4 — Soundness of the per-block validator (issue #58).

    [umbra_rot_core::validate_block] is the `memory_protection_server`'s per-block
    check: derive the block's measurement (HMAC under a zero base key) and accept
    iff it equals the expected measurement. It composes `derive_key` and the T1
    accept gate `verify_measurement`. We prove it SOUND: a `true` result implies
    the block's derived measurement is exactly the expected one — no block whose
    measurement differs is ever validated. This is a direct corollary of T1
    (Rot_Verify), now lifted to the memory-protection server. *)

Require Import Coq.NArith.NArith.
Require Import Coq.Lists.List.
Require Import Rot_Verify.
Import ListNotations.

Section ValidateSoundness.

  (* The block's derived measurement (HMAC under the zero base key) — opaque, as
     in the extracted `derive_key`. *)
  Variable measure_block : list N -> list N.

  (* validate_block accepts iff the gate accepts the derived measurement against
     the expected one (exactly umbra_rot_core::validate_block). *)
  Definition validate_block (data expected : list N) : bool :=
    ct_eq (measure_block data) expected.

  (** T4 — VALIDATOR SOUNDNESS. A validated block's derived measurement is the
      expected measurement. Contrapositive: a block whose measurement differs is
      rejected. *)
  Theorem validate_block_sound :
    forall data expected,
      validate_block data expected = true ->
      measure_block data = expected.
  Proof.
    intros data expected H. unfold validate_block in H.
    apply ct_eq_correct in H. exact H.
  Qed.

End ValidateSoundness.
