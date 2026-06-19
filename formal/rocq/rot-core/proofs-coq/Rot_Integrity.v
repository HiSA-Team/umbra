(** T3 — Root-of-Trust integrity (issue #58): no tampered/substituted code is
    ever accepted.

    Composes T1 (the accept gate is sound, Rot_Verify) and T2 (the measurement
    chain is injective under idealized HMAC, Rot_Chain). The
    [authenticate_and_decrypt] / boot acceptance path accepts an enclave only if
    `verify_measurement(measured, registered) = true`, where `measured` is the
    chained measurement of the presented blocks and `registered` is the
    measurement bound at enclave-create time. We prove: acceptance forces the
    presented block sequence to BE the registered one.

    This is the code-level, content-integrity strengthening of the ProVerif
    property `Execute(b) ⇒ RegisterBlock(b)`: not merely "every executed block
    was registered", but "the executed code is bit-for-bit the registered code". *)

Require Import Coq.NArith.NArith.
Require Import Coq.Lists.List.
Require Import Rot_Verify.
Require Import Rot_Chain.
Import ListNotations.

Section RoTIntegrity.

  (* A measurement / block is a byte string (the gate compares byte lists; the
     chain folds byte-string blocks). HMAC is the opaque, idealized primitive. *)
  Notation tag := (list N).

  Variable hmac : tag -> tag -> tag.
  Hypothesis hmac_injective :
    forall k1 b1 k2 b2, hmac k1 b1 = hmac k2 b2 -> k1 = k2 /\ b1 = b2.

  (* The chained measurement at this instantiation (T2's `chain`). *)
  Notation measure := (chain tag tag hmac).

  (** ROOT-OF-TRUST INTEGRITY. If the boot accept gate accepts the presented
      blocks against the registered measurement (`ct_eq` of the two chained
      measurements is true) and the lengths match, then the presented blocks are
      exactly the registered blocks. No substituted or tampered enclave passes. *)
  Theorem rot_integrity :
    forall registered presented anchor,
      length presented = length registered ->
      ct_eq (measure anchor presented) (measure anchor registered) = true ->
      presented = registered.
  Proof.
    intros registered presented anchor Hlen Haccept.
    (* T1: the gate accepts only equal measurements. *)
    apply ct_eq_correct in Haccept.
    (* T2: equal measurements + equal length force equal block sequences. *)
    apply (chain_injective tag tag hmac hmac_injective) with (k := anchor).
    - exact Hlen.
    - exact Haccept.
  Qed.

  (** Contrapositive, spelled out: any presented sequence that differs from the
      registered one (same length) is rejected by the gate. *)
  Corollary rot_tamper_rejected :
    forall registered presented anchor,
      length presented = length registered ->
      presented <> registered ->
      ct_eq (measure anchor presented) (measure anchor registered) = false.
  Proof.
    intros registered presented anchor Hlen Hneq.
    destruct (ct_eq (measure anchor presented) (measure anchor registered)) eqn:E.
    - exfalso. apply Hneq. apply rot_integrity with (anchor := anchor); assumption.
    - reflexivity.
  Qed.

End RoTIntegrity.
