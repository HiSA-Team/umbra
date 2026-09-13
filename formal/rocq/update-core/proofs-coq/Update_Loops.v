(** Update_Loops.v — ADEQUACY of the fuel shim for this crate's two loops.

    `AeneasLoopShim.loop` runs its body with a fixed fuel constant; the shared
    library's `AeneasLoopModel` gives the fuel-free ITree model of the same
    combinator and proves (`loop_model_bound`) that under a strictly decreasing
    measure the model's result IS the result of the run with fuel `S (m s)`.
    Here that theorem is instantiated for the two extracted compare loops with
    the index measure `len - i` and the discharged premise that the body never
    returns `Fail_ OutOfFuel` (both from Update_Safety), and the run with fuel
    `S (m s)` is identified with the shim's `loop` (`ct_eqN_loop_bounded`):

        loop_model body s ≈ Ret (ct_eqN_loop … s)

    with no fuel constant named anywhere. This file requires ITree; NOTHING in
    the crypto tier, in chain-core, or elsewhere in this project requires this
    file (it is a leaf, checked by the fast gate's Require walk). *)

Require Import Primitives.
Import Primitives.
Require Import AeneasLoopShim.
Import AeneasLoopShim.
Require Import Coq.ZArith.ZArith.
Require Import Lia.
Require Import Update_Types.
Import Update_Types.
Require Import Update_FunsExternal.
Import Update_FunsExternal.
Require Import Update_Funs.
Import Update_Funs.
Require Import Update_Safety.
Require Import AeneasLoopModel.
From ITree Require Import ITree ITreeFacts.
Import ITreeNotations.
Local Open Scope Z_scope.
Local Open Scope itree_scope.

(* The measure both loops decrease on every `Cont` step: bytes left to compare. *)
Definition ct_eq16_measure (s : u8 * usize) : nat := Z.to_nat (16 - to_Z (snd s)).
Definition ct_eq32_measure (s : u8 * usize) : nat := Z.to_nat (32 - to_Z (snd s)).

(** The 16-byte compare loop: the ITree model returns exactly what the
    extracted (fuel-shimmed) loop returns, from any state. *)
Theorem ct_eq16_loop_adequate :
  forall (a b : array u8 16%usize) (d : u8) (i : usize),
    loop_model (fun '(d1, i1) => ct_eq16_loop_body a b d1 i1) (d, i)
    ≈ Ret (ct_eq16_loop a b d i).
Proof.
  intros a b d i. rewrite ct_eq16_loop_bounded.
  exact (loop_model_bound _ ct_eq16_measure (d, i)
           (ct_eq16_body_no_oof a b) (ct_eq16_body_dec a b)).
Qed.

(** The 32-byte compare loop, likewise; no length premise on the slice is
    needed because the body's only failure channel is `Failure`. *)
Theorem ct_eq32_loop_adequate :
  forall (a : array u8 32%usize) (b : slice u8) (d : u8) (i : usize),
    loop_model (fun '(d1, i1) => ct_eq32_loop_body a b d1 i1) (d, i)
    ≈ Ret (ct_eq32_loop a b d i).
Proof.
  intros a b d i. rewrite ct_eq32_loop_bounded.
  exact (loop_model_bound _ ct_eq32_measure (d, i)
           (ct_eq32_body_no_oof a b) (ct_eq32_body_dec a b)).
Qed.

(* ===================================================================== *)
(* MECHANISED ASSUMPTION AUDIT: both instances must be closed under the   *)
(* global context (ITree's own development is axiom-free at these lemmas). *)
(* ===================================================================== *)
Print Assumptions ct_eq16_loop_adequate.
Print Assumptions ct_eq32_loop_adequate.
