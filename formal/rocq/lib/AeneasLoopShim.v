(* MANUAL SHIM (issue #58): control_flow + fuel loop the Coq backend omits. *)
Require Import Primitives.
Import Primitives.
Inductive control_flow (Cont_ty Done_ty : Type) : Type :=
| Cont : Cont_ty -> control_flow Cont_ty Done_ty
| Done : Done_ty -> control_flow Cont_ty Done_ty.
Arguments Cont {Cont_ty Done_ty}.
Arguments Done {Cont_ty Done_ty}.
Fixpoint loop_fuel {S B : Type} (n : nat) (f : S -> result (control_flow S B)) (s : S) : result B :=
  match n with
  | O => Fail_ OutOfFuel
  | Datatypes.S n' => match f s with
                      | Ok (Done b) => Ok b
                      | Ok (Cont s') => loop_fuel n' f s'
                      | Fail_ e => Fail_ e end
  end.
Definition loop {S B : Type} (f : S -> result (control_flow S B)) (s : S) : result B := loop_fuel 1000000 f s.
