(* Conservativity of the mk_array patch at the extracted instances: an
   `array T n` is determined by its underlying list, because the length
   proof lives in Z, whose equality is decidable (UIP by Hedberg). Hence
   ANY consistent replacement for the removed `Primitives.mk_array` agrees
   with `mk_array4`/`mk_array15` wherever the extracted body uses them. *)
Require Import Primitives.
Import Primitives.
Require Import Update_FunsExternal.
Require Import ZArith Eqdep_dec List.
Import ListNotations.

Lemma array_ext : forall (T : Type) (n : usize) (a b : array T n),
  proj1_sig a = proj1_sig b -> a = b.
Proof.
  intros T n [la pa] [lb pb] H; simpl in H; subst lb.
  f_equal. apply Eqdep_dec.UIP_dec, Z.eq_dec.
Qed.

Lemma mk_array4_canonical : forall b0 b1 b2 b3 (a : array u8 4%usize),
  proj1_sig a = [b0; b1; b2; b3] -> a = Update_FunsExternal.mk_array4 b0 b1 b2 b3.
Proof. intros; apply array_ext; assumption. Qed.

Lemma mk_array15_canonical :
  forall b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14
         (a : array u8 15%usize),
  proj1_sig a = [b0;b1;b2;b3;b4;b5;b6;b7;b8;b9;b10;b11;b12;b13;b14] ->
  a = Update_FunsExternal.mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14.
Proof. intros; apply array_ext; assumption. Qed.
