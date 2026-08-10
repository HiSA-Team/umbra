(** VALUE LAYER — from "the constant-time comparator returned true" to "the byte
    sequences are equal".

    `Update_Auth.accept_implies_auth_gates` (P1) proves that an accepted package
    passed both gates, i.e. `ct_eq16 … = Ok true` and `ct_eq32 … = Ok true`. That
    is a statement about a BOOLEAN, not about bytes: nothing in it says the nonce
    the parser compared is the nonce the caller armed. This file closes that step
    for the two extracted comparators, by the same accumulator invariant
    `rot-core`'s T1 uses:

        the OR-fold of XORs is zero  <->  every XOR was zero  <->  every byte pair
        was equal.

    It rests on the VALUE half of Update_Safety's quarantine (`u8_xor_to_Z`,
    `u8_or_to_Z`, `array_index_usize_ext`, `slice_index_usize_ext`), all of which
    `Update_Model.v` discharges against the concrete list model.

    CONCLUSION SHAPE. The comparators' operands are `u8 = {z : Z | 0 <= z <= 255}`,
    a sigma type over a `Prop`. Two `u8`s with the same `to_Z` are equal only up to
    proof irrelevance, which is not provable in Coq without an axiom — so rather
    than assume one, every statement below concludes at the REPRESENTED VALUE:
    "both reads succeed and the two bytes have the same `to_Z`". That is the honest
    formulation and it is exactly what a byte-equality claim means. *)

Require Import Primitives.
Import Primitives.
Require Import AeneasLoopShim.
Import AeneasLoopShim.
Require Import Coq.ZArith.ZArith.
Require Import Coq.Bool.Bool.
Require Import Lia.
Require Import Update_Types.
Import Update_Types.
Require Import Update_FunsExternal.
Import Update_FunsExternal.
Require Import Update_Funs.
Import Update_Funs.
Require Import Update_Safety.
Local Open Scope Z_scope.
Local Open Scope Primitives_scope.

(* --------------------------------------------------------------------- *)
(* Scalar helpers.                                                        *)
(* --------------------------------------------------------------------- *)

Lemma tz0u8 : to_Z (0%u8) = 0. Proof. reflexivity. Qed.

(* `d s= 0%u8 = true` is `to_Z d = 0`. *)
Lemma u8_eqb_zero : forall d : u8, (d s= 0%u8) = true -> to_Z d = 0.
Proof.
  intros d H. unfold scalar_eqb in H. apply Z.eqb_eq in H.
  rewrite tz0u8 in H. exact H.
Qed.

(* `usize_add i 1 = Ok j` pins j's value. *)
Lemma usize_add1_val : forall (i j : usize), usize_add i 1%usize = Ok j -> to_Z j = to_Z i + 1.
Proof.
  intros i j H. unfold usize_add, scalar_add in H.
  apply mk_scalar_to_Z in H. rewrite H, tz1. reflexivity.
Qed.

(* Monadic inversion. Used instead of `destruct`/`remember` on the loop call:
   those match SYNTACTICALLY, and the extracted `fun '(d1,i1) => …` binder does
   not print-match a hand-written copy, whereas `apply … in` unifies up to
   conversion. *)
Lemma bind_ok_inv : forall {A B} (m : result A) (f : A -> result B) (v : B),
  bind m f = Ok v -> exists x, m = Ok x /\ f x = Ok v.
Proof.
  intros A B m f v H. destruct m as [x|e]; cbn [bind] in H;
    [ exists x; split; [ reflexivity | exact H ] | discriminate ].
Qed.

(* `to_Z d = 0` is `d s= 0%u8 = true` — the converse of `u8_eqb_zero`, needed
   by the completeness direction below. *)
Lemma u8_eqb_zero_intro : forall d : u8, to_Z d = 0 -> (d s= 0%u8) = true.
Proof.
  intros d H. unfold scalar_eqb. apply Z.eqb_eq. rewrite tz0u8. exact H.
Qed.

(* The accumulator invariant, in the direction the completeness proof needs:
   OR-ing in the XOR of two EQUAL bytes leaves a zero accumulator zero. *)
Lemma or_xor_zero : forall (d x y : u8),
  to_Z d = 0 -> to_Z x = to_Z y -> to_Z (u8_or d (u8_xor x y)) = 0.
Proof.
  intros d x y Hd Hxy.
  rewrite u8_or_to_Z, u8_xor_to_Z, Hd, Hxy.
  rewrite Z.lxor_nilpotent. reflexivity.
Qed.

(* --------------------------------------------------------------------- *)
(* ct_eq16 — array vs array, fixed 16-byte window.                        *)
(* --------------------------------------------------------------------- *)

Lemma ct_eq16_loop_sound :
  forall (fuel : nat) (a b : array u8 16%usize) (d : u8) (i : usize) (dfin : u8),
    loop_fuel fuel (fun '(d1, i1) => ct_eq16_loop_body a b d1 i1) (d, i) = Ok dfin ->
    to_Z dfin = 0 ->
    to_Z d = 0
    /\ (forall k : usize, to_Z i <= to_Z k < 16 ->
          exists x y, array_index_usize a k = Ok x
                   /\ array_index_usize b k = Ok y
                   /\ to_Z x = to_Z y).
Proof.
  induction fuel as [|n IH]; intros a b d i dfin Hloop Hz.
  - simpl in Hloop. discriminate.
  - rewrite loop_step in Hloop. cbn beta iota in Hloop.
    unfold ct_eq16_loop_body in Hloop.
    destruct (i s< 16%usize) eqn:Hlt.
    + destruct (array_index_usize a i) as [x1|] eqn:Hx1;
        [ cbn [bind] in Hloop | cbn [bind] in Hloop; discriminate ].
      destruct (array_index_usize b i) as [x2|] eqn:Hx2;
        [ cbn [bind] in Hloop | cbn [bind] in Hloop; discriminate ].
      destruct (usize_add i 1%usize) as [i4|] eqn:Hi4;
        [ cbn [bind] in Hloop | cbn [bind] in Hloop; discriminate ].
      destruct (IH a b (u8_or d (u8_xor x1 x2)) i4 dfin Hloop Hz) as [Hd1 Hrest].
      rewrite u8_or_to_Z in Hd1.
      apply (proj1 (Z.lor_eq_0_iff _ _)) in Hd1 as [Hd0 Hxor0].
      rewrite u8_xor_to_Z in Hxor0. apply (proj1 (Z.lxor_eq_0_iff _ _)) in Hxor0.
      split; [ exact Hd0 |].
      intros k Hk.
      assert (Hi4v : to_Z i4 = to_Z i + 1) by (apply usize_add1_val; exact Hi4).
      destruct (Z.eq_dec (to_Z k) (to_Z i)) as [Hke|Hkne].
      * exists x1, x2.
        rewrite (array_index_usize_ext a k i Hke), (array_index_usize_ext b k i Hke).
        repeat split; [ exact Hx1 | exact Hx2 | exact Hxor0 ].
      * apply Hrest. lia.
    + injection Hloop as Hloop. subst dfin.
      split; [ exact Hz |].
      intros k Hk. exfalso.
      apply Z.ltb_ge in Hlt. rewrite tz16 in Hlt. lia.
Qed.

(** THE 16-BYTE GATE IS A BYTE EQUALITY. *)
Theorem ct_eq16_sound : forall (a b : array u8 16%usize),
  ct_eq16 a b = Ok true ->
  forall k : usize, 0 <= to_Z k < 16 ->
    exists x y, array_index_usize a k = Ok x
             /\ array_index_usize b k = Ok y
             /\ to_Z x = to_Z y.
Proof.
  intros a b Heq k Hk. unfold ct_eq16 in Heq.
  apply bind_ok_inv in Heq as [dfin [Hl Hz]].
  injection Hz as Hz. apply u8_eqb_zero in Hz.
  unfold ct_eq16_loop, loop in Hl.
  destruct (ct_eq16_loop_sound _ a b 0%u8 0%usize dfin Hl Hz) as [_ Hall].
  apply Hall. rewrite tz0. exact Hk.
Qed.

(** … AND CONVERSELY: EQUAL BYTES MAKE THE 16-BYTE GATE PASS.

    `ct_eq16_sound` is an implication from the comparator's verdict to the
    bytes. The CONVERSE — equal bytes force the verdict `Ok true` — is what a
    key-less simulator of the device needs: it is the half that says the
    structural nonce guard is exactly a byte-equality test and hides no further
    condition. Same loop, same accumulator invariant, run forwards. *)

Lemma ct_eq16_loop_complete :
  forall (fuel : nat) (a b : array u8 16%usize) (d : u8) (i : usize),
    0 <= to_Z i <= 16 -> (Z.to_nat (16 - to_Z i) < fuel)%nat ->
    to_Z d = 0 ->
    (forall k : usize, to_Z i <= to_Z k < 16 ->
       forall x y, array_index_usize a k = Ok x -> array_index_usize b k = Ok y ->
         to_Z x = to_Z y) ->
    exists dfin, loop_fuel fuel (fun '(d1, i1) => ct_eq16_loop_body a b d1 i1) (d, i)
                 = Ok dfin /\ to_Z dfin = 0.
Proof.
  induction fuel as [|n IH]; intros a b d i Hi Hfuel Hd Heq.
  - simpl in Hfuel. lia.
  - rewrite loop_step. cbn beta iota. unfold ct_eq16_loop_body.
    destruct (Z_lt_le_dec (to_Z i) 16) as [Hlt | Hge].
    + assert (Hc : (i s< 16%usize) = true) by (apply Z.ltb_lt; rewrite tz16; lia).
      rewrite Hc.
      destruct (array_index_usize_ok a i) as [x1 Hx1]; [ rewrite tz16; lia | ].
      destruct (array_index_usize_ok b i) as [x2 Hx2]; [ rewrite tz16; lia | ].
      rewrite Hx1, Hx2. cbn beta iota.
      destruct (usize_add_ok i 1%usize) as [i4 [Hi4 Hi4v]].
      { rewrite tz1. pose proof u32max_big. lia. }
      rewrite tz1 in Hi4v. rewrite Hi4. cbn beta iota.
      apply IH.
      * lia.
      * assert (Hlt2 : (Z.to_nat (16 - to_Z i4) < Z.to_nat (16 - to_Z i))%nat)
          by (apply Z2Nat.inj_lt; lia).
        lia.
      * apply (or_xor_zero d x1 x2 Hd). exact (Heq i ltac:(lia) x1 x2 Hx1 Hx2).
      * intros k Hk. apply Heq. lia.
    + assert (Hc : (i s< 16%usize) = false) by (apply Z.ltb_ge; rewrite tz16; lia).
      rewrite Hc. exists d. split; [ reflexivity | exact Hd ].
Qed.

Theorem ct_eq16_complete : forall (a b : array u8 16%usize),
  (forall k : usize, 0 <= to_Z k < 16 ->
     forall x y, array_index_usize a k = Ok x -> array_index_usize b k = Ok y ->
       to_Z x = to_Z y) ->
  ct_eq16 a b = Ok true.
Proof.
  intros a b Heq. unfold ct_eq16, ct_eq16_loop, loop.
  destruct (ct_eq16_loop_complete 1000000 a b 0%u8 0%usize) as [dfin [Hl Hz]].
  - rewrite tz0. lia.
  - rewrite tz0. apply Nat.ltb_lt. vm_compute. reflexivity.
  - exact tz0u8.
  - intros k Hk. apply Heq. rewrite tz0 in Hk. lia.
  - rewrite Hl. cbn [bind]. rewrite (u8_eqb_zero_intro dfin Hz). reflexivity.
Qed.

(* --------------------------------------------------------------------- *)
(* ct_eq32 — array vs slice, fixed 32-byte window (the tag comparison).   *)
(* --------------------------------------------------------------------- *)

Lemma ct_eq32_loop_sound :
  forall (fuel : nat) (a : array u8 32%usize) (b : slice u8) (d : u8) (i : usize) (dfin : u8),
    loop_fuel fuel (fun '(d1, i1) => ct_eq32_loop_body a b d1 i1) (d, i) = Ok dfin ->
    to_Z dfin = 0 ->
    to_Z d = 0
    /\ (forall k : usize, to_Z i <= to_Z k < 32 ->
          exists x y, array_index_usize a k = Ok x
                   /\ slice_index_usize b k = Ok y
                   /\ to_Z x = to_Z y).
Proof.
  induction fuel as [|n IH]; intros a b d i dfin Hloop Hz.
  - simpl in Hloop. discriminate.
  - rewrite loop_step in Hloop. cbn beta iota in Hloop.
    unfold ct_eq32_loop_body in Hloop.
    destruct (i s< 32%usize) eqn:Hlt.
    + destruct (array_index_usize a i) as [x1|] eqn:Hx1;
        [ cbn [bind] in Hloop | cbn [bind] in Hloop; discriminate ].
      destruct (slice_index_usize b i) as [x2|] eqn:Hx2;
        [ cbn [bind] in Hloop | cbn [bind] in Hloop; discriminate ].
      destruct (usize_add i 1%usize) as [i4|] eqn:Hi4;
        [ cbn [bind] in Hloop | cbn [bind] in Hloop; discriminate ].
      destruct (IH a b (u8_or d (u8_xor x1 x2)) i4 dfin Hloop Hz) as [Hd1 Hrest].
      rewrite u8_or_to_Z in Hd1.
      apply (proj1 (Z.lor_eq_0_iff _ _)) in Hd1 as [Hd0 Hxor0].
      rewrite u8_xor_to_Z in Hxor0. apply (proj1 (Z.lxor_eq_0_iff _ _)) in Hxor0.
      split; [ exact Hd0 |].
      intros k Hk.
      assert (Hi4v : to_Z i4 = to_Z i + 1) by (apply usize_add1_val; exact Hi4).
      destruct (Z.eq_dec (to_Z k) (to_Z i)) as [Hke|Hkne].
      * exists x1, x2.
        rewrite (array_index_usize_ext a k i Hke), (slice_index_usize_ext b k i Hke).
        repeat split; [ exact Hx1 | exact Hx2 | exact Hxor0 ].
      * apply Hrest. lia.
    + injection Hloop as Hloop. subst dfin.
      split; [ exact Hz |].
      intros k Hk. exfalso.
      apply Z.ltb_ge in Hlt. rewrite tz32 in Hlt. lia.
Qed.

(** THE 32-BYTE TAG GATE IS A BYTE EQUALITY. *)
Theorem ct_eq32_sound : forall (a : array u8 32%usize) (b : slice u8),
  ct_eq32 a b = Ok true ->
  to_Z (slice_len b) = 32
  /\ forall k : usize, 0 <= to_Z k < 32 ->
       exists x y, array_index_usize a k = Ok x
                /\ slice_index_usize b k = Ok y
                /\ to_Z x = to_Z y.
Proof.
  intros a b Heq. unfold ct_eq32 in Heq.
  destruct (slice_len b s<> 32%usize) eqn:Hne; [ discriminate |].
  assert (Hlen : to_Z (slice_len b) = 32).
  { unfold scalar_neqb, scalar_eqb in Hne. apply negb_false_iff in Hne.
    apply Z.eqb_eq in Hne. rewrite tz32 in Hne. exact Hne. }
  split; [ exact Hlen |].
  apply bind_ok_inv in Heq as [dfin [Hl Hz]].
  injection Hz as Hz. apply u8_eqb_zero in Hz.
  unfold ct_eq32_loop, loop in Hl.
  destruct (ct_eq32_loop_sound _ a b 0%u8 0%usize dfin Hl Hz) as [_ Hall].
  intros k Hk. apply Hall. rewrite tz0. exact Hk.
Qed.

(** … AND CONVERSELY FOR THE 32-BYTE TAG GATE. The length premise is not
    incidental: `ct_eq32` returns `Ok false` outright when the compared slice is
    not 32 bytes long, so byte agreement over `[0,32)` alone does not force the
    verdict. *)

Lemma ct_eq32_loop_complete :
  forall (fuel : nat) (a : array u8 32%usize) (b : slice u8) (d : u8) (i : usize),
    to_Z (slice_len b) = 32 ->
    0 <= to_Z i <= 32 -> (Z.to_nat (32 - to_Z i) < fuel)%nat ->
    to_Z d = 0 ->
    (forall k : usize, to_Z i <= to_Z k < 32 ->
       forall x y, array_index_usize a k = Ok x -> slice_index_usize b k = Ok y ->
         to_Z x = to_Z y) ->
    exists dfin, loop_fuel fuel (fun '(d1, i1) => ct_eq32_loop_body a b d1 i1) (d, i)
                 = Ok dfin /\ to_Z dfin = 0.
Proof.
  induction fuel as [|n IH]; intros a b d i Hlen Hi Hfuel Hd Heq.
  - simpl in Hfuel. lia.
  - rewrite loop_step. cbn beta iota. unfold ct_eq32_loop_body.
    destruct (Z_lt_le_dec (to_Z i) 32) as [Hlt | Hge].
    + assert (Hc : (i s< 32%usize) = true) by (apply Z.ltb_lt; rewrite tz32; lia).
      rewrite Hc.
      destruct (array_index_usize_ok a i) as [x1 Hx1]; [ rewrite tz32; lia | ].
      destruct (slice_index_usize_ok b i) as [x2 Hx2]; [ rewrite Hlen; lia | ].
      rewrite Hx1, Hx2. cbn beta iota.
      destruct (usize_add_ok i 1%usize) as [i4 [Hi4 Hi4v]].
      { rewrite tz1. pose proof u32max_big. lia. }
      rewrite tz1 in Hi4v. rewrite Hi4. cbn beta iota.
      apply IH.
      * exact Hlen.
      * lia.
      * assert (Hlt2 : (Z.to_nat (32 - to_Z i4) < Z.to_nat (32 - to_Z i))%nat)
          by (apply Z2Nat.inj_lt; lia).
        lia.
      * apply (or_xor_zero d x1 x2 Hd). exact (Heq i ltac:(lia) x1 x2 Hx1 Hx2).
      * intros k Hk. apply Heq. lia.
    + assert (Hc : (i s< 32%usize) = false) by (apply Z.ltb_ge; rewrite tz32; lia).
      rewrite Hc. exists d. split; [ reflexivity | exact Hd ].
Qed.

Theorem ct_eq32_complete : forall (a : array u8 32%usize) (b : slice u8),
  to_Z (slice_len b) = 32 ->
  (forall k : usize, 0 <= to_Z k < 32 ->
     forall x y, array_index_usize a k = Ok x -> slice_index_usize b k = Ok y ->
       to_Z x = to_Z y) ->
  ct_eq32 a b = Ok true.
Proof.
  intros a b Hlen Heq. unfold ct_eq32.
  assert (Hc : (slice_len b s<> 32%usize) = false).
  { unfold scalar_neqb, scalar_eqb. apply negb_false_iff. apply Z.eqb_eq.
    rewrite tz32. exact Hlen. }
  rewrite Hc. unfold ct_eq32_loop, loop.
  destruct (ct_eq32_loop_complete 1000000 a b 0%u8 0%usize Hlen)
    as [dfin [Hl Hz]].
  - rewrite tz0. lia.
  - rewrite tz0. apply Nat.ltb_lt. vm_compute. reflexivity.
  - exact tz0u8.
  - intros k Hk. apply Heq. rewrite tz0 in Hk. lia.
  - rewrite Hl. cbn [bind]. rewrite (u8_eqb_zero_intro dfin Hz). reflexivity.
Qed.
