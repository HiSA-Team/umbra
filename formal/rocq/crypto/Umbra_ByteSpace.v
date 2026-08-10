(** THE BYTE-VALID SUBIMAGE — re-indexing the message space at `256^76`.

    WHY THIS FILE EXISTS. `Umbra_Canonical`'s dead-zone section proves that
    `[0, 257^76)` is the WRONG message space for the game. `257^76` counts
    76-digit base-257 NUMERALS, and base-257 digit `256` is the out-of-range
    sentinel of `Update_Encoding.rdA`; a message whose expansion uses it
    decodes under `canon91` to a 91-element list containing `256`, which is
    provably not `bytes91` of any array. On that 25.64 % of the space
    `ByteSeam` constrains the seam function nowhere, and
    `restricted_space_still_admits_a_broken_seam` turns the hole into an
    adversary with advantage 1.

    WHAT THIS FILE DOES. It supplies the right index set and the maps between
    the two.

      `spread`  : a base-256 numeral `j` in, the base-257 numeral with the
                  SAME seventy-six digits out. Injective, in range, and — the point —
                  its canonical decoding is byte-valid at all ninety-one
                  positions.
      `shrink`  : the left inverse, taking each base-257 digit modulo 256.
                  Total, so it can be applied to any wire message.

    THE ENCODING IS NOT RE-BASED. Base-257 is load-bearing for `msg_of_pkg`
    injectivity precisely BECAUSE of the sentinel: it is what keeps a failed
    read from colliding with a real byte value, and `enc_from_inj`,
    `msg_of_pre_inj` and `canon91_injective` all rest on the digit bound being
    `256` rather than `255`. Re-basing the encoding would have to re-establish
    all of them by other means. Nothing here touches the encoding; the change
    is entirely in WHICH integers the game hands it.

    WHAT THIS BUYS, EXACTLY, AND WHAT IT DOES NOT.
    * `spread_canon91_allbytes` (Qed): every message of the new space decodes
      to ninety-one GENUINE BYTES — the fifteen label bytes included, which
      needed `pKG_TAG_LABEL`'s reads to be shown to succeed. So the dead zone
      is unreachable from the new space, and the counterexample construction —
      patch the seam wherever `allbytes` is false — has nothing to patch.
    * `byte_vectors_are_arrays_pins_the_seam` (Qed) is the positive form, and
      it needs ONE further premise, named `ArrayVectors`: that every 91-element
      list of bytes is the read-sequence of some `array u8 91`. That is a true
      statement about Rust arrays which the Aeneas Coq backend does not let one
      prove, because `Primitives.array_index_usize` is a bare axiom with no law
      relating any constructor to indexing. Under it, any two seams satisfying
      `ByteSeam` AGREE at every message of the new space — which is the exact
      negation of the counterexample.

    So the residual after this file is a single named model-level premise about
    the extraction, not an unfalsifiable condition on the seam. That is a
    strictly better place to be, and it is not the same as closed. *)

Require Import Primitives.
Import Primitives.
Require Import Coq.ZArith.ZArith.
Require Import Lia.
Require Import List.
Import ListNotations.
Require Import Update_Types.
Import Update_Types.
Require Import Update_FunsExternal.
Import Update_FunsExternal.
Require Import Update_Funs.
Import Update_Funs.
Require Import Update_Safety.
Require Import Update_Crypto.
Require Import Update_Forgery.
Require Import Update_Encoding.
Require Import Umbra_Canonical.

Local Open Scope Z_scope.
Local Open Scope Primitives_scope.

(* ===================================================================== *)
(* BASE-256 EVALUATION — the mirror of `enc_from`, one digit narrower     *)
(* ===================================================================== *)

Fixpoint encB (f : Z -> Z) (start : Z) (k : nat) : Z :=
  match k with
  | O => 0
  | S k' => f start + 256 * encB f (start + 1) k'
  end.

Definition dig256 (v i : Z) : Z := (v / 256 ^ i) mod 256.

Lemma pow256_pos : forall i, 0 <= i -> 0 < 256 ^ i.
Proof. intros i Hi. apply Z.pow_pos_nonneg; lia. Qed.

Lemma dig256_range : forall v i, 0 <= dig256 v i <= 255.
Proof.
  intros v i. unfold dig256.
  pose proof (Z.mod_pos_bound (v / 256 ^ i) 256). lia.
Qed.

Lemma encB_bound : forall (k : nat) (f : Z -> Z) (a : Z),
  (forall i, 0 <= i < Z.of_nat k -> 0 <= f (a + i) <= 255) ->
  0 <= encB f a k < 256 ^ Z.of_nat k.
Proof.
  induction k as [| k IH]; intros f a Hf; cbn [encB].
  - cbn. lia.
  - assert (Ha : 0 <= f a <= 255).
    { pose proof (Hf 0 ltac:(rewrite Nat2Z.inj_succ; lia)) as H.
      replace (a + 0) with a in H by lia. exact H. }
    assert (Hrec : 0 <= encB f (a + 1) k < 256 ^ Z.of_nat k).
    { apply IH. intros i Hi. replace (a + 1 + i) with (a + (1 + i)) by lia.
      apply Hf. rewrite Nat2Z.inj_succ. lia. }
    rewrite Nat2Z.inj_succ, Z.pow_succ_r by lia. lia.
Qed.

Lemma encB_digits : forall (k : nat) (b : Z -> Z) (a : Z),
  (forall i, 0 <= i < Z.of_nat k -> 0 <= b (a + i) <= 255) ->
  forall i, 0 <= i < Z.of_nat k -> dig256 (encB b a k) i = b (a + i).
Proof.
  induction k as [| k IH]; intros b a Hb i Hi; [ cbn in Hi; lia |].
  cbn [encB].
  assert (Hhead : 0 <= b a <= 255).
  { pose proof (Hb 0 ltac:(rewrite Nat2Z.inj_succ; lia)) as H.
    replace (a + 0) with a in H by lia. exact H. }
  assert (Hb' : forall j, 0 <= j < Z.of_nat k -> 0 <= b (a + 1 + j) <= 255).
  { intros j Hj. replace (a + 1 + j) with (a + (1 + j)) by lia.
    apply Hb. rewrite Nat2Z.inj_succ. lia. }
  assert (Hrest : 0 <= encB b (a + 1) k).
  { pose proof (encB_bound k b (a + 1) Hb') as H. lia. }
  destruct (Z.eq_dec i 0) as [Hz | Hnz].
  - subst i. unfold dig256. cbn [Z.pow]. rewrite Z.div_1_r.
    replace (a + 0) with a by lia.
    rewrite (Z.mul_comm 256 (encB b (a + 1) k)), Z.mod_add by lia.
    apply Z.mod_small. lia.
  - assert (Hi1 : 0 <= i - 1 < Z.of_nat k) by (rewrite Nat2Z.inj_succ in Hi; lia).
    assert (Hdiv : (b a + 256 * encB b (a + 1) k) / 256
                   = encB b (a + 1) k).
    { rewrite (Z.mul_comm 256 (encB b (a + 1) k)), Z.div_add by lia.
      rewrite (Z.div_small (b a) 256) by lia. lia. }
    unfold dig256.
    replace (256 ^ i) with (256 * 256 ^ (i - 1))
      by (rewrite <- Z.pow_succ_r by lia; f_equal; lia).
    rewrite <- Z.div_div by (try lia; apply pow256_pos; lia).
    rewrite Hdiv.
    pose proof (IH b (a + 1) Hb' (i - 1) Hi1) as Hstep.
    unfold dig256 in Hstep. rewrite Hstep.
    f_equal. lia.
Qed.

Lemma encB_of_digits : forall (k : nat) (v : Z) (b : Z -> Z) (a : Z),
  0 <= v ->
  (forall i, 0 <= i < Z.of_nat k -> b (a + i) = dig256 v i) ->
  encB b a k = v mod 256 ^ Z.of_nat k.
Proof.
  induction k as [| k IH]; intros v b a Hv Hb.
  - cbn. rewrite Z.mod_1_r. reflexivity.
  - cbn [encB].
    assert (Hhead : b a = v mod 256).
    { replace a with (a + 0) by lia. rewrite Hb by (rewrite Nat2Z.inj_succ; lia).
      unfold dig256. cbn [Z.pow]. rewrite Z.div_1_r. reflexivity. }
    assert (Htail : encB b (a + 1) k = (v / 256) mod 256 ^ Z.of_nat k).
    { apply IH; [ apply Z.div_pos; lia |].
      intros i Hi. replace (a + 1 + i) with (a + (1 + i)) by lia.
      rewrite Hb by (rewrite Nat2Z.inj_succ; lia).
      unfold dig256. rewrite Z.div_div by (try lia; apply pow256_pos; lia).
      f_equal. f_equal. rewrite <- Z.pow_succ_r by lia. f_equal. lia. }
    assert (Hpow : 256 ^ Z.of_nat (S k) = 256 * 256 ^ Z.of_nat k).
    { rewrite Nat2Z.inj_succ, <- Z.pow_succ_r; [ reflexivity | lia ]. }
    rewrite Hhead, Htail, Hpow.
    symmetry. apply Z.rem_mul_r; [ lia | apply pow256_pos; lia ].
Qed.

(* ===================================================================== *)
(* THE TWO MAPS                                                           *)
(* ===================================================================== *)

(** THE RE-INDEXING. `j` is a 76-digit base-256 numeral; `spread j` is the
    base-257 numeral with the same seventy-six digits. Its digits are therefore all
    genuine bytes, which is the entire point. *)
Definition spread (j : Z) : Z := enc_from (dig256 j) 0 76.

(** THE LEFT INVERSE. Total on all of `Z`, because it has to be applied to
    whatever integer a wire package encodes to — including one whose digits
    carry the sentinel. Taking each digit modulo 256 is the clamp. *)
Definition shrink (v : Z) : Z := encB (fun i => dig v i mod 256) 0 76.

Lemma dig_mod256_range : forall v i, 0 <= dig v i mod 256 <= 255.
Proof. intros v i. pose proof (Z.mod_pos_bound (dig v i) 256). lia. Qed.

Lemma spread_range : forall j, 0 <= spread j < 257 ^ 76.
Proof.
  intro j. unfold spread.
  assert (Hb : forall i, 0 <= i < Z.of_nat 76 -> 0 <= dig256 j (0 + i) <= 256).
  { intros i _. pose proof (dig256_range j (0 + i)). lia. }
  pose proof (enc_from_bound 76 (dig256 j) 0 Hb) as H.
  replace (Z.of_nat 76) with 76 in H by reflexivity. exact H.
Qed.

Lemma shrink_range : forall v, 0 <= shrink v < 256 ^ 76.
Proof.
  intro v. unfold shrink.
  assert (Hb : forall i, 0 <= i < Z.of_nat 76 ->
                 0 <= dig v (0 + i) mod 256 <= 255).
  { intros i _. apply dig_mod256_range. }
  pose proof (encB_bound 76 (fun i => dig v i mod 256) 0 Hb) as H.
  replace (Z.of_nat 76) with 76 in H by reflexivity. exact H.
Qed.

(** THE DIGITS OF `spread j` ARE `j`'S OWN, hence bytes. *)
Lemma spread_digits : forall j i, 0 <= i < 76 -> dig (spread j) i = dig256 j i.
Proof.
  intros j i Hi. unfold spread.
  assert (Hb : forall t, 0 <= t < Z.of_nat 76 -> 0 <= dig256 j (0 + t) <= 256).
  { intros t _. pose proof (dig256_range j (0 + t)). lia. }
  pose proof (enc_from_digits 76 (dig256 j) 0 Hb i
                ltac:(replace (Z.of_nat 76) with 76 by reflexivity; lia)) as H.
  rewrite H. f_equal; lia.
Qed.

Lemma spread_is_byte_valid : forall j i, 0 <= i < 76 -> dig (spread j) i <= 255.
Proof.
  intros j i Hi. rewrite spread_digits by exact Hi.
  pose proof (dig256_range j i). lia.
Qed.

(** AND `shrink` UNDOES IT on the new space. *)
Theorem shrink_spread : forall j, 0 <= j < 256 ^ 76 -> shrink (spread j) = j.
Proof.
  intros j Hj. unfold shrink.
  assert (Hb : forall i, 0 <= i < Z.of_nat 76 ->
                 (fun t => dig (spread j) t mod 256) (0 + i) = dig256 j i).
  { intros i Hi. cbn beta.
    replace (Z.of_nat 76) with 76 in Hi by reflexivity.
    replace (0 + i) with i by lia.
    rewrite spread_digits by lia.
    apply Z.mod_small. pose proof (dig256_range j i). lia. }
  pose proof (encB_of_digits 76 j (fun t => dig (spread j) t mod 256) 0
                ltac:(lia) Hb) as H.
  rewrite H. replace (Z.of_nat 76) with 76 by reflexivity.
  apply Z.mod_small. exact Hj.
Qed.

Theorem spread_injective : forall j j',
  0 <= j < 256 ^ 76 -> 0 <= j' < 256 ^ 76 -> spread j = spread j' -> j = j'.
Proof.
  intros j j' Hj Hj' Heq.
  rewrite <- (shrink_spread j Hj), <- (shrink_spread j' Hj'), Heq. reflexivity.
Qed.

(** AND `spread` UNDOES `shrink` wherever the digits were bytes to begin with —
    which is what an ACCEPTED package's message satisfies. *)
Theorem spread_shrink : forall v,
  0 <= v < 257 ^ 76 -> (forall i, 0 <= i < 76 -> dig v i <= 255) ->
  spread (shrink v) = v.
Proof.
  intros v Hv Hb. unfold spread.
  assert (Hd : forall i, 0 <= i < Z.of_nat 76 ->
                 dig256 (shrink v) (0 + i) = dig v i).
  { intros i Hi. replace (Z.of_nat 76) with 76 in Hi by reflexivity.
    replace (0 + i) with i by lia.
    unfold shrink.
    assert (Hbb : forall t, 0 <= t < Z.of_nat 76 ->
                    0 <= (fun s => dig v s mod 256) (0 + t) <= 255).
    { intros t _. cbn beta. apply dig_mod256_range. }
    rewrite (encB_digits 76 (fun s => dig v s mod 256) 0 Hbb i
               ltac:(replace (Z.of_nat 76) with 76 by reflexivity; lia)).
    cbn beta. replace (0 + i) with i by lia.
    apply Z.mod_small.
    pose proof (dig_range v i). pose proof (Hb i Hi). lia. }
  pose proof (enc_from_of_digits 76 v (dig256 (shrink v)) 0 ltac:(lia) Hd) as H.
  rewrite H. replace (Z.of_nat 76) with 76 by reflexivity.
  apply Z.mod_small. exact Hv.
Qed.

(* ===================================================================== *)
(* EVERY POSITION OF `canon91 (spread j)` IS A GENUINE BYTE               *)
(*                                                                        *)
(* Three ranges, three arguments. `[0,15)` is the domain-separation label, *)
(* and its bytes needed `pKG_TAG_LABEL`'s reads to be shown to succeed —   *)
(* which they can be, because it is `array_to_slice` of a 15-element array *)
(* and `slice_len_array_to_slice` gives the length. `[15,43)` and `[43,91)`*)
(* are the two windows, and both reduce to digits of the message itself.   *)
(* ===================================================================== *)

Lemma label_len : to_Z (slice_len pKG_TAG_LABEL) = 15.
Proof.
  unfold pKG_TAG_LABEL. rewrite slice_len_array_to_slice. reflexivity.
Qed.

(** THE LABEL BYTES ARE BYTES. Where `Umbra_Canonical` left this to the caller,
    it is discharged here. *)
Lemma label_is_a_byte : forall i, 0 <= i < 15 ->
  0 <= rdS pKG_TAG_LABEL i <= 255.
Proof.
  intros i Hi. unfold rdS.
  assert (Hmax : 0 <= i <= usize_max).
  { pose proof usize_max_bound as Hb. unfold u32_max in Hb. lia. }
  destruct (slice_index_usize_ok pKG_TAG_LABEL (uz i)) as [v Hv].
  { rewrite (to_Z_uz i Hmax), label_len. lia. }
  rewrite Hv. apply u8_to_Z_range.
Qed.

(** The low window's digits are the message's own. *)
Lemma dig_of_low_window : forall m t, 0 <= t < 28 ->
  dig (m mod 257 ^ 28) t = dig m t.
Proof.
  intros m t Ht.
  assert (HPt : 0 < 257 ^ t) by (apply pow257_pos; lia).
  assert (HP : 0 < 257 ^ 28) by (apply pow257_pos; lia).
  assert (HS : 257 ^ 28 = 257 ^ t * (257 * 257 ^ (27 - t))).
  { replace (257 * 257 ^ (27 - t)) with (257 ^ (28 - t)).
    - rewrite <- Z.pow_add_r by lia. f_equal. lia.
    - rewrite <- Z.pow_succ_r by lia. f_equal. lia. }
  set (q := m / 257 ^ 28). set (r := m mod 257 ^ 28).
  assert (HD : m = 257 ^ t * (257 * 257 ^ (27 - t)) * q + r).
  { unfold q, r. rewrite <- HS. apply Z.div_mod. lia. }
  unfold dig. rewrite HD.
  replace (257 ^ t * (257 * 257 ^ (27 - t)) * q + r)
    with (r + (257 ^ (27 - t) * q * 257) * 257 ^ t) by ring.
  rewrite Z.div_add by lia.
  rewrite Z.mod_add by lia. reflexivity.
Qed.

(** The high window's digits are the message's, shifted by 28. *)
Lemma dig_of_high_window : forall m s, 0 <= s ->
  dig (m / 257 ^ 28) s = dig m (28 + s).
Proof.
  intros m s Hs. unfold dig.
  rewrite Z.div_div
    by (pose proof (pow257_pos 28 ltac:(lia));
        pose proof (pow257_pos s Hs); lia).
  rewrite <- Z.pow_add_r by lia. reflexivity.
Qed.

(** EVERY PREIMAGE POSITION OF A BYTE-VALID MESSAGE IS A BYTE. *)
Lemma canon_rd_is_a_byte : forall m i,
  (forall t, 0 <= t < 76 -> dig m t <= 255) ->
  0 <= i < 91 -> 0 <= canon_rd m i <= 255.
Proof.
  intros m i Hb Hi. unfold canon_rd.
  destruct (Z.ltb_spec i 15) as [Hl | Hl].
  - apply label_is_a_byte. lia.
  - destruct (Z.ltb_spec i 43) as [Hm | Hm].
    + rewrite dig_of_low_window by lia.
      pose proof (dig_range m (i - 15)). pose proof (Hb (i - 15) ltac:(lia)).
      lia.
    + rewrite dig_of_high_window by lia.
      pose proof (dig_range m (28 + (i - 43))).
      pose proof (Hb (28 + (i - 43)) ltac:(lia)). lia.
Qed.

Theorem canon91_of_byte_valid : forall m,
  (forall t, 0 <= t < 76 -> dig m t <= 255) -> allbytes (canon91 m) = true.
Proof.
  intros m Hb. apply allbytes_spec. intros z Hz.
  unfold canon91 in Hz. apply in_map_iff in Hz. destruct Hz as [i [Heq Hi]].
  apply in_seq in Hi. subst z. apply canon_rd_is_a_byte; [ exact Hb | lia ].
Qed.

(** THE HEADLINE OF THE RE-INDEXING: no message of the new space reaches the
    dead zone. *)
Theorem spread_canon91_allbytes : forall j, allbytes (canon91 (spread j)) = true.
Proof.
  intro j. apply canon91_of_byte_valid. intros t Ht.
  apply spread_is_byte_valid. exact Ht.
Qed.

(** So the counterexample of `Umbra_Canonical` has nothing to bite on: the
    patched seam and the original agree at every message of the new space. *)
Theorem seam_patch_is_invisible_on_the_new_space :
  forall (mb0 : byteseam_t) (alt : list Z -> Z) (kb : list Z) (j : Z),
    seam_patch mb0 alt kb (canon91 (spread j)) = mb0 kb (canon91 (spread j)).
Proof.
  intros mb0 alt kb j. apply seam_patch_agrees. apply spread_canon91_allbytes.
Qed.

(* ===================================================================== *)
(* WHAT IS STILL NEEDED, NAMED — AND WHAT IT THEN GIVES                   *)
(* ===================================================================== *)

(** THE ONE REMAINING MODEL-LEVEL PREMISE. Every 91-element list of byte values
    is the read-sequence of some `array u8 91`.

    This is TRUE of Rust arrays and is not provable here: `Primitives.
    array_index_usize` is a bare axiom with no law relating any constructor to
    indexing, so the Aeneas Coq backend exposes no way to build an array with
    known reads. (`Update_Model.v` §5 records that the backend's `mk_array` is
    inconsistent and is deliberately not used, so it is not an escape either.)

    It is stated as a PREMISE rather than an `Axiom` so that it appears in the
    closed type of everything that uses it and a reader can see exactly what is
    being taken on trust. *)
Definition ArrayVectors : Prop :=
  forall b : list Z,
    length b = 91%nat -> allbytes b = true ->
    exists p : array u8 91%usize, bytes91 p = b.

(** UNDER IT, `ByteSeam` PINS THE SEAM AT EVERY MESSAGE OF THE NEW SPACE:
    the value is a real evaluation of the device's engine, not an arbitrary
    extension of it. *)
Theorem byte_vectors_are_arrays_pins_the_seam :
  ArrayVectors ->
  forall (macf : slice u8 -> array u8 91%usize -> array u8 32%usize)
         (mb : byteseam_t),
    ByteSeam macf mb ->
    forall (kb : slice u8) (j : Z),
      exists p : array u8 91%usize,
        mb (kbytes kb) (canon91 (spread j)) = tag_of_arr (macf kb p).
Proof.
  intros HAV macf mb Hbs kb j.
  destruct (HAV (canon91 (spread j)) (canon91_length _)
              (spread_canon91_allbytes j)) as [p Hp].
  exists p. rewrite <- Hp. symmetry. apply Hbs.
Qed.

(** AND THEREFORE ANY TWO SEAMS THE PREMISE ADMITS AGREE THERE — which is the
    exact negation of `Umbra_Canonical.restricted_space_still_admits_a_broken_
    seam`. On `[0, 257^76)` that theorem builds two `ByteSeam` seams that
    DISAGREE at a reachable message; on the re-indexed space no such pair
    exists. The counterexample is not merely unbuilt, it is refuted. *)
Theorem no_broken_seam_on_the_byte_valid_space :
  ArrayVectors ->
  forall (macf : slice u8 -> array u8 91%usize -> array u8 32%usize)
         (mb mb' : byteseam_t),
    ByteSeam macf mb -> ByteSeam macf mb' ->
    forall (kb : slice u8) (j : Z),
      mb (kbytes kb) (canon91 (spread j))
      = mb' (kbytes kb) (canon91 (spread j)).
Proof.
  intros HAV macf mb mb' Hbs Hbs' kb j.
  destruct (HAV (canon91 (spread j)) (canon91_length _)
              (spread_canon91_allbytes j)) as [p Hp].
  rewrite <- Hp, <- Hbs, <- Hbs'. reflexivity.
Qed.

(** THE TWO MAPS AT THE `nat` INDEXING THE GAME USES. The SSProve tier cannot
    import `ZArith` — `N_scope` would steal mathcomp's `%N` delimiter and
    silently change what its statements mean — so anything it must NAME has to
    be `nat`-valued and defined here. *)
Definition spread_idx (j : nat) : nat := Z.to_nat (spread (Z.of_nat j)).

Definition shrink_idx (v : nat) : nat := Z.to_nat (shrink (Z.of_nat v)).

Lemma spread_idx_val : forall j, Z.of_nat (spread_idx j) = spread (Z.of_nat j).
Proof.
  intro j. unfold spread_idx. rewrite Z2Nat.id; [ reflexivity |].
  apply spread_range.
Qed.

(** The message preimage the game's index actually reaches. *)
Definition canon91_of_idx (j : nat) : list Z := canon91 (spread (Z.of_nat j)).

Lemma canon91_of_idx_length : forall j, length (canon91_of_idx j) = 91%nat.
Proof. intro j. apply canon91_length. Qed.

Theorem canon91_of_idx_allbytes : forall j, allbytes (canon91_of_idx j) = true.
Proof. intro j. apply spread_canon91_allbytes. Qed.

(** DISTINCT INDICES, DISTINCT PREIMAGES — the non-vacuity statement at the new
    space, and now the preimages are known to be genuine byte vectors. *)
Theorem canon91_of_idx_injective : forall j j' : nat,
  (Z.of_nat j < 256 ^ 76)%Z -> (Z.of_nat j' < 256 ^ 76)%Z ->
  j <> j' -> canon91_of_idx j <> canon91_of_idx j'.
Proof.
  intros j j' Hj Hj' Hne Heq. apply Hne. apply Nat2Z.inj.
  apply spread_injective; [ lia | lia |].
  apply canon91_injective; [ apply spread_range | apply spread_range | exact Heq ].
Qed.

(** THE PINNED MAC AT THE RE-INDEXED SPACE. `MG_of` precomposed with `spread`:
    the game hands it a base-256 numeral, and what reaches the engine is the
    canonical decoding of the base-257 numeral with those same digits. *)
Definition MG_spread (mb : byteseam_t) (kb : slice u8) (j : nat) : nat :=
  MG_of mb kb (spread_idx j).

Theorem MG_spread_is_determined :
  ArrayVectors ->
  forall (macf : slice u8 -> array u8 91%usize -> array u8 32%usize)
         (mb mb' : byteseam_t),
    ByteSeam macf mb -> ByteSeam macf mb' ->
    forall (kb : slice u8) (j : nat), MG_spread mb kb j = MG_spread mb' kb j.
Proof.
  intros HAV macf mb mb' Hbs Hbs' kb j.
  unfold MG_spread, MG_of. rewrite spread_idx_val.
  f_equal. exact (no_broken_seam_on_the_byte_valid_space HAV macf mb mb'
                    Hbs Hbs' kb (Z.of_nat j)).
Qed.

(** AND ITS COLLISIONS ARE ENGINE COLLISIONS AT DISTINCT BYTE VECTORS —
    `Umbra_Canonical.MG_of_in_range_collision_is_engine_collision` transported
    to the new index set, where the two preimages are now known to be REAL
    91-byte vectors rather than merely distinct lists. *)
Theorem MG_spread_collision_is_engine_collision :
  forall (mb : byteseam_t) (kb : slice u8) (j j' : nat),
    (Z.of_nat j < 256 ^ 76)%Z -> (Z.of_nat j' < 256 ^ 76)%Z ->
    j <> j' ->
    MG_spread mb kb j = MG_spread mb kb j' ->
    exists b b' : list Z,
      b <> b' /\ length b = 91%nat /\ length b' = 91%nat /\
      allbytes b = true /\ allbytes b' = true /\
      Z.to_nat (mb (kbytes kb) b) = Z.to_nat (mb (kbytes kb) b').
Proof.
  intros mb kb j j' Hj Hj' Hne Heq.
  exists (canon91_of_idx j), (canon91_of_idx j').
  split; [| split; [| split; [| split; [| split ]]]].
  - apply canon91_of_idx_injective; assumption.
  - apply canon91_of_idx_length.
  - apply canon91_of_idx_length.
  - apply canon91_of_idx_allbytes.
  - apply canon91_of_idx_allbytes.
  - unfold MG_spread, MG_of in Heq. unfold canon91_of_idx.
    rewrite <- !spread_idx_val. exact Heq.
Qed.
