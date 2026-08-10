(** THE CANONICAL PREIMAGE — pinning the abstract MAC to the real seam, without
    a choice axiom, and saying exactly which bytes it covers.

    WHY THIS FILE EXISTS. Until this revision the only justification that C1e
    (`Umbra_WireConverse.SeamC1e`) is satisfiable was
    `restricted_C1e_is_realisable`, which obtained its `MG` by CLASSICAL CHOICE.
    That is enough to show the hypothesis is not vacuous and nothing more: off
    the image of the assembled encoding the chosen `MG` is unconstrained, so
    "HMAC-SHA256 is EUF-CMA-secure" does NOT transfer to it. The realiser had to
    become a COMPUTED function of the seam before the right-hand side of the
    bound could be read as an HMAC advantage.

    WHAT IS DONE. `canon_rd` decodes a message integer back into the 91 byte
    VALUES of the preimage that produced it: base-257 digits for the 76-byte
    authenticated core, and the fixed constant `pKG_TAG_LABEL` for the 15-byte
    domain-separation label the encoding never reads. `MG_of` is then

      MG_of mb kb m := mb (key bytes of kb) (canonical 91 bytes of m)

    — the seam itself, applied to the canonical decoding. No `classic`, no
    `constructive_indefinite_description`, and the value at EVERY `m`, on the
    image of the encoding or off it, is a real HMAC evaluation.

    WHY AN ARRAY CANNOT BE BUILT, AND WHAT IS ASSUMED INSTEAD. The obvious
    definition is `MG kb m := tag_of_arr (macf kb (canonical_preimage m))` with
    `canonical_preimage : Z -> array u8 91`. It is not available: `array u8 91`
    is inhabited, but `Primitives.array_index_usize` is a BARE axiom with no law
    relating any constructor to indexing at general `n` (`Update_Model.v` §5
    records that the backend's `mk_array` is inconsistent and is deliberately
    not used), so no constructible array has known reads. The seam is therefore
    factored the other way, through `ByteSeam`:

      ByteSeam macf mb  :=  forall kb p, tag_of_arr (macf kb p)
                                       = mb (kbytes kb) (bytes91 p)

    "the HMAC engine's output is a function of the key byte string and the 91
    preimage byte values". That is the constructive content of the old premise
    `Hreads` (byte agreement implies tag agreement) — `ByteSeam_reads` below
    derives `Hreads` from it — and it is a true statement about any HMAC
    implementation. The classical description step that used to sit inside the
    proof is thus replaced by a premise that NAMES the function, which is the
    only form from which a canonical realiser can be computed.

    WHAT THE MAC COVERS, AND WHAT IT DOES NOT. See the last section. The
    package tag authenticates `pkg[4,32)` and `pkg[32,80)` and NOTHING ELSE:
    the update blob's own body is outside the preimage, and
    `blob_body_is_not_covered_by_pkg_tag` proves it by exhibiting the
    invariance. Read that theorem before reading the word "verified" anywhere
    near this development. *)

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
Local Open Scope Z_scope.
Local Open Scope Primitives_scope.

(* ===================================================================== *)
(* BASE-257 DIGITS                                                        *)
(* ===================================================================== *)

(** The `i`-th base-257 digit of `v`. `enc_from` (Update_Encoding.v) is the
    base-257 evaluation of a window; `dig` is its inverse, digit by digit. *)
Definition dig (v i : Z) : Z := (v / 257 ^ i) mod 257.

Lemma dig_range : forall v i, 0 <= dig v i <= 256.
Proof. intros v i. unfold dig. pose proof (Z.mod_pos_bound (v / 257 ^ i) 257). lia. Qed.

Lemma pow257_pos : forall i, 0 <= i -> 0 < 257 ^ i.
Proof. intros i Hi. apply Z.pow_pos_nonneg; lia. Qed.

(** DECODING IS A LEFT INVERSE OF `enc_from`: the digits of a window's encoding
    are the window's own reads. Only the digit bound is used, so this is a
    statement about base-257 arithmetic and about nothing else. *)
Lemma enc_from_digits : forall (k : nat) (b : Z -> Z) (a : Z),
  (forall i, 0 <= i < Z.of_nat k -> 0 <= b (a + i) <= 256) ->
  forall i, 0 <= i < Z.of_nat k -> dig (enc_from b a k) i = b (a + i).
Proof.
  induction k as [| k IH]; intros b a Hb i Hi; [ cbn in Hi; lia |].
  cbn [enc_from].
  assert (Hhead : 0 <= b a <= 256).
  { pose proof (Hb 0 ltac:(rewrite Nat2Z.inj_succ; lia)) as H.
    replace (a + 0) with a in H by lia. exact H. }
  assert (Hb' : forall j, 0 <= j < Z.of_nat k -> 0 <= b (a + 1 + j) <= 256).
  { intros j Hj. replace (a + 1 + j) with (a + (1 + j)) by lia.
    apply Hb. rewrite Nat2Z.inj_succ. lia. }
  assert (Hrest : 0 <= enc_from b (a + 1) k).
  { pose proof (enc_from_bound k b (a + 1) Hb') as H. lia. }
  destruct (Z.eq_dec i 0) as [Hz | Hnz].
  - subst i. unfold dig. cbn [Z.pow]. rewrite Z.div_1_r.
    replace (a + 0) with a by lia.
    rewrite (Z.mul_comm 257 (enc_from b (a + 1) k)), Z.mod_add by lia.
    apply Z.mod_small. lia.
  - assert (Hi1 : 0 <= i - 1 < Z.of_nat k) by (rewrite Nat2Z.inj_succ in Hi; lia).
    assert (Hdiv : (b a + 257 * enc_from b (a + 1) k) / 257
                   = enc_from b (a + 1) k).
    { rewrite (Z.mul_comm 257 (enc_from b (a + 1) k)), Z.div_add by lia.
      rewrite (Z.div_small (b a) 257) by lia. lia. }
    unfold dig.
    replace (257 ^ i) with (257 * 257 ^ (i - 1))
      by (rewrite <- Z.pow_succ_r by lia; f_equal; lia).
    rewrite <- Z.div_div by (try lia; apply pow257_pos; lia).
    rewrite Hdiv.
    pose proof (IH b (a + 1) Hb' (i - 1) Hi1) as Hstep.
    unfold dig in Hstep. rewrite Hstep.
    f_equal. lia.
Qed.

(** ENCODING IS A RIGHT INVERSE, MODULO THE WINDOW WIDTH: a window whose reads
    ARE the digits of `v` encodes back to `v mod 257^k`. This is the direction
    that gives the canonical decoding a left inverse, hence injectivity. *)
Lemma enc_from_of_digits : forall (k : nat) (v : Z) (b : Z -> Z) (a : Z),
  0 <= v ->
  (forall i, 0 <= i < Z.of_nat k -> b (a + i) = dig v i) ->
  enc_from b a k = v mod 257 ^ Z.of_nat k.
Proof.
  induction k as [| k IH]; intros v b a Hv Hb.
  - cbn. rewrite Z.mod_1_r. reflexivity.
  - cbn [enc_from].
    assert (Hhead : b a = v mod 257).
    { replace a with (a + 0) by lia. rewrite Hb by (rewrite Nat2Z.inj_succ; lia).
      unfold dig. cbn [Z.pow]. rewrite Z.div_1_r. reflexivity. }
    assert (Htail : enc_from b (a + 1) k = (v / 257) mod 257 ^ Z.of_nat k).
    { apply IH; [ apply Z.div_pos; lia |].
      intros i Hi. replace (a + 1 + i) with (a + (1 + i)) by lia.
      rewrite Hb by (rewrite Nat2Z.inj_succ; lia).
      unfold dig. rewrite Z.div_div by (try lia; apply pow257_pos; lia).
      f_equal. f_equal. rewrite <- Z.pow_succ_r by lia. f_equal. lia. }
    assert (Hpow : 257 ^ Z.of_nat (S k) = 257 * 257 ^ Z.of_nat k).
    { rewrite Nat2Z.inj_succ, <- Z.pow_succ_r; [ reflexivity | lia ]. }
    rewrite Hhead, Htail, Hpow.
    symmetry. apply Z.rem_mul_r; [ lia | apply pow257_pos; lia ].
Qed.

(* ===================================================================== *)
(* THE CANONICAL DECODING OF A MESSAGE INTEGER                            *)
(* ===================================================================== *)

(** `msg_of_pre` is `enc_from (rdA pre) 15 28 + 257^28 * enc_from (rdA pre) 43 48`
    — the low window is `pre[15,43)` and the high window is `pre[43,91)`. So the
    low window is `m mod 257^28` and the high window is `m / 257^28`, and each
    byte is one base-257 digit of the corresponding window. Offsets `[0,15)` are
    the domain-separation label, which the encoding never reads and `Assembles`
    clause (i) pins to the constant `pKG_TAG_LABEL`. *)
Definition canon_rd (m : Z) (i : Z) : Z :=
  if Z.ltb i 15 then rdS pKG_TAG_LABEL i
  else if Z.ltb i 43 then dig (m mod 257 ^ 28) (i - 15)
  else dig (m / 257 ^ 28) (i - 43).

Lemma canon_rd_label : forall m i, 0 <= i < 15 ->
  canon_rd m i = rdS pKG_TAG_LABEL i.
Proof.
  intros m i Hi. unfold canon_rd.
  destruct (Z.ltb_spec i 15); [ reflexivity | lia ].
Qed.

Lemma canon_rd_low : forall m i, 0 <= i < 28 ->
  canon_rd m (15 + i) = dig (m mod 257 ^ 28) i.
Proof.
  intros m i Hi. unfold canon_rd.
  destruct (Z.ltb_spec (15 + i) 15); [ lia |].
  destruct (Z.ltb_spec (15 + i) 43); [| lia ].
  f_equal. lia.
Qed.

Lemma canon_rd_high : forall m i, 0 <= i < 48 ->
  canon_rd m (43 + i) = dig (m / 257 ^ 28) i.
Proof.
  intros m i Hi. unfold canon_rd.
  destruct (Z.ltb_spec (43 + i) 15); [ lia |].
  destruct (Z.ltb_spec (43 + i) 43); [ lia |].
  f_equal. lia.
Qed.

(** The two windows of `msg_of_pre`, recovered from the integer. *)
Lemma msg_of_pre_windows : forall p : array u8 91%usize,
  msg_of_pre p mod 257 ^ 28 = enc_from (rdA p) 15 28
  /\ msg_of_pre p / 257 ^ 28 = enc_from (rdA p) 43 48.
Proof.
  intro p.
  pose proof (enc_from_bound 28 (rdA p) 15 (fun j _ => rdA_digit p (15 + j))) as B1.
  replace (Z.of_nat 28) with 28 in B1 by reflexivity.
  assert (HM : 0 < 257 ^ 28) by (apply pow257_pos; lia).
  unfold msg_of_pre. split.
  - rewrite (Z.mul_comm (257 ^ 28)), Z.mod_add by lia. apply Z.mod_small. lia.
  - rewrite (Z.mul_comm (257 ^ 28)), Z.div_add by lia.
    rewrite (Z.div_small (enc_from (rdA p) 15 28)) by lia. lia.
Qed.

(** THE FAITHFULNESS OF THE DECODING. For an ASSEMBLED preimage, the canonical
    decoding of its encoded core reproduces all 91 of its byte values: the 76
    core bytes by base-257 digit extraction, and the 15 label bytes because
    `Assembles` pins them to the same constant on both sides. This is the
    theorem that makes `MG_of` agree with the seam on the whole image of the
    encoding — the constructive replacement for the classical choice step. *)
Theorem canon_rd_of_assembled : forall (pre : array u8 91%usize) (f : Fields),
  AssemblesF pre f ->
  forall i, 0 <= i < 91 -> canon_rd (msg_of_pre pre) i = rdA pre i.
Proof.
  intros pre f HA i Hi.
  destruct (msg_of_pre_windows pre) as [Hlow Hhigh].
  destruct (Z.lt_ge_cases i 15) as [Hlt15 | Hge15].
  - (* the label: `Assembles` clause (i) pins it to `pKG_TAG_LABEL`. *)
    rewrite canon_rd_label by lia.
    pose proof usize_max_bound as Hub. unfold u32_max in Hub.
    unfold AssemblesF, Assembles in HA. destruct HA as [Hl _].
    assert (Hu : to_Z (uz i) = i) by (apply to_Z_uz; lia).
    unfold rdA, rdS. rewrite (Hl (uz i) (uz i) ltac:(lia) ltac:(lia)).
    reflexivity.
  - destruct (Z.lt_ge_cases i 43) as [Hlt43 | Hge43].
    + replace i with (15 + (i - 15)) by lia.
      rewrite canon_rd_low by lia. rewrite Hlow.
      apply (enc_from_digits 28 (rdA pre) 15
               (fun j _ => rdA_digit pre (15 + j)) (i - 15)).
      replace (Z.of_nat 28) with 28 by reflexivity. lia.
    + replace i with (43 + (i - 43)) by lia.
      rewrite canon_rd_high by lia. rewrite Hhigh.
      apply (enc_from_digits 48 (rdA pre) 43
               (fun j _ => rdA_digit pre (43 + j)) (i - 43)).
      replace (Z.of_nat 48) with 48 by reflexivity. lia.
Qed.

(* ===================================================================== *)
(* THE DECODING IS INJECTIVE ON THE RANGE THE PROTOCOL USES               *)
(* ===================================================================== *)

(** The encoding, as a function of a byte reader rather than of an array.
    Definitionally equal to `msg_of_pre` at `rdA`. *)
Definition msg_of_bytes (b : Z -> Z) : Z :=
  enc_from b 15 28 + 257 ^ 28 * enc_from b 43 48.

Lemma msg_of_pre_as_bytes : forall p : array u8 91%usize,
  msg_of_pre p = msg_of_bytes (rdA p).
Proof. reflexivity. Qed.

(** Every message the protocol can produce is a 76-digit base-257 numeral. *)
Lemma msg_of_pre_lt : forall p : array u8 91%usize, msg_of_pre p < 257 ^ 76.
Proof.
  intro p.
  pose proof (enc_from_bound 28 (rdA p) 15 (fun j _ => rdA_digit p (15 + j))) as B1.
  pose proof (enc_from_bound 48 (rdA p) 43 (fun j _ => rdA_digit p (43 + j))) as B2.
  replace (Z.of_nat 28) with 28 in B1 by reflexivity.
  replace (Z.of_nat 48) with 48 in B2 by reflexivity.
  assert (Hsplit : 257 ^ 76 = 257 ^ 28 * 257 ^ 48) by (rewrite <- Z.pow_add_r by lia; reflexivity).
  assert (HM : 0 < 257 ^ 28) by (apply pow257_pos; lia).
  unfold msg_of_pre. nia.
Qed.

Lemma msg_of_pkg_lt : forall pkg : slice u8, msg_of_pkg pkg < 257 ^ 76.
Proof.
  intro pkg.
  pose proof (enc_from_bound 28 (rdS pkg) 4 (fun j _ => rdS_digit pkg (4 + j))) as B1.
  pose proof (enc_from_bound 48 (rdS pkg) 32 (fun j _ => rdS_digit pkg (32 + j))) as B2.
  replace (Z.of_nat 28) with 28 in B1 by reflexivity.
  replace (Z.of_nat 48) with 48 in B2 by reflexivity.
  assert (Hsplit : 257 ^ 76 = 257 ^ 28 * 257 ^ 48) by (rewrite <- Z.pow_add_r by lia; reflexivity).
  assert (HM : 0 < 257 ^ 28) by (apply pow257_pos; lia).
  unfold msg_of_pkg. nia.
Qed.

(** THE ROUND TRIP. Re-encoding the canonical decoding returns the message, for
    every message in the protocol's range. So `canon_rd` is injective there, and
    the abstract MAC `MG_of mb kb` is the seam precomposed with an INJECTIVE
    message encoding — which is the shape under which an EUF-CMA assumption on
    the seam carries over to the abstract MAC. *)
Theorem canon_rd_roundtrip : forall m, 0 <= m < 257 ^ 76 ->
  msg_of_bytes (canon_rd m) = m.
Proof.
  intros m Hm.
  assert (HM : 0 < 257 ^ 28) by (apply pow257_pos; lia).
  assert (HN : 0 < 257 ^ 48) by (apply pow257_pos; lia).
  assert (Hsplit : 257 ^ 76 = 257 ^ 28 * 257 ^ 48) by (rewrite <- Z.pow_add_r by lia; reflexivity).
  assert (Hlow : enc_from (canon_rd m) 15 28 = m mod 257 ^ 28).
  { rewrite (enc_from_of_digits 28 (m mod 257 ^ 28) (canon_rd m) 15).
    - replace (Z.of_nat 28) with 28 by reflexivity.
      rewrite Z.mod_mod by lia. reflexivity.
    - pose proof (Z.mod_pos_bound m (257 ^ 28) HM). lia.
    - intros i Hi. apply canon_rd_low.
      replace (Z.of_nat 28) with 28 in Hi by reflexivity. lia. }
  assert (Hhigh : enc_from (canon_rd m) 43 48 = m / 257 ^ 28).
  { rewrite (enc_from_of_digits 48 (m / 257 ^ 28) (canon_rd m) 43).
    - replace (Z.of_nat 48) with 48 by reflexivity.
      apply Z.mod_small. split; [ apply Z.div_pos; lia |].
      apply Z.div_lt_upper_bound; lia.
    - apply Z.div_pos; lia.
    - intros i Hi. apply canon_rd_high.
      replace (Z.of_nat 48) with 48 in Hi by reflexivity. lia. }
  unfold msg_of_bytes. rewrite Hlow, Hhigh.
  pose proof (Z.div_mod m (257 ^ 28) ltac:(lia)) as HD. lia.
Qed.

(* ===================================================================== *)
(* BYTE VIEWS, AND THE SEAM AS A FUNCTION OF THEM                         *)
(* ===================================================================== *)

(** The 91 preimage byte values, and the canonical 91 byte values of a message
    integer, as lists — so that the seam premise below can be stated without
    functional extensionality (two byte READERS agreeing on `[0,91)` are not
    equal functions; the two lists ARE equal). *)
Definition bytes91 (p : array u8 91%usize) : list Z :=
  map (fun i : nat => rdA p (Z.of_nat i)) (seq 0 91).

Definition canon91 (m : Z) : list Z :=
  map (fun i : nat => canon_rd m (Z.of_nat i)) (seq 0 91).

(** The key material's byte values. Term equality of `slice u8` is not
    available (`u8` is a sigma over a `Prop`), so key identity is stated at
    byte-value granularity throughout, exactly as everywhere else here. *)
Definition kbytes (kb : slice u8) : list Z := map to_Z (proj1_sig kb).

Lemma canon91_of_assembled : forall (pre : array u8 91%usize) (f : Fields),
  AssemblesF pre f -> canon91 (msg_of_pre pre) = bytes91 pre.
Proof.
  intros pre f HA. unfold canon91, bytes91. apply map_ext_in.
  intros i Hi. apply in_seq in Hi.
  apply (canon_rd_of_assembled pre f HA). lia.
Qed.

Lemma canon91_length : forall m, length (canon91 m) = 91%nat.
Proof.
  intro m. unfold canon91. rewrite map_length, seq_length. reflexivity.
Qed.

Lemma canon91_nth : forall (m : Z) (k : nat), (k < 91)%nat ->
  nth k (canon91 m) (canon_rd m (Z.of_nat 0)) = canon_rd m (Z.of_nat k).
Proof.
  intros m k Hk. unfold canon91.
  rewrite (map_nth (fun j : nat => canon_rd m (Z.of_nat j)) (seq 0 91) 0%nat k).
  rewrite seq_nth by exact Hk.
  replace (0 + k)%nat with k by lia. reflexivity.
Qed.

Lemma canon91_pointwise : forall m m', canon91 m = canon91 m' ->
  forall i, 0 <= i < 91 -> canon_rd m i = canon_rd m' i.
Proof.
  intros m m' Heq i Hi.
  assert (Hk : (Z.to_nat i < 91)%nat) by lia.
  pose proof (canon91_nth m (Z.to_nat i) Hk) as H1.
  pose proof (canon91_nth m' (Z.to_nat i) Hk) as H2.
  rewrite Heq in H1.
  rewrite (nth_indep (canon91 m') (canon_rd m (Z.of_nat 0))
                     (canon_rd m' (Z.of_nat 0))) in H1
    by (rewrite canon91_length; exact Hk).
  rewrite H2 in H1.
  replace (Z.of_nat (Z.to_nat i)) with i in H1 by lia.
  symmetry. exact H1.
Qed.

(** THE CANONICAL DECODING IS INJECTIVE on the protocol's message range. *)
Theorem canon91_injective : forall m m',
  0 <= m < 257 ^ 76 -> 0 <= m' < 257 ^ 76 -> canon91 m = canon91 m' -> m = m'.
Proof.
  intros m m' Hm Hm' Heq.
  pose proof (canon91_pointwise m m' Heq) as Hpt.
  assert (Hmb : msg_of_bytes (canon_rd m) = msg_of_bytes (canon_rd m')).
  { unfold msg_of_bytes. f_equal.
    - apply (enc_from_shift 28). intros i Hi.
      replace (Z.of_nat 28) with 28 in Hi by reflexivity. apply Hpt. lia.
    - f_equal. apply (enc_from_shift 48). intros i Hi.
      replace (Z.of_nat 48) with 48 in Hi by reflexivity. apply Hpt. lia. }
  rewrite (canon_rd_roundtrip m Hm), (canon_rd_roundtrip m' Hm') in Hmb.
  exact Hmb.
Qed.

(* ===================================================================== *)
(* THE SEAM PREMISE, AND THE CANONICAL REALISER                           *)
(* ===================================================================== *)

(** The type of a byte-level HMAC engine: key bytes and preimage bytes in, tag
    encoding out. Named so the SSProve tier can mention it without importing
    `Primitives`' notations. *)
Definition byteseam_t : Type := list Z -> list Z -> Z.

(** THE PREMISE. The device's seam is a function of the key BYTES and the 91
    preimage BYTES. This is what "the HMAC engine reads bytes" means when it is
    written down as a function rather than as a congruence; `ByteSeam_reads`
    below recovers the congruence form. It carries no unforgeability — the
    constant function satisfies it, exactly as it satisfies C1. *)
Definition ByteSeam
    (m : slice u8 -> array u8 91%usize -> array u8 32%usize)
    (mb : byteseam_t) : Prop :=
  forall (kb : slice u8) (p : array u8 91%usize),
    tag_of_arr (m kb p) = mb (kbytes kb) (bytes91 p).

(** THE CANONICAL REALISER. Note what it is: the SEAM, applied to the canonical
    byte decoding of the message. Not a choice function — a definition.

    TWO LIMITS OF THIS, BOTH FORCED BY THE SAME WALL, BOTH STILL OPEN.
    (i) `mb` returns a `Z` — `tag_of_arr`'s base-257 encoding of the tag — not
    the `array u8 32` the engine produces, so `ByteSeam` constrains the ENCODED
    tag and not the array term. Nothing downstream needs the array (the game
    compares tag integers), but the premise is weaker than "the engine is this
    function" reads.
    (ii) `ByteSeam` pins `mb` only where `bytes91` reaches. `Primitives.
    array_index_usize` is a bare axiom with no law relating any constructor to
    indexing, so NO constructible `array u8 91` has known reads, and this
    development cannot prove that `canon91 m` is `bytes91` of anything for an
    in-range `m` that no assembled preimage produces. On such messages `MG_of`
    is `mb` at an unconstrained argument — and `Z.to_nat` then also leaves the
    tag range unproved. The bound therefore quantifies over seams that are the
    real engine where the device looks and arbitrary elsewhere in range. The
    "intended reading" that instantiates `mb` at the real engine's byte
    function has NO REFERENT on the dead zone: HMAC-SHA256 has no value on a
    91-element list containing 256. See the dead-zone section below for the
    machine-checked consequence at the `257^76` indexing, and
    `Umbra_ByteSpace.v` for the fix — re-indexing the game at the byte-valid
    subimage `256^76`, after which the construction has nothing to patch and,
    under the single named premise `ArrayVectors`, is refuted outright. Limit
    (i) is untouched by that and remains open. *)
Definition MG_of (mb : byteseam_t) (kb : slice u8) (msg : nat) : nat :=
  Z.to_nat (mb (kbytes kb) (canon91 (Z.of_nat msg))).

(** C1e HOLDS OF IT, CONSTRUCTIVELY. `Print Assumptions` on this theorem lists
    the quarantined Aeneas axioms and nothing else — in particular no
    `classic` and no `constructive_indefinite_description`. *)
Theorem MG_of_satisfies_C1e :
  forall (m : slice u8 -> array u8 91%usize -> array u8 32%usize)
         (mb : byteseam_t),
    ByteSeam m mb ->
    forall (kb : slice u8) (pre : array u8 91%usize) (f : Fields),
      AssemblesF pre f ->
      MG_of mb kb (Z.to_nat (msg_of_pre pre)) = Z.to_nat (tag_of_arr (m kb pre)).
Proof.
  intros m mb Hbs kb pre f HA. unfold MG_of.
  rewrite Z2Nat.id by apply msg_of_pre_nonneg.
  rewrite (canon91_of_assembled pre f HA).
  f_equal. symmetry. apply Hbs.
Qed.

(** THE PREMISE IS STRONGER THAN THE OLD ONE, IN THE RIGHT DIRECTION. `Hreads`
    — the hypothesis the classical realiser used — is a CONSEQUENCE of
    `ByteSeam`. So nothing that used to be provable stops being provable, and
    the only thing traded away is the classical description step. *)
Lemma ByteSeam_reads :
  forall (m : slice u8 -> array u8 91%usize -> array u8 32%usize)
         (mb : byteseam_t),
    ByteSeam m mb ->
    forall (kb : slice u8) (p q : array u8 91%usize),
      (forall i, 0 <= i < 91 -> rdA p i = rdA q i) ->
      tag_of_arr (m kb p) = tag_of_arr (m kb q).
Proof.
  intros m mb Hbs kb p q Hpq. rewrite !Hbs. f_equal.
  unfold bytes91. apply map_ext_in. intros i Hi. apply in_seq in Hi.
  apply Hpq. lia.
Qed.

(* ===================================================================== *)
(* THE ABSTRACT GAME'S MESSAGE SPACE WAS TOO BIG — THE DEFECT, AND THE FIX *)
(*                                                                        *)
(* WHAT PINNING THE MAC MADE VISIBLE. `Umbra_EUFCMA`'s message space USED *)
(* TO BE `nat`. The device's engine hashes NINETY-ONE BYTES. So no total *)
(* `MAC : nat -> nat` built from that engine can be injectively encoded — *)
(* pigeonhole, infinitely many messages against finitely many preimages — *)
(* and `MG_of` is no exception: `MG_of_collides_above_range` below        *)
(* exhibits the collision explicitly, at `m` and `m + 257^76`, for EVERY  *)
(* seam.                                                                  *)
(*                                                                        *)
(* THE CONSEQUENCE, STATED PLAINLY. In the abstract EUF-CMA game an       *)
(* adversary may query `gettag m`, receive `t`, and submit                *)
(* `checktag (m + 257^76, t)`. The real package answers `true` (the tags  *)
(* are equal), the ideal package answers `false` (the pair was never      *)
(* issued), so `Advantage (EUF_CMA n (MG_of mb ∘ dkey))` was 1. The bound  *)
(* `device_forgery_le_eufcma_at_the_real_seam` was TRUE and VACUOUS: its   *)
(* right-hand side was not small, and could not be made small by any       *)
(* assumption about HMAC-SHA256. The theorem below is UNCHANGED and still  *)
(* true; what changed is the game it is played in.                        *)
(*                                                                        *)
(* THIS IS NOT A REGRESSION — IT IS A DISCLOSURE. The previous, classical *)
(* realiser had the same defect and worse: off the image of the encoding  *)
(* it was an arbitrary chosen function, which collides at least as badly  *)
(* (the obvious witness sends every off-image message to 0). Pinning the  *)
(* MAC did not create the collision; it made it computable, and therefore *)
(* statable, and therefore this comment.                                  *)
(*                                                                        *)
(* WHAT IS NOT AFFECTED. Nothing on the left-hand side. The device never  *)
(* produces an out-of-range message: `msg_of_pkg_lt` bounds every message *)
(* read off the wire by `257^76`, and `Umbra_WireConverse.wmsg_in_range`  *)
(* says it for the game's own reader. `canon91_injective` is exactly the  *)
(* statement that the encoding is faithful on that range, so the ONLY     *)
(* obstruction is out-of-range messages, which no package can encode to.  *)
(*                                                                        *)
(* THE FIX, DONE. The EUF-CMA game's message space is no longer `nat`: it *)
(* is `chFin MsgB`, the ordinals below an abstract bound, instantiated at  *)
(* `257^76` in `Umbra_RealGame.MSGB`. The two perfect-indistinguishability *)
(* links were re-proved there and in `Umbra_Reduction.v` at the restricted *)
(* space. The collision below is UNCHANGED and still true — it is simply   *)
(* no longer playable, because `m` and `m + 257^76` are never both in the  *)
(* message space: `pigeonhole_witness_leaves_the_range` (Qed) is that      *)
(* statement, and `MG_of_in_range_collision_is_engine_collision` (Qed) is  *)
(* the positive form — in range, every collision of the abstract MAC is a  *)
(* collision OF THE ENGINE at two distinct 91-byte inputs, which is the    *)
(* event an EUF-CMA assumption on HMAC-SHA256 bounds.                      *)
(* ===================================================================== *)

Lemma canon_rd_collides_above_range : forall m i,
  0 <= i < 91 -> canon_rd (m + 257 ^ 76) i = canon_rd m i.
Proof.
  intros m i Hi.
  assert (E76 : 257 ^ 76 = 257 ^ 28 * 257 ^ 48)
    by (rewrite <- Z.pow_add_r by lia; reflexivity).
  assert (P28 : 0 < 257 ^ 28) by (apply pow257_pos; lia).
  unfold canon_rd.
  destruct (Z.ltb_spec i 15); [ reflexivity |].
  assert (Hmod : (m + 257 ^ 76) mod 257 ^ 28 = m mod 257 ^ 28).
  { rewrite E76, (Z.mul_comm (257 ^ 28) (257 ^ 48)), Z.mod_add by lia.
    reflexivity. }
  assert (Hdiv : (m + 257 ^ 76) / 257 ^ 28 = m / 257 ^ 28 + 257 ^ 48).
  { rewrite E76, (Z.mul_comm (257 ^ 28) (257 ^ 48)), Z.div_add by lia.
    reflexivity. }
  destruct (Z.ltb_spec i 43).
  - rewrite Hmod. reflexivity.
  - rewrite Hdiv. unfold dig.
    set (j := i - 43).
    assert (Hj : 0 <= j < 48) by (unfold j; lia).
    assert (Hs : 257 ^ 48 = 257 ^ (48 - j) * 257 ^ j)
      by (rewrite <- Z.pow_add_r by lia; f_equal; lia).
    rewrite Hs, Z.div_add by (apply Z.pow_nonzero; lia).
    replace (257 ^ (48 - j)) with (257 * 257 ^ (48 - j - 1))
      by (rewrite <- Z.pow_succ_r by lia; f_equal; lia).
    rewrite (Z.mul_comm 257 (257 ^ (48 - j - 1))), Z.mod_add by lia.
    reflexivity.
Qed.

Lemma canon91_collides_above_range : forall m,
  canon91 (m + 257 ^ 76) = canon91 m.
Proof.
  intro m. unfold canon91. apply map_ext_in. intros i Hi. apply in_seq in Hi.
  apply canon_rd_collides_above_range. lia.
Qed.

(** THE COLLISION, FOR EVERY SEAM. No hypothesis on `mb` at all: the abstract
    MAC is not injectively encoded over `nat`, and no choice of engine can make
    it so. See the section header for what this costs and what it does not. *)
Theorem MG_of_collides_above_range :
  forall (mb : byteseam_t) (kb : slice u8) (m : nat),
    MG_of mb kb (m + Z.to_nat (257 ^ 76)) = MG_of mb kb m.
Proof.
  intros mb kb m. unfold MG_of.
  replace (Z.of_nat (m + Z.to_nat (257 ^ 76)))
    with (Z.of_nat m + 257 ^ 76)
    by (rewrite Nat2Z.inj_add, Z2Nat.id;
        [ reflexivity | apply Z.pow_nonneg; lia ]).
  rewrite canon91_collides_above_range. reflexivity.
Qed.

(* --------------------------------------------------------------------- *)
(* THE RESTRICTED MESSAGE SPACE: WHAT IT BUYS                             *)
(* --------------------------------------------------------------------- *)

(** The message encoding as the game sees it: a `nat` message, its 91 bytes. *)
Definition canon91_of_nat (m : nat) : list Z := canon91 (Z.of_nat m).

Lemma canon91_of_nat_length : forall m, length (canon91_of_nat m) = 91%nat.
Proof. intro m. apply canon91_length. Qed.

(** THE ENCODING IS INJECTIVE ON THE RESTRICTED SPACE. `canon91_injective`
    restated at `nat` messages, which is the indexing the game uses. *)
Theorem canon91_of_nat_injective_in_range :
  forall m m' : nat,
    (Z.of_nat m < 257 ^ 76)%Z -> (Z.of_nat m' < 257 ^ 76)%Z ->
    canon91_of_nat m = canon91_of_nat m' -> m = m'.
Proof.
  intros m m' Hm Hm' Heq. apply Nat2Z.inj.
  apply canon91_injective; [ lia | lia | exact Heq ].
Qed.

(** THE PIGEONHOLE WITNESS IS NOT IN THE RESTRICTED SPACE. The adversary that
    made the `nat`-message-space game vacuous queried `gettag m` and submitted
    `checktag (m + 257^76, t)`; the second message is out of range for every
    `m`, so the query is not one the restricted game accepts. *)
Theorem pigeonhole_witness_leaves_the_range :
  forall m : nat, ~ (Z.of_nat (m + Z.to_nat (257 ^ 76)) < 257 ^ 76)%Z.
Proof.
  intro m.
  assert (Hp : (0 < 257 ^ 76)%Z) by (apply Z.pow_pos_nonneg; lia).
  rewrite Nat2Z.inj_add, Z2Nat.id by lia. lia.
Qed.

(** IN RANGE, EVERY COLLISION OF THE ABSTRACT MAC IS A COLLISION OF THE ENGINE.

    This is the non-vacuity statement, and it is deliberately not "MG_of is
    injective": `MG_of` ends in a 32-byte tag and no such theorem is true, for
    any seam. What is true, and is what an EUF-CMA assumption on HMAC-SHA256
    speaks about, is that a collision between two DISTINCT in-range messages
    forces the engine to agree at two DISTINCT 91-byte inputs. Over the old
    `nat` message space this failed in the worst possible way: the two messages
    had the SAME 91 bytes, so the collision was in the encoding and no
    assumption about the engine could exclude it. *)
Theorem MG_of_in_range_collision_is_engine_collision :
  forall (mb : byteseam_t) (kb : slice u8) (m m' : nat),
    (Z.of_nat m < 257 ^ 76)%Z -> (Z.of_nat m' < 257 ^ 76)%Z ->
    m <> m' ->
    MG_of mb kb m = MG_of mb kb m' ->
    exists b b' : list Z,
      b <> b' /\ length b = 91%nat /\ length b' = 91%nat /\
      Z.to_nat (mb (kbytes kb) b) = Z.to_nat (mb (kbytes kb) b').
Proof.
  intros mb kb m m' Hm Hm' Hne Heq.
  exists (canon91_of_nat m), (canon91_of_nat m').
  split; [| split; [| split ]].
  - intro Hc. apply Hne. apply canon91_of_nat_injective_in_range; assumption.
  - apply canon91_of_nat_length.
  - apply canon91_of_nat_length.
  - exact Heq.
Qed.

(** WHY THE PROVISIONING MAP MUST BE INJECTIVE. The abstract MAC the game
    samples is `MG_of mb (dkey k)`, and `MG_of` sees the key only through its
    BYTES. Two game keys provisioned to the same key string are therefore the
    SAME abstract MAC, and the game's `uniform KeyN` sampling ranges over fewer
    than `2^n` distinct HMAC keys. That is the failure mode an injectivity
    hypothesis on `dkey` excludes; see `Umbra_RealGame.dkey_faithful`. *)
Theorem MG_of_collapses_on_equal_key_bytes :
  forall (mb : byteseam_t) (kb kb' : slice u8),
    kbytes kb = kbytes kb' -> MG_of mb kb = MG_of mb kb'.
Proof. intros mb kb kb' H. unfold MG_of. rewrite H. reflexivity. Qed.

(* ===================================================================== *)
(* THE DEAD ZONE — WHERE `ByteSeam` CONSTRAINS NOTHING, AND WHAT AN       *)
(* ADVERSARY DOES THERE. READ THIS BEFORE READING THE BOUND.              *)
(*                                                                        *)
(* The restriction of the game's message space to `[0, 257^76)` killed    *)
(* the encoding-periodicity collision above. It restricted to the WRONG    *)
(* SET, and this section is the machine-checked demonstration.            *)
(*                                                                        *)
(* `257^76` is the number of 76-digit base-257 NUMERALS. The physically    *)
(* realisable subset is `256^76`: the digit value 256 is the OUT-OF-RANGE  *)
(* SENTINEL of `Update_Encoding.rdA` (`| _ => 256`), so a message whose    *)
(* base-257 expansion uses the digit 256 decodes, under `canon91`, to a    *)
(* 91-element list that contains 256 — and such a list is provably not     *)
(* `bytes91` of ANY `array u8 91` (`dead_zone_is_no_preimage` below, from  *)
(* `array_index_usize_ok` and `u8_to_Z_range`). `ByteSeam` quantifies      *)
(* only over `bytes91 p`, so on that whole region it constrains `mb`       *)
(* NOWHERE. The region is not a rounding error: it is                      *)
(* `1 - (256/257)^76 = 25.64 %` of the game's message space.               *)
(*                                                                        *)
(* WHAT THAT COSTS. The two theorems at the end of this section say it     *)
(* precisely. Given ANY seam function `mb0` satisfying `ByteSeam`, there   *)
(* is another one that satisfies `ByteSeam` too, agrees with `mb0` at      *)
(* every genuine byte list — hence is the SAME real engine everywhere the  *)
(* real engine is defined — and yet collides the pinned MAC `MG_of` at     *)
(* two distinct in-range messages, or collides a dead-zone message with    *)
(* any live message the caller names. The adversary that plays it is       *)
(* concrete: ask `dsign 256` for a tag `t`, submit a package encoding to   *)
(* the live message carrying `t`, and `RED_dev` asks                       *)
(* `checktag (m0, t)` — the real device says TRUE and the ideal device     *)
(* says FALSE. Advantage 1.                                                *)
(*                                                                        *)
(* SO: `device_forgery_le_eufcma_at_the_real_seam` is a bound over a       *)
(* CLASS of seams, and the class provably contains members that make its   *)
(* right-hand side 1. It is NOT a bound at the real engine's own byte      *)
(* function, because HMAC-SHA256 has no value on a 91-element list         *)
(* containing 256 — 256 is not a byte. Every instantiation of `mb` is an   *)
(* arbitrary extension of the engine off the byte-valid subimage, and      *)
(* extensions that break the bound exist. No prose about HMAC excludes     *)
(* them; only re-indexing the message space at the byte-valid subimage     *)
(* does — which is what `Umbra_ByteSpace.v` then does. THESE THEOREMS ARE  *)
(* KEPT anyway: they are the record of what the `257^76` revision shipped, *)
(* and the statement the fix has to be measured against.                   *)
(* ===================================================================== *)

(** A genuine byte value, as a boolean, and the list-wide version. *)
Definition byteb (z : Z) : bool := andb (Z.leb 0 z) (Z.leb z 255).

Definition allbytes (b : list Z) : bool := forallb byteb b.

Lemma byteb_true_iff : forall z, byteb z = true <-> 0 <= z <= 255.
Proof.
  intro z. unfold byteb. split.
  - intro H. destruct (Z.leb_spec 0 z); destruct (Z.leb_spec z 255);
      cbn in H; try discriminate; lia.
  - intro H. destruct (Z.leb_spec 0 z); destruct (Z.leb_spec z 255);
      cbn; try reflexivity; lia.
Qed.

Lemma allbytes_spec : forall b,
  allbytes b = true <-> (forall z, In z b -> 0 <= z <= 255).
Proof.
  intro b. unfold allbytes. rewrite forallb_forall. split.
  - intros H z Hz. apply byteb_true_iff. apply H. exact Hz.
  - intros H z Hz. apply byteb_true_iff. apply H. exact Hz.
Qed.

Lemma allbytes_false_of_witness : forall (b : list Z) (z : Z),
  In z b -> ~ (0 <= z <= 255) -> allbytes b = false.
Proof.
  intros b z Hin Hout. destruct (allbytes b) eqn:E; [| reflexivity ].
  exfalso. apply Hout. exact (proj1 (allbytes_spec b) E z Hin).
Qed.

(** EVERY READ OF A 91-BYTE ARRAY IS A GENUINE BYTE. This is where the
    sentinel is excluded: `array_index_usize_ok` says an in-bounds read
    succeeds, and `u8_to_Z_range` says its value is in `[0,255]`, so the
    `| _ => 256` branch of `rdA` is unreachable at indices below 91. *)
Lemma rdA91_is_a_byte : forall (p : array u8 91%usize) (i : nat),
  (i < 91)%nat -> 0 <= rdA p (Z.of_nat i) <= 255.
Proof.
  intros p i Hi. unfold rdA.
  assert (Hlt : Z.of_nat i < 91) by lia.
  assert (Hmax : 0 <= Z.of_nat i <= usize_max).
  { pose proof usize_max_bound as Hb. unfold u32_max in Hb. lia. }
  assert (H75 : to_Z 91%usize = 91) by reflexivity.
  destruct (array_index_usize_ok p (uz (Z.of_nat i))) as [v Hv].
  { rewrite (to_Z_uz (Z.of_nat i) Hmax), H75. lia. }
  rewrite Hv. apply u8_to_Z_range.
Qed.

(** THE IMAGE OF `bytes91` IS INSIDE THE BYTE-VALID LISTS. *)
Lemma bytes91_allbytes : forall p : array u8 91%usize,
  allbytes (bytes91 p) = true.
Proof.
  intro p. apply allbytes_spec. intros z Hz.
  unfold bytes91 in Hz. apply in_map_iff in Hz. destruct Hz as [i [Heq Hi]].
  apply in_seq in Hi. subst z. apply rdA91_is_a_byte. lia.
Qed.

(** SO A LIST CARRYING THE SENTINEL IS NOT A PREIMAGE, AND `ByteSeam` SAYS
    NOTHING ABOUT `mb` THERE. *)
Theorem dead_zone_is_no_preimage : forall (b : list Z) (p : array u8 91%usize),
  allbytes b = false -> b <> bytes91 p.
Proof.
  intros b p Hb Heq. subst b. rewrite bytes91_allbytes in Hb. discriminate.
Qed.

(** THE ATTACK PRIMITIVE: patch a seam function anywhere `ByteSeam` cannot
    see. `seam_patch mb0 alt` is `mb0` on every byte-valid list and `alt` —
    a function of the key bytes alone — everywhere else. *)
Definition seam_patch (mb0 : byteseam_t) (alt : list Z -> Z) : byteseam_t :=
  fun kb b => if allbytes b then mb0 kb b else alt kb.

Lemma seam_patch_ByteSeam :
  forall (macf : slice u8 -> array u8 91%usize -> array u8 32%usize)
         (mb0 : byteseam_t) (alt : list Z -> Z),
    ByteSeam macf mb0 -> ByteSeam macf (seam_patch mb0 alt).
Proof.
  intros macf mb0 alt H kb p. unfold seam_patch.
  rewrite bytes91_allbytes. apply H.
Qed.

Lemma seam_patch_agrees : forall (mb0 : byteseam_t) (alt : list Z -> Z) kb b,
  allbytes b = true -> seam_patch mb0 alt kb b = mb0 kb b.
Proof. intros mb0 alt kb b H. unfold seam_patch. rewrite H. reflexivity. Qed.

(* --------------------------------------------------------------------- *)
(* THE WITNESSES: TWO IN-RANGE MESSAGES WHOSE CANONICAL DECODING IS DEAD  *)
(* --------------------------------------------------------------------- *)

Lemma small_lt_pow257_76 : forall z, 0 <= z < 66049 -> 0 <= z < 257 ^ 76.
Proof.
  intros z Hz. split; [ lia |].
  assert (H2 : 257 ^ 2 = 66049) by reflexivity.
  assert (H : 257 ^ 2 <= 257 ^ 76) by (apply Z.pow_le_mono_r; lia).
  lia.
Qed.

(** The low window is taken modulo `257^28`, and `257 | 257^28`, so the
    window's own least significant digit is the message's. *)
Lemma mod257_of_low_window : forall m, (m mod 257 ^ 28) mod 257 = m mod 257.
Proof.
  intro m.
  assert (HP : 0 < 257 ^ 28) by (apply pow257_pos; lia).
  assert (HS : 257 ^ 28 = 257 ^ 27 * 257)
    by (replace 28 with (27 + 1) by lia; rewrite Z.pow_add_r by lia;
        rewrite Z.pow_1_r; reflexivity).
  set (q := m / 257 ^ 28).
  rewrite (Z.mod_eq m (257 ^ 28)) by lia. fold q.
  assert (HR : m - 257 ^ 28 * q = m + (- (257 ^ 27 * q)) * 257)
    by (rewrite HS; ring).
  rewrite HR, Z.mod_add by lia. reflexivity.
Qed.

(** Digit 0 of the authenticated core sits at preimage offset 15, and it is
    the message's own residue mod 257 — at every message, in range or not. *)
Lemma canon_rd_digit0 : forall m, canon_rd m 15 = m mod 257.
Proof.
  intro m. unfold canon_rd.
  destruct (Z.ltb_spec 15 15); [ lia |].
  destruct (Z.ltb_spec 15 43); [| lia ].
  unfold dig. replace (15 - 15) with 0 by lia.
  rewrite Z.pow_0_r, Z.div_1_r. apply mod257_of_low_window.
Qed.

(** A message whose least significant base-257 digit is the SENTINEL decodes
    to a list `ByteSeam` never mentions. No size hypothesis: this is true of
    EVERY message of the game's space, and it is one in every 257 of them. *)
Lemma canon91_dead_of_digit0 : forall m,
  m mod 257 = 256 -> allbytes (canon91 m) = false.
Proof.
  intros m Hd.
  assert (Hin : In (canon_rd m (Z.of_nat 15)) (canon91 m)).
  { unfold canon91.
    apply (in_map (fun i : nat => canon_rd m (Z.of_nat i)) (seq 0 91) 15%nat).
    apply in_seq. lia. }
  assert (Hval : canon_rd m (Z.of_nat 15) = 256).
  { assert (Hc : Z.of_nat 15 = 15) by reflexivity. rewrite Hc.
    rewrite canon_rd_digit0. exact Hd. }
  rewrite Hval in Hin.
  apply (allbytes_false_of_witness _ 256 Hin). lia.
Qed.

(** ONE MESSAGE IN EVERY 257 IS DEAD BY ITS LAST DIGIT ALONE — a lower bound
    on the dead zone that needs no counting argument. The true density, over
    all seventy-six digits, is `1 - (256/257)^76 = 25.64 %`; that figure is
    arithmetic about the encoding and is not formalised here. *)
Theorem dead_zone_meets_every_residue_class :
  forall j : Z, 0 <= j -> allbytes (canon91 (256 + 257 * j)) = false.
Proof.
  intros j Hj. apply canon91_dead_of_digit0.
  rewrite (Z.mul_comm 257 j), Z.mod_add by lia.
  apply Z.mod_small. lia.
Qed.

(** The two concrete witnesses: `256` and `513`, both `≡ 256 (mod 257)`. *)
Lemma canon91_256_dead : allbytes (canon91_of_nat 256) = false.
Proof.
  unfold canon91_of_nat.
  assert (Hz : Z.of_nat 256 = 256) by reflexivity. rewrite Hz.
  apply canon91_dead_of_digit0. reflexivity.
Qed.

Lemma canon91_513_dead : allbytes (canon91_of_nat 513) = false.
Proof.
  unfold canon91_of_nat.
  assert (Hz : Z.of_nat 513 = 513) by reflexivity. rewrite Hz.
  apply canon91_dead_of_digit0. reflexivity.
Qed.

(* --------------------------------------------------------------------- *)
(* THE TWO COUNTEREXAMPLES                                                *)
(* --------------------------------------------------------------------- *)

(** THE RESTRICTED MESSAGE SPACE DOES NOT MAKE THE BOUND NON-VACUOUS.

    For every seam function the premise admits there is another one the
    premise ALSO admits, equal to it at every genuine byte list — so
    indistinguishable from the real engine anywhere the real engine is
    defined — under which the pinned MAC collides at two DISTINCT messages
    of the game's own message space. The collision is in the ENCODING's dead
    zone, not in the engine, so no EUF-CMA assumption about HMAC-SHA256
    excludes it. This is the same defect class as
    `MG_of_collides_above_range`, one level down. *)
Theorem restricted_space_still_admits_a_broken_seam :
  forall (macf : slice u8 -> array u8 91%usize -> array u8 32%usize)
         (mb0 : byteseam_t),
    ByteSeam macf mb0 ->
    exists mb : byteseam_t,
      ByteSeam macf mb
      /\ (forall kb b, allbytes b = true -> mb kb b = mb0 kb b)
      /\ exists m m' : nat,
           (Z.of_nat m < 257 ^ 76)%Z /\ (Z.of_nat m' < 257 ^ 76)%Z
           /\ m <> m'
           /\ forall kb : slice u8, MG_of mb kb m = MG_of mb kb m'.
Proof.
  intros macf mb0 Hbs.
  exists (seam_patch mb0 (fun _ => 0)). split; [| split ].
  - apply seam_patch_ByteSeam. exact Hbs.
  - intros kb b Hb. apply seam_patch_agrees. exact Hb.
  - exists 256%nat, 513%nat. split; [| split; [| split ]].
    + assert (Hz : Z.of_nat 256 = 256) by reflexivity. rewrite Hz.
      apply small_lt_pow257_76. lia.
    + assert (Hz : Z.of_nat 513 = 513) by reflexivity. rewrite Hz.
      apply small_lt_pow257_76. lia.
    + discriminate.
    + intro kb. unfold MG_of, seam_patch.
      change (canon91 (Z.of_nat 256)) with (canon91_of_nat 256).
      change (canon91 (Z.of_nat 513)) with (canon91_of_nat 513).
      rewrite canon91_256_dead, canon91_513_dead. reflexivity.
Qed.

(** AND THE DEAD ZONE COLLIDES WITH WHATEVER LIVE MESSAGE THE ATTACKER PICKS.

    Sharper than the theorem above, and it is the shape the attack uses: the
    adversary asks the signing oracle to tag the dead-zone message `256`,
    receives a tag, and that tag is the pinned MAC of a LIVE message `m0` of
    its choosing. Submitting a package that encodes to `m0` and carries that
    tag is accepted by the real device and refused by the ideal one. *)
Theorem dead_zone_collides_with_any_live_message :
  forall (macf : slice u8 -> array u8 91%usize -> array u8 32%usize)
         (mb0 : byteseam_t) (m0 : nat),
    ByteSeam macf mb0 ->
    allbytes (canon91_of_nat m0) = true ->
    exists mb : byteseam_t,
      ByteSeam macf mb
      /\ (forall kb b, allbytes b = true -> mb kb b = mb0 kb b)
      /\ forall kb : slice u8, MG_of mb kb 256 = MG_of mb kb m0.
Proof.
  intros macf mb0 m0 Hbs Hlive.
  exists (seam_patch mb0 (fun kb => mb0 kb (canon91_of_nat m0))).
  split; [| split ].
  - apply seam_patch_ByteSeam. exact Hbs.
  - intros kb b Hb. apply seam_patch_agrees. exact Hb.
  - intro kb. unfold MG_of, seam_patch.
    change (canon91 (Z.of_nat 256)) with (canon91_of_nat 256).
    change (canon91 (Z.of_nat m0)) with (canon91_of_nat m0).
    rewrite canon91_256_dead, Hlive. reflexivity.
Qed.

(** THE `allbytes` HYPOTHESIS OF THE SECOND THEOREM IS DISCHARGEABLE, and is
    left on the caller only because this file cannot reach the lemma that does
    it. `pKG_TAG_LABEL` is `array_to_slice` of a 15-element array, so its reads
    succeed and are bytes (`Umbra_ByteSpace.label_is_a_byte`, Qed), and
    `Umbra_ByteSpace.canon91_of_byte_valid` (Qed) then gives `allbytes` for any
    message whose seventy-six digits are bytes — every message of the re-indexed
    space, in particular. The counterexample above does not need any of it. *)

(* ===================================================================== *)
(* WHAT THE PACKAGE TAG COVERS — AND WHAT IT DOES NOT                     *)
(*                                                                        *)
(* READ THIS BEFORE READING "VERIFIED SECURE ENCLAVE UPDATE" ANYWHERE.     *)
(*                                                                        *)
(* `msg_of_pkg` reads `pkg[4,32)` — nonce, author_id, version, blob_len —  *)
(* and `pkg[32,80)`, which is `blob[0,48)`, the FULL 48-byte UMBR header   *)
(* (v2; v1 covered only its `header.hmac` field `blob[16,48)`). Those 76   *)
(* bytes are the ENTIRE authenticated core. The blob's own BODY —          *)
(* `blob[48,blob_len)` at `pkg[80, len-32)` — is NOT in the preimage, and  *)
(* `parse_and_verify` performs no check on it: it copies `blob[0,48)`      *)
(* into its header scratch, tags the fixed core, and returns the whole     *)
(* blob unexamined as `verifiedUpdate_blob`.                               *)
(*                                                                        *)
(* SO: blob INTEGRITY is not established by anything in THIS FILE, nor by  *)
(* the update-core chain. It rests on a second, CHAINED HMAC that the      *)
(* firmware computes over the blob and compares against the authenticated  *)
(* `header.hmac` window. That chained HMAC is a DIFFERENT component: it is *)
(* not part of the `umbra-update-core` crate.                              *)
(*                                                                        *)
(* IT IS NO LONGER UNVERIFIED. It is carved into `crates/umbra-chain-core`,*)
(* extracted by the same Charon/Aeneas pipeline, and proved in             *)
(* `../chain-core/proofs-coq/`: `Chain_Body.chain_accept_pins_the_blob_body`*)
(* (Qed) says two blobs accepted against the same `header.hmac` window     *)
(* either agree on every byte of the folded region or exhibit an HMAC      *)
(* collision, and `Chain_Compose.verified_update_pins_the_blob_body` (Qed) *)
(* joins that to P2 at exactly the window this file is about.              *)
(*                                                                        *)
(* WHAT IS THEREFORE TRUE, EXACTLY. The package tag authenticates the      *)
(* FULL 48-byte header — its `header.hmac` field included — and nothing    *)
(* more. Blob-BODY integrity reduces to the chained-HMAC check against     *)
(* that `header.hmac` value — which covers `blob[48, 48+288*n)` and NOT    *)
(* the relocation table after the blocks (`Chain_Residual`, Qed).          *)
(* ===================================================================== *)

(** THE INVARIANCE, MACHINE-CHECKED. Two packages of the same length that agree
    on the authenticated core `[4,32) u [32,80)` and on the trailing 32-byte tag
    produce the SAME `msg_of_pkg` and the SAME `tag_of_pkg`, however they differ
    elsewhere — in particular on `[80, len-32)` (`blob[48,blob_len)`, the blob
    body). The package-tag check cannot separate them. This is the precise sense
    in which the blob body is unauthenticated by the tag this development
    verifies. *)
Theorem blob_body_is_not_covered_by_pkg_tag :
  forall p q : slice u8,
    to_Z (slice_len p) = to_Z (slice_len q) ->
    (forall i, 4 <= i < 32 -> rdS p i = rdS q i) ->
    (forall i, 32 <= i < 80 -> rdS p i = rdS q i) ->
    (forall i, to_Z (slice_len p) - 32 <= i < to_Z (slice_len p) ->
       rdS p i = rdS q i) ->
    msg_of_pkg p = msg_of_pkg q /\ tag_of_pkg p = tag_of_pkg q.
Proof.
  intros p q Hlen Hcore Hhdr Htag. split.
  - unfold msg_of_pkg. f_equal.
    + apply (enc_from_shift 28 (rdS p) (rdS q) 4 4).
      intros i Hi. cbn in Hi. apply Hcore. lia.
    + f_equal. apply (enc_from_shift 48 (rdS p) (rdS q) 32 32).
      intros i Hi. cbn in Hi. apply Hhdr. lia.
  - unfold tag_of_pkg. rewrite <- Hlen.
    apply (enc_from_shift 32 (rdS p) (rdS q)
             (to_Z (slice_len p) - 32) (to_Z (slice_len p) - 32)).
    intros i Hi. cbn in Hi. apply Htag. lia.
Qed.
