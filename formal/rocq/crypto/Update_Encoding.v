(** THE TYPE BRIDGE — Aeneas `array u8 n` / `slice u8` ⇄ a plain `Z`.

    WHY A BRIDGE IS NEEDED AT ALL. The verified parser lives over Aeneas's
    `Primitives`: `array u8 91` is `{l : list u8 | length l = 91}` and
    `array_index_usize` is an opaque `Axiom`. A game-based cryptographic library
    (SSProve) needs its message space to be a `choice_type` — a countable type
    with decidable equality — and cannot use an opaque sigma type whose equality
    is not even decidable. Worse, `u8` is a sigma type over a `Prop`, so two
    bytes with the same value are not provably equal as Coq terms without proof
    irrelevance (this is already noted in Update_Auth.v). The development can
    therefore only ever observe BYTE VALUES, never array identity.

    The bridge takes that seriously instead of papering over it: it maps arrays
    and slices into `Z` THROUGH THEIR READS, so that

       "the reads agree"  ==>  "the encodings are equal"

    holds by construction, and equality of encodings is ordinary Leibniz
    equality on `Z` — which is exactly what a game's "was this message queried?"
    test needs.

    BASE 257, NOT 256. `rdS`/`rdA` are TOTAL: an out-of-range or failing read
    returns the sentinel 256. Base 257 keeps the digit expansion injective even
    with that sentinel present, so a failing read can never be confused with a
    byte value. Nothing downstream depends on which sentinel is used, but the
    choice removes a class of "your encoding collides" objection.

    WHAT IS ENCODED. The 76-byte AUTHENTICATED CORE of the protocol — precisely
    the bytes of the HMAC preimage at offsets [15,91), i.e. everything except
    the 15-byte constant domain-separation label:

       pre[15,31)  nonce        = pkg[ 4,20)
       pre[31,35)  author_id    = pkg[20,24)
       pre[35,39)  version      = pkg[24,28)
       pre[39,43)  blob_len     = pkg[28,32)
       pre[43,91)  header       = blob[0,48) = pkg[32,80)   (the full UMBR header)

    This is the right message space for the EUF-CMA game: `Update_Crypto`'s
    `Assembles` says the preimage is `LABEL ++ core`, and `assembly_injective`
    says the core determines all five semantic fields. So a statement about
    these 76 bytes is a statement about the five fields, and the reduction never
    has to invert the encoding.

    THE HEADLINE OF THIS FILE (`accept_encodes`): on acceptance, the encoding of
    the preimage the DEVICE hashed equals the encoding computed from the WIRE
    BYTES alone, and likewise for the tag. That is what makes the reduction
    implementable: a reduction holding no key can compute the message and tag it
    must forward to its EUF-CMA challenger, from the submitted package only.

    NO NEW AXIOMS. `Print Assumptions accept_encodes` lists exactly the 38
    quarantined Primitives/Update_Safety axioms the existing chain already has;
    the injectivity theorems below need strict subsets of those, and
    `enc_from_inj` is closed under the global context. THAT COUNT IS A TIER-D
    STATEMENT ONLY: Tier G (Umbra_EUFCMA.v, Umbra_Reduction.v) carries SSProve's
    own 7-axiom base, which is DISJOINT from these 38 and includes an admitted
    lemma. See README.md, "Axiom budget". *)

Require Import Primitives.
Import Primitives.
Require Import Coq.ZArith.ZArith.
Require Import Coq.Bool.Bool.
Require Import Coq.Bool.Sumbool.
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
Local Open Scope Z_scope.
Local Open Scope Primitives_scope.

(* ===================================================================== *)
(* TOTAL INDEXING                                                         *)
(* ===================================================================== *)

(** A total `Z -> usize`. Out-of-range arguments collapse to 0; every use below
    is guarded by an in-range proof, so the collapse is never exercised. *)
Definition uz (z : Z) : usize :=
  match mk_scalar Usize z with
  | Ok u => u
  | _ => 0%usize
  end.

Lemma mk_usize_full : forall z, 0 <= z <= usize_max ->
  exists s : usize, mk_scalar Usize z = Ok s /\ to_Z s = z.
Proof.
  intros z Hz. unfold mk_scalar.
  assert (Hb : scalar_in_bounds Usize z = true).
  { unfold scalar_in_bounds. apply andb_true_intro. split.
    - unfold scalar_ge_min. apply orb_true_iff. right.
      apply Z.leb_le. rewrite usize_min_eq. lia.
    - unfold scalar_le_max. apply orb_true_iff. right.
      apply Z.leb_le. rewrite usize_max_eq. lia. }
  destruct (sumbool_of_bool (scalar_in_bounds Usize z)) as [Hs|Hs].
  - eexists. split; [ reflexivity |]. unfold to_Z; reflexivity.
  - rewrite Hb in Hs. discriminate.
Qed.

Lemma to_Z_uz : forall z, 0 <= z <= usize_max -> to_Z (uz z) = z.
Proof.
  intros z Hz. unfold uz.
  destruct (mk_usize_full z Hz) as [s [Hs Hv]]. rewrite Hs. exact Hv.
Qed.

(** Total byte readers. The sentinel 256 is out of the byte range and is
    distinguishable from every real byte because the digit base is 257. *)
Definition rdA {n : usize} (a : array u8 n) (z : Z) : Z :=
  match array_index_usize a (uz z) with Ok b => to_Z b | _ => 256 end.

Definition rdS (s : slice u8) (z : Z) : Z :=
  match slice_index_usize s (uz z) with Ok b => to_Z b | _ => 256 end.

Lemma rdA_at : forall {n : usize} (a : array u8 n) (i : usize),
  0 <= to_Z i <= usize_max ->
  rdA a (to_Z i) = match array_index_usize a i with Ok b => to_Z b | _ => 256 end.
Proof.
  intros n a i Hi. unfold rdA.
  rewrite (array_index_usize_ext a (uz (to_Z i)) i); [ reflexivity |].
  apply to_Z_uz. exact Hi.
Qed.

Lemma rdS_at : forall (s : slice u8) (i : usize),
  0 <= to_Z i <= usize_max ->
  rdS s (to_Z i) = match slice_index_usize s i with Ok b => to_Z b | _ => 256 end.
Proof.
  intros s i Hi. unfold rdS.
  rewrite (slice_index_usize_ext s (uz (to_Z i)) i); [ reflexivity |].
  apply to_Z_uz. exact Hi.
Qed.

(* ===================================================================== *)
(* BASE-257 WINDOW ENCODING                                               *)
(* ===================================================================== *)

Fixpoint enc_from (f : Z -> Z) (start : Z) (k : nat) : Z :=
  match k with
  | O => 0
  | S k' => f start + 257 * enc_from f (start + 1) k'
  end.

(** The only structural lemma needed: two windows with pointwise-equal reads
    encode to the same integer, even when they sit at different offsets. This
    is what turns "the device hashed these bytes" into "the wire carries these
    bytes" as an equation between plain integers. *)
Lemma enc_from_shift : forall (k : nat) (f g : Z -> Z) (a b : Z),
  (forall i, 0 <= i < Z.of_nat k -> f (a + i) = g (b + i)) ->
  enc_from f a k = enc_from g b k.
Proof.
  induction k as [| k IH]; intros f g a b H; [ reflexivity |].
  cbn [enc_from].
  assert (H0 : f a = g b).
  { replace a with (a + 0) by lia. replace b with (b + 0) by lia.
    apply H. lia. }
  assert (Hrec : enc_from f (a + 1) k = enc_from g (b + 1) k).
  { apply IH. intros i Hi.
    replace (a + 1 + i) with (a + (1 + i)) by lia.
    replace (b + 1 + i) with (b + (1 + i)) by lia.
    apply H. lia. }
  rewrite H0, Hrec. reflexivity.
Qed.

(* ===================================================================== *)
(* THE PROTOCOL'S MESSAGE AND TAG ENCODINGS                               *)
(* ===================================================================== *)

(** The 76-byte authenticated core, read off the HMAC PREIMAGE. *)
Definition msg_of_pre (pre : array u8 91%usize) : Z :=
  enc_from (rdA pre) 15 28 + 257 ^ 28 * enc_from (rdA pre) 43 48.

(** The same 76 bytes, read off the WIRE. `[4,32)` is the fixed header's
    nonce/author/version/blob_len region; `[32,80)` is `blob[0,48)`, the full
    48-byte UMBR-header window, since `blob` starts at 32. Computable by anyone
    holding the package — in particular by a reduction that holds no key. *)
Definition msg_of_pkg (pkg : slice u8) : Z :=
  enc_from (rdS pkg) 4 28 + 257 ^ 28 * enc_from (rdS pkg) 32 48.

Definition tag_of_arr (t : array u8 32%usize) : Z := enc_from (rdA t) 0 32.

Definition tag_of_pkg (pkg : slice u8) : Z :=
  enc_from (rdS pkg) (to_Z (slice_len pkg) - 32) 32.

(* ===================================================================== *)
(* THE ENCODING IS INJECTIVE                                              *)
(*                                                                        *)
(* WHY THIS SECTION EXISTS. Without it, the step from `the vendor never    *)
(* signed these five fields` to `this integer is not in the game query      *)
(* set` is PROSE. `Update_Forgery.assemble_injective` does NOT             *)
(* close that gap: it is stated over `ByteEq`, i.e. it takes byte          *)
(* agreement as a HYPOTHESIS and concludes field agreement. What the       *)
(* crypto layer actually needs is the step BEFORE that one — from an       *)
(* equation between the plain integers `msg_of_pre` produces, back to      *)
(* agreement of the underlying reads. That step is proved here.            *)
(*                                                                        *)
(* IT IS AN HONEST BASE-257 ARGUMENT, NOT AN ASSUMPTION. Every digit the   *)
(* encoding sees lies in [0,256]: a successful read yields a `u8`, whose   *)
(* `to_Z` is bounded by the scalar's own proof component, and a failing    *)
(* read yields the sentinel 256. 256 is a LEGAL digit in base 257, so it   *)
(* collides with nothing, and the expansion is recoverable digit by digit. *)
(*                                                                        *)
(* WHAT GRANULARITY THE CONCLUSION HAS, AND WHY IT IS NOT `ByteEq`.        *)
(* `ByteEq` is TERM equality of `array_index_usize` results. An equation   *)
(* between integers cannot yield it: `to_Z b1 = to_Z b2` gives `b1 = b2`   *)
(* only under proof irrelevance for `0 <= x <= 255` (`u8` is a sigma type  *)
(* over a `Prop` — the point Update_Auth.v already makes), and this        *)
(* development deliberately assumes neither proof irrelevance nor          *)
(* functional extensionality. So the conclusion is stated at `to_Z`        *)
(* granularity, as `ReadEq`/`FieldsEqR` below. That is not a cop-out: byte *)
(* VALUES are the security-relevant notion — same nonce bytes, same author *)
(* id, same version, same blob_len, same header bytes — and Aeneas term    *)
(* identity is a modelling artefact. `ByteEq_ReadEq` records that the      *)
(* new relation is genuinely implied by the old one.                       *)
(* ===================================================================== *)

(** A byte's value is in range — read straight off the scalar's own proof
    component. Destructing `b` first is deliberate: reducing the bound INSIDE
    `proj1_sig`'s implicit predicate argument would leave `lia` with two
    syntactically distinct atoms for the same projection. *)
Lemma u8_to_Z_range : forall b : u8, 0 <= to_Z b <= 255.
Proof.
  intro b. unfold to_Z. destruct b as [x Hx].
  cbn. cbn in Hx. unfold u8_min, u8_max in Hx. lia.
Qed.

(** Every digit of the encoding is a legal base-257 digit. *)
Lemma rdA_digit : forall {n : usize} (a : array u8 n) (z : Z),
  0 <= rdA a z <= 256.
Proof.
  intros n a z. unfold rdA.
  destruct (array_index_usize a (uz z)) as [b|e]; [| lia].
  pose proof (u8_to_Z_range b). lia.
Qed.

Lemma rdS_digit : forall (s : slice u8) (z : Z), 0 <= rdS s z <= 256.
Proof.
  intros s z. unfold rdS.
  destruct (slice_index_usize s (uz z)) as [b|e]; [| lia].
  pose proof (u8_to_Z_range b). lia.
Qed.

(** A `k`-digit window is below `257^k`. Needed to peel the two windows of
    `msg_of_pre` apart before either can be inverted. *)
Lemma enc_from_bound : forall (k : nat) (f : Z -> Z) (a : Z),
  (forall i, 0 <= i < Z.of_nat k -> 0 <= f (a + i) <= 256) ->
  0 <= enc_from f a k < 257 ^ Z.of_nat k.
Proof.
  induction k as [| k IH]; intros f a Hf; cbn [enc_from].
  - cbn. lia.
  - assert (Ha : 0 <= f a <= 256).
    { pose proof (Hf 0 ltac:(rewrite Nat2Z.inj_succ; lia)) as H.
      replace (a + 0) with a in H by lia. exact H. }
    assert (Hrec : 0 <= enc_from f (a + 1) k < 257 ^ Z.of_nat k).
    { apply IH. intros i Hi. replace (a + 1 + i) with (a + (1 + i)) by lia.
      apply Hf. rewrite Nat2Z.inj_succ. lia. }
    rewrite Nat2Z.inj_succ, Z.pow_succ_r by lia. lia.
Qed.

(** THE CORE LEMMA. Equal base-257 window encodings force equal digits, even
    when the two windows sit at different offsets. The digit bound is the only
    hypothesis; nothing about arrays, slices or the protocol appears. *)
Lemma enc_from_inj : forall (k : nat) (f g : Z -> Z) (a b : Z),
  (forall i, 0 <= i < Z.of_nat k -> 0 <= f (a + i) <= 256) ->
  (forall i, 0 <= i < Z.of_nat k -> 0 <= g (b + i) <= 256) ->
  enc_from f a k = enc_from g b k ->
  forall i, 0 <= i < Z.of_nat k -> f (a + i) = g (b + i).
Proof.
  induction k as [| k IH]; intros f g a b Hf Hg Heq i Hi.
  - cbn in Hi. lia.
  - cbn [enc_from] in Heq.
    assert (Ha : 0 <= f a <= 256).
    { pose proof (Hf 0 ltac:(rewrite Nat2Z.inj_succ; lia)) as H.
      replace (a + 0) with a in H by lia. exact H. }
    assert (Hb : 0 <= g b <= 256).
    { pose proof (Hg 0 ltac:(rewrite Nat2Z.inj_succ; lia)) as H.
      replace (b + 0) with b in H by lia. exact H. }
    (* the head digit is the residue mod 257, so it is pinned … *)
    assert (H0 : f a = g b) by lia.
    (* … and the tails then agree as integers. *)
    assert (Hrec : enc_from f (a + 1) k = enc_from g (b + 1) k) by lia.
    destruct (Z.eq_dec i 0) as [Hz | Hnz].
    + subst i. replace (a + 0) with a by lia. replace (b + 0) with b by lia.
      exact H0.
    + assert (Hi' : 0 <= i - 1 < Z.of_nat k)
        by (rewrite Nat2Z.inj_succ in Hi; lia).
      assert (Hf' : forall j, 0 <= j < Z.of_nat k -> 0 <= f (a + 1 + j) <= 256).
      { intros j Hj. replace (a + 1 + j) with (a + (1 + j)) by lia.
        apply Hf. rewrite Nat2Z.inj_succ. lia. }
      assert (Hg' : forall j, 0 <= j < Z.of_nat k -> 0 <= g (b + 1 + j) <= 256).
      { intros j Hj. replace (b + 1 + j) with (b + (1 + j)) by lia.
        apply Hg. rewrite Nat2Z.inj_succ. lia. }
      pose proof (IH f g (a + 1) (b + 1) Hf' Hg' Hrec (i - 1) Hi') as Hstep.
      replace (a + i) with (a + 1 + (i - 1)) by lia.
      replace (b + i) with (b + 1 + (i - 1)) by lia.
      exact Hstep.
Qed.

(** Splitting a two-window sum. `msg_of_pre` is `low + 257^28 * high`; with
    `low` below `257^28` the two halves are recovered separately. *)
Lemma split_radix : forall (M A1 B1 A2 B2 : Z),
  0 < M -> 0 <= A1 < M -> 0 <= A2 < M ->
  A1 + M * B1 = A2 + M * B2 -> A1 = A2 /\ B1 = B2.
Proof.
  intros M A1 B1 A2 B2 HM H1 H2 Heq.
  assert (HA : A1 = A2).
  { assert (E1 : (A1 + M * B1) mod M = A1).
    { rewrite (Z.mul_comm M B1), Z.mod_add by lia. apply Z.mod_small; lia. }
    assert (E2 : (A2 + M * B2) mod M = A2).
    { rewrite (Z.mul_comm M B2), Z.mod_add by lia. apply Z.mod_small; lia. }
    rewrite <- E1, <- E2, Heq. reflexivity. }
  split; [ exact HA |].
  subst A2. assert (HB : M * B1 = M * B2) by lia.
  apply (proj1 (Z.mul_cancel_l B1 B2 M ltac:(lia))). exact HB.
Qed.

(** THE INJECTIVITY OF THE MESSAGE ENCODING. Two preimages with the same
    encoded core have the same 76 core bytes. This is the statement the crypto
    layer needs and did not have: it turns an equation between the integers a
    game stores in its query set back into a statement about protocol bytes. *)
Theorem msg_of_pre_inj : forall p q : array u8 91%usize,
  msg_of_pre p = msg_of_pre q ->
  forall i, 15 <= i < 91 -> rdA p i = rdA q i.
Proof.
  intros p q Heq i Hi.
  assert (HM : 0 < 257 ^ 28) by (apply Z.pow_pos_nonneg; lia).
  pose proof (enc_from_bound 28 (rdA p) 15 (fun j _ => rdA_digit p (15 + j)))
    as B1.
  pose proof (enc_from_bound 28 (rdA q) 15 (fun j _ => rdA_digit q (15 + j)))
    as B2.
  replace (Z.of_nat 28) with 28 in B1, B2 by reflexivity.
  unfold msg_of_pre in Heq.
  destruct (split_radix (257 ^ 28)
              (enc_from (rdA p) 15 28) (enc_from (rdA p) 43 48)
              (enc_from (rdA q) 15 28) (enc_from (rdA q) 43 48)
              HM B1 B2 Heq) as [Hlow Hhigh].
  destruct (Z.lt_ge_cases i 43) as [Hlt | Hge].
  - pose proof (enc_from_inj 28 (rdA p) (rdA q) 15 15
                  (fun j _ => rdA_digit p (15 + j))
                  (fun j _ => rdA_digit q (15 + j)) Hlow (i - 15)
                  ltac:(replace (Z.of_nat 28) with 28 by reflexivity; lia)) as H.
    replace (15 + (i - 15)) with i in H by lia. exact H.
  - pose proof (enc_from_inj 48 (rdA p) (rdA q) 43 43
                  (fun j _ => rdA_digit p (43 + j))
                  (fun j _ => rdA_digit q (43 + j)) Hhigh (i - 43)
                  ltac:(replace (Z.of_nat 48) with 48 by reflexivity; lia)) as H.
    replace (43 + (i - 43)) with i in H by lia. exact H.
Qed.

(** Both message encodings are non-negative, so the `Z.to_nat` the game layer
    applies to them loses nothing. Needed wherever a statement about the game's
    `nat`-valued query set has to be pulled back to an equation in `Z`. *)
Lemma msg_of_pre_nonneg : forall p : array u8 91%usize, 0 <= msg_of_pre p.
Proof.
  intro p. unfold msg_of_pre.
  pose proof (enc_from_bound 28 (rdA p) 15 (fun j _ => rdA_digit p (15 + j)))
    as B1.
  pose proof (enc_from_bound 48 (rdA p) 43 (fun j _ => rdA_digit p (43 + j)))
    as B2.
  assert (HM : 0 < 257 ^ 28) by (apply Z.pow_pos_nonneg; lia).
  assert (0 <= 257 ^ 28 * enc_from (rdA p) 43 48)
    by (apply Z.mul_nonneg_nonneg; lia).
  lia.
Qed.

Lemma msg_of_pkg_nonneg : forall pkg : slice u8, 0 <= msg_of_pkg pkg.
Proof.
  intro pkg. unfold msg_of_pkg.
  pose proof (enc_from_bound 28 (rdS pkg) 4 (fun j _ => rdS_digit pkg (4 + j)))
    as B1.
  pose proof (enc_from_bound 48 (rdS pkg) 32 (fun j _ => rdS_digit pkg (32 + j)))
    as B2.
  assert (HM : 0 < 257 ^ 28) by (apply Z.pow_pos_nonneg; lia).
  assert (0 <= 257 ^ 28 * enc_from (rdS pkg) 32 48)
    by (apply Z.mul_nonneg_nonneg; lia).
  lia.
Qed.

(* ===================================================================== *)
(* FROM EQUAL ENCODINGS TO EQUAL PROTOCOL FIELDS                          *)
(* ===================================================================== *)

(** Observational equality of two byte arrays at the granularity this
    development can actually establish from an integer equation: their total
    reads agree. Weaker than `Update_Forgery.ByteEq` (see `ByteEq_ReadEq`),
    and the right notion for a statement whose premise is an equation in `Z`. *)
Definition ReadEq {n : usize} (p q : array u8 n) : Prop :=
  forall i, 0 <= i < to_Z n -> rdA p i = rdA q i.

Lemma ByteEq_ReadEq : forall {n : usize} (p q : array u8 n),
  ByteEq p q -> ReadEq p q.
Proof.
  intros n p q H i Hi.
  pose proof (to_Z_usize_bounds n) as Hn.
  assert (Hu : to_Z (uz i) = i) by (apply to_Z_uz; lia).
  unfold rdA. rewrite (H (uz i) ltac:(lia)). reflexivity.
Qed.

(** The five protocol fields, compared at read granularity. *)
Definition FieldsEqR (f g : Fields) : Prop :=
  ReadEq f.(fld_nonce) g.(fld_nonce)
  /\ to_Z f.(fld_author)   = to_Z g.(fld_author)
  /\ to_Z f.(fld_version)  = to_Z g.(fld_version)
  /\ to_Z f.(fld_blob_len) = to_Z g.(fld_blob_len)
  /\ ReadEq f.(fld_hdr) g.(fld_hdr).

Lemma FieldsEq_FieldsEqR : forall f g, FieldsEq f g -> FieldsEqR f g.
Proof.
  intros f g [H1 [H2 [H3 [H4 H5]]]].
  repeat split; try assumption; apply ByteEq_ReadEq; assumption.
Qed.

(** An `Assembles` window clause, transported to the total readers. *)
Lemma window_rdA :
  forall {m : usize} (pre : array u8 91%usize) (w : array u8 m) (off : Z),
    0 <= off -> off + to_Z m <= 91 ->
    (forall i j : usize, 0 <= to_Z i < to_Z m -> to_Z j = off + to_Z i ->
       array_index_usize pre j = array_index_usize w i) ->
    forall x, 0 <= x < to_Z m -> rdA w x = rdA pre (off + x).
Proof.
  intros m pre w off Hoff Hm Hw x Hx.
  pose proof usize_max_bound as Hub. unfold u32_max in Hub.
  assert (Hux : to_Z (uz x) = x) by (apply to_Z_uz; lia).
  assert (Huj : to_Z (uz (off + x)) = off + x) by (apply to_Z_uz; lia).
  unfold rdA.
  rewrite (Hw (uz x) (uz (off + x)) ltac:(lia) ltac:(lia)).
  reflexivity.
Qed.

(** A u32's little-endian bytes, read totally. *)
Lemma le_bytes_rdA : forall (x : u32) (i : Z), 0 <= i < 4 ->
  rdA (core_num_U32_to_le_bytes x) i = (to_Z x / 256 ^ i) mod 256.
Proof.
  intros x i Hi.
  pose proof usize_max_bound as Hub. unfold u32_max in Hub.
  assert (Hu : to_Z (uz i) = i) by (apply to_Z_uz; lia).
  destruct (u32_to_le_bytes_val x (uz i) ltac:(lia)) as [bv [Hb Hv]].
  unfold rdA. rewrite Hb, Hv, Hu. reflexivity.
Qed.

(** A u32 field of the preimage is pinned by the four core bytes above it. *)
Lemma u32_window_determined :
  forall (p q : array u8 91%usize) (x y : u32) (off : Z),
    15 <= off -> off + 4 <= 91 ->
    (forall i j : usize, 0 <= to_Z i < 4 -> to_Z j = off + to_Z i ->
       array_index_usize p j = array_index_usize (core_num_U32_to_le_bytes x) i) ->
    (forall i j : usize, 0 <= to_Z i < 4 -> to_Z j = off + to_Z i ->
       array_index_usize q j = array_index_usize (core_num_U32_to_le_bytes y) i) ->
    (forall i, 15 <= i < 91 -> rdA p i = rdA q i) ->
    to_Z x = to_Z y.
Proof.
  intros p q x y off Hlo Hhi Hx Hy Hr.
  apply digits_determine. intros k Hk.
  rewrite <- (le_bytes_rdA x (to_Z k) Hk), <- (le_bytes_rdA y (to_Z k) Hk).
  rewrite (window_rdA p (core_num_U32_to_le_bytes x) off
             ltac:(lia) ltac:(rewrite tz4; lia)
             ltac:(rewrite tz4; exact Hx) (to_Z k) ltac:(rewrite tz4; lia)).
  rewrite (window_rdA q (core_num_U32_to_le_bytes y) off
             ltac:(lia) ltac:(rewrite tz4; lia)
             ltac:(rewrite tz4; exact Hy) (to_Z k) ltac:(rewrite tz4; lia)).
  apply Hr. lia.
Qed.

(** THE WRAPPER. Equal encoded cores force equal protocol fields. Together
    with `accept_encodes` this is what licenses reading the game's message
    space back as a statement about nonce / author_id / version / blob_len /
    header — the step that `assemble_injective` alone does NOT provide,
    because it assumes byte agreement rather than deriving it. *)
Theorem msg_determines_fields :
  forall (p q : array u8 91%usize) (f g : Fields),
    AssemblesF p f -> AssemblesF q g ->
    msg_of_pre p = msg_of_pre q ->
    FieldsEqR f g.
Proof.
  intros p q f g HA HB Heq.
  pose proof (msg_of_pre_inj p q Heq) as Hr.
  unfold AssemblesF, Assembles in HA, HB.
  destruct HA as [_ [Hn1 [Ha1 [Hv1 [Hb1 Hh1]]]]].
  destruct HB as [_ [Hn2 [Ha2 [Hv2 [Hb2 Hh2]]]]].
  repeat apply conj.
  - (* nonce, at [15,31) *)
    intros i Hi. rewrite tz16 in Hi.
    rewrite (window_rdA p f.(fld_nonce) 15
               ltac:(lia) ltac:(rewrite tz16; lia)
               ltac:(rewrite tz16; exact Hn1) i ltac:(rewrite tz16; lia)).
    rewrite (window_rdA q g.(fld_nonce) 15
               ltac:(lia) ltac:(rewrite tz16; lia)
               ltac:(rewrite tz16; exact Hn2) i ltac:(rewrite tz16; lia)).
    apply Hr. lia.
  - exact (u32_window_determined p q _ _ 31 ltac:(lia) ltac:(lia) Ha1 Ha2 Hr).
  - exact (u32_window_determined p q _ _ 35 ltac:(lia) ltac:(lia) Hv1 Hv2 Hr).
  - exact (u32_window_determined p q _ _ 39 ltac:(lia) ltac:(lia) Hb1 Hb2 Hr).
  - (* full UMBR header, at [43,91) *)
    intros i Hi. rewrite tz48 in Hi.
    rewrite (window_rdA p f.(fld_hdr) 43
               ltac:(lia) ltac:(rewrite tz48; lia)
               ltac:(rewrite tz48; exact Hh1) i ltac:(rewrite tz48; lia)).
    rewrite (window_rdA q g.(fld_hdr) 43
               ltac:(lia) ltac:(rewrite tz48; lia)
               ltac:(rewrite tz48; exact Hh2) i ltac:(rewrite tz48; lia)).
    apply Hr. lia.
Qed.

(** The two preimages of an assembled pair also agree on the LABEL, which
    `msg_of_pre` never reads: `Assembles` pins those 15 bytes to the constant
    `pKG_TAG_LABEL`. Hence equal encodings give agreement on ALL 91 bytes, not
    just the core. This is what makes the guarded C1e realisable. *)
Lemma assembled_label_agrees :
  forall (p q : array u8 91%usize) (f g : Fields),
    AssemblesF p f -> AssemblesF q g ->
    forall i, 0 <= i < 15 -> rdA p i = rdA q i.
Proof.
  intros p q f g HA HB i Hi.
  pose proof usize_max_bound as Hub. unfold u32_max in Hub.
  unfold AssemblesF, Assembles in HA, HB.
  destruct HA as [Hl1 _]. destruct HB as [Hl2 _].
  assert (Hu : to_Z (uz i) = i) by (apply to_Z_uz; lia).
  unfold rdA.
  rewrite (Hl1 (uz i) (uz i) ltac:(lia) ltac:(lia)).
  rewrite (Hl2 (uz i) (uz i) ltac:(lia) ltac:(lia)).
  reflexivity.
Qed.

Theorem assembled_msg_determines_all_bytes :
  forall (p q : array u8 91%usize) (f g : Fields),
    AssemblesF p f -> AssemblesF q g ->
    msg_of_pre p = msg_of_pre q ->
    forall i, 0 <= i < 91 -> rdA p i = rdA q i.
Proof.
  intros p q f g HA HB Heq i Hi.
  destruct (Z.lt_ge_cases i 15) as [Hlt | Hge].
  - exact (assembled_label_agrees p q f g HA HB i ltac:(lia)).
  - exact (msg_of_pre_inj p q Heq i ltac:(lia)).
Qed.

(* ===================================================================== *)
(* THE MINIMUM-LENGTH GUARD, RE-DERIVED                                   *)
(*                                                                        *)
(* Needed to place `blob[0,48)` inside `pkg` at [32,80): the sub-slice      *)
(* read law only applies inside the range's length. The parser's very first *)
(* guard rejects anything shorter than FIXED_PREFIX + MIN_BLOB + 32 = 112,  *)
(* so acceptance carries that bound. Walked over the verbatim extracted     *)
(* body, like every other statement in this development.                   *)
(* ===================================================================== *)

Lemma accept_implies_len_ge_112 :
  forall {HS : Type} (inst : PkgHmac_t HS) (pkg : slice u8)
         (en : array u8 16%usize) (h : HS) (key : slice u8) r,
    parse_and_verify inst pkg en h key = Ok (Core_result_Result_Ok r) ->
    112 <= to_Z (slice_len pkg).
Proof.
  intros HS inst pkg en h key r Hacc.
  unfold parse_and_verify in Hacc. cbv zeta in Hacc.
  destruct (usize_add fIXED_PREFIX mIN_BLOB) as [i1|] eqn:E1;
    cbn [bind] in Hacc; [| discriminate Hacc].
  destruct (usize_add i1 32%usize) as [i2|] eqn:E2;
    cbn [bind] in Hacc; [| discriminate Hacc].
  assert (Hi1 : to_Z i1 = 80).
  { unfold usize_add, scalar_add in E1. apply mk_scalar_to_Z in E1.
    rewrite tz_fixed, tz_min in E1. lia. }
  assert (Hi2 : to_Z i2 = 112).
  { unfold usize_add, scalar_add in E2. apply mk_scalar_to_Z in E2.
    rewrite tz32 in E2. lia. }
  destruct (slice_len pkg s< i2) eqn:Eg.
  - injection Hacc as Hacc. discriminate Hacc.
  - unfold scalar_ltb in Eg. apply Z.ltb_ge in Eg. lia.
Qed.

(* ===================================================================== *)
(* THE HEADLINE: acceptance pins the DEVICE'S preimage/tag encodings to    *)
(* the encodings a key-less party computes from the wire.                  *)
(* ===================================================================== *)

Section Bridge.

Context {HS : Type}.
Variable inst : PkgHmac_t HS.
Variable h    : HS.
Variable key  : slice u8.
Variable mac  : slice u8 -> array u8 91%usize -> array u8 32%usize.
Hypothesis Hseam :
  forall k p, inst.(PkgHmac_t_hmac_pkg) h k p = Ok (mac k p).

Theorem accept_encodes :
  forall (pkg : slice u8) (en : array u8 16%usize) r,
    parse_and_verify inst pkg en h key = Ok (Core_result_Result_Ok r) ->
    exists (f : Fields) (pre : array u8 91%usize) (t : array u8 32%usize),
      (* the message/tag pair the DEVICE authenticated … *)
      AssemblesF pre f
      /\ t = mac key pre
      /\ f.(fld_author)  = r.(verifiedUpdate_author_id)
      /\ f.(fld_version) = r.(verifiedUpdate_version)
      (* … encodes to exactly what a key-less party reads off the wire. *)
      /\ msg_of_pre pre  = msg_of_pkg pkg
      /\ tag_of_arr t    = tag_of_pkg pkg.
Proof.
  intros pkg en r Hacc.
  pose proof (accept_implies_len_ge_112 inst pkg en h key r Hacc) as Hlen.
  pose proof usize_max_bound as Hub. unfold u32_max in Hub.
  pose proof (to_Z_usize_bounds (slice_len pkg)) as Hlub.
  destruct (accept_implies_authenticated_fields inst h key mac Hseam pkg en r Hacc)
    as [tag_off [expect [nonce [hdr [bl [pre
       [Htoff [Hcpt [Hexp [HA [Hcarry [Hc [Hd [_ [He [Hf [Hg [Hblob Hh]]]]]]]]]]]]]]]]]].
  exists (mkFields nonce r.(verifiedUpdate_author_id) r.(verifiedUpdate_version) bl hdr),
         pre, expect.
  cbn [fld_nonce fld_author fld_version fld_blob_len fld_hdr].
  split; [ exact HA |]. split; [ exact Hexp |].
  split; [ reflexivity |]. split; [ reflexivity |].

  (* ---- the 76-byte core ------------------------------------------------ *)
  assert (W1 : forall i, 0 <= i < 28 -> rdA pre (15 + i) = rdS pkg (4 + i)).
  { intros i Hi.
    assert (Hj : to_Z (uz (15 + i)) = 15 + i) by (apply to_Z_uz; lia).
    assert (Hk : to_Z (uz (4 + i)) = 4 + i) by (apply to_Z_uz; lia).
    unfold rdA, rdS.
    destruct (Z.lt_ge_cases i 16) as [Hlt|Hge].
    - (* nonce window, TERM equality *)
      assert (Hi0 : to_Z (uz i) = i) by (apply to_Z_uz; lia).
      rewrite (Hd (uz i) (uz (15 + i)) (uz (4 + i)) ltac:(lia) ltac:(lia) ltac:(lia)).
      reflexivity.
    - destruct (Z.lt_ge_cases i 20) as [Hlt2|Hge2].
      + assert (Hi0 : to_Z (uz (i - 16)) = i - 16) by (apply to_Z_uz; lia).
        destruct (He (uz (i - 16)) (uz (15 + i)) (uz (4 + i))
                     ltac:(lia) ltac:(lia) ltac:(lia)) as [x [y [Hx [Hy Hxy]]]].
        rewrite Hx, Hy. exact Hxy.
      + destruct (Z.lt_ge_cases i 24) as [Hlt3|Hge3].
        * assert (Hi0 : to_Z (uz (i - 20)) = i - 20) by (apply to_Z_uz; lia).
          destruct (Hf (uz (i - 20)) (uz (15 + i)) (uz (4 + i))
                       ltac:(lia) ltac:(lia) ltac:(lia)) as [x [y [Hx [Hy Hxy]]]].
          rewrite Hx, Hy. exact Hxy.
        * assert (Hi0 : to_Z (uz (i - 24)) = i - 24) by (apply to_Z_uz; lia).
          destruct (Hg (uz (i - 24)) (uz (15 + i)) (uz (4 + i))
                       ltac:(lia) ltac:(lia) ltac:(lia)) as [x [y [Hx [Hy Hxy]]]].
          rewrite Hx, Hy. exact Hxy. }

  assert (W2 : forall i, 0 <= i < 48 -> rdA pre (43 + i) = rdS pkg (32 + i)).
  { intros i Hi.
    assert (Hi0 : to_Z (uz i) = i) by (apply to_Z_uz; lia).
    assert (Hj : to_Z (uz (43 + i)) = 43 + i) by (apply to_Z_uz; lia).
    assert (Hm : to_Z (uz (32 + i)) = 32 + i) by (apply to_Z_uz; lia).
    unfold rdA, rdS.
    rewrite (Hh (uz i) (uz (43 + i)) (uz i) ltac:(lia) ltac:(lia) ltac:(lia)).
    rewrite (slice_index_range_val pkg r.(verifiedUpdate_blob)
               fIXED_PREFIX tag_off (uz i) (uz (32 + i))
               Hblob ltac:(lia) ltac:(rewrite tz_fixed; lia)
               ltac:(rewrite tz_fixed; lia)).
    reflexivity. }

  split.
  { unfold msg_of_pre, msg_of_pkg. f_equal.
    - apply (enc_from_shift 28 (rdA pre) (rdS pkg) 15 4).
      intros i Hi. apply W1. simpl in Hi. lia.
    - f_equal. apply (enc_from_shift 48 (rdA pre) (rdS pkg) 43 32).
      intros i Hi. apply W2. simpl in Hi. lia. }

  (* ---- the tag --------------------------------------------------------- *)
  unfold tag_of_arr, tag_of_pkg.
  apply (enc_from_shift 32 (rdA expect) (rdS pkg) 0 (to_Z (slice_len pkg) - 32)).
  intros i Hi. simpl in Hi.
  assert (Hi0 : to_Z (uz i) = i) by (apply to_Z_uz; lia).
  assert (Hjj : to_Z (uz (to_Z (slice_len pkg) - 32 + i))
                = to_Z (slice_len pkg) - 32 + i) by (apply to_Z_uz; lia).
  unfold rdA, rdS.
  replace (0 + i) with i by lia.
  destruct (Hcarry (uz i) (uz (to_Z (slice_len pkg) - 32 + i))
                   ltac:(lia) ltac:(lia)) as [x [y [Hx [Hy Hxy]]]].
  rewrite Hx, Hy. exact Hxy.
Qed.

End Bridge.
