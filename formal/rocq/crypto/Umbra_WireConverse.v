(** THE FACTORISATION, AT THE WIRE — `Umbra_RealGame`'s `Hfactorise` as a
    THEOREM.

    `Update_Converse.accept_factorises` (Qed) is stated over an Aeneas
    `slice u8`. The SSProve tier's adversary submits `list nat`, marshalled by
    `Umbra_Wire.wire`. This file transports the factorisation across that
    marshalling and, crucially, exhibits the CONCRETE `struct_ok` the game needs:
    a `list nat -> bool` that mentions no key.

    WHAT `wstruct_ok` IS. Branches 1–5 of `parse_and_verify`, evaluated on the
    wire bytes: the 112-byte minimum length, the magic word, `blob_len >=
    MIN_BLOB`, the offset-consistency equation, and a 16-way byte comparison
    against the armed nonce. `wstruct_ok_iff` (Qed) proves it is exactly
    `Update_Converse.StructOk` on the marshalled package, so the boolean is not
    a re-statement of the guards but the guards themselves.

    IT IS NOT REQUIRED TO REDUCE. `wstruct_ok` is built out of `rdS`/`rdA`,
    which are defined over the Aeneas `slice_index_usize`/`array_index_usize`
    AXIOMS, so it is a stuck term in Coq. That is irrelevant, for exactly the
    reason `Umbra_Wire.v`'s header gives for `accepts`: SSProve needs a
    `bool`-VALUED function, not a computable one. What matters is that no key
    occurs in it — which is a syntactic fact — so a key-less reduction can
    evaluate it in the model.

    NOTHING NEW IS ASSUMED. `Print Assumptions wire_accept_factorises` lists
    exactly the quarantined Aeneas/Update_Safety axioms the chain already
    carries. C1 (`SeamC1`) and C1e (`SeamC1e`) appear as named PREMISES of the
    statement, not as axioms — they are the two seams `Umbra_DeviceLink.v`
    already documents, and the three theorems at the bottom exhibit a COMPUTED
    realiser of C1e (`Umbra_Canonical.MG_of`), uniformly in the key and along
    an arbitrary key-provisioning map. No classical axiom is used. *)

Require Import Primitives.
Import Primitives.
Require Import Coq.ZArith.ZArith.
Require Import Coq.Bool.Bool.
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
Require Import Update_Converse.
Require Import Umbra_Canonical.
Require Import Umbra_ByteSpace.
Require Import Umbra_DeviceLink.
Require Import Umbra_Wire.
Local Open Scope Z_scope.
Local Open Scope Primitives_scope.

(* ===================================================================== *)
(* THE CONCRETE, KEY-FREE `struct_ok`                                     *)
(* ===================================================================== *)

Definition wlen (p : list nat) : Z := to_Z (slice_len (wire p)).

(** BRANCHES 1–5 OF THE EXTRACTED PARSER, AS A BOOLEAN OF THE WIRE BYTES AND
    THE ARMED NONCE. No key occurs. *)
Definition wstruct_ok (en p : list nat) : bool :=
  andb (andb (andb (andb
    (Z.leb 112 (wlen p))
    (Z.eqb (ldec (rdS (wire p)) 0) (to_Z uPDATE_MAGIC)))
    (Z.leb 48 (ldec (rdS (wire p)) 28)))
    (Z.eqb (wlen p - 64) (ldec (rdS (wire p)) 28)))
    (forallb (fun i : nat => Z.eqb (rdS (wire p) (4 + Z.of_nat i))
                                   (rdA (nonce16 en) (Z.of_nat i)))
             (seq 0 16)).

Lemma wstruct_ok_iff : forall en p : list nat,
  wstruct_ok en p = true <-> StructOk (wire p) (nonce16 en).
Proof.
  intros en p. unfold wstruct_ok, StructOk, wlen.
  rewrite !andb_true_iff.
  split.
  - intros [[[[H1 H2] H3] H4] H5].
    apply Z.leb_le in H1. apply Z.eqb_eq in H2.
    apply Z.leb_le in H3. apply Z.eqb_eq in H4.
    rewrite forallb_forall in H5.
    repeat (split; [ assumption |]).
    intros i Hi.
    specialize (H5 (Z.to_nat i) ltac:(apply in_seq; lia)).
    apply Z.eqb_eq in H5.
    replace (Z.of_nat (Z.to_nat i)) with i in H5 by lia.
    exact H5.
  - intros [H1 [H2 [H3 [H4 H5]]]].
    repeat split.
    + apply Z.leb_le. exact H1.
    + apply Z.eqb_eq. exact H2.
    + apply Z.leb_le. exact H3.
    + apply Z.eqb_eq. exact H4.
    + apply forallb_forall. intros i Hi. apply in_seq in Hi.
      apply Z.eqb_eq. apply H5. lia.
Qed.

(* ===================================================================== *)
(* THE TWO SEAMS, NAMED SO THAT THE SSProve TIER NEED NOT SPELL THEM       *)
(* ===================================================================== *)

(** The device-side HMAC, as a function of key material and preimage. *)
Definition macf_t : Type := slice u8 -> array u8 91%usize -> array u8 32%usize.

(** C1 — the seam is a deterministic keyed function. Carries no unforgeability:
    the constant function satisfies it. *)
Definition SeamC1 {H : Type} (i : PkgHmac_t H) (hs : H) (m : macf_t) : Prop :=
  forall k p, i.(PkgHmac_t_hmac_pkg) hs k p = Ok (m k p).

(** C1e — the seam factors through the byte encoding, ON ASSEMBLED PREIMAGES.
    Verbatim from `Umbra_DeviceLink.v`, guard included; see that file for why
    the unguarded form is FALSE at a real HMAC and why this one is realisable. *)
Definition SeamC1e (m : macf_t) (kb : slice u8) (M : nat -> nat) : Prop :=
  forall (pre : array u8 91%usize) (f : Fields),
    AssemblesF pre f ->
    M (Z.to_nat (msg_of_pre pre)) = Z.to_nat (tag_of_arr (m kb pre)).

(* ===================================================================== *)
(* THE FACTORISATION AT THE WIRE                                          *)
(* ===================================================================== *)

Lemma accepts_iff :
  forall {H : Type} (i : PkgHmac_t H) (hs : H) (kb : slice u8) (en p : list nat),
    accepts i hs kb en p = true
    <-> exists r, parse_and_verify i (wire p) (nonce16 en) hs kb
                  = Ok (Core_result_Result_Ok r).
Proof.
  intros H i hs kb en p. split.
  - apply accepts_true.
  - intros [r Hr]. unfold accepts. rewrite Hr. reflexivity.
Qed.

(** (F), AT THE WIRE. The device's verdict on the submitted bytes is the
    conjunction of a key-free boolean and ONE tag equation in `nat` — which is
    exactly the query a key-less EUF-CMA reduction can forward to its
    challenger. This is `Umbra_RealGame.Hfactorise`, as a theorem. *)
Theorem wire_accept_factorises :
  forall {H : Type} (i : PkgHmac_t H) (hs : H) (kb : slice u8) (m : macf_t),
    SeamC1 i hs m ->
    forall M : nat -> nat, SeamC1e m kb M ->
    forall en p : list nat,
      accepts i hs kb en p = true
      <-> (wstruct_ok en p = true /\ wtag p = M (wmsg p)).
Proof.
  intros H i hs kb m Hs M Hf en p.
  rewrite accepts_iff, wstruct_ok_iff.
  unfold wtag, wmsg.
  exact (accept_factorises i hs kb m Hs unit (fun _ => M) tt
           (fun pre f HA => Hf pre f HA) (wire p) (nonce16 en)).
Qed.

(* ===================================================================== *)
(* C1e IS SATISFIED BY A COMPUTED REALISER — NOT A CHOSEN ONE             *)
(*                                                                        *)
(* WHAT CHANGED, AND WHY IT MATTERED. Until this revision the only        *)
(* instantiation of C1e was obtained by `ClassicalEpsilon`. That is       *)
(* enough to rule out vacuity and nothing more: off the image of the      *)
(* assembled encoding the chosen `MG` is unconstrained, so the inference  *)
(* from EUF-CMA security of HMAC-SHA256 to a small right-hand side in     *)
(* `device_forgery_le_eufcma` was NOT licensed. It is now: the            *)
(* realiser is `Umbra_Canonical.MG_of`, which is the seam itself applied  *)
(* to the canonical byte decoding of the message, at every argument.      *)
(*                                                                        *)
(* `Print Assumptions` on any of the three theorems below reports the     *)
(* quarantined Aeneas symbols and nothing else — no `classic`, no         *)
(* `constructive_indefinite_description`.                                 *)
(* ===================================================================== *)

(** THE CANONICAL REALISER SATISFIES C1e. Premise: `ByteSeam` — the seam is a
    function of the key BYTES and the 91 preimage BYTES. That is what C1e was
    meant to say and what every HMAC engine satisfies;
    `Umbra_Canonical.ByteSeam_reads` derives from it the byte-congruence form
    the previous revision assumed. *)
Theorem SeamC1e_canonical :
  forall (m : macf_t) (mb : byteseam_t),
    ByteSeam m mb -> forall kb : slice u8, SeamC1e m kb (MG_of mb kb).
Proof.
  intros m mb Hbs kb pre f HA.
  exact (MG_of_satisfies_C1e m mb Hbs kb pre f HA).
Qed.

(** C1e IS INSTANTIABLE, UNIFORMLY IN THE KEY. The SSProve tier needs one
    realiser covering EVERY key, so this produces a single
    `slice u8 -> nat -> nat`. Constructive: the witness is exhibited. *)
Theorem SeamC1e_realisable :
  forall m : macf_t,
    (exists mb : byteseam_t, ByteSeam m mb) ->
    exists MG : slice u8 -> nat -> nat, forall kb, SeamC1e m kb (MG kb).
Proof.
  intros m [mb Hbs]. exists (MG_of mb).
  intro kb. exact (SeamC1e_canonical m mb Hbs kb).
Qed.

(** EVERY MESSAGE THE GAME'S OWN READER PRODUCES IS IN THE ENCODING'S RANGE.
    This is the half of `Umbra_Canonical`'s message-space defect that is NOT
    affected: the collision `MG_of_collides_above_range` exhibits lives entirely
    above `257^76`, and no wire package can encode to such a message. The defect
    is in the abstract game's message space, not in anything the device does.
    Read the section header of `Umbra_Canonical.v` for what that costs. *)
Lemma wmsg_in_range : forall p : list nat,
  (Z.of_nat (wmsg p) < 257 ^ 76)%Z.
Proof.
  intro p. unfold wmsg.
  rewrite Z2Nat.id by apply msg_of_pkg_nonneg.
  apply msg_of_pkg_lt.
Qed.

(** THE COMPOSITION THE SSProve TIER ACTUALLY NEEDS. `Umbra_RealGame`'s
    `Hfactor` is indexed by the GAME key — `forall k : Key n, SeamC1e macf
    (dkey k) (MAC k)` — not by key material, so `SeamC1e_realisable` above
    stops one step short of the hypothesis it is supposed to justify. This is
    that step, over an arbitrary key type and an arbitrary provisioning map, so
    it can be instantiated at `Key n` and `dkey` without SSProve appearing
    here. It is applied in `Umbra_RealGame.Hfactor_is_realisable`. *)
Theorem SeamC1e_realisable_over_keymap :
  forall {K : Type} (m : macf_t) (dk : K -> slice u8) (mb : byteseam_t),
    ByteSeam m mb ->
    exists MAC : K -> nat -> nat, forall k : K, SeamC1e m (dk k) (MAC k).
Proof.
  intros K m dk mb Hbs. exists (fun k => MG_of mb (dk k)).
  intro k. exact (SeamC1e_canonical m mb Hbs (dk k)).
Qed.

(* ===================================================================== *)
(* THE PROTOCOL'S MESSAGE BOUND, AT THE `nat` INDEXING THE GAME USES       *)
(*                                                                        *)
(* The game-based tier cannot state any of this itself. SSProve's tactics  *)
(* need mathcomp's `ssrnat`, whose scope delimiter `%N` collides with      *)
(* `ZArith`'s `N_scope`; importing `ZArith` into `Umbra_RealGame.v` makes  *)
(* `(wmsg p < MsgN)%N` a statement about binary naturals. So every fact    *)
(* that mentions `Z` is proved HERE, in the bare-Coq tier, and exported at *)
(* `Peano` comparisons, which mathcomp's `ltP` converts in one step.       *)
(*                                                                        *)
(* THE BRIDGE IS PROVED AT AN ABSTRACT BOUND. THAT IS GOOD HYGIENE, NOT A  *)
(* NECESSITY, AND AN EARLIER REVISION OF THIS HEADER CLAIMED OTHERWISE.    *)
(*                                                                        *)
(* WHAT WAS CLAIMED (commit 69be0e5 and this header, at the v1 bound       *)
(* `257^60`): that a direct proof of the concrete-bound instance of        *)
(* `(m < Z.to_nat B)%nat <-> (Z.of_nat m < B)%Z` elaborates                *)
(* fine and then HANGS AT `Qed`, measured at >11 minutes. WHAT IS TRUE:    *)
(* the same script — `Nat2Z.inj_lt`, then `Z2Nat.id` — at the concrete     *)
(* bound compiles in 0.35 s WALL INCLUDING `Qed` on this machine. The      *)
(* claim is refuted; whatever the earlier measurement was measuring, it    *)
(* was not this. The abstract-`B` shape is kept because it is the right    *)
(* shape — it states the fact once and keeps the kernel's check symbolic   *)
(* for any bound a later revision picks — but it is a CHOICE, not a        *)
(* workaround for a wall.                                                  *)
(*                                                                        *)
(* THE `Positive` CLAIM IS ALSO REFUTED. This header used to say that      *)
(* `Umbra_RealGame` passes the `Positive` instance explicitly because      *)
(* typeclass resolution — whose first hint is `reflexivity` — would try   *)
(* evaluate the bound. It does not: `Definition probe : Positive MSGBn :=  *)
(* _.` resolves to `erefl` and the whole file typechecks in ~1 s. Passing  *)
(* the instance explicitly is still preferable — it keeps the instantiated *)
(* statements readable and pins WHICH proof of positivity is in the        *)
(* closed type — but, again, a choice.                                     *)
(*                                                                        *)
(* THE TWO SHAPE CONSTRAINTS THAT ARE REAL, AND WERE RE-CONFIRMED:         *)
(*   * the bound must be `mkpos MsgN`, not a bare `positive` variable —    *)
(*     the derived `NoConfusion` for `choice_type` only reduces on a       *)
(*     constructor application, and `simplify_eq_rel` otherwise fails with *)
(*     `No head found`;                                                    *)
(*   * `MSGB` must be a `Notation`, not a `Definition` — `rewrite /MSGB`   *)
(*     normalises beta-iota after the delta step and does not return       *)
(*     (measured at the v1 bound `257^60`: 2 m 38 s and 1.16 GB, still     *)
(*     climbing when killed; the v2 numerals are larger still).            *)
(*                                                                        *)
(* The `%N` / `N_scope` constraint above is likewise real: it silently     *)
(* changes what the statements MEAN, which is worse than a hang.           *)
(* ===================================================================== *)

Section NatZBridge.

Variable B : Z.
Hypothesis HB : (0 <= B)%Z.

Lemma lt_toNat_iff : forall m : nat,
  (m < Z.to_nat B)%nat <-> (Z.of_nat m < B)%Z.
Proof.
  intro m. rewrite Nat2Z.inj_lt. rewrite Z2Nat.id by exact HB. reflexivity.
Qed.

Lemma toNat_pos : (0 < B)%Z -> (0 < Z.to_nat B)%nat.
Proof. intro H. apply lt_toNat_iff. simpl. exact H. Qed.

End NatZBridge.

(** `257^76` — the number of 76-digit base-257 numerals, i.e. the exact size of
    the authenticated core's encoding — as a `nat`. Never evaluated. *)
Definition MSGBn : nat := Z.to_nat (257 ^ 76).

Lemma pow257_76_nonneg : (0 <= 257 ^ 76)%Z.
Proof. apply Z.pow_nonneg; discriminate. Qed.

Lemma MSGBn_pos : (0 < MSGBn)%nat.
Proof. exact (toNat_pos (257 ^ 76) pow257_76_nonneg (pow257_pos 76 ltac:(lia))). Qed.

(** Below the bound is exactly in the encoding's range, and conversely. *)
Lemma lt_MSGBn_in_range : forall m : nat,
  (m < MSGBn)%nat -> (Z.of_nat m < 257 ^ 76)%Z.
Proof. intro m. exact (proj1 (lt_toNat_iff (257 ^ 76) pow257_76_nonneg m)). Qed.

Lemma in_range_lt_MSGBn : forall m : nat,
  (Z.of_nat m < 257 ^ 76)%Z -> (m < MSGBn)%nat.
Proof. intro m. exact (proj2 (lt_toNat_iff (257 ^ 76) pow257_76_nonneg m)). Qed.

(** THE SIDE-CONDITION THE RESTRICTED GAME CARRIES. Every message any wire
    package can encode to is below the bound — so restricting the message space
    to `[0, MSGBn)` gives up nothing on the left-hand side of the bound. *)
Lemma wmsg_lt_MSGBn : forall p : list nat, (wmsg p < MSGBn)%nat.
Proof. intro p. apply in_range_lt_MSGBn. apply wmsg_in_range. Qed.

(** DISTINCT MESSAGES OF THE RESTRICTED SPACE HAVE DISTINCT PREIMAGES. *)
Theorem msg_space_preimages_distinct : forall m m' : nat,
  (m < MSGBn)%nat -> (m' < MSGBn)%nat -> m <> m' ->
  canon91_of_nat m <> canon91_of_nat m'.
Proof.
  intros m m' Hm Hm' Hne Heq. apply Hne.
  apply canon91_of_nat_injective_in_range;
    [ apply lt_MSGBn_in_range | apply lt_MSGBn_in_range | ]; assumption.
Qed.

(** AND EVERY COLLISION OF THE ABSTRACT MAC INSIDE IT IS AN ENGINE COLLISION.
    This is the non-vacuity statement the restricted message space buys; see
    `Umbra_Canonical.MG_of_in_range_collision_is_engine_collision`. *)
Theorem msg_space_collision_is_engine_collision :
  forall (mb : byteseam_t) (kb : slice u8) (m m' : nat),
    (m < MSGBn)%nat -> (m' < MSGBn)%nat -> m <> m' ->
    MG_of mb kb m = MG_of mb kb m' ->
    exists b b' : list Z,
      b <> b' /\ length b = 91%nat /\ length b' = 91%nat /\
      Z.to_nat (mb (kbytes kb) b) = Z.to_nat (mb (kbytes kb) b').
Proof.
  intros mb kb m m' Hm Hm' Hne Heq.
  apply (MG_of_in_range_collision_is_engine_collision mb kb m m');
    [ apply lt_MSGBn_in_range | apply lt_MSGBn_in_range | | ]; assumption.
Qed.

(* ===================================================================== *)
(* AND WHAT IT DOES NOT BUY — THE COUNTEREXAMPLE, AT THE GAME'S BOUND     *)
(*                                                                        *)
(* `Umbra_Canonical`'s dead-zone section, restated at `MSGBn` so that the  *)
(* statements are literally about the message space `Umbra_RealGame`'s     *)
(* `MSGB` instantiates. The reading is: restricting the message space to   *)
(* `[0, 257^76)` removed the periodicity collision and did NOT make the    *)
(* bound non-vacuous, because `257^76` is still the wrong set. The         *)
(* byte-valid subimage is `256^76`; on the remaining 25.64 % — the         *)
(* messages whose base-257 expansion uses the sentinel digit 256 —         *)
(* `ByteSeam` constrains the seam function nowhere, and the two theorems   *)
(* below exhibit seams that satisfy the premise, agree with the real       *)
(* engine at every genuine byte list, and lose the game outright.          *)
(* ===================================================================== *)

Theorem restricted_space_still_admits_a_broken_seam_at_MSGBn :
  forall (macf : slice u8 -> array u8 91%usize -> array u8 32%usize)
         (mb0 : byteseam_t),
    ByteSeam macf mb0 ->
    exists mb : byteseam_t,
      ByteSeam macf mb
      /\ (forall kb b, allbytes b = true -> mb kb b = mb0 kb b)
      /\ exists m m' : nat,
           (m < MSGBn)%nat /\ (m' < MSGBn)%nat /\ m <> m'
           /\ forall kb : slice u8, MG_of mb kb m = MG_of mb kb m'.
Proof.
  intros macf mb0 Hbs.
  destruct (restricted_space_still_admits_a_broken_seam macf mb0 Hbs)
    as [mb [Hmb [Hagree [m [m' [Hm [Hm' [Hne Hcol]]]]]]]].
  exists mb. split; [ exact Hmb | split; [ exact Hagree |]].
  exists m, m'. split; [| split; [| split ]].
  - apply in_range_lt_MSGBn. exact Hm.
  - apply in_range_lt_MSGBn. exact Hm'.
  - exact Hne.
  - exact Hcol.
Qed.

(** The dead-zone message `256` is itself inside the game's message space, so
    the signing query the attack needs is one the restricted game accepts. *)
Lemma dead_witness_in_msg_space : (256 < MSGBn)%nat.
Proof.
  apply in_range_lt_MSGBn.
  assert (Hz : Z.of_nat 256 = 256) by reflexivity. rewrite Hz.
  apply (small_lt_pow257_76 256). lia.
Qed.

Theorem dead_zone_collides_with_any_live_message_at_MSGBn :
  forall (macf : slice u8 -> array u8 91%usize -> array u8 32%usize)
         (mb0 : byteseam_t) (m0 : nat),
    ByteSeam macf mb0 ->
    (m0 < MSGBn)%nat ->
    allbytes (canon91_of_nat m0) = true ->
    exists mb : byteseam_t,
      ByteSeam macf mb
      /\ (forall kb b, allbytes b = true -> mb kb b = mb0 kb b)
      /\ (256 < MSGBn)%nat
      /\ forall kb : slice u8, MG_of mb kb 256 = MG_of mb kb m0.
Proof.
  intros macf mb0 m0 Hbs _ Hlive.
  destruct (dead_zone_collides_with_any_live_message macf mb0 m0 Hbs Hlive)
    as [mb [Hmb [Hagree Hcol]]].
  exists mb. split; [ exact Hmb | split; [ exact Hagree | split ]].
  - exact dead_witness_in_msg_space.
  - exact Hcol.
Qed.

(* ===================================================================== *)
(* THE FIX: THE GAME'S MESSAGE INDEX, AT THE BYTE-VALID SUBIMAGE          *)
(*                                                                        *)
(* `Umbra_ByteSpace` supplies `spread` and `shrink`. What is missing to    *)
(* index the game by `256^76` instead of `257^76` is the wire side: an     *)
(* index reader `widx` that is TOTAL on all submissions, lands in the new  *)
(* space unconditionally, and agrees with `wmsg` through `spread`          *)
(* whenever the package passes the key-free structural guards. The last    *)
(* is the only one with content, and it comes from the guards themselves:  *)
(* `wstruct_ok` forces a length of at least 112 bytes, so every read the   *)
(* encoding performs — `[4,32)` and `[32,80)` — is IN BOUNDS and returns   *)
(* a genuine byte rather than `rdS`'s sentinel.                            *)
(* ===================================================================== *)

(** An in-bounds wire read is a genuine byte. The sentinel branch of `rdS` is
    unreachable below the package length. *)
Lemma wire_read_is_a_byte : forall (p : list nat) (i : Z),
  112 <= wlen p -> 0 <= i < 112 -> 0 <= rdS (wire p) i <= 255.
Proof.
  intros p i Hlen Hi. unfold rdS.
  assert (Hmax : 0 <= i <= usize_max).
  { pose proof usize_max_bound as Hb. unfold u32_max in Hb. lia. }
  destruct (slice_index_usize_ok (wire p) (uz i)) as [v Hv].
  { rewrite (to_Z_uz i Hmax). unfold wlen in Hlen. lia. }
  rewrite Hv. apply u8_to_Z_range.
Qed.

(** The two windows of `msg_of_pkg`, recovered from the integer — the slice
    counterpart of `Update_Encoding.msg_of_pre_windows`. *)
Lemma msg_of_pkg_windows : forall pkg : slice u8,
  msg_of_pkg pkg mod 257 ^ 28 = enc_from (rdS pkg) 4 28
  /\ msg_of_pkg pkg / 257 ^ 28 = enc_from (rdS pkg) 32 48.
Proof.
  intro pkg.
  pose proof (enc_from_bound 28 (rdS pkg) 4 (fun j _ => rdS_digit pkg (4 + j)))
    as B1.
  replace (Z.of_nat 28) with 28 in B1 by reflexivity.
  assert (HM : 0 < 257 ^ 28) by (apply pow257_pos; lia).
  unfold msg_of_pkg. split.
  - rewrite (Z.mul_comm (257 ^ 28)), Z.mod_add by lia. apply Z.mod_small. lia.
  - rewrite (Z.mul_comm (257 ^ 28)), Z.div_add by lia.
    rewrite (Z.div_small (enc_from (rdS pkg) 4 28)) by lia. lia.
Qed.

(** EVERY DIGIT OF AN ACCEPTED PACKAGE'S MESSAGE IS A BYTE. This is what makes
    `256^76` the right index set rather than a convenient one: the messages the
    device can actually be made to authenticate all lie in the subimage. *)
Theorem wstruct_ok_msg_is_byte_valid : forall en p : list nat,
  wstruct_ok en p = true ->
  forall t, 0 <= t < 76 -> dig (msg_of_pkg (wire p)) t <= 255.
Proof.
  intros en p Hok t Ht.
  assert (Hlen : 112 <= wlen p).
  { unfold wstruct_ok in Hok. rewrite !andb_true_iff in Hok.
    destruct Hok as [[[[H1 _] _] _] _]. apply Z.leb_le in H1. exact H1. }
  destruct (msg_of_pkg_windows (wire p)) as [Hlo Hhi].
  destruct (Z.ltb_spec t 28) as [Hc | Hc].
  - rewrite <- (dig_of_low_window (msg_of_pkg (wire p)) t ltac:(lia)).
    rewrite Hlo.
    assert (Hb : forall i, 0 <= i < Z.of_nat 28 ->
                   0 <= rdS (wire p) (4 + i) <= 256).
    { intros i _. pose proof (rdS_digit (wire p) (4 + i)). lia. }
    rewrite (enc_from_digits 28 (rdS (wire p)) 4 Hb t
               ltac:(replace (Z.of_nat 28) with 28 by reflexivity; lia)).
    pose proof (wire_read_is_a_byte p (4 + t) Hlen ltac:(lia)). lia.
  - assert (Heq : dig (msg_of_pkg (wire p)) t
                  = dig (msg_of_pkg (wire p) / 257 ^ 28) (t - 28)).
    { rewrite (dig_of_high_window (msg_of_pkg (wire p)) (t - 28) ltac:(lia)).
      f_equal. lia. }
    rewrite Heq, Hhi.
    assert (Hb : forall i, 0 <= i < Z.of_nat 48 ->
                   0 <= rdS (wire p) (32 + i) <= 256).
    { intros i _. pose proof (rdS_digit (wire p) (32 + i)). lia. }
    rewrite (enc_from_digits 48 (rdS (wire p)) 32 Hb (t - 28)
               ltac:(replace (Z.of_nat 48) with 48 by reflexivity; lia)).
    pose proof (wire_read_is_a_byte p (32 + (t - 28)) Hlen ltac:(lia)). lia.
Qed.

(** THE GAME'S MESSAGE INDEX. Total, so `dsubmit` still takes an arbitrary
    `list nat`; the clamp inside `shrink` fires only on packages the structural
    guards already reject. *)
Definition widx (p : list nat) : nat := Z.to_nat (shrink (msg_of_pkg (wire p))).

(** The size of the byte-valid message space, as a `nat`. Never evaluated, for
    the same reason `MSGBn` is not. *)
Definition MSGB256n : nat := Z.to_nat (256 ^ 76).

Lemma pow256_76_nonneg : (0 <= 256 ^ 76)%Z.
Proof. apply Z.pow_nonneg; discriminate. Qed.

Lemma MSGB256n_pos : (0 < MSGB256n)%nat.
Proof.
  exact (toNat_pos (256 ^ 76) pow256_76_nonneg (pow256_pos 76 ltac:(lia))).
Qed.

(** THE SIDE-CONDITION, DISCHARGED UNCONDITIONALLY. `shrink` lands in the new
    space by construction, so — unlike the `257^76` indexing — this needs no
    fact about the package at all. *)
Lemma widx_lt_MSGB256n : forall p : list nat, (widx p < MSGB256n)%nat.
Proof.
  intro p. unfold widx, MSGB256n.
  apply (proj2 (lt_toNat_iff (256 ^ 76) pow256_76_nonneg _)).
  rewrite Z2Nat.id by apply shrink_range. apply shrink_range.
Qed.

(** AND ON ACCEPTED PACKAGES THE INDEX IS FAITHFUL: re-spreading it returns the
    message the device actually authenticates. *)
Theorem widx_spreads_back : forall en p : list nat,
  wstruct_ok en p = true -> spread_idx (widx p) = wmsg p.
Proof.
  intros en p Hok. unfold spread_idx, widx, wmsg.
  rewrite Z2Nat.id by apply shrink_range.
  f_equal. apply spread_shrink.
  - split; [ apply msg_of_pkg_nonneg | apply msg_of_pkg_lt ].
  - intros i Hi. exact (wstruct_ok_msg_is_byte_valid en p Hok i Hi).
Qed.

(* --------------------------------------------------------------------- *)
(* THE NEW SPACE'S PROPERTIES, IN THE FORM THE GAME TIER CAN QUOTE        *)
(* --------------------------------------------------------------------- *)

Lemma lt_MSGB256n_in_range : forall m : nat,
  (m < MSGB256n)%nat -> (Z.of_nat m < 256 ^ 76)%Z.
Proof.
  intro m. exact (proj1 (lt_toNat_iff (256 ^ 76) pow256_76_nonneg m)).
Qed.

(** DISTINCT MESSAGES OF THE NEW SPACE HAVE DISTINCT PREIMAGES — the
    non-vacuity statement, unchanged in force from the `257^76` indexing. *)
Theorem msg_space256_preimages_distinct : forall m m' : nat,
  (m < MSGB256n)%nat -> (m' < MSGB256n)%nat -> m <> m' ->
  canon91_of_idx m <> canon91_of_idx m'.
Proof.
  intros m m' Hm Hm' Hne.
  apply canon91_of_idx_injective;
    [ apply lt_MSGB256n_in_range | apply lt_MSGB256n_in_range | ]; assumption.
Qed.

(** AND — THIS IS WHAT THE RE-INDEXING ADDS — THOSE PREIMAGES ARE GENUINE BYTE
    VECTORS, at EVERY message of the space, with no side-condition. On the
    `257^76` indexing this was false on 25.64 % of the space, which is exactly
    what `restricted_space_still_admits_a_broken_seam_at_MSGBn` exploits. *)
Theorem msg_space256_preimages_are_bytes : forall m : nat,
  allbytes (canon91_of_idx m) = true.
Proof. intro m. apply canon91_of_idx_allbytes. Qed.

(** THE COUNTEREXAMPLE IS REFUTED ON THE NEW SPACE, not merely unbuilt. Under
    `ArrayVectors` — every 91-byte vector is some array's read-sequence, true of
    Rust and unprovable against a bare `array_index_usize` — any two seams the
    premise admits give the SAME pinned MAC at every message of the space.
    There is no `mb` to patch. *)
Theorem msg_space256_pins_the_seam :
  ArrayVectors ->
  forall (macf : macf_t) (mb mb' : byteseam_t),
    ByteSeam macf mb -> ByteSeam macf mb' ->
    forall (kb : slice u8) (m : nat), MG_spread mb kb m = MG_spread mb' kb m.
Proof.
  intros HAV macf mb mb' Hbs Hbs' kb m.
  exact (MG_spread_is_determined HAV macf mb mb' Hbs Hbs' kb m).
Qed.

(** AND EVERY COLLISION INSIDE IT IS A COLLISION OF THE SEAM AT TWO DISTINCT
    REAL BYTE VECTORS, byte-validity of both preimages included.

    THE NAME IS DELIBERATELY NOT "engine collision". This statement carries no
    premise, and without one its conclusion is about `mb` — the abstract seam —
    not about `macf`, the device's HMAC. The two are identified only on the
    image of `bytes91`, so reading this as a collision OF THE ENGINE, i.e. as
    the event an EUF-CMA assumption on HMAC-SHA256 bounds, additionally needs
    `ArrayVectors` (every 91-byte list is some array's read-sequence) together
    with `ByteSeam macf mb`. Under those two the reading is exact: the `b`, `b'`
    produced here are `bytes91` of real arrays and `mb (kbytes kb)` on them is
    literally `tag_of_arr (macf kb _)`. `Umbra_ArrayVectors` proves that premise
    both satisfiable and necessary. *)
Theorem msg_space256_collision_is_seam_collision_at_byte_vectors :
  forall (mb : byteseam_t) (kb : slice u8) (m m' : nat),
    (m < MSGB256n)%nat -> (m' < MSGB256n)%nat -> m <> m' ->
    MG_spread mb kb m = MG_spread mb kb m' ->
    exists b b' : list Z,
      b <> b' /\ length b = 91%nat /\ length b' = 91%nat /\
      allbytes b = true /\ allbytes b' = true /\
      Z.to_nat (mb (kbytes kb) b) = Z.to_nat (mb (kbytes kb) b').
Proof.
  intros mb kb m m' Hm Hm' Hne Heq.
  apply (MG_spread_collision_is_engine_collision mb kb m m');
    [ apply lt_MSGB256n_in_range | apply lt_MSGB256n_in_range | | ]; assumption.
Qed.

(** THE COUNTEREXAMPLE, REFUTED RATHER THAN AVOIDED. On the `257^76` indexing,
    `restricted_space_still_admits_a_broken_seam_at_MSGBn` builds a conforming
    seam that collides the pinned MAC where the original does not. Under
    `ArrayVectors` no such pair exists on the byte-valid space: every collision
    of a patched seam is already a collision of the one it was patched from, so
    there is no advantage to be gained by choosing the seam. *)
Theorem patching_cannot_create_a_collision_at_MSGB256n :
  ArrayVectors ->
  forall (macf : macf_t) (mb mb0 : byteseam_t),
    ByteSeam macf mb -> ByteSeam macf mb0 ->
    forall (kb : slice u8) (m m' : nat),
      MG_spread mb kb m = MG_spread mb kb m' ->
      MG_spread mb0 kb m = MG_spread mb0 kb m'.
Proof.
  intros HAV macf mb mb0 Hbs Hbs0 kb m m' Heq.
  rewrite <- (msg_space256_pins_the_seam HAV macf mb mb0 Hbs Hbs0 kb m).
  rewrite <- (msg_space256_pins_the_seam HAV macf mb mb0 Hbs Hbs0 kb m').
  exact Heq.
Qed.
