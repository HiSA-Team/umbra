(** THE DEVICE LINK — real acceptance implies the game's win condition.

    This is the joint between the two halves of the crypto layer. On one side,
    `Update_Encoding.accept_encodes` (Qed) says that on acceptance the DEVICE'S
    preimage and tag encode to the integers a key-less party reads off the WIRE.
    On the other, `Umbra_Reduction`'s UPD game declares a submitted package a
    win when `tag_of_pkg p = MAC k (msg_of_pkg p)`. This file proves that the
    former implies the latter — so every package the real device accepts is a
    UPD-game win, and the UPD game is a RELAXATION of the real device rather
    than a different problem.

    IT DELIBERATELY DOES NOT IMPORT SSProve. The abstract MAC is taken over an
    arbitrary key type `K`, so this file builds with a bare Coq 8.18 and stays
    in the mathcomp-free tier. `K` is instantiated at SSProve's `Key n` where
    the bound is quoted, and nothing about that instantiation is used here.

    THE ONE NEW ASSUMPTION IS `Hfactor` (C1e), and it is stated only for
    ASSEMBLED preimages. See its comment below: the guard is not a convenience,
    it is what keeps the hypothesis satisfiable at a real HMAC seam. C1e is a
    modelling artefact of Aeneas's opaque arrays, not a cryptographic claim.
    Since the canonical-realiser revision it is not merely satisfiable but
    satisfied by a COMPUTED witness (`Umbra_Canonical.MG_of`), so the abstract
    MAC on the right-hand side of the crypto bound is the device's own seam and
    not an arbitrary function agreeing with it on part of its domain. *)

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
Require Import Update_Crypto.
Require Import Update_Forgery.
Require Import Update_Encoding.
Require Import Umbra_Canonical.
Local Open Scope Z_scope.
Local Open Scope Primitives_scope.

Section DeviceLink.

(* ---- the device, exactly as in Update_Crypto ---- *)
Context {HS : Type}.
Variable inst : PkgHmac_t HS.
Variable hs   : HS.
Variable key  : slice u8.
Variable macf : slice u8 -> array u8 91%usize -> array u8 32%usize.

(** C1 — the seam is a deterministic keyed function. Inherited verbatim; it
    carries no unforgeability (the constant function satisfies it). *)
Hypothesis Hseam :
  forall k p, inst.(PkgHmac_t_hmac_pkg) hs k p = Ok (macf k p).

(* ---- the abstract MAC of the game, over an arbitrary key type ---- *)
Context (K : Type).
Variable MACg : K -> nat -> nat.
Variable k0 : K.

(** C1e — THE SEAM FACTORS THROUGH THE BYTE ENCODING, ON ASSEMBLED PREIMAGES.

    `macf key pre` is a function of an Aeneas `array u8 91`, an opaque sigma
    type. `MACg k0` is a function of the integer that `msg_of_pre` reads out of
    that array. C1e says the two agree — equivalently, that the seam's output
    depends on nothing but the byte VALUES of its input, and that the device's
    provisioned key corresponds to the game key `k0`.

    WHY THIS IS NOT A CRYPTOGRAPHIC ASSUMPTION. It says nothing about hardness,
    randomness or collisions; the constant function satisfies it just as it
    satisfies C1. It is needed purely because Aeneas gives no extensionality
    for arrays: two arrays with identical bytes are not provably equal terms
    (u8 is a sigma type over a `Prop`, so that would need proof irrelevance —
    see the note in Update_Auth.v), and therefore `macf` cannot be shown to
    respect byte equality from the inside. Any real HMAC engine reads bytes.

    WHY THE `AssemblesF` GUARD IS LOAD-BEARING, AND WHY REMOVING IT WOULD MAKE
    C1e FALSE. `msg_of_pre` reads offsets [15,91) ONLY — the 15-byte domain-
    separation label at [0,15) is never read. So the left-hand side is a
    function of the 76-byte core alone. Stated over ALL 91-byte preimages, C1e
    would therefore FORCE `macf key` to return the same tag for two preimages
    that share a core but carry different labels:

      forall p q, (forall i, 15 <= i < 91 -> rdA p i = rdA q i) ->
        tag_of_arr (macf key p) = tag_of_arr (macf key q)

    which is a direct consequence of the unguarded form and which HMAC-SHA256
    does not satisfy. Universal quantification here makes the hypothesis
    STRONGER and FALSE, not safer: no choice of `MACg`/`k0` could satisfy it at
    a real seam, and a false hypothesis proves anything.

    The guard removes exactly that. `Assembles` clause 1 (Update_Crypto.v) pins
    `pre[0,15)` to the CONSTANT `pKG_TAG_LABEL`, so any two assembled preimages
    already agree on the label; the label carries no varying information, and
    the core determines all 91 bytes. Restricting to assembled preimages is
    therefore not a weakening of what the device does — every preimage the
    device ever hashes is assembled (`compute_pkg_tag_assembles`, Qed) — while
    it IS what makes C1e satisfiable by a real HMAC: for assembled preimages
    the pairs (msg_of_pre pre, tag_of_arr (macf key pre)) form a FUNCTIONAL
    relation, so some `MACg k0` realising them exists.

    Both halves of that argument are machine-checked at the end of this file:
    `unguarded_C1e_forces_label_obliviousness` (the guard is NECESSARY),
    `restricted_C1e_is_functional` (with the guard the relation is a FUNCTION)
    and `restricted_C1e_is_realisable` (so a `MACg` satisfying C1e EXISTS —
    and, since this revision, is COMPUTED from the seam by
    `Umbra_Canonical.MG_of` rather than chosen classically). No theorem in this
    file uses a classical axiom; see the axiom budget in README.md. *)
Hypothesis Hfactor :
  forall (pre : array u8 91%usize) (f : Fields),
    AssemblesF pre f ->
    MACg k0 (Z.to_nat (msg_of_pre pre))
    = Z.to_nat (tag_of_arr (macf key pre)).

(** THE LINK. Whatever the device accepts is a valid message/tag pair for the
    abstract MAC, at the wire level — computable by anyone holding the package
    and no key. This is the event the UPD game's `submit` oracle tests. *)
Theorem device_accept_implies_submit_true :
  forall (pkg : slice u8) (en : array u8 16%usize) r,
    parse_and_verify inst pkg en hs key = Ok (Core_result_Result_Ok r) ->
    Z.to_nat (tag_of_pkg pkg) = MACg k0 (Z.to_nat (msg_of_pkg pkg)).
Proof.
  intros pkg en r Hacc.
  destruct (accept_encodes inst hs key macf Hseam pkg en r Hacc)
    as [f [pre [t [HA [Ht [_ [_ [Hm Htg]]]]]]]].
  rewrite <- Hm, <- Htg, Ht.
  symmetry. exact (Hfactor pre f HA).
Qed.

(** … and the fields it authenticates are pinned. Restating, at the point where
    the crypto bound is quoted, what the encoded message MEANS: by
    `Update_Forgery.assemble_injective` two packages whose 76-byte cores agree
    have the same nonce, author_id, version, blob_len and header bytes. So
    "the device never signed this core" and "the device never signed these
    fields" are the same statement. *)
Theorem accepted_core_determines_fields :
  forall (pkg : slice u8) (en : array u8 16%usize) r,
    parse_and_verify inst pkg en hs key = Ok (Core_result_Result_Ok r) ->
    exists (f : Fields) (pre : array u8 91%usize),
      AssemblesF pre f
      /\ msg_of_pre pre = msg_of_pkg pkg
      /\ f.(fld_author)  = r.(verifiedUpdate_author_id)
      /\ f.(fld_version) = r.(verifiedUpdate_version)
      /\ (forall (g : Fields) (q : array u8 91%usize),
            AssemblesF q g -> ByteEq pre q -> FieldsEq f g).
Proof.
  intros pkg en r Hacc.
  destruct (accept_encodes inst hs key macf Hseam pkg en r Hacc)
    as [f [pre [t [HA [_ [Ha [Hv [Hm _]]]]]]]].
  exists f, pre.
  split; [ exact HA |]. split; [ exact Hm |].
  split; [ exact Ha |]. split; [ exact Hv |].
  intros g q HAq Hbe.
  apply (assemble_injective pre q _ g); [ exact HA | exact HAq | exact Hbe ].
Qed.

(** … and the fields are pinned by the ENCODED MESSAGE, not only by byte
    agreement. This is the version the game needs: its query set stores plain
    integers, so the hypothesis available at the game level is an equation in
    `Z`, never `ByteEq`. `accepted_core_determines_fields` above cannot be used
    for that — it takes `ByteEq` as a premise. `msg_determines_fields` derives
    field agreement from the integer alone, at read granularity (see the header
    of Update_Encoding.v for why `ByteEq` is unobtainable from an integer
    equation without proof irrelevance). *)
Theorem accepted_msg_determines_fields :
  forall (pkg : slice u8) (en : array u8 16%usize) r,
    parse_and_verify inst pkg en hs key = Ok (Core_result_Result_Ok r) ->
    exists (f : Fields) (pre : array u8 91%usize),
      AssemblesF pre f
      /\ msg_of_pre pre = msg_of_pkg pkg
      /\ f.(fld_author)  = r.(verifiedUpdate_author_id)
      /\ f.(fld_version) = r.(verifiedUpdate_version)
      /\ (forall (g : Fields) (q : array u8 91%usize),
            AssemblesF q g -> msg_of_pre q = msg_of_pkg pkg -> FieldsEqR f g).
Proof.
  intros pkg en r Hacc.
  destruct (accept_encodes inst hs key macf Hseam pkg en r Hacc)
    as [f [pre [t [HA [_ [Ha [Hv [Hm _]]]]]]]].
  exists f, pre.
  split; [ exact HA |]. split; [ exact Hm |].
  split; [ exact Ha |]. split; [ exact Hv |].
  intros g q HAq Hmq.
  apply (msg_determines_fields pre q f g HA HAq).
  rewrite Hm, Hmq. reflexivity.
Qed.

(* ===================================================================== *)
(* WHY THE GUARD ON C1e IS BOTH NECESSARY AND SUFFICIENT                  *)
(*                                                                        *)
(* These two theorems are the machine-checked version of the argument in   *)
(* the C1e comment above. Neither is used by anything; they exist so the   *)
(* justification for the shape of the hypothesis is checked rather than    *)
(* asserted.                                                              *)
(* ===================================================================== *)

(** NECESSARY. Had C1e been stated over ALL 91-byte preimages — as an earlier
    revision of this file did — it would have FORCED the seam to ignore the
    15-byte domain-separation label, because `msg_of_pre` never reads it. That
    is a property HMAC-SHA256 does not have, so the unguarded hypothesis is not
    merely strong: at a real seam it is FALSE, and a false hypothesis proves
    anything. Note that this theorem needs no assumption about `macf` at all —
    the obligation is forced by the shape of the statement alone. *)
Theorem unguarded_C1e_forces_label_obliviousness :
  forall MG : nat -> nat,
    (forall pre : array u8 91%usize,
       MG (Z.to_nat (msg_of_pre pre)) = Z.to_nat (tag_of_arr (macf key pre))) ->
    forall p q : array u8 91%usize,
      (forall i, 15 <= i < 91 -> rdA p i = rdA q i) ->
      Z.to_nat (tag_of_arr (macf key p)) = Z.to_nat (tag_of_arr (macf key q)).
Proof.
  intros MG Hall p q Hcore.
  assert (Hmsg : msg_of_pre p = msg_of_pre q).
  { unfold msg_of_pre. f_equal.
    - apply (enc_from_shift 28 (rdA p) (rdA q) 15 15).
      intros i Hi. cbn in Hi. apply Hcore. lia.
    - f_equal. apply (enc_from_shift 48 (rdA p) (rdA q) 43 43).
      intros i Hi. cbn in Hi. apply Hcore. lia. }
  rewrite <- (Hall p), <- (Hall q), Hmsg. reflexivity.
Qed.

(** SUFFICIENT. With the guard, the relation C1e constrains is a FUNCTION of
    `msg_of_pre pre`, so some `MACg k0` realising it exists. The only premise
    is that the seam reads its input as bytes — which is what C1e was supposed
    to say in the first place, and which every HMAC engine satisfies. The work
    is done by `assembled_msg_determines_all_bytes`: the encoded core pins the
    76 core bytes (base-257 injectivity) and `Assembles` clause 1 pins the 15
    label bytes to the constant `pKG_TAG_LABEL`, so all 91 agree. *)
Theorem restricted_C1e_is_functional :
  (forall p q : array u8 91%usize,
     (forall i, 0 <= i < 91 -> rdA p i = rdA q i) ->
     tag_of_arr (macf key p) = tag_of_arr (macf key q)) ->
  forall (p q : array u8 91%usize) (f g : Fields),
    AssemblesF p f -> AssemblesF q g ->
    msg_of_pre p = msg_of_pre q ->
    tag_of_arr (macf key p) = tag_of_arr (macf key q).
Proof.
  intros Hreads p q f g HA HB Heq.
  apply Hreads.
  exact (assembled_msg_determines_all_bytes p q f g HA HB Heq).
Qed.

(** SUFFICIENT, CONCLUDED — AND NOW COMPUTED RATHER THAN CHOSEN.
    `restricted_C1e_is_functional` proves the relation is a function; it never
    produces a `MACg`. An earlier revision took the remaining step with
    `ClassicalEpsilon`, and that was the wrong instrument: a chosen `MG` is
    unconstrained OFF the image of the encoding, so an unforgeability assumption
    on the seam says nothing about it, and the right-hand side of the crypto
    bound could not be read as an HMAC advantage.

    It is now `Umbra_Canonical.MG_of` — the seam applied to the CANONICAL byte
    decoding of the message — proved to satisfy C1e by
    `Umbra_Canonical.MG_of_satisfies_C1e`, with no classical axiom anywhere.
    This theorem is that result, restated in this file's section variables. The
    premise is `ByteSeam`: the seam is a FUNCTION of the key bytes and the 91
    preimage bytes, which is the constructive content of the old `Hreads`
    (`Umbra_Canonical.ByteSeam_reads` derives `Hreads` from it). *)
Theorem restricted_C1e_is_realisable :
  forall mb : byteseam_t,
    ByteSeam macf mb ->
    exists MG : nat -> nat,
      forall (pre : array u8 91%usize) (f : Fields),
        AssemblesF pre f ->
        MG (Z.to_nat (msg_of_pre pre)) = Z.to_nat (tag_of_arr (macf key pre)).
Proof.
  intros mb Hbs. exists (MG_of mb key).
  intros pre f HA. exact (MG_of_satisfies_C1e macf mb Hbs key pre f HA).
Qed.

(* ===================================================================== *)
(* THE FRESHNESS SEAM (C2) — NAMED, NOT CLOSED                            *)
(*                                                                        *)
(* WHY THIS SECTION EXISTS. Freshness is the half of EUF-CMA that says the *)
(* forged message was never QUERIED, and until now it was not connected to *)
(* anything at all. `Update_Forgery.accept_off_query_set_is_fresh_forgery` *)
(* parameterises over an abstract `Q : list Fields`, and NOTHING anywhere  *)
(* relates `Q` to the game's `S_loc`. There is no extracted signing        *)
(* function on the Aeneas side — the update-core crate contains the        *)
(* DEVICE's parser, not the VENDOR's signer — so there is no Coq object to *)
(* walk in order to prove the correspondence, and none is proved here.     *)
(*                                                                        *)
(* WHAT IS DONE INSTEAD. The correspondence is stated as ONE named         *)
(* hypothesis, C2, and the consequence that the crypto layer actually      *)
(* needs is derived from it. That converts an invisible gap into a visible  *)
(* one; it does not close it. C2 is the assumption that the vendor's        *)
(* signing service tags exactly what it says it tags — i.e. that the        *)
(* integers the game accumulates in `S_loc` are precisely the encodings of  *)
(* the packages the vendor signed. It is a statement about a component that *)
(* IS NOT VERIFIED AND NOT EVEN EXTRACTED. A reviewer should treat it as    *)
(* one of the two open seams of this development, alongside the unlifted    *)
(* probability step in README.md.                                          *)
(* ===================================================================== *)

Section FreshnessSeam.

(** `Q` — the field tuples the vendor was asked to sign. `Sloc` — the game's
    query set, as the membership predicate on the integers the game stores. *)
Variable Q : list Fields.
Variable Sloc : nat -> Prop.

(** C2a — everything the vendor signs lands in the query set. Used by
    `accept_of_signed_fields_is_in_query_set` below and by NOTHING else; in
    particular it is NOT used by the freshness theorem, whose section-closed
    type does not mention it. See that theorem's comment for why it is
    nonetheless kept. *)
Hypothesis Hsign_complete :
  forall (g : Fields) (q : array u8 91%usize),
    In g Q -> AssemblesF q g -> Sloc (Z.to_nat (msg_of_pre q)).

(** C2b — and nothing else does: every integer in the query set is the
    encoding of an assembled preimage of some tuple the vendor signed. This is
    the direction the security argument uses, and the ONLY one of the two that
    the freshness theorem below depends on. *)
Hypothesis Hsign_sound :
  forall m : nat, Sloc m ->
    exists (g : Fields) (q : array u8 91%usize),
      In g Q /\ AssemblesF q g /\ m = Z.to_nat (msg_of_pre q).

(** THE CONSEQUENCE. If the device accepts a package whose five fields are not
    (`FieldsEqR`-)among the tuples the vendor signed, then the integer the game
    would test is NOT in the query set — so the accepted package is a FRESH
    valid pair, which is what an EUF-CMA challenger requires on top of the
    validity already given by `device_accept_implies_submit_true`.

    Note where the strength comes from: `msg_determines_fields` (encoding
    injectivity) is what makes "not among the signed tuples" imply "not among
    the signed integers". Without it this theorem would not be provable, which
    is the concrete reason the injectivity work was needed.

    IT USES C2b ONLY. Coq generalises a closed section theorem over exactly the
    section hypotheses its proof used, and `Check` on the closed type of this
    one shows `Hsign_sound` and no `Hsign_complete`. That is not an oversight:
    freshness is the claim that nothing OUTSIDE the signed set is in `Sloc`,
    which is C2b's direction. C2a is discharged separately, below. *)
Theorem accept_of_unsigned_fields_is_off_query_set :
  forall (pkg : slice u8) (en : array u8 16%usize) r,
    parse_and_verify inst pkg en hs key = Ok (Core_result_Result_Ok r) ->
    exists f : Fields,
      f.(fld_author)  = r.(verifiedUpdate_author_id)
      /\ f.(fld_version) = r.(verifiedUpdate_version)
      /\ ((forall g, In g Q -> ~ FieldsEqR f g) ->
          ~ Sloc (Z.to_nat (msg_of_pkg pkg))).
Proof.
  intros pkg en r Hacc.
  destruct (accept_encodes inst hs key macf Hseam pkg en r Hacc)
    as [f [pre [t [HA [_ [Ha [Hv [Hm _]]]]]]]].
  exists f. split; [ exact Ha |]. split; [ exact Hv |].
  intros Hunsigned Hin.
  destruct (Hsign_sound _ Hin) as [g [q [HgQ [HAq Hmq]]]].
  apply (Hunsigned g HgQ).
  apply (msg_determines_fields pre q f g HA HAq).
  rewrite Hm. apply Z2Nat.inj.
  - apply msg_of_pkg_nonneg.
  - apply msg_of_pre_nonneg.
  - exact Hmq.
Qed.

(** WHERE C2a IS USED, AND WHY IT IS WORTH KEEPING. C2b alone is satisfied
    VACUOUSLY by `Sloc := fun _ => False`, and under that reading the theorem
    above is true and empty: every accepted package would be "fresh" because the
    query set is empty. C2a is what forbids that reading — it forces the query
    set to contain the encoding of everything the vendor actually signed — and
    this theorem is the only place the force is applied. The two hypotheses
    together say `Sloc` is EXACTLY the encodings of `Q`: C2a that it is no
    smaller, C2b that it is no larger. Only the second is needed to conclude
    freshness; the first is needed for that conclusion to mean anything. *)
Theorem accept_of_signed_fields_is_in_query_set :
  forall (pkg : slice u8) (en : array u8 16%usize) r,
    parse_and_verify inst pkg en hs key = Ok (Core_result_Result_Ok r) ->
    exists f : Fields,
      f.(fld_author)  = r.(verifiedUpdate_author_id)
      /\ f.(fld_version) = r.(verifiedUpdate_version)
      /\ (In f Q -> Sloc (Z.to_nat (msg_of_pkg pkg))).
Proof.
  intros pkg en r Hacc.
  destruct (accept_encodes inst hs key macf Hseam pkg en r Hacc)
    as [f [pre [t [HA [_ [Ha [Hv [Hm _]]]]]]]].
  exists f. split; [ exact Ha |]. split; [ exact Hv |].
  intros HinQ. rewrite <- Hm. exact (Hsign_complete f pre HinQ HA).
Qed.

(** THE WIN CONDITION, IN ONE STATEMENT. An EUF-CMA challenger accepts a forgery
    when it is BOTH valid (the tag really is the MAC of the message) AND fresh
    (the message was never queried). Until this revision those two halves lived
    in two theorems that shared no statement — `device_accept_implies_submit_true`
    for validity, `accept_of_unsigned_fields_is_off_query_set` for freshness —
    and nothing anywhere said they hold of the SAME package at the same time.
    They do, and this is that statement: both halves are about the one integer
    `Z.to_nat (msg_of_pkg pkg)` read off the wire.

    Its closed type therefore mentions everything: `MACg`, `k0` and `Hfactor`
    from the validity side, `Q`, `Sloc` and `Hsign_sound` from the freshness
    side. That is the point — it is the first theorem in the development in
    which the two seams appear together.

    Validity does not actually need the "never signed" premise (it holds of
    every accepted package); it is stated under the premise anyway because the
    conjunction under that premise IS the game's win predicate. *)
Theorem accept_of_unsigned_fields_is_valid_and_fresh :
  forall (pkg : slice u8) (en : array u8 16%usize) r,
    parse_and_verify inst pkg en hs key = Ok (Core_result_Result_Ok r) ->
    exists f : Fields,
      f.(fld_author)  = r.(verifiedUpdate_author_id)
      /\ f.(fld_version) = r.(verifiedUpdate_version)
      /\ ((forall g, In g Q -> ~ FieldsEqR f g) ->
          Z.to_nat (tag_of_pkg pkg) = MACg k0 (Z.to_nat (msg_of_pkg pkg))
          /\ ~ Sloc (Z.to_nat (msg_of_pkg pkg))).
Proof.
  intros pkg en r Hacc.
  destruct (accept_of_unsigned_fields_is_off_query_set pkg en r Hacc)
    as [f [Ha [Hv Hfresh]]].
  exists f. split; [ exact Ha |]. split; [ exact Hv |].
  intros Hunsigned. split.
  - exact (device_accept_implies_submit_true pkg en r Hacc).
  - exact (Hfresh Hunsigned).
Qed.

End FreshnessSeam.

End DeviceLink.
