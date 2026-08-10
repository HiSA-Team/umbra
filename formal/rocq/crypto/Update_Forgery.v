(** THE REDUCTION CORE — what an accepted package gives you, in the exact shape
    an EUF-CMA reduction consumes.

    WHY THIS FILE EXISTS. The update-core development proves FUNCTIONAL facts:
    acceptance implies the compared tag equals `mac key pre` for a 91-byte
    preimage whose every byte is pinned (P2, `accept_implies_authenticated_
    fields`), and the assembly of that preimage is injective in the five
    protocol fields (`assembly_injective`). Neither statement mentions an
    adversary, and the only crypto-ish hypothesis in the whole chain — C1
    (`Hseam`) — says merely that the seam is a deterministic function of
    (key, preimage). The constant function satisfies C1. So nothing there rules
    out a forgery.

    The missing step is not another functional lemma. It is the observation that
    P2 + `assembly_injective` already hand you, from any accepted package, the
    two things an EUF-CMA challenger checks:

      (V) VALIDITY — a pair (pre, t) with t = mac key pre; and
      (F) FRESHNESS — if the package's five-field tuple differs from every tuple
          the device was asked to tag, then `pre` differs, bytewise, from every
          preimage the tagging oracle ever saw.

    (V) is P2 clause (b). (F) is the contrapositive of `assembly_injective`.
    This file states that pairing once, as a theorem, so the probabilistic layer
    (Umbra_EUFCMA.v / Umbra_Reduction.v) has a purely syntactic obligation to
    discharge and no arithmetic left to do inside a game hop.

    WHAT THIS FILE STILL DOES NOT DO. It is deterministic Coq: no distributions,
    no advantage, no adversary. It says "an accepted-but-unsigned package IS a
    valid fresh forgery"; it does not say forgeries are hard. That implication —
    "hard to forge ⇒ hard to get an unsigned package accepted" — is the
    reduction, and it needs the probabilistic layer. Read this file as the
    interface, not the result.

    ASSUMPTION BUDGET. Everything below lives in a `Section` with the same C1
    seam hypothesis as `Update_Crypto`; no new axioms, no new hypotheses. The
    quarantined array axioms of `Primitives`/`Update_Safety` are inherited
    unchanged (see ../update-core/proofs-coq/Update_Model.v for their
    consistency witness). *)

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
Local Open Scope Z_scope.
Local Open Scope Primitives_scope.

(* ===================================================================== *)
(* The protocol's message space: the five authenticated fields.           *)
(*                                                                        *)
(* This — not the 91-byte preimage — is the natural EUF-CMA message space  *)
(* for the UPDATE protocol, because it is what a signer is asked to        *)
(* authorise and what a verifier hands back. The preimage is an encoding   *)
(* detail; `assembly_injective` is exactly the statement that the encoding  *)
(* loses nothing, which is what lets a reduction move between the two.     *)
(* ===================================================================== *)

Record Fields : Type := mkFields {
  fld_nonce    : array u8 16%usize;
  fld_author   : u32;
  fld_version  : u32;
  fld_blob_len : u32;
  fld_hdr      : array u8 48%usize;
}.

(** Equality on messages, at the granularity the development can actually
    observe. `array_index_usize` is an opaque Axiom of the Aeneas Primitives
    (see AENEAS_COQ_MKARRAY_BUG.md), so two arrays are indistinguishable to
    every theorem here exactly when their in-range reads agree. Using Leibniz
    equality instead would be UNSOUND to claim: nothing in the development can
    prove or refute it for arrays built by the opaque constructors. Byte
    equality is therefore the honest notion, and it is the one
    `assembly_injective` is stated in. *)
Definition ByteEq {n : usize} (p q : array u8 n) : Prop :=
  forall j : usize, 0 <= to_Z j < to_Z n ->
    array_index_usize p j = array_index_usize q j.

Definition FieldsEq (f g : Fields) : Prop :=
  ByteEq f.(fld_nonce) g.(fld_nonce)
  /\ to_Z f.(fld_author)   = to_Z g.(fld_author)
  /\ to_Z f.(fld_version)  = to_Z g.(fld_version)
  /\ to_Z f.(fld_blob_len) = to_Z g.(fld_blob_len)
  /\ ByteEq f.(fld_hdr) g.(fld_hdr).

(** `Assembles`, packaged per-message. *)
Definition AssemblesF (pre : array u8 91%usize) (f : Fields) : Prop :=
  Assembles pre f.(fld_nonce) f.(fld_author) f.(fld_version)
                f.(fld_blob_len) f.(fld_hdr).

(* --- `FieldsEq` is an equivalence (needed to state "fresh" coherently) --- *)

Lemma ByteEq_refl : forall {n : usize} (p : array u8 n), ByteEq p p.
Proof. intros n p j _. reflexivity. Qed.

Lemma ByteEq_sym : forall {n : usize} (p q : array u8 n),
  ByteEq p q -> ByteEq q p.
Proof. intros n p q H j Hj. symmetry. exact (H j Hj). Qed.

Lemma ByteEq_trans : forall {n : usize} (p q r : array u8 n),
  ByteEq p q -> ByteEq q r -> ByteEq p r.
Proof.
  intros n p q r H1 H2 j Hj. rewrite (H1 j Hj). exact (H2 j Hj).
Qed.

Lemma FieldsEq_refl : forall f, FieldsEq f f.
Proof.
  intros f. repeat split; try reflexivity; apply ByteEq_refl.
Qed.

Lemma FieldsEq_sym : forall f g, FieldsEq f g -> FieldsEq g f.
Proof.
  intros f g [H1 [H2 [H3 [H4 H5]]]].
  repeat split; try (symmetry; assumption); apply ByteEq_sym; assumption.
Qed.

Lemma FieldsEq_trans : forall f g k, FieldsEq f g -> FieldsEq g k -> FieldsEq f k.
Proof.
  intros f g k [A1 [A2 [A3 [A4 A5]]]] [B1 [B2 [B3 [B4 B5]]]].
  repeat split;
    try (etransitivity; eassumption);
    eapply ByteEq_trans; eassumption.
Qed.

(* ===================================================================== *)
(* STEP 1 — the encoding is injective on messages.                        *)
(*                                                                        *)
(* `assembly_injective` restated over `Fields`/`FieldsEq`. Zero crypto      *)
(* hypotheses: this is arithmetic about disjoint windows of a 91-byte      *)
(* buffer, already `Qed` in Update_Crypto.                                *)
(* ===================================================================== *)

Theorem assemble_injective :
  forall (pre1 pre2 : array u8 91%usize) (f g : Fields),
    AssemblesF pre1 f -> AssemblesF pre2 g ->
    ByteEq pre1 pre2 -> FieldsEq f g.
Proof.
  intros pre1 pre2 f g HA HB Hag.
  unfold AssemblesF in HA, HB.
  assert (Hag' : forall j : usize, 0 <= to_Z j < 91 ->
            array_index_usize pre1 j = array_index_usize pre2 j).
  { intros j Hj. apply Hag. rewrite tz91. exact Hj. }
  destruct (assembly_injective pre1 pre2
              f.(fld_nonce) f.(fld_author) f.(fld_version) f.(fld_blob_len) f.(fld_hdr)
              g.(fld_nonce) g.(fld_author) g.(fld_version) g.(fld_blob_len) g.(fld_hdr)
              HA HB Hag') as [Hn [Ha [Hv [Hb Hh]]]].
  unfold FieldsEq. repeat apply conj.
  - intros j Hj. apply Hn. rewrite tz16 in Hj. exact Hj.
  - exact Ha.
  - exact Hv.
  - exact Hb.
  - intros j Hj. apply Hh. rewrite tz48 in Hj. exact Hj.
Qed.

(** The contrapositive — the form the reduction uses. Distinct messages have
    distinct preimages, so a message the tagging oracle never saw yields a
    preimage the tagging oracle never saw. *)
Corollary assemble_injective_contra :
  forall (pre1 pre2 : array u8 91%usize) (f g : Fields),
    AssemblesF pre1 f -> AssemblesF pre2 g ->
    ~ FieldsEq f g -> ~ ByteEq pre1 pre2.
Proof.
  intros pre1 pre2 f g HA HB Hne Hbe.
  exact (Hne (assemble_injective pre1 pre2 f g HA HB Hbe)).
Qed.

(* ===================================================================== *)
(* STEP 2 — from an accepted package to a (V)+(F) forgery pair.           *)
(* ===================================================================== *)

Section Reduction.

(* The device: one seam instance, one handle, one key — as in Update_Crypto. *)
Context {HS : Type}.
Variable inst : PkgHmac_t HS.
Variable h    : HS.
Variable key  : slice u8.

(* C1, verbatim: the seam is a deterministic keyed function. No more. *)
Variable mac : slice u8 -> array u8 91%usize -> array u8 32%usize.
Hypothesis Hseam :
  forall k p, inst.(PkgHmac_t_hmac_pkg) h k p = Ok (mac k p).

(** The tag the device would produce for a message. This is the MAC whose
    unforgeability the probabilistic layer assumes: `MAC(key, f)` where the
    preimage encoding is inlined. *)
Definition Tags (f : Fields) (t : array u8 32%usize) : Prop :=
  compute_pkg_tag inst f.(fld_nonce) f.(fld_author) f.(fld_version)
                       f.(fld_blob_len) f.(fld_hdr) h key = Ok t.

(** Every tag the device emits is `mac key` of the message's encoding. *)
Lemma Tags_is_mac_of_encoding :
  forall f t, Tags f t ->
    exists pre : array u8 91%usize, AssemblesF pre f /\ t = mac key pre.
Proof.
  intros f t Ht. unfold Tags in Ht.
  destruct (compute_pkg_tag_assembles inst h key
              f.(fld_nonce) f.(fld_author) f.(fld_version)
              f.(fld_blob_len) f.(fld_hdr) t Ht) as [pre [Hm HA]].
  exists pre. split; [ exact HA |].
  rewrite Hseam in Hm. injection Hm as Hm. symmetry. exact Hm.
Qed.

(** The package carries the tag `t` in its last 32 bytes. *)
Definition TagCarried (pkg : slice u8) (t : array u8 32%usize) : Prop :=
  forall i j : usize, 0 <= to_Z i < 32 ->
    to_Z j = to_Z (slice_len pkg) - 32 + to_Z i ->
    exists x y, array_index_usize t i = Ok x
             /\ slice_index_usize pkg j = Ok y
             /\ to_Z x = to_Z y.

(** THE EXTRACTION THEOREM. From any package the device accepts, read off a
    message `f`, an encoding `pre` of it, and a tag `t` such that:

      (P) `f` is pinned to what the caller and the device can see — its
          author_id and version are LITERALLY the record handed back, and its
          nonce is the ARMED nonce `en` byte for byte;
      (V) `t = mac key pre` and `pre` encodes `f`, i.e. (f, t) is a valid
          message/tag pair under the device key;
      (C) the package really carries `t` in its tag field;
      (F) `pre` collides bytewise with the encoding of another message only if
          that message equals `f`.

    (V)+(F) is precisely what an EUF-CMA challenger checks. (P) is what makes
    the freshness side-condition CHECKABLE by a reduction: the reduction knows
    `f` from the accepted package and the armed nonce, so it can decide whether
    it forwarded `f` to its tagging oracle.

    Everything is derived from `accept_implies_authenticated_fields` (P2) and
    `assembly_injective`, both `Qed` in Update_Crypto. No new hypothesis. *)
Theorem accept_yields_valid_forgery :
  forall (pkg : slice u8) (en : array u8 16%usize) r,
    parse_and_verify inst pkg en h key = Ok (Core_result_Result_Ok r) ->
    exists (f : Fields) (pre : array u8 91%usize) (t : array u8 32%usize),
      (* (P) the message is pinned to observable data *)
      f.(fld_author)  = r.(verifiedUpdate_author_id)
      /\ f.(fld_version) = r.(verifiedUpdate_version)
      /\ (forall i : usize, 0 <= to_Z i < 16 ->
            exists x y, array_index_usize f.(fld_nonce) i = Ok x
                     /\ array_index_usize en i = Ok y
                     /\ to_Z x = to_Z y)
      (* (V) it is a VALID pair under the device key *)
      /\ AssemblesF pre f
      /\ t = mac key pre
      /\ Tags f t
      (* (C) and the package really carries that tag *)
      /\ TagCarried pkg t
      (* (F) freshness transfer: any colliding encoding is an encoding of f *)
      /\ (forall (g : Fields) (q : array u8 91%usize),
            AssemblesF q g -> ByteEq pre q -> FieldsEq f g).
Proof.
  intros pkg en r Hacc.
  destruct (accept_implies_authenticated_fields inst h key mac Hseam pkg en r Hacc)
    as [tag_off [expect [nonce [hdr [bl [pre
       [Htoff [Hcpt [Hexp [HA [Hcarry [_ [_ [Hen _]]]]]]]]]]]]]].
  exists (mkFields nonce r.(verifiedUpdate_author_id) r.(verifiedUpdate_version) bl hdr),
         pre, expect.
  cbn [fld_nonce fld_author fld_version fld_blob_len fld_hdr].
  split; [ reflexivity |]. split; [ reflexivity |].
  split.
  { (* (P) nonce = armed nonce, lifted from the preimage window [15,31) *)
    intros i Hi.
    destruct (exists_usize (15 + to_Z i) ltac:(pose proof u32max_big; lia)) as [j Hj].
    destruct (Hen i j Hi Hj) as [x [y [Hx [Hy Hxy]]]].
    unfold AssemblesF in HA. cbn [fld_nonce] in *.
    destruct HA as [_ [A1 _]].
    exists x, y. rewrite <- (A1 i j Hi Hj). auto. }
  split; [ exact HA |].
  split; [ exact Hexp |].
  split; [ exact Hcpt |].
  split.
  { (* (C) *)
    intros i j Hi Hj. apply (Hcarry i j Hi). lia. }
  (* (F) *)
  intros g q HAq Hbe.
  apply (assemble_injective pre q _ g); [ exact HA | exact HAq | exact Hbe ].
Qed.

(** THE FRESHNESS-TRANSFER COROLLARY — the statement the game hop needs.

    `Q` is the list of messages the reduction forwarded to its tagging oracle,
    and `enc` maps each to the encoding the oracle actually saw. If the accepted
    package's message is not (`FieldsEq`-)among them, then the extracted
    preimage is not (`ByteEq`-)among the oracle's queries. Hence the extracted
    pair is a FRESH valid forgery in the 91-byte-preimage message space too.

    `Q` IS ABSTRACT HERE, AND NOTHING IN THIS FILE RELATES IT TO THE GAME'S
    `S_loc`. That correspondence is the freshness seam; it is stated explicitly
    as C2 in `Umbra_DeviceLink.FreshnessSeam` and it is an ASSUMPTION about the
    vendor's signing service, which is neither verified nor extracted. Read this
    corollary as the device-side half only. *)
Corollary accept_off_query_set_is_fresh_forgery :
  forall (pkg : slice u8) (en : array u8 16%usize) r
         (Q : list Fields) (enc : Fields -> array u8 91%usize),
    (forall g, In g Q -> AssemblesF (enc g) g) ->
    parse_and_verify inst pkg en h key = Ok (Core_result_Result_Ok r) ->
    exists (f : Fields) (pre : array u8 91%usize) (t : array u8 32%usize),
      f.(fld_author)  = r.(verifiedUpdate_author_id)
      /\ f.(fld_version) = r.(verifiedUpdate_version)
      /\ AssemblesF pre f
      /\ t = mac key pre
      /\ TagCarried pkg t
      /\ ((forall g, In g Q -> ~ FieldsEq f g) ->
          forall g, In g Q -> ~ ByteEq pre (enc g)).
Proof.
  intros pkg en r Q enc Henc Hacc.
  destruct (accept_yields_valid_forgery pkg en r Hacc)
    as [f [pre [t [Ha [Hv [_ [HA [Ht [_ [Hc Hfresh]]]]]]]]]].
  exists f, pre, t.
  split; [ exact Ha |]. split; [ exact Hv |]. split; [ exact HA |].
  split; [ exact Ht |]. split; [ exact Hc |].
  intros Hnotin g Hg Hbe.
  exact (Hnotin g Hg (Hfresh g (enc g) (Henc g Hg) Hbe)).
Qed.

End Reduction.
