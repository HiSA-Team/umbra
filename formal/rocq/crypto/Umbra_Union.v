(** THE UNION — an accepted package's BODY is the signed package's body, or the
    signing service never issued its (core, tag) pair.

    ------------------------------------------------------------------------
    THE GAP THIS FILE CLOSES, AND THE ONE IT DOES NOT.

    Two theorems stood side by side and did not meet.

      TIER D (`chain-core/proofs-coq/Chain_Compose.v`,
      `verified_update_pins_the_blob_body`, Qed, bare Coq): two packages the
      extracted parser accepts, CARRYING THE SAME 32 TRAILING TAG BYTES, have
      equal blob bodies or exhibit a collision. Its hypothesis is tag REUSE, so
      the sentence it supports is "accept the same tag twice and the two bodies
      agree". A reader who wants "an accepted body is the one the vendor
      signed" is not served: the adversary is free to attach a FRESH tag.

      TIER G (`Umbra_RealGame.v`, `device_forgery_le_eufcma[_at_the_real_seam]`,
      Qed, SSProve): producing a package the device accepts whose 76-byte
      authenticated CORE and tag the signing oracle never issued costs an
      EUF-CMA forgery. Its conclusion is about the CORE. It says nothing about
      the blob body — by construction: `Umbra_Canonical.
      blob_body_is_not_covered_by_pkg_tag` (Qed) proves the package tag does not
      cover the body at all.

    The union is the case split on whether the accepted package's (core, tag)
    pair is one the signing service issued. This file mechanises it. The
    fresh-tag branch lands in Tier G's forgery event; the reused-CORE branch
    lands in `Umbra_UnionCore.wire_accepted_equal_indices_pin_the_blob_body`,
    which is NOT `Chain_Compose`'s theorem — it is the strengthening this work
    had to prove first, because `Chain_Compose`'s hypothesis (same trailing tag
    bytes) is not what the game hands over (same message index).

    ------------------------------------------------------------------------
    WHAT THE UNION IS AND IS NOT — read this before quoting it.

    IS. "For a package the device accepts: either its blob body agrees, byte for
    byte over the folded region, with the body of a package carrying the same
    signed core, or the CHAINED-MEASUREMENT seam collided (witnesses exhibited),
    or the ideal device rejects it — the event `device_forgery_le_eufcma`
    bounds."

    IS NOT, and each of these is a deliberate limit, not an oversight:

    (1) IT IS NOT A SINGLE PROBABILITY STATEMENT. The three disjuncts are not
        pushed into one inequality inside the SSProve game. Section
        "THE OBSTRUCTION" at the bottom of this file states exactly why, and
        that negative is one of this file's results.

    (2) "SIGNED" IS NOT "AUTHENTIC". The game's `dsign` oracle signs an
        ADVERSARY-CHOSEN message index. So membership in the query set means
        "the adversary obtained a signature on this core", not "the vendor
        intended this body". The correspondence between the vendor's real
        signing service and the game's query set is the named seam C2
        (`Umbra_DeviceLink.v`, `FreshnessSeam`), assumed and not proved — there
        is no extracted signer to walk. The union inherits that assumption
        verbatim and does not upgrade it.

    (3) THE BLOCK COUNT IS DERIVED, NOT POSTULATED. Each chain gate supplies its
        own successful `blob_block_count` result. Equal authenticated cores pin
        `blob[0,48)`, including magic and `code_size`; `Chain_Value.
        successful_blob_block_counts_agree` then proves the two results equal.
        The union therefore accepts two independent counts and reports body
        agreement over the accepted package's folded region.

    (4) THE CHAIN SEAM IS STILL A DISJUNCT. What DID disappear is
        `Chain_Compose.MacCollisionOnPackages`, the PACKAGE-tag seam's
        collision — and its disappearance is the tell that the union is a join
        and not a `\/`. It is gone because the reused-core branch gives equal
        MAC INPUTS (`Umbra_UnionCore.accepted_equal_cores_agree_on_the_preimage`
        proves the two preimages are the same TERM), where tag reuse gives only
        equal MAC OUTPUTS. That matters cryptographically: EUF-CMA does not
        bound collision-finding, so a surviving `MacCollisionOnPackages` could
        never have been discharged by Tier G. What survives is a collision of
        the CHAINED-MEASUREMENT seam, a different keyed function over the master
        key, for which this development contains NO game and NO bound. It is a
        named, witness-pinned event and it is disclosed as such.

    ------------------------------------------------------------------------
    WHERE THE CONTENT ACTUALLY IS — STATED SO IT CANNOT BE MISCREDITED.

    The theorem below is LOGICALLY EQUIVALENT to
    `Umbra_UnionCore.accepted_equal_indices_pin_the_blob_body`. Forward is the
    proof given here. Backward: instantiate `S` with the single-entry map
    `setm emptym (widx_ord p, wtag p) tt`; membership then holds, acceptance
    supplies `struct_ok`, so `iverdict S p = true` refutes the third disjunct,
    and the bridge hypothesis is discharged from `widx p = widx q` — leaving
    exactly UnionCore's conclusion. It is `A \/ B \/ ~C` with `C -> …` in the
    hypotheses, i.e. UnionCore with an excluded middle wrapped round it.

    So what CLOSED the gap is `Umbra_UnionCore.v` — the move from "the same 32
    trailing tag bytes" to "the same authenticated core", which is what killed
    the package-MAC collision disjunct. THIS file adds vocabulary, not content:
    it states the join in the game's own terms, with the third disjunct being
    `Umbra_RealGame.ideal_verdict` itself rather than a re-modelled event, so
    that the two tiers meet inside a typechecked statement instead of inside a
    paragraph. That is worth having and it is not the same as closing the gap.
    Anything that credits this file with closing residual (ii) is overclaiming.

    ------------------------------------------------------------------------
    WHERE THE HYPOTHESES SIT. The vendor's package `q` is a UNIVERSALLY
    QUANTIFIED PARAMETER whose properties are HYPOTHESES. There is no
    existential over a witness package anywhere in the conclusion — that shape
    would let the adversary's own blob discharge the disjunct and reduce the
    theorem to "the body equals itself", which is the `Assembles` failure mode
    this development has already been bitten by once. The determinacy lemma the
    discipline requires is `Umbra_UnionCore.
    accepted_equal_cores_agree_on_the_preimage` (Qed): the 91-byte preimage is a
    FUNCTION of the authenticated core, so all packages carrying one signed core
    have one header-HMAC window, and the theorem below is symmetric in `p` and
    `q`.

    ------------------------------------------------------------------------
    THIS FILE IS NOT MATHCOMP-FREE. THE UNION THEOREM, MEASURED, STILL IS
    CLASSICAL-AXIOM-FREE — and that was not expected.

    `Print Assumptions accepted_body_is_the_signed_body_or_a_forgery` lists 41
    constants: 40 Aeneas/Primitives quarantine axioms plus
    `Chain_Value.array_u8_ext` (Q21). NO `boolp.*`, no `realsum`, no `classic`.
    The reason is that the union is a case split on a BOOLEAN — membership in
    `domm S` — composed with the deterministic tier, and neither step touches
    mathcomp-analysis's measure theory. Its deterministic half
    (`Umbra_UnionCore.accepted_equal_cores_pin_the_blob_body`) carries 40 of
    those 41.

    THE CLASSICAL AXIOMS ARRIVE ONE THEOREM LATER, at
    `forgery_disjunct_is_bounded_by_eufcma` — 50 constants, of which
    `boolp.constructive_indefinite_description`,
    `boolp.functional_extensionality_dep`, `boolp.propositional_extensionality`
    and `realsum.__admitted__interchange_psum` are inherited verbatim from
    `Umbra_RealGame.device_forgery_le_eufcma_at_the_real_seam`. So the honest
    statement is: the CASE SPLIT is constructive; the BOUND on its third
    disjunct is not. `Print Assumptions` at the bottom of this file emits both,
    so neither figure has to be taken on trust.

    (Counted as the number of entries `Print Assumptions` lists — one per line
    at column 0 of the `Axioms:` block.)

    `update-core/` and `chain-core/` acquire NO dependency from this file:
    nothing next door requires anything here, and the new edge runs one way,
    crypto -> chain-core. *)

From SSProve.Relational Require Import OrderEnrichedCategory GenericRulesSimple.

Set Warnings "-notation-overridden,-ambiguous-paths".
From mathcomp Require Import all_ssreflect all_algebra reals distr realsum
  ssrnat ssreflect ssrfun ssrbool ssrnum eqtype choice seq.
Set Warnings "notation-overridden,ambiguous-paths".

From SSProve.Mon Require Import SPropBase.
From SSProve.Crypt Require Import Axioms ChoiceAsOrd SubDistr Couplings
  UniformDistrLemmas FreeProbProg Theta_dens RulesStateProb
  pkg_core_definition choice_type pkg_composition pkg_rhl Package Prelude.

From extructures Require Import ord fset fmap.

Import SPropNotations.
Import PackageNotation.

Set Bullet Behavior "Strict Subproofs".
Set Default Goal Selector "!".

From UmbraCrypto Require Import Umbra_EUFCMA.
From UmbraCrypto Require Import Umbra_Canonical.
From UmbraCrypto Require Import Umbra_ByteSpace.
From UmbraCrypto Require Import Umbra_Wire.
From UmbraCrypto Require Import Umbra_WireConverse.
From UmbraCrypto Require Import Umbra_RealGame.
From UmbraCrypto Require Import Umbra_UnionCore.

(** The game's message space: `256^76`, the byte-valid subimage — the set of
    76-byte authenticated cores, exactly. A `Notation`, for the reason
    `Umbra_RealGame.v` gives: as a `Definition` every `rewrite /MSGB` would
    normalise a unary numeral with ~10^144 successors. *)
Notation MSGB := MSGB256n.

Section Union.

(* --------------------------------------------------------------------- *)
(* THE DEVICE — the same one `Umbra_RealGame.v`'s bound is about.          *)
(* --------------------------------------------------------------------- *)

Variable nk : nat.                      (* the key-length exponent *)
Context {HS : Type}.
Variable inst : hmac_inst HS.           (* the extracted parser's HMAC seam *)
Variable hs   : HS.
Variable en   : list nat.               (* the provisioned anti-rollback nonce *)
Variable dkey : Key nk -> key_bytes.    (* the provisioning map *)
Variable macf : macf_t.

(** C1 — the package-tag seam is a deterministic function of key material and
    preimage. The constant function satisfies it, so it carries no
    unforgeability. Verbatim the hypothesis `Update_Crypto`'s P2, `Chain_Compose`
    and `Umbra_RealGame` all run under. *)
Hypothesis Hseam : SeamC1 inst hs macf.

(* --------------------------------------------------------------------- *)
(* THE CHAINED-MEASUREMENT DEVICE — a SECOND seam, with no assumption at   *)
(* all on it, and no game bounding it.                                     *)
(* --------------------------------------------------------------------- *)

Context {CS : Type}.
Variable cinst  : Chain_Funs.ChainHmac_t CS.
Variable ch     : CS.
Variable master : Chain_Trace.ckey.

(** The signing service's issue set, AT THE GAME'S OWN LOCATION TYPE — the
    type of `Umbra_RealGame.S_loc`, not a lookalike `{fmap … -> unit}`. *)
Notation qset := (@S_loc MSGB MSGB_positive).

(** THE IDEAL DEVICE'S VERDICT. NOT redefined here: this is
    `Umbra_RealGame.ideal_verdict`, the function `DEV_pkg_ff`'s `dsubmit`
    oracle RETURNS. Transcribing it instead — which an earlier revision of this
    file did — would have made the union's central claim (that its third
    disjunct is the game's own rejection event) a claim carried by comment
    rather than by the kernel: edit `DEV_pkg_ff` and nothing would catch the
    drift. Now they cannot diverge, because there is one definition. *)
Notation iverdict := (@ideal_verdict MSGB MSGB_positive en).

(* ===================================================================== *)
(* THE UNION.                                                             *)
(* ===================================================================== *)

(** For a package `p` the device accepts, and a package `q` carrying the core
    the signing service issued for it: either the accepted body IS the signed
    body over the whole folded region, or the CHAINED seam collided with the
    colliding pair exhibited, or the ideal device rejects `p` — the EUF-CMA
    forgery event `device_forgery_le_eufcma` bounds.

    EVERY HYPOTHESIS IS LOAD-BEARING; deleting any one breaks the proof.
      * `Hseam` (C1) — without it `Update_Crypto`'s P2 does not fire, so there
        is no preimage and no header-HMAC window.
      * the two parse equations — acceptance is what supplies the preimage
        windows AND the key-free structural guards that make the game's index
        faithful to the core (`widx_spreads_back`).
      * `Hhonest` — without it, membership in the issue set says nothing about
        `q`, and the two cores are unrelated.
      * the two `ChainAccepts` — each supplies its independently parsed count;
        their equality is a conclusion of the signed-core branch.

    NOTE WHAT IS *NOT* A HYPOTHESIS, and used to be. `Chain_Compose` needs the
    two packages to have equal length and equal 32 trailing tag bytes. Both are
    gone. Equal length is free here (`wstruct_ok` clause 4 ties the length to
    `blob_len`, which is INSIDE the core), and the tag agreement is exactly what
    the union replaces by the case split. *)
Theorem accepted_body_is_the_signed_body_or_a_forgery :
  forall (k : Key nk) (S : qset) (p q : list nat)
         (rp rq : vupd) (np nq : blkcount),
    (* (1) the device accepted the adversary's package `p` *)
    Accepted inst hs (dkey k) en p rp ->
    (* (2) the device also accepts the vendor's package `q` *)
    Accepted inst hs (dkey k) en q rq ->
    (* (3) `q` IS the vendor's package for `p`'s core: if the signing service
       ever issued `p`'s (core, tag) pair, then `q` carries that core. The
       existential lives HERE, in the hypothesis, never in the conclusion. *)
    (((@widx_ord MSGB MSGB_positive p, wtag p) \in domm S) ->
       @widx_ord MSGB MSGB_positive q = @widx_ord MSGB MSGB_positive p) ->
    (* (4) both blobs pass the firmware's chained-measurement gate. Their
       independently obtained block counts are proved equal in the signed-core
       branch; they need not be postulated equal here. *)
    ChainAccepts cinst ch master (vblob rp) np ->
    ChainAccepts cinst ch master (vblob rq) nq ->
    (* THEN one of three, and the third is the event Tier G bounds. *)
    BodiesAgree (vblob rp) (vblob rq) np
    \/ Chain_Body.SeamCollisionInRuns cinst ch master (vblob rp) (vblob rq)
    \/ iverdict S p = false.
Proof.
  move=> k S p q rp rq np nq Ap Aq Hhonest Cp Cq.
  case Hmem : ((@widx_ord MSGB MSGB_positive p, wtag p) \in domm S).
  - (* THE SIGNED-CORE BRANCH. The game's index is faithful to the core on
       structurally-accepted packages, so equal indices are equal cores. *)
    have Hidx : widx p = widx q.
    { have Hq := Hhonest Hmem.
      rewrite -(@widx_ord_val MSGB MSGB_positive widx_lt_MSGB p)
              -(@widx_ord_val MSGB MSGB_positive widx_lt_MSGB q).
      by rewrite Hq. }
    case: (accepted_equal_indices_pin_the_blob_body
             inst hs (dkey k) macf Hseam cinst ch master
             en p q rp rq np nq Ap Aq Hidx Cp Cq) => [Hbody | Hcoll].
    + by left.
    + by right; left.
  - (* THE FRESH-TAG BRANCH. The ideal device rejects, so the two worlds of
       `DEV` disagree on this submission. *)
    right. right. by rewrite /ideal_verdict Hmem andbF.
Qed.

(** THE THIRD DISJUNCT IS EXACTLY A DISAGREEMENT BETWEEN THE TWO WORLDS OF
    `DEV`. `dev_accepts` is the REAL oracle's body (the extracted
    `parse_and_verify`); `ideal_verdict` (Umbra_RealGame) is the IDEAL oracle's. So the union's
    forgery branch is not a re-modelled event: it is the very thing
    `Advantage DEV A` measures. *)
Lemma forgery_disjunct_is_a_real_ideal_disagreement :
  forall (k : Key nk) (S : qset) (p : list nat),
    @dev_accepts nk HS inst hs en dkey k p = true ->
    iverdict S p = false ->
    @dev_accepts nk HS inst hs en dkey k p <> iverdict S p.
Proof. move=> k S p Hreal Hideal. by rewrite Hreal Hideal. Qed.

(** … AND THE ACCEPTANCE HYPOTHESIS OF THE UNION IS THAT SAME REAL VERDICT.
    Stated so that no theorem carries both `dev_accepts p = true` and the parse
    equation: the second implies the first, so carrying both would be
    decoration. *)
Lemma union_hypothesis_is_the_real_oracle :
  forall (k : Key nk) (p : list nat) (rp : vupd),
    Accepted inst hs (dkey k) en p rp ->
    @dev_accepts nk HS inst hs en dkey k p = true.
Proof.
  move=> k p rp Hp. rewrite /dev_accepts.
  by apply: (proj2 (parse_ok_iff_accepts inst hs (dkey k) en p)); exists rp.
Qed.

(** THE BOUND ON THE THIRD DISJUNCT, IN THIS SECTION'S OWN VARIABLES. A
    RESTATEMENT of `Umbra_RealGame.device_forgery_le_eufcma_at_the_real_seam`
    and nothing more — it is here so that a reader can see that the game whose
    advantage bounds the union's forgery branch is the game over THIS device,
    with THIS seam, THIS provisioning map and THIS nonce, rather than a
    similarly-named one. *)
Corollary forgery_disjunct_is_bounded_by_eufcma :
  forall (mb : byteseam_t),
    ByteSeam macf mb ->
    forall (LA : {fset Location}) (A : raw_package),
      ValidPackage LA (@DEV_I MSGB MSGB_positive) A_export A ->
      fdisjoint LA (EUF_locs_tt nk :|: @EUF_locs_ff nk MSGB MSGB_positive) ->
      (Advantage
         (@DEV nk MSGB MSGB_positive (MACb_canonical mb dkey) HS inst hs en dkey) A
       <= Advantage
            (@EUF_CMA nk MSGB MSGB_positive (@MACg nk (MACb_canonical mb dkey)))
            (A ∘ @RED_dev MSGB MSGB_positive en))%R.
Proof.
  move=> mb Hbs LA A vA Hd.
  exact: (device_forgery_le_eufcma_at_the_real_seam nk HS inst hs en dkey
            macf mb Hseam Hbs LA A vA Hd).
Qed.

End Union.

(* ===================================================================== *)
(* THE OBSTRUCTION — WHY THE THREE DISJUNCTS DO NOT BECOME ONE            *)
(* PROBABILITY STATEMENT, AND WHAT WOULD HAVE TO CHANGE.                  *)
(*                                                                        *)
(* This is a NEGATIVE RESULT and it is reported as one. The union above    *)
(* is a fully mechanised case split, not an inequality. Pushing it into    *)
(* a single SSProve bound of the shape                                    *)
(*                                                                        *)
(*   Advantage UNION A <= Advantage (EUF_CMA …) (A ∘ RED) + (collision)    *)
(*                                                                        *)
(* was attempted and does not close, for two independent reasons. Neither  *)
(* is a proof-engineering difficulty; both are missing modelling objects.  *)
(*                                                                        *)
(* O1 — THE SUBMISSION ORACLE CANNOT CONDITION ON THE CHAIN GATE. A game   *)
(* pair whose ideal world enforced "the body is the signed body" would     *)
(* need its `dsubmit` oracle to reject packages whose bodies differ. The   *)
(* union's body conclusion is conditional on `ChainAccepts` for BOTH       *)
(* blobs, and `dev_accepts` — the real oracle — is                         *)
(* `Update_Funs.parse_and_verify`, which performs no check on the blob     *)
(* body whatsoever (`Umbra_Canonical.blob_body_is_not_covered_by_pkg_tag`, *)
(* Qed). So the ideal oracle cannot compute the condition under which the  *)
(* union's first disjunct holds, and `DEV false ≈₀ UNION false` is not     *)
(* provable — it is FALSE as stated, because a submission that passes the  *)
(* tag gate and fails the chain gate is accepted by one and rejected by    *)
(* the other. Closing O1 means putting `Chain_Funs.verify_blob_chain`      *)
(* INSIDE the submit oracle — which is faithful to the firmware, since the *)
(* firmware runs both — and that is a modelling extension this development *)
(* has not made.                                                          *)
(*                                                                        *)
(* O2 — THE CHAIN SEAM HAS NO GAME. `Chain_Body.SeamCollisionInRuns` is a  *)
(* `Prop` about deterministic data. SSProve's `Advantage` is a difference  *)
(* of probabilities over a game pair; there is no distribution anywhere    *)
(* near the chained-measurement seam in this development, no key sampling  *)
(* for `master`, and no collision-resistance game to absorb the disjunct   *)
(* into. An additive term for it cannot be written down, let alone         *)
(* bounded. Writing `+ Pr[collision]` without such a game would be exactly *)
(* the fabricated bound this work is trying not to produce. Closing O2     *)
(* means a second game — collision resistance of the chained HMAC under a  *)
(* sampled `master` — and a second reduction.                              *)
(*                                                                        *)
(* O3 -- CLOSED AT THE COMPOSITION BOUNDARY. The union accepts independent *)
(* counts `np` and `nq`. Equal signed cores pin the full header;             *)
(* `successful_blob_block_counts_agree` derives `np = nq` from the two      *)
(* successful count parses, and only then invokes the equal-length trace     *)
(* theorem. The chain theorem in isolation still says nothing about two      *)
(* accepted blobs with different authenticated headers; the composition does *)
(* not need such a statement.                                                 *)
(*                                                                        *)
(* WHAT IS TRUE TODAY, THEN, IS THE CASE SPLIT: on a submission the real   *)
(* device accepts, either the body is pinned (deterministically, modulo    *)
(* the chain seam) or the real and ideal oracles disagree on that very     *)
(* submission — and the probability of the latter, over the sampled key,   *)
(* is what `device_forgery_le_eufcma` bounds by an EUF-CMA advantage. The  *)
(* step this development does NOT take is from `the two oracles disagree   *)
(* on p` to `the probability of the union's bad event is at most the       *)
(* advantage`, which needs the two obstructions above removed first.       *)
(* ===================================================================== *)

(* ===================================================================== *)
(* MECHANISED ASSUMPTION AUDIT. Compiling this file emits the full axiom   *)
(* budget of the union theorem. The `boolp.*` constants are mathcomp-      *)
(* analysis's classical axioms, inherited through SSProve; they are NOT    *)
(* in the deterministic half's budget (`Umbra_UnionCore.v`, 40 axioms, no  *)
(* classical logic) -- and, measured, they are NOT in the union theorem's  *)
(* budget either (41, still no classical axiom). They appear only in       *)
(* `forgery_disjunct_is_bounded_by_eufcma`, which inherits them from Tier  *)
(* G. Both listings are emitted below so the split is checkable.           *)
(* ===================================================================== *)
Print Assumptions accepted_body_is_the_signed_body_or_a_forgery.
Print Assumptions forgery_disjunct_is_bounded_by_eufcma.
