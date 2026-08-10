(** THE REDUCTION — an accepted-but-unsigned update package is a MAC forgery.

    This is the deliverable. Everything before it is functional correctness;
    this file is where "the adversary cannot do X" is finally a statement with
    an adversary, a probability and a bound in it.

    THE CHAIN, IN ONE PARAGRAPH. Update_Encoding.`accept_encodes` (Qed) says:
    whenever `parse_and_verify` accepts a package, the 76-byte authenticated
    core and the 32-byte tag that the DEVICE hashed encode to exactly the
    integers a key-less party reads off the WIRE. Composing that with C1e below
    gives `device_accept_implies_submit_true` (Qed): acceptance implies
    `tag_of_pkg pkg = MAC k (msg_of_pkg pkg)`, i.e. the accepted package is a
    valid message/tag pair for the abstract MAC. The SSProve half then shows
    that the game in which an adversary wins by producing such a pair for an
    unissued message is, up to a perfectly-simulating reduction package `RED`,
    the EUF-CMA game of Umbra_EUFCMA.v. The bound is
    `Advantage UPD A <= Advantage EUF_CMA (A ∘ RED)`.

    WHY THE MESSAGE SPACE IS THE 76-BYTE CORE AND NOT THE FIVE FIELDS. The
    fields are what a reader cares about; the bytes are what the MAC sees.
    Update_Crypto.`assembly_injective` (Qed) is exactly the bridge between the
    two — distinct field tuples give distinct cores — and Update_Forgery.
    `assemble_injective` restates it over `Fields`/`FieldsEq`. So a statement
    about unissued CORES is a statement about unissued FIELD TUPLES, and the
    reduction never has to invert an encoding. Stating the game at the byte
    level also removes any suspicion that the encoding was chosen to make the
    proof work.

    WHAT IS ASSUMED HERE, IN FULL.

      (C1)  `Hseam` — inherited verbatim from Update_Crypto: the seam is a
            deterministic function of (key, preimage). No unforgeability.

      (C1e) `Hfactor` — NEW, and the only new assumption in the Tier-D files.
            It says that ON ASSEMBLED PREIMAGES the device's seam FACTORS
            THROUGH THE BYTE ENCODING: the tag of a preimage that `Assembles`
            some field tuple depends on nothing but the integer `msg_of_pre`
            reads out of it, and equals the abstract `MAC k0` of that integer.
            This is not a cryptographic assumption. It is the statement that
            HMAC-SHA256 reads its input as bytes — vacuously true of every real
            implementation — and it is needed only because Aeneas models
            `array u8 91` as an opaque sigma type on which byte equality does
            not imply term equality (see Update_Encoding.v's header).

            THE `AssemblesF` GUARD IS NOT COSMETIC. `msg_of_pre` reads offsets
            [15,91) only, so without the guard C1e would force the seam to
            ignore the 15-byte domain-separation label — a property HMAC-SHA256
            does not have, making the hypothesis FALSE rather than merely
            strong. `Assembles` pins those 15 bytes to a constant, so under the
            guard the label never varies and the restricted hypothesis is
            realisable. Both directions are machine-checked in
            Umbra_DeviceLink.v: `unguarded_C1e_forces_label_obliviousness` and
            `restricted_C1e_is_functional`.

            `k0 : K` is a section VARIABLE. Nothing in Tier D relates it to a
            sampled key — there is no Coq object identifying it with the game's
            `k`, and the Tier-D files contain no distributions at all. Read C1e
            as "for the device's provisioned key there EXISTS a game key `k0`
            whose abstract MAC agrees with the seam on assembled preimages".
            That the provisioned key is uniform is the standard key-generation
            assumption and is NOT formalised here.

      (EUF-CMA of the seam) — NOT assumed, but APPEARING ON THE RIGHT-HAND SIDE
            of the bound. This is the point of the whole exercise: the security
            of the update protocol is now reduced to a named, standard,
            falsifiable cryptographic assumption instead of resting on a
            functional statement that the constant function satisfies.

    WHAT IS *NOT* CLOSED — read this before quoting the bound.

      THIS FILE CONTAINS NO UMBRA CONTENT. `Print Assumptions
      update_forgery_le_eufcma` shows no Aeneas axiom and no `Update_*`
      dependency: `UPD` is `EUF_CMA` with the oracles renamed and the
      verification query pre-composed with two arbitrary readers, so `RED` is a
      bijection of oracle names and both hops are perfect for trivial reasons.
      This file would compile unchanged if `parse_and_verify` did not exist.
      All Umbra-specific content is in Tier D; the tiers meet only through
      `device_accept_implies_submit_true`, and that meeting is the event
      inclusion whose lifting to probabilities is the open obligation below.

      The `submit` oracle of the UPD game returns the TAG-VERIFICATION verdict
      `tag_of_pkg p == MAC k (msg_of_pkg p)`, not `parse_and_verify` accepted.
      The deterministic theorem `device_accept_implies_submit_true` shows real
      acceptance IMPLIES that verdict, so the UPD game is a RELAXATION of the
      real device: every real-device forgery is a UPD win, hence
      Pr[real forgery] <= Pr[UPD win] <= Advantage EUF_CMA. That first
      inequality is an inclusion of events, proved here as a Coq implication
      (`device_accept_implies_submit_true`), but it is NOT lifted into SSProve:
      doing so would need the real device's acceptance predicate to be a
      `raw_code` over a `choice_type` package space, which in turn needs the
      CONVERSE characterisation (structural guards + matching tag ==> accepts)
      that this development does not prove. See README.md, "The remaining
      obligation". Anyone quoting a fully machine-checked end-to-end bound is
      overstating this file. *)

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

From Equations Require Import Equations.
Require Equations.Prop.DepElim.

Set Equations With UIP.

Set Bullet Behavior "Strict Subproofs".
Set Default Goal Selector "!".
Set Primitive Projections.

Import Num.Def.
Import Num.Theory.
Import Order.POrderTheory.

From UmbraCrypto Require Import Umbra_EUFCMA.

(* ===================================================================== *)
(* PART 1 — the game hop, in SSProve. No Aeneas types appear here.        *)
(* ===================================================================== *)

Section UpdateForgery.

Variable (n : nat).

(** THE MESSAGE BOUND. Abstract here, as it is in `Umbra_EUFCMA.v` and for the
    same reason: it is instantiated at `257^76` only in `Umbra_RealGame.v`, and
    only by applying finished theorems, so no tactic in this tier ever meets a
    concrete numeral of that size. *)
Variable (MsgN : nat).
Context {HMsgN : Positive MsgN}.

Notation " 'msg " := (Msg MsgN) (in custom pack_type at level 2).
Notation " 'msg " := (Msg MsgN) (at level 2) : package_scope.

Context (MAC : Key n -> nat -> nat).

#[local] Open Scope package_scope.

Definition sign   : nat := 2.
Definition submit : nat := 3.

Definition UPD_I :=
  [interface
    #val #[sign]   : 'msg → 'nat ;
    #val #[submit] : 'nat → 'bool ].

(** The adversary's package space and its reading.

    A wire package is an Aeneas `slice u8`, which is not a `choice_type` and
    therefore cannot be an oracle argument. Instead the adversary names a
    package by a natural number and the game reads its authenticated core and
    its tag through `msgN` / `tagN`, which are UNIVERSALLY QUANTIFIED.

    AN EARLIER VERSION OF THIS COMMENT DEFENDED THAT BADLY, and the bad defence
    should not be repeated: it said "given any target package `s`, take
    `msgN := fun _ => msg_of_pkg s`, so every slice is reachable". A CONSTANT
    reader models an adversary that submits one fixed package chosen
    non-adaptively before the game starts, and "for each `s` there is an
    instantiation reaching `s`" is not "one instantiation reaches every `s`".

    What the modelling actually needs is a single INJECTION from wire packages
    into the message space, and the games instantiated at that one reader. Such
    an injection exists — `msg_of_pkg` and `tag_of_pkg` are non-negative
    integers (`Update_Encoding.msg_of_pkg_nonneg`) bounded by `257^76`
    (`Umbra_Canonical.msg_of_pkg_lt`) — but it is NOT constructed in this
    development. Nothing below depends on the defence: the theorem is proved for
    EVERY `msgN`/`tagN`, so it holds for the right pair too. The gap is in the
    modelling story, not in the proof.

    SINCE THE MESSAGE-SPACE REVISION `msgN` LANDS IN `Msg MsgN` BY TYPE, not in
    `nat`. That is not cosmetic: with the message space `nat` this game was
    vacuous at the MAC the device computes, because the pinned MAC collides with
    period `257^76` (`Umbra_Canonical.MG_of_collides_above_range`, Qed). The
    finite message space is what removes the collision's witness from the game;
    see `Umbra_EUFCMA.v`'s header. `tagN` is still `nat -> nat`, and that is
    sound for the same reason it was before: a tag is only ever COMPARED, never
    decoded, so no encoding periodicity can reach it. *)
Context (msgN : nat -> Msg MsgN).
Context (tagN : nat -> nat).

(** REAL: the device tag-checks whatever the adversary submits. *)
Definition UPD_pkg_tt : package (EUF_locs_tt n) [interface] UPD_I :=
  [package
    #def #[sign] (m : 'msg) : 'nat {
      k ← kgen n ;;
      ret (MAC k (nat_of_ord m))
    } ;
    #def #[submit] (p : 'nat) : 'bool {
      k ← kgen n ;;
      ret (tagN p == MAC k (nat_of_ord (msgN p)))
    }
  ].

(** IDEAL: only packages whose core was actually signed can pass. *)
Definition UPD_pkg_ff : package (EUF_locs_ff n MsgN) [interface] UPD_I :=
  [package
    #def #[sign] (m : 'msg) : 'nat {
      S ← get (S_loc MsgN) ;;
      k ← kgen n ;;
      let t := MAC k (nat_of_ord m) in
      #put (S_loc MsgN) := setm S (m, t) tt ;;
      ret t
    } ;
    #def #[submit] (p : 'nat) : 'bool {
      S ← get (S_loc MsgN) ;;
      ret ((msgN p, tagN p) \in domm S)
    }
  ].

Definition UPD := mkpair UPD_pkg_tt UPD_pkg_ff.

(** THE REDUCTION PACKAGE. Stateless, key-less: it forwards signing requests
    verbatim and turns a submitted package into a single verification query on
    the pair it reads off the wire. Any adversary against the update protocol
    becomes, composed with this, an adversary against EUF-CMA. *)
Definition RED : package fset0
  [interface
    #val #[gettag]   : 'msg → 'nat ;
    #val #[checktag] : 'msg × 'nat → 'bool ]
  [interface
    #val #[sign]   : 'msg → 'nat ;
    #val #[submit] : 'nat → 'bool ] :=
  [package
    #def #[sign] (m : 'msg) : 'nat {
      #import {sig #[gettag] : 'msg → 'nat } as gt ;;
      t ← gt m ;;
      ret t
    } ;
    #def #[submit] (p : 'nat) : 'bool {
      #import {sig #[checktag] : 'msg × 'nat → 'bool } as ct ;;
      b ← ct (msgN p, tagN p) ;;
      ret b
    }
  ].

Lemma UPD_tt_link : UPD true ≈₀ RED ∘ EUF_CMA n MsgN MAC true.
Proof.
  apply: eq_rel_perf_ind_eq.
  simplify_eq_rel m.
  all: apply rpost_weaken_rule with eq;
    last by move=> [? ?] [? ?] [].
  all: simplify_linking.
  all: simplify_linking.
  all: ssprove_sync_eq.
  all: case => [k|].
  all: by apply: rreflexivity_rule.
Qed.

Lemma UPD_ff_link : UPD false ≈₀ RED ∘ EUF_CMA n MsgN MAC false.
Proof.
  apply: eq_rel_perf_ind_eq.
  simplify_eq_rel m.
  all: apply rpost_weaken_rule with eq;
    last by move=> [? ?] [? ?] [].
  all: simplify_linking.
  all: simplify_linking.
  all: ssprove_code_simpl.
  all: ssprove_sync_eq => S.
  all: by apply: rreflexivity_rule.
Qed.

#[local] Open Scope ring_scope.

(** THE BOUND. An adversary's advantage in the update-forgery game is at most
    its advantage — through `RED` — in the EUF-CMA game of the underlying MAC.

    Read: if the device's HMAC is EUF-CMA-secure, then no adversary with
    chosen-message access to the signing service can get the device to accept a
    package whose authenticated core it never signed, except with the same
    negligible probability. That is a security statement about an attack, which
    is what the functional layer could not express. *)
Theorem update_forgery_le_eufcma :
  forall LA (A : raw_package),
    ValidPackage LA UPD_I A_export A ->
    fdisjoint LA (EUF_locs_tt n :|: EUF_locs_ff n MsgN) ->
    Advantage UPD A <= Advantage (EUF_CMA n MsgN MAC) (A ∘ RED).
Proof.
  move=> LA A vA H.
  rewrite Advantage_E Advantage_E Advantage_link.
  ssprove triangle (UPD false) [::
    RED ∘ EUF_CMA n MsgN MAC false ;
    RED ∘ EUF_CMA n MsgN MAC true
  ] (UPD true) A as ineq.
  apply: le_trans; first by apply: ineq.
  rewrite !fdisjointUr in H.
  move: H => /andP [H1 H2].
  rewrite UPD_ff_link ?fdisjointUr ?H1 ?H2 ?fdisjoints0 //.
  rewrite (Advantage_sym (RED ∘ EUF_CMA n MsgN MAC true) (UPD true) A).
  rewrite UPD_tt_link ?fdisjointUr ?H1 ?H2 ?fdisjoints0 //.
  by rewrite GRing.add0r GRing.addr0.
Qed.

End UpdateForgery.
