(** EUF-CMA FOR A MAC, IN SSProve — the game the update protocol reduces to.

    This is the file that introduces an ADVERSARY, a PROBABILITY and an
    ADVANTAGE into a development that previously had none of the three. It
    contains no Umbra-specific content: it is the textbook existential-
    unforgeability-under-chosen-message-attack game, in the state-separating
    style SSProve uses, over an abstract keyed function

        MAC : Key -> nat -> nat

    played on a FINITE message space `'fin MsgB` and a tag space `nat`.

    WHY THE MESSAGE SPACE IS FINITE, AND WHY THAT IS THE WHOLE POINT OF THIS
    REVISION. Until this revision the message space was `nat`, and the game was
    therefore VACUOUS at the MAC the device actually computes. The device's
    engine hashes NINETY-ONE BYTES; the abstract MAC is that engine
    precomposed with `Umbra_Canonical.canon91`, the base-257 decoding of the
    message integer. `canon91` is periodic with period `257^76`
    (`Umbra_Canonical.canon91_collides_above_range`, Qed), so over `nat` the
    abstract MAC collides — `MG_of_collides_above_range` exhibits
    `MAC k m = MAC k (m + 257^76)` for EVERY seam, with no hypothesis at all.
    An adversary then queries `gettag m`, submits `checktag (m + 257^76, t)`,
    and separates the real from the ideal package with advantage 1. Any bound
    whose right-hand side is `Advantage EUF_CMA` was true and said nothing.

    Restricting the message space to `'fin MsgB` — the ordinals below `MsgB` —
    removes the collision by removing its witness from the game: instantiated at
    `MsgB = 257^76` (`Umbra_RealGame.MSGpos`) the encoding is INJECTIVE on the
    whole space (`Umbra_Canonical.canon91_injective`, Qed), so two distinct game
    messages are two distinct 91-byte preimages and the right-hand side is the
    advantage against the engine at genuinely distinct inputs. Nothing on the
    left-hand side is given up: `Umbra_WireConverse.wmsg_in_range` (Qed) says
    every message any wire package can encode to is already below `257^76`.

    `MAC` itself is still typed `Key -> nat -> nat`; the game applies it at
    `nat_of_ord m`. So the object on the right-hand side is exactly the
    RESTRICTION of the device's MAC to the encoding's range, and no coercion or
    re-indexing of the deterministic tier was needed to say so.

    THE GAME. Two packages exporting the same interface:

      gettag   (m)      the tagging oracle — chosen-message attack
      checktag (m, t)   the verification oracle

    In the REAL package (`b = true`) `checktag` verifies honestly:
    `t == MAC k m`. In the IDEAL package (`b = false`) it answers `true` only
    for pairs `gettag` actually emitted. So the two packages differ EXACTLY on
    the event "the adversary submitted a valid pair that was never issued" —
    that is, on a forgery. `Advantage EUF_CMA A` is therefore the EUF-CMA
    advantage of `A` in the usual sense, and "MAC is EUF-CMA-secure" is the
    statement that it is negligible.

    Structure and tactics follow SSProve's own `examples/PRFMAC.v`, which
    formalises the same game for a PRF-based MAC; the difference is that
    `MAC` here is an arbitrary keyed function rather than a PRF, because the
    reduction in Umbra_Reduction.v must hold for whatever the device's HMAC
    engine computes.

    WHAT THIS FILE DOES NOT DO. It does not prove that any particular MAC is
    EUF-CMA-secure — no one can, unconditionally. EUF-CMA of HMAC-SHA256 is the
    assumption the whole layer rests on, and it is made HERE, visibly, as a
    game whose advantage appears on the right-hand side of the final bound. *)

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

(** `choice_type` has no set former, so — as in SSProve's own examples — a set
    is a map to units and `domm` recovers it. *)
Definition chSet t := chMap t 'unit.
Notation " 'set t " := (chSet t) (in custom pack_type at level 2).
Notation " 'set t " := (chSet t) (at level 2) : package_scope.

Definition tt := Datatypes.tt.

Section EUFCMA.

(** The key space is `2^n` for an abstract `n`, so the key can be sampled
    uniformly. Nothing below depends on `n`. *)
Variable (n : nat).

Definition KeyN : nat := 2 ^ n.
Definition Key : choice_type := chFin (mkpos KeyN).

(** THE MESSAGE SPACE — a finite type, and the reason this file was rewritten.
    `MsgB` stays ABSTRACT throughout the game-based tier: every tactic that
    decides an `fset` membership or a `choice_type` equality would otherwise
    meet a concrete `257^76` in unary. It is instantiated exactly once, in
    `Umbra_RealGame`, by applying the finished theorems. *)
Variable (MsgN : nat).
Context {HMsgN : Positive MsgN}.

Definition Msg : choice_type := chFin (mkpos MsgN).

(** THE BOUND IS CARRIED AS A `nat` PLUS A `Positive` INSTANCE, NOT AS A
    `positive`, AND THAT IS NOT COSMETIC. With the bound a bare `positive`
    VARIABLE, `chFin MsgB` is not a constructor application, Equations' derived
    `NoConfusion` for `choice_type` gets stuck on `MsgB = MsgB`, and the
    `eq_rect` that `simplify_eq_rel` leaves behind never reduces —
    `DEV_tt_link` then fails with `Tactic failure: No head found`. Writing the
    bound as `mkpos MsgN` restores the constructor and every SSProve tactic
    used below goes through unchanged. SSProve's own `examples/PRF.v` uses
    `'fin (2^n)`, i.e. the same shape. *)
Notation " 'msg " := (Msg) (in custom pack_type at level 2).
Notation " 'msg " := (Msg) (at level 2) : package_scope.

(** The MAC under attack. An arbitrary keyed function: no structure assumed,
    so the reduction cannot accidentally exploit any. *)
Context (MAC : Key -> nat -> nat).

#[local] Open Scope package_scope.

Definition k_loc : Location := ('option Key ; 0).
Definition S_loc : Location := ('set ('msg × 'nat) ; 1).

Definition gettag : nat := 0.
Definition checktag : nat := 1.

Definition mkpair {Lt Lf E}
  (t : package Lt [interface] E) (f : package Lf [interface] E) :
  loc_GamePair E := fun b => if b then {locpackage t} else {locpackage f}.

(** Lazy key generation: the key is sampled uniformly on first use and cached,
    so both oracles see the same key without the game having an explicit
    setup phase. *)
Definition kgen : raw_code Key :=
  k_init ← get k_loc ;;
  match k_init with
  | None =>
      k <$ uniform KeyN ;;
      #put k_loc := Some k ;;
      ret k
  | Some k => ret k
  end.

Lemma kgen_valid {L I} : k_loc \in L -> ValidCode L I kgen.
Proof.
  move=> H.
  apply: valid_getr => [// | [k|]].
  1: by apply: valid_ret.
  apply: valid_sampler => k.
  apply: valid_putr => //.
  by apply: valid_ret => //.
Qed.

Hint Extern 1 (ValidCode ?L ?I kgen) =>
  eapply kgen_valid ; auto_in_fset : typeclass_instances ssprove_valid_db.

Definition EUF_I :=
  [interface
    #val #[gettag]   : 'msg → 'nat ;
    #val #[checktag] : 'msg × 'nat → 'bool ].

Definition EUF_locs_tt := fset [:: k_loc].
Definition EUF_locs_ff := fset [:: k_loc; S_loc].

(** REAL: verification is the honest MAC check. *)
Definition EUF_pkg_tt : package EUF_locs_tt [interface] EUF_I :=
  [package
    #def #[gettag] (m : 'msg) : 'nat {
      k ← kgen ;;
      ret (MAC k (nat_of_ord m))
    } ;
    #def #[checktag] ('(m, t) : 'msg × 'nat) : 'bool {
      k ← kgen ;;
      ret (t == MAC k (nat_of_ord m))
    }
  ].

(** IDEAL: verification accepts only pairs the tagging oracle issued. An
    adversary distinguishing the two has, by definition, produced a valid tag
    on a message/tag pair that was never issued. *)
Definition EUF_pkg_ff : package EUF_locs_ff [interface] EUF_I :=
  [package
    #def #[gettag] (m : 'msg) : 'nat {
      S ← get S_loc ;;
      k ← kgen ;;
      let t := MAC k (nat_of_ord m) in
      #put S_loc := setm S (m, t) tt ;;
      ret t
    } ;
    #def #[checktag] ('(m, t) : 'msg × 'nat) : 'bool {
      S ← get S_loc ;;
      ret ((m, t) \in domm S)
    }
  ].

Definition EUF_CMA := mkpair EUF_pkg_tt EUF_pkg_ff.

End EUFCMA.

(* ===================================================================== *)
(* MOVING A `nat` INTO THE MESSAGE SPACE                                  *)
(*                                                                        *)
(* The reduction packages read a `nat` off the wire and must hand it to    *)
(* `checktag`, whose argument is now an ordinal. `ord_of_nat` is the total *)
(* map that does it: the identity below the bound, and the canonical zero  *)
(* above it. Keeping it TOTAL is deliberate — the packages then carry no   *)
(* proof argument, and the range side-condition appears where it belongs,  *)
(* as an explicit hypothesis of the perfect-indistinguishability links and *)
(* of the bound itself. *)
(* ===================================================================== *)

Definition ord_of_nat {B : positive} (m : nat) : chFin B :=
  insubd (Ordinal (cond_pos B)) m.

Lemma ord_of_nat_val :
  forall (B : positive) (m : nat),
    (m < B)%N -> nat_of_ord (@ord_of_nat B m) = m.
Proof. move=> B m h. by rewrite /ord_of_nat insubdK. Qed.

(** The section-local `kgen` validity hint does not survive `End`, and
    Umbra_Reduction.v builds packages over the same `kgen`. Re-declare it in
    the generalised form so package elaboration there works without copying
    any definition across the file boundary. *)
Hint Extern 1 (ValidCode ?L ?I (kgen ?n)) =>
  eapply kgen_valid ; auto_in_fset
  : typeclass_instances ssprove_valid_db.
