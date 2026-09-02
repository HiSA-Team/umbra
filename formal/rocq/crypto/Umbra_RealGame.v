(** THE REAL ORACLE — `parse_and_verify` INSIDE SSProve.

    ------------------------------------------------------------------------
    READ THIS FIRST: THE BOUND DOES NOT COVER THE UPDATE BLOB.

    The authenticated message is `msg_of_pkg` — `pkg[4,32)` (nonce, author_id,
    version, blob_len) and `pkg[32,80)` (which is `blob[0,48)`, the FULL 48-byte
    UMBR header, `header.hmac` field included). SEVENTY-SIX BYTES, and nothing
    else. The blob's own body — `blob[48,blob_len)` — is NOT in the HMAC
    preimage, and `parse_and_verify` performs no check on it: it copies
    `blob[0,48)` into its header scratch, tags the fixed core, and returns the
    whole blob unexamined.
    `Umbra_Canonical.blob_body_is_not_covered_by_pkg_tag` (Qed) proves the
    consequence: two packages of equal length agreeing on the authenticated core
    and on the trailing tag have the SAME `msg_of_pkg` and the SAME
    `tag_of_pkg`, however they differ in the blob body.

    So blob integrity is NOT established here. It rests on a second, CHAINED
    HMAC that the firmware computes over the blob and compares against the
    authenticated `header.hmac` window. That component is not part of the
    `umbra-update-core` crate, was not extracted by Aeneas, and is verified
    nowhere in `formal/`. What this development gives it is exactly one thing:
    the 32-byte value it compares against is authenticated. Every reader of the
    phrase "verified secure enclave update" will read blob integrity into it,
    and that reading is wrong.

    ------------------------------------------------------------------------
    WHAT THIS FILE CHANGES. `Umbra_Reduction.v` says of itself: "THIS FILE
    CONTAINS NO UMBRA CONTENT ... it would compile unchanged if
    `parse_and_verify` did not exist", because its `submit` oracle returns a
    tag-verification verdict rather than the device's. Here `submit` returns
    the device's verdict: the oracle body is `ret (accepts ...)`, and
    `accepts` is the Aeneas-extracted `parse_and_verify` (Umbra_Wire.v). This
    file does NOT compile if `parse_and_verify` is removed, and
    `Print Assumptions device_forgery_le_eufcma` lists 50 axioms: 43 Aeneas —
    20 bare uninterpreted backend declarations carrying no proposition, 3
    `usize`/`isize` bound propositions, and all 20 of `Update_Safety`'s
    quarantine laws, every one discharged against the concrete list model in
    `Update_Model.v` — alongside SSProve's own 7-axiom base. (An earlier
    revision of this header said 42/22; both figures were wrong. Re-measured.)

    ------------------------------------------------------------------------
    (a) WHAT SSPROVE REQUIRES OF AN ORACLE, AND WHAT IT DOES NOT.

    `pkg_core_definition.v:41`  `Definition opsig := ident * (choice_type * choice_type).`
    `pkg_core_definition.v:92`  `Inductive raw_code (A : choiceType) := | ret (x : A) | ...`
    `pkg_notation.v:208`        `#def #[f] (x : A) : B { e }`, `A B` in `custom pack_type`.

    So the requirement is on the oracle's ARGUMENT and RESULT TYPES only: they
    must be `choice_type` codes. There is NO requirement that the function
    computing the result be a morphism of choice structures, be computable, or
    even reduce: `ret` takes any inhabitant of `chElement B`. An oracle may
    therefore apply an arbitrary total Coq function to its argument — including
    one whose definition unfolds to `Primitives`' AXIOMS.

    That is the whole trick, and it is why the type obstruction everyone
    (including `Umbra_Reduction.v`'s own header) expected is not there. An
    Aeneas `slice u8` genuinely is not a `choice_type` and cannot be made one.
    But it does not need to be. `chList chNat` is a `choice_type`; the
    adversary submits the WIRE BYTES, which is what a real attacker actually
    controls, and `Umbra_Wire.wire` marshals them into `slice u8` inside the
    oracle body.

    ------------------------------------------------------------------------
    (b) WHERE THE REAL OBSTRUCTION IS: SIMULABILITY, NOT TYPING.

    A reduction to EUF-CMA holds no key. To answer a `submit` query with the
    DEVICE'S verdict it would have to run `parse_and_verify`, which HMACs. It
    cannot. So a key-less `RED` can only answer with `checktag`'s verdict — and
    that is exactly the relaxation that made `Umbra_Reduction.v` vacuous.

    The only way out is to FACTOR the device's verdict into a key-free part and
    a single tag check:

      accepts key p  =  struct_ok p  &&  (wtag p == MAC k (widx p))          (F)

    with `struct_ok` key-free. Then `RED` answers `submit p` by querying
    `checktag (widx p, wtag p)` and conjoining `struct_ok p`, which simulates
    BOTH sides perfectly, and the bound follows. (`widx` was `wmsg` until the
    message space was re-indexed at the byte-valid subimage; the two agree
    through `spread` wherever `struct_ok` holds, which is the only place (F)
    says anything.)

    (F) IS NOW A THEOREM. It was a section `Hypothesis` in every earlier
    revision of this file, and that hypothesis was the single thing standing
    between the development and an end-to-end machine-checked bound: its
    left-to-right half was free (`Umbra_Wire.wire_accept_implies_submit_true`,
    Qed) but its CONVERSE half — structural guards plus a matching tag imply
    acceptance — was assumed, as was the existence of a concrete `struct_ok`.
    Both are now proved over the verbatim extracted body:

      `Update_Converse.accept_implies_struct` — acceptance implies branches 1–5
          of `parse_and_verify` (length, magic, `blob_len >= MIN_BLOB`, offset
          consistency, nonce comparison), each as an equation on package BYTES;
      `Update_Converse.parse_walk` — those same five guards drive the body to a
          SINGLE tag comparison, over a preimage that assembles this package's
          fields and encodes to `msg_of_pkg`;
      `Update_Value.ct_eq16_complete` / `ct_eq32_complete` — the comparators'
          converse direction (equal bytes ⇒ verdict `true`), which did not
          exist before and is the only genuinely new proof engineering;
      `Umbra_WireConverse.wstruct_ok` — the concrete key-free `struct_ok`,
          proved equal to branches 1–5 by `wstruct_ok_iff`.

    `Hfactorise` below is the resulting Lemma. Nothing about it is assumed.

    ------------------------------------------------------------------------
    (c) WHAT IS STILL ASSUMED HERE, AND WHAT IT IS NOT. Two named seams
    survive, both inherited verbatim from the deterministic tier: C1
    (`SeamC1` — the HMAC seam is a deterministic function of key material and
    preimage, satisfied by the constant function) and C1e (`SeamC1e` — the seam
    reads its input as BYTES, and `dkey k` is the device-side realisation of
    the game key `k`). Neither carries unforgeability;
    `Umbra_DeviceLink.unguarded_C1e_forces_label_obliviousness` shows why C1e's
    `AssemblesF` guard is necessary and `Umbra_WireConverse.SeamC1e_realisable`
    shows C1e is instantiable, so neither is vacuous. The probability content is
    still carried entirely by SSProve's relational logic in the two links
    below; the seams are equations between `bool`s and byte encodings and
    mention no distribution, adversary or advantage.

    ------------------------------------------------------------------------
    (d) WHAT `MAC` IS, AND WHY THAT USED TO BE THE LARGEST GAP. `MAC` is a
    section `Context` variable: the bound holds for whatever `MAC` satisfies
    C1e. Until the canonical-realiser revision the ONLY exhibited witness came
    from `ClassicalEpsilon`, which pins `MAC` to the seam on the image of the
    assembled encoding and leaves it arbitrary everywhere else — so the
    inference "HMAC-SHA256 is EUF-CMA-secure, therefore the right-hand side is
    small" was NOT licensed by anything in the development.

    It is now. `MAC_canonical` (bottom of this file) is a computed definition:
    the seam at the device's key bytes, applied to the canonical 91-byte
    decoding of the message, at EVERY argument.
    `device_forgery_le_eufcma_at_the_real_seam` instantiates the bound at it,
    under the premise `Umbra_Canonical.ByteSeam` (the engine is a function of
    the key bytes and the preimage bytes — the constant function satisfies it,
    so it carries no unforgeability).
    `Umbra_Canonical.canon91_injective` proves the message encoding injective on
    the protocol's message range, which is the shape under which an EUF-CMA
    assumption on the engine transfers to it. `MAC_canonical` has since been
    split in two: `MACb_canonical` is the base MAC C1e ties to the seam, and
    the GAME's MAC is `MACg` at it, i.e. `Umbra_ByteSpace.MG_spread` — the same
    engine, indexed by the byte-valid subimage. See the next paragraph.

    WHAT PINNING EXPOSED, AND WHY THE MESSAGE SPACE IS FINITE. Pinning the MAC
    made a modelling defect exhibitable. When the game's message space was `nat`
    the pinned MAC provably collided — `Umbra_Canonical.MG_of_collides_above_
    range` (Qed, NO hypothesis on the seam) gives `MAC k m = MAC k (m + 257^76)`
    — so an adversary queried `gettag m`, submitted `checktag (m + 257^76, t)`,
    and separated the two packages with advantage 1. The bound was TRUE and
    VACUOUS: its right-hand side was 1, and no assumption about HMAC-SHA256
    could make it small.

    The message space is now `Umbra_EUFCMA.Msg`, i.e. `chFin` at a bound, and
    the bound is `MSGB = 256^76` (bottom of this file). The collision theorem is
    unchanged and still true; it is simply no longer playable.

    IT WAS `257^76` FOR ONE REVISION, AND THAT WAS THE WRONG SET. `257^76`
    counts 76-digit base-257 NUMERALS, and base-257 digit `256` is
    `Update_Encoding.rdA`'s OUT-OF-RANGE SENTINEL. So on 25.64 % of that space
    `canon91` produced a 91-element list containing `256` — provably not
    `bytes91` of any array — and `ByteSeam` constrained `mb` there NOWHERE.
    `Umbra_WireConverse.restricted_space_still_admits_a_broken_seam_at_MSGBn`
    and `dead_zone_collides_with_any_live_message_at_MSGBn` (both Qed, 10
    quarantine axioms, no classical anything) build, from ANY `mb0` the premise
    admits, another `mb` the premise also admits which agrees with `mb0` at
    every genuine byte list — the same real engine everywhere the engine is
    defined — and under which the pinned MAC collides inside the game's own
    message space. The adversary: `dsign 256` → `t`; submit a package encoding
    to a live `m0` carrying `t`; `RED_dev` asks `checktag (m0, t)`; real says
    true, ideal says false. ADVANTAGE 1. Those theorems are KEPT in the tree.
    They are the honest record of what the previous revision shipped.

    `256^76` IS THE FIX. `Umbra_ByteSpace.spread` is the inclusion of the
    76-digit base-256 numerals into the base-257 ones — same digits, different
    radix — and `spread_canon91_allbytes` (Qed) proves that every message of the
    new space decodes to ninety-one GENUINE BYTES, the fifteen label positions
    included. The patching construction therefore has nothing to patch
    (`Umbra_WireConverse.msg_space256_preimages_are_bytes`), and under the one
    named premise `Umbra_ByteSpace.ArrayVectors` it is REFUTED rather than
    merely unbuilt: `msg_space256_pins_the_seam` (Qed) says any two seams the
    premise admits give the SAME pinned MAC at every message of the space, and
    `patching_cannot_create_a_collision_at_MSGB256n` (Qed) that no choice of
    conforming seam creates a collision the engine did not already have.

    `game_messages_have_distinct_preimages` (Qed) is the positive form of
    non-vacuity: distinct messages of the game's message space decode to
    distinct 91-byte preimages, so every in-range collision of the abstract MAC
    is a collision OF THE ENGINE at two distinct inputs — the event an EUF-CMA
    assumption bounds. It is NOT injectivity of `MG_of`, which is false for
    every seam. `game_messages_decode_to_bytes` (Qed) is what the re-indexing
    adds: those preimages are BYTE VECTORS, at every message, unconditionally.

    Nothing on the LEFT-hand side was given up ON THE SUBMISSION ORACLE:
    `dsubmit` still takes an arbitrary `'list 'nat`. Where the `257^76`
    indexing needed `msg_of_pkg_lt` to bound the wire message, the byte-valid
    indexing needs nothing at all: the submission is read through
    `Umbra_WireConverse.widx`, which is `shrink` of the wire message and lands
    in `[0, 256^76)` BY CONSTRUCTION (`widx_lt_MSGB256n`, Qed). The clamp inside
    `shrink` can only fire on packages the key-free structural guards already
    reject, because an accepted package is at least 112 bytes long and every
    read the encoding performs is then in bounds — that is
    `wstruct_ok_msg_is_byte_valid` (Qed), and `widx_spreads_back` (Qed) is the
    consequence: on an accepted package the index spreads back to exactly the
    message the device authenticates.

    ONE THING THE RESTRICTION DOES NARROW, AND IT IS LOAD-BEARING. The SIGNING
    oracle `dsign` takes a `'msg` rather than a `'nat`, so the modelled
    adversary cannot ask the signing service to tag a message outside the space.
    That is a narrower adversary class, and the narrowing is doing real work: an
    adversary that CAN get an out-of-range message signed WINS WITH ADVANTAGE 1
    against the pinned MAC. Not a conjecture —
    `Umbra_Canonical.MG_of_collides_above_range` (Qed, in this directory, with
    NO hypothesis on the seam) gives `MAC k m = MAC k (m + 257^76)` for every
    seam whatever, so `gettag m` followed by `checktag (m + 257^76, t)`
    separates the two packages outright. The justification for excluding that
    adversary is now sharper than it was: the space is exactly the set of
    76-BYTE authenticated cores, which is exactly what a real signing service
    signs. It remains a modelling choice, not a theorem.

    ------------------------------------------------------------------------
    (e) SCOPE LIMITS THIS FILE INHERITS AND DOES NOT RESTATE ELSEWHERE.
      * `AeneasLoopShim.loop = loop_fuel 1000000`. The Coq backend omits
        Aeneas's loop combinator, so the shim supplies a FUEL-BOUNDED one.
        Every "total" statement about the extracted code therefore means
        "terminates within 10^6 iterations". The parser's loops are 16- and
        32-iteration byte comparisons, so the bound is never approached — but
        it is a bound, and it is part of the model.
      * `Umbra_Wire.MAX_PKG = 65536`, exactly the N657 Secure scratch bound.
        The adversary's `list nat` submission is truncated there, matching the
        firmware front gate; packages beyond the device limit are rejected by
        the implementation and outside the modelled attack surface.
      * `dkey`, the game-key-to-key-material map, is otherwise unconstrained;
        see `Hdkey_inj` below for what injectivity buys and what is still
        prose. `Hdkey_inj` is DOCUMENTATION: it is not in the closed type of
        either bound.
      * `ByteSeam` pins the engine's byte function only where `bytes91`
        reaches, and `mb` returns the tag's base-257 ENCODING rather than the
        `array u8 32`. Both are forced by `Primitives.array_index_usize` being
        a bare axiom, so that no constructible array has known reads; see the
        note at `Umbra_Canonical.MG_of`. After the re-indexing this is a
        SINGLE NAMED PREMISE and no longer an exhibitable defect:
        `Umbra_ByteSpace.ArrayVectors` — every 91-element list of bytes is
        some array's read-sequence — is what would close it, it is true of
        Rust, it is unprovable against a bare `array_index_usize`, and it does
        NOT appear in the closed type of the bound. A reader who declines to
        grant it gets a bound over a class of seams on which no counterexample
        is constructible; a reader who grants it gets the engine, pinned. *)

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
From UmbraCrypto Require Import Umbra_Canonical.
From UmbraCrypto Require Import Umbra_ByteSpace.
From UmbraCrypto Require Import Umbra_ArrayVectors.
From UmbraCrypto Require Import Umbra_Wire.
From UmbraCrypto Require Import Umbra_WireConverse.

(** `chList` has no shorthand in SSProve's `pack_type` custom entry. It is a
    `choice_type` constructor like any other; this is the missing notation. *)
Notation " 'list x " := (chList x) (in custom pack_type at level 2).
Notation " 'list x " := (chList x) (at level 2) : package_scope.

Section DeviceForgery.

Variable (n : nat).

(** THE MESSAGE SPACE OF THE GAME — a `nat` bound plus its `Positive` instance,
    exactly as in `Umbra_EUFCMA.v`, and abstract for the same two reasons: the
    derived `NoConfusion` for `choice_type` only reduces when the bound is a
    constructor application, and a concrete `257^76` would be a unary numeral
    with ~10^144 successors. It is instantiated at the bottom of this file. *)
Variable (MsgN : nat).
Context {HMsgN : Positive MsgN}.

Notation " 'msg " := (Msg MsgN) (in custom pack_type at level 2).
Notation " 'msg " := (Msg MsgN) (at level 2) : package_scope.

(** THE ABSTRACT MAC, AT THE ENCODING'S OWN INDEXING. `MACb` is what C1e ties
    to the seam: a function of the base-257 message integer, which is the shape
    `Umbra_WireConverse.SeamC1e` speaks. It is NOT the game's MAC. *)
Context (MACb : Key n -> nat -> nat).

(** THE GAME'S MAC, AT THE BYTE-VALID INDEXING. The game's message space is now
    `256^76`, the messages that CONSIST OF BYTES, and `spread_idx` is the
    inclusion into the base-257 numerals: same seventy-six digits, different radix.

    WHY. `Umbra_Canonical`'s dead-zone section proves that indexing the game by
    `257^76` leaves 25.64 % of the space where `ByteSeam` constrains nothing and
    a seam satisfying the premise loses the game outright. `Umbra_ByteSpace.
    spread_canon91_allbytes` (Qed) is what changes: every message of THIS space
    decodes to ninety-one genuine bytes, so the patched-seam construction has
    nothing to patch. *)
Definition MACg (k : Key n) (j : nat) : nat := MACb k (spread_idx j).

#[local] Open Scope package_scope.

(* --------------------------------------------------------------------- *)
(* THE DEVICE                                                             *)
(* --------------------------------------------------------------------- *)

Context {HS : Type}.

(** The extracted parser's HMAC instance and handle, and the expected
    anti-rollback nonce the device is provisioned with. *)
Variable inst : hmac_inst HS.
Variable hs   : HS.
Variable en   : list nat.

(** THE KEY CORRESPONDENCE, MADE EXPLICIT. The game samples `k : Key n`; the
    device holds key MATERIAL of type `slice u8`. `dkey` is the provisioning
    map. `Umbra_DeviceLink.v` left this implicit — its `k0` was a section
    variable with, in its own words, "no Coq object identifying it with the
    game's `k`". Naming the map is what lets the device's verdict depend on
    the SAMPLED key, which is what a probability statement needs. *)
Variable dkey : Key n -> key_bytes.

(** THE TWO SEAMS THE DETERMINISTIC TIER ALREADY CARRIES, and nothing else.

    C1 (`SeamC1`) says the HMAC seam is a deterministic function of key material
    and preimage — the constant function satisfies it, so it carries no
    unforgeability. C1e (`SeamC1e`) says the seam's output depends only on the
    BYTE VALUES of an assembled preimage, and that the device's provisioned key
    material `dkey k` realises the game key `k`; `Umbra_DeviceLink.v` documents
    at length why the `AssemblesF` guard is load-bearing and why the unguarded
    form would be FALSE at a real HMAC. `Umbra_WireConverse.SeamC1e_realisable`
    proves a uniform C1e EXISTS, so this is not vacuous. *)
Variable macf : macf_t.
Hypothesis Hseam  : SeamC1 inst hs macf.
Hypothesis Hfactor : forall k : Key n, SeamC1e macf (dkey k) (MACb k).

(** THE PROVISIONING MAP IS INJECTIVE — stated at byte-value granularity,
    because term equality of `slice u8` is not available in this development
    (`u8` is a sigma over a `Prop`; see `Umbra_Wire.v`'s header).

    WHY IT IS HERE. The bound below does NOT need it: `device_forgery_le_eufcma`
    holds for any `dkey`, and Coq's section generalisation confirms this by not
    quantifying over `Hdkey_inj` in that theorem's closed type. What needs it is
    the READING of the bound. `Umbra_Canonical.MG_of` — the canonical realiser
    of C1e — sees the key only through `kbytes`, so if `dkey` collapses two game
    keys onto one key string then those two game keys are literally the same
    abstract MAC (`Umbra_Canonical.MG_of_collapses_on_equal_key_bytes`), and the
    game's `uniform KeyN` sampling ranges over fewer than `2^n` distinct HMAC
    keys. In the extreme, a constant `dkey` makes the right-hand side the
    advantage against ONE fixed key, which is not what any EUF-CMA assumption
    about HMAC-SHA256 asserts.

    WHAT IS AND IS NOT ESTABLISHED. `dkey_faithful` below is the whole formal
    content: distinct game keys are provisioned to distinct key strings, so the
    key material the device holds ranges over exactly `2^n` values as `k` does.
    The measure-theoretic step from there — that the pushforward of `uniform
    KeyN` along an injection is uniform on the image, hence that the RHS is an
    HMAC advantage under a uniform key — is NOT formalised. It is stated here so
    the reader can see where it is being taken on faith.

    SO: THIS HYPOTHESIS IS DOCUMENTATION, AND SHOULD NOT BE QUOTED AS ANYTHING
    ELSE. It is not load-bearing. `Check device_forgery_le_eufcma` and `Check
    device_forgery_le_eufcma_at_the_real_seam` show it absent from both closed
    types; the only way to make it load-bearing would be to formalise the
    pushforward step above, which this development does not attempt. *)
Hypothesis Hdkey_inj :
  forall k k' : Key n, kbytes (dkey k) = kbytes (dkey k') -> k = k'.

Theorem dkey_faithful : forall k k' : Key n,
  k <> k' -> kbytes (dkey k) <> kbytes (dkey k').
Proof. move=> k k' Hne Heq. by apply: Hne; apply: Hdkey_inj. Qed.

(** The key-free part of the device's acceptance test: magic, length and offset
    guards and the nonce comparison — everything `parse_and_verify` checks
    before it HMACs. NOT a section variable any more: this is the concrete
    boolean of `Umbra_WireConverse`, and `wstruct_ok_iff` (Qed) proves it is
    branches 1–5 of the extracted parser. *)
Definition struct_ok : list nat -> bool := wstruct_ok en.

(** THE DEVICE'S VERDICT — the extracted `parse_and_verify`, nothing else. *)
Definition dev_accepts (k : Key n) (p : list nat) : bool :=
  accepts inst hs (dkey k) en p.

Lemma bool_eq_iff : forall b1 b2 : bool, (b1 = true <-> b2 = true) -> b1 = b2.
Proof.
  move=> b1 b2 H. case: b1 H; case: b2 => H //.
  - exfalso. by discriminate (proj1 H erefl).
  - exact (proj2 H erefl).
Qed.

(** (F), NO LONGER AN ASSUMPTION.

    This was a section `Hypothesis` until `Update_Converse.v` closed the
    converse-parser obligation. It is now `Umbra_WireConverse.wire_accept_
    factorises` — a theorem about the extracted body, whose two halves are
    `accept_implies_struct` (acceptance implies branches 1–5) and `parse_walk`
    (branches 1–5 drive the body to the tag gate), both Qed over
    `Update_Funs.parse_and_verify`.

    STATED POINTWISE, which is the weakest form that does the job. An earlier
    draft stated it as an equation between FUNCTIONS, because that lets
    `rewrite` reach under the sampler's binder in `DEV_tt_link`; without
    `functional_extensionality` that form is strictly stronger, so it is not
    used. `DEV_tt_link` opens the binder with `rsame_head_cmd` instead. *)
(** THE INDEX AGREES WITH THE ENCODING WHERE THE GUARDS HOLD. `MACg` is
    `MACb` at the spread index; on a package the structural guards accept, the
    spread index IS the encoded message (`Umbra_WireConverse.widx_spreads_back`,
    Qed, whose content is that an accepted package is at least 112 bytes long,
    so every read the encoding performs is in bounds and returns a byte rather
    than `rdS`'s sentinel). Off the guards nothing is claimed, and nothing needs
    to be: `struct_ok p` gates both sides of the factorisation. *)
Lemma MACg_at_accepted : forall (k : Key n) (p : list nat),
  struct_ok p = true -> MACg k (widx p) = MACb k (wmsg p).
Proof.
  move=> k p Hok. rewrite /MACg.
  by rewrite (widx_spreads_back en p Hok).
Qed.

Lemma Hfactorise :
  forall (k : Key n) (p : list nat),
    dev_accepts k p = struct_ok p && (wtag p == MACg k (widx p)).
Proof.
  move=> k p. apply: bool_eq_iff.
  rewrite /dev_accepts.
  split.
  - move=> Hacc.
    case: (proj1 (wire_accept_factorises inst hs (dkey k) macf Hseam
                    (MACb k) (Hfactor k) en p) Hacc) => H1 H2.
    have H1' : struct_ok p = true by rewrite /struct_ok.
    rewrite H1' /=. apply/eqP. by rewrite (MACg_at_accepted k p H1').
  - move=> /andP [H1 /eqP H2].
    apply: (proj2 (wire_accept_factorises inst hs (dkey k) macf Hseam
                     (MACb k) (Hfactor k) en p)).
    split; first by rewrite -/(struct_ok p).
    by rewrite H2 (MACg_at_accepted k p H1).
Qed.

Lemma Hfactorise_at : forall (k : Key n) (p : list nat),
  accepts inst hs (dkey k) en p = struct_ok p && (wtag p == MACg k (widx p)).
Proof. move=> k p. exact: Hfactorise. Qed.

(** THE ASSUMPTION BUDGET, MADE CHECKABLE. `Hfactorise` implies the forward
    link — and `Umbra_Wire.forward_link_holds` (Qed) proves that SAME
    predicate from C1 and C1e alone, with no `Hfactorise` anywhere. So the two
    agree where they overlap, and the genuinely new content of `Hfactorise` is
    exactly what is left over: the CONVERSE (structural guards plus a matching
    tag imply acceptance) and the existence of a concrete key-free
    `struct_ok`. That is the "converse parser" obligation and nothing more. *)
Lemma factorise_gives_forward : forall k : Key n,
  ForwardLink inst hs (dkey k) en (MACb k).
Proof.
  move=> k p Hacc.
  case: (proj1 (wire_accept_factorises inst hs (dkey k) macf Hseam
                  (MACb k) (Hfactor k) en p) Hacc) => _ H2.
  exact: H2.
Qed.

(* --------------------------------------------------------------------- *)
(* THE GAME                                                               *)
(* --------------------------------------------------------------------- *)

(** THE MESSAGE BOUND COVERS THE WIRE ENCODING. This is the ONE side-condition
    the restricted message space costs, and it is discharged at the bottom of
    this file by `wmsg_lt_MSGB` (Qed), which is `Umbra_WireConverse.
    wmsg_in_range` transported from `Z` to `ssrnat`. It is a hypothesis rather
    than a package parameter so that it appears in the closed type of the
    bound, where a reader can see it. *)
Hypothesis Hrange : forall p : list nat, (widx p < MsgN)%N.

(** The wire message's INDEX, as an element of the game's message space.
    `ord_of_nat` is total — it clamps above the bound — and `Hrange` says the
    clamp never fires, so `widx_ord_val` below is an equation, not an
    approximation. Unlike the `257^76` indexing, `Hrange` here is discharged
    with no fact about the package at all: `shrink` lands in `[0, 256^76)` by
    construction (`Umbra_WireConverse.widx_lt_MSGB256n`, Qed). *)
Definition widx_ord (p : list nat) : Msg MsgN :=
  @ord_of_nat (mkpos MsgN) (widx p).

Lemma widx_ord_val : forall p : list nat, nat_of_ord (widx_ord p) = widx p.
Proof.
  move=> p. rewrite /widx_ord.
  exact: (ord_of_nat_val (mkpos MsgN) (widx p) (Hrange p)).
Qed.

Definition dsign   : nat := 2.
Definition dsubmit : nat := 3.

(** The adversary submits WIRE BYTES. `'list 'nat` is a `choice_type`; a
    package of at most `Umbra_Wire.MAX_PKG` bytes is exactly a value of it,
    and `Umbra_Wire.wire_bytes` (Qed) shows the marshalling preserves the byte
    values, so nothing on the wire is unreachable. *)
Definition DEV_I :=
  [interface
    #val #[dsign]   : 'msg → 'nat ;
    #val #[dsubmit] : 'list 'nat → 'bool ].

(** REAL: the device runs the extracted parser on what the adversary sent. *)
Definition DEV_pkg_tt : package (EUF_locs_tt n) [interface] DEV_I :=
  [package
    #def #[dsign] (m : 'msg) : 'nat {
      k ← kgen n ;;
      ret (MACg k (nat_of_ord m))
    } ;
    #def #[dsubmit] (p : 'list 'nat) : 'bool {
      k ← kgen n ;;
      ret (dev_accepts k p)
    }
  ].

(** THE IDEAL DEVICE'S VERDICT, AS A NAMED FUNCTION.

    Named rather than inlined for ONE reason, and it is not tidiness.
    `Umbra_Union.v`'s third disjunct is `ideal_verdict S p = false`, and the
    entire load-bearing claim of that file is that this disjunct IS the game's
    own rejection event rather than a re-modelled lookalike. If the ideal
    oracle inlined its body and `Umbra_Union.v` transcribed it, the two could
    drift apart under any later edit and nothing in the kernel would notice —
    a claim carried by comment instead of by typechecking, which is the exact
    class of gap this development has already been bitten by. `DEV_pkg_ff`
    below returns this function, so they cannot diverge.

    Note the asymmetry this removes: the REAL side was already tied, because
    `dev_accepts` is the very definition `DEV_pkg_tt` invokes. *)
Definition ideal_verdict (S : S_loc MsgN) (p : list nat) : bool :=
  struct_ok p && ((widx_ord p, wtag p) \in domm S).

(** IDEAL: the device additionally refuses any package whose (core, tag) pair
    the signing service never issued. Distinguishing the two IS getting the
    real device to accept an unsigned package. *)
Definition DEV_pkg_ff : package (EUF_locs_ff n MsgN) [interface] DEV_I :=
  [package
    #def #[dsign] (m : 'msg) : 'nat {
      S ← get (S_loc MsgN) ;;
      k ← kgen n ;;
      let t := MACg k (nat_of_ord m) in
      #put (S_loc MsgN) := setm S (m, t) tt ;;
      ret t
    } ;
    #def #[dsubmit] (p : 'list 'nat) : 'bool {
      S ← get (S_loc MsgN) ;;
      ret (ideal_verdict S p)
    }
  ].

Definition DEV := mkpair DEV_pkg_tt DEV_pkg_ff.

(** THE REDUCTION. Key-less and stateless. It reads the wire package with the
    CONCRETE readers `wmsg`/`wtag` — not the abstract `msgN`/`tagN` of
    `Umbra_Reduction.v` — and conjoins the key-free structural guards. *)
Definition RED_dev : package fset0
  [interface
    #val #[gettag]   : 'msg → 'nat ;
    #val #[checktag] : 'msg × 'nat → 'bool ]
  DEV_I :=
  [package
    #def #[dsign] (m : 'msg) : 'nat {
      #import {sig #[gettag] : 'msg → 'nat } as gt ;;
      t ← gt m ;;
      ret t
    } ;
    #def #[dsubmit] (p : 'list 'nat) : 'bool {
      #import {sig #[checktag] : 'msg × 'nat → 'bool } as ct ;;
      b ← ct (widx_ord p, wtag p) ;;
      ret (struct_ok p && b)
    }
  ].

Lemma DEV_tt_link : DEV true ≈₀ RED_dev ∘ EUF_CMA n MsgN MACg true.
Proof.
  apply: eq_rel_perf_ind_eq.
  simplify_eq_rel m.
  all: apply rpost_weaken_rule with eq;
    last by move=> [? ?] [? ?] [].
  all: simplify_linking.
  all: simplify_linking.
  all: ssprove_code_simpl.
  all: ssprove_sync_eq.
  all: case => [k|].
  (* Key already cached: the two `ret`s differ by exactly `Hfactorise`. *)
  1,3: rewrite ?widx_ord_val ?Hfactorise; by apply: rreflexivity_rule.
  (* Key sampled here. `ssprove_sync_eq`'s pattern does not match a bare
     `sampler`, and `rewrite` cannot reach under its binder, so open the
     sampler and the `put` by hand and rewrite inside. *)
  all: eapply (rsame_head_cmd (cmd_sample _)) => a.
  all: eapply (@rsame_head_cmd _ _ (fun z => _) (fun z => _) (cmd_put _ _)) => z.
  all: rewrite ?widx_ord_val ?Hfactorise; by apply: rreflexivity_rule.
Qed.

Lemma DEV_ff_link : DEV false ≈₀ RED_dev ∘ EUF_CMA n MsgN MACg false.
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

(** THE BOUND, OVER THE EXTRACTED PARSER.

    Unlike `Umbra_Reduction.update_forgery_le_eufcma`, the left-hand side is a
    game whose `submit` oracle IS `Update_Funs.parse_and_verify`. Removing the
    extracted code removes this statement. *)
Theorem device_forgery_le_eufcma :
  forall LA (A : raw_package),
    ValidPackage LA DEV_I A_export A ->
    fdisjoint LA (EUF_locs_tt n :|: EUF_locs_ff n MsgN) ->
    Advantage DEV A <= Advantage (EUF_CMA n MsgN MACg) (A ∘ RED_dev).
Proof.
  move=> LA A vA H.
  rewrite Advantage_E Advantage_E Advantage_link.
  ssprove triangle (DEV false) [::
    RED_dev ∘ EUF_CMA n MsgN MACg false ;
    RED_dev ∘ EUF_CMA n MsgN MACg true
  ] (DEV true) A as ineq.
  apply: le_trans; first by apply: ineq.
  rewrite !fdisjointUr in H.
  move: H => /andP [H1 H2].
  rewrite DEV_ff_link ?fdisjointUr ?H1 ?H2 ?fdisjoints0 //.
  rewrite (Advantage_sym (RED_dev ∘ EUF_CMA n MsgN MACg true) (DEV true) A).
  rewrite DEV_tt_link ?fdisjointUr ?H1 ?H2 ?fdisjoints0 //.
  by rewrite GRing.add0r GRing.addr0.
Qed.

End DeviceForgery.

(* ===================================================================== *)
(* THE MESSAGE BOUND, MADE CONCRETE                                       *)
(*                                                                        *)
(* Everything above is stated at an ABSTRACT bound `MsgN`. This section    *)
(* supplies the bound the protocol actually needs — `256^76`, the number   *)
(* of 76-BYTE authenticated cores — and discharges the one side-condition  *)
(* the restricted game carries.                                            *)
(*                                                                        *)
(* IT USED TO BE `257^76`, AND THAT WAS WRONG. `257^76` counts 76-digit    *)
(* base-257 NUMERALS, and base-257 digit 256 is `Update_Encoding.rdA`'s    *)
(* out-of-range sentinel: 25.64 % of that space decodes to a 91-element    *)
(* list containing 256, which is provably not `bytes91` of any array, so   *)
(* `ByteSeam` constrains the seam there NOWHERE. `Umbra_WireConverse.      *)
(* restricted_space_still_admits_a_broken_seam_at_MSGBn` (Qed) turns that  *)
(* hole into an adversary with advantage 1. The counterexample is kept in  *)
(* the tree; this section is the fix.                                      *)
(*                                                                        *)
(* THE SIDE-CONDITION IS NOW FREE. At `257^76` it was `wmsg p < MSGB`,     *)
(* which needed `msg_of_pkg_lt`. At `256^76` it is `widx p < MSGB`, and    *)
(* `widx` is `shrink` of the wire message, which lands in the space BY     *)
(* CONSTRUCTION. Nothing about the package is used.                        *)
(*                                                                        *)
(* THE NUMERAL IS NEVER EVALUATED, AND THAT IS DELIBERATE. As a `nat` it   *)
(* is a unary numeral with ~10^144 successors, so every proof below keeps  *)
(* it behind `Z.to_nat` and reasons in `Z`.                                *)
(*                                                                        *)
(* THE `Positive` INSTANCE IS PASSED EXPLICITLY — BUT NOT BECAUSE          *)
(* RESOLUTION HANGS. An earlier revision of this header said typeclass     *)
(* resolution, "whose first hint for `Positive` is `reflexivity`", would   *)
(* try to evaluate the bound and never return. MEASURED: it does not.      *)
(* `Definition probe : Positive MSGB256n := _.` resolves to `erefl`,       *)
(* kernel                                                                  *)
(* check included, in about a second. The explicit instance is kept        *)
(* because it makes the instantiated statements say WHICH positivity proof *)
(* is in their closed type, which matters when a reader checks the closed  *)
(* type — not because the alternative diverges. See                        *)
(* `Umbra_WireConverse.v`'s header for the two shape constraints that ARE  *)
(* real (`mkpos` vs a bare `positive`; `MSGB` as a `Notation`) and the two *)
(* that were claimed and are refuted.                                      *)
(* ===================================================================== *)

(** A NOTATION, NOT A DEFINITION, AND THIS ONE IS GENUINELY LOAD-BEARING —
    re-confirmed, unlike two neighbouring claims that were not. With `MSGB` a
    `Definition`, every proof below needs `rewrite /MSGB` to see the bound, and
    ssreflect's `rewrite /c` normalises beta-iota after the delta step — which
    on `Z.to_nat (256^76)` does not return (measured at the v1 bound `257^60`:
    2 m 38 s and 1.16 GB on `game_msg_lt`, still climbing when killed, before
    `Qed` is even reached; `256^76` is LARGER as a unary numeral). A notation is expanded
    at parse time and no tactic ever has to unfold anything. *)
Notation MSGB := MSGB256n.

Section RealMessageSpace.

(** `ZArith` IS DELIBERATELY NOT IMPORTED HERE. Its `N_scope` steals mathcomp's
    `%N` delimiter, and `(wmsg p < MsgN)%N` then becomes a statement about
    binary naturals. Every `Z`-level fact below is therefore proved next door in
    `Umbra_WireConverse.v` (bare Coq) and imported at `Peano` comparisons, which
    `ltP` converts in one step. *)
Lemma MSGB_positive : Positive MSGB.
Proof. rewrite /Positive. apply/ltP. exact: MSGB256n_pos. Qed.

(** THE SIDE-CONDITION OF THE BOUND, DISCHARGED — and, unlike its predecessor,
    with no fact about the package. `Umbra_WireConverse.widx_lt_MSGB256n` (Qed)
    is `shrink_range` transported to `ssrnat`; `shrink` lands in `[0, 256^76)`
    by construction. *)
Lemma widx_lt_MSGB : forall p : list nat, (widx p < MSGB)%N.
Proof. move=> p. apply/ltP. exact: widx_lt_MSGB256n. Qed.

(** Every element of the game's message space is below the bound. Stated at
    `%coq_nat` because that is the comparison the Tier-D lemmas next door use —
    in a mathcomp file `%nat` is `ssrnat`'s `leq`, not Peano's `lt`. *)
Lemma game_msg_lt : forall m : @Msg MSGB MSGB_positive,
  (nat_of_ord m < MSGB)%coq_nat.
Proof. move=> m. apply/ltP. exact: ltn_ord. Qed.

(** THE NON-VACUITY CERTIFICATE, AT THE GAME'S OWN MESSAGE SPACE — AND, SINCE
    the re-indexing, the DEAD-ZONE certificate as well.

    Two things are now true of every message of `'fin MSGB`, and the second is
    what the previous revision could not state.

    (i) DISTINCT MESSAGES HAVE DISTINCT PREIMAGES. Over `nat` the abstract MAC
    collided with period `257^76` (`Umbra_Canonical.MG_of_collides_above_range`,
    Qed, no hypothesis at all); over `'fin MSGB` that adversary has nowhere to
    go, and a collision of the pinned MAC is a collision OF THE ENGINE at two
    distinct 91-byte inputs — the event an EUF-CMA assumption bounds.

    (ii) EVERY PREIMAGE IS A GENUINE BYTE VECTOR. This is what indexing by
    `256^76` rather than `257^76` buys. At `257^76`, 25.64 % of the space
    decoded to a list containing `256` — not a byte, hence not `bytes91` of any
    array, hence a point where `ByteSeam` said nothing and a conforming seam
    could be patched to lose the game outright. That set is now unreachable.

    WHAT NEITHER IS. Neither is injectivity of the pinned MAC, and no such
    theorem can be proved: it ends in a 32-byte tag and starts from `256^76`
    messages, so it collides by pigeonhole for every seam, exactly as a real
    HMAC does. *)
Theorem game_messages_have_distinct_preimages :
  forall m m' : @Msg MSGB MSGB_positive,
    m <> m' -> canon91_of_idx (nat_of_ord m) <> canon91_of_idx (nat_of_ord m').
Proof.
  move=> m m' Hne.
  apply: msg_space256_preimages_distinct.
  - exact: game_msg_lt.
  - exact: game_msg_lt.
  - move=> Hv. by apply: Hne; apply: ord_inj.
Qed.

Theorem game_messages_decode_to_bytes :
  forall m : @Msg MSGB MSGB_positive,
    allbytes (canon91_of_idx (nat_of_ord m)) = true.
Proof. move=> m. exact: msg_space256_preimages_are_bytes. Qed.

(** SPELT OUT AS THE SEAM COLLISION AT TWO REAL BYTE VECTORS IT FORCES — an
    ENGINE collision once `ArrayVectors` identifies the seam with `macf` there —
    AND AS THE STATEMENT THAT NO CONFORMING SEAM CAN BE PATCHED ON THIS SPACE:
    see `Umbra_WireConverse.msg_space256_collision_is_seam_collision_at_byte_vectors`
    and `Umbra_WireConverse.msg_space256_pins_the_seam` (both Qed). They are stated
    there rather than here only because their conclusions mention `Z`, and
    `ZArith` cannot be imported into this file without `N_scope` capturing
    mathcomp's `%N`. *)

End RealMessageSpace.

(* ===================================================================== *)
(* THE ABSTRACT MAC, PINNED TO THE DEVICE'S OWN SEAM                      *)
(*                                                                        *)
(* WHAT THIS SECTION IS FOR. `device_forgery_le_eufcma` above is stated    *)
(* over an ABSTRACT `MAC`, tied to the real seam only by the hypothesis    *)
(* `Hfactor` and only on the image of the assembled encoding. Until the    *)
(* realiser of `Hfactor` became a computed function, that was as far as    *)
(* the statement went — and it was NOT enough to conclude anything from    *)
(* EUF-CMA security of HMAC-SHA256, because a classically chosen `MAC` is  *)
(* unconstrained off that image.                                          *)
(*                                                                        *)
(* The two results below close that. `Hfactor_is_realisable` exhibits a    *)
(* `MAC : Key n -> nat -> nat` satisfying the hypothesis — the             *)
(* composition `Umbra_WireConverse.SeamC1e_realisable` stopped one step    *)
(* short of, since it delivered `slice u8 -> nat -> nat`. And              *)
(* `device_forgery_le_eufcma_at_the_real_seam` instantiates the bound at   *)
(* that MAC AND at the concrete message bound `MSGB = 256^76`, so the game *)
(* on the right-hand side is EUF-CMA, over the finite message space        *)
(* `'fin MSGB`, for                                                       *)
(*                                                                        *)
(*     MAC k m  =  seam (device key bytes of k) (canonical 91 bytes of m)  *)
(*                                                                        *)
(* i.e. the device's HMAC engine precomposed with a message encoding that  *)
(* `Umbra_Canonical.canon91_injective` proves INJECTIVE on that whole      *)
(* space. Under that shape, an EUF-CMA assumption on the engine does       *)
(* transfer — which it did NOT before the message space was restricted;    *)
(* see `game_messages_have_distinct_preimages` above.                      *)
(*                                                                        *)
(* THE PREMISE IS `ByteSeam`, NOT UNFORGEABILITY. It says the engine's     *)
(* output is a function of the key bytes and the 91 preimage bytes. The    *)
(* constant function satisfies it. Nothing here proves, or could prove,    *)
(* that HMAC-SHA256 is EUF-CMA-secure.                                    *)
(*                                                                        *)
(* AND THE PREMISE DOES NOT PIN THE ENGINE ON THE WHOLE SPACE. The claim   *)
(* two paragraphs up — that an EUF-CMA assumption on the engine does       *)
(* transfer — holds only on the byte-valid subimage `256^76`. On the       *)
(* other 25.64 % of `'fin MSGB` the premise is silent, and                 *)
(* `Umbra_WireConverse.restricted_space_still_admits_a_broken_seam_at_     *)
(* MSGBn` (Qed) exhibits a seam satisfying `ByteSeam`, agreeing with any   *)
(* given one at every genuine byte list, under which the transfer FAILS    *)
(* and the right-hand side is 1. `MAC_canonical` at the real engine is     *)
(* not a well-defined instantiation: HMAC-SHA256 has no value on a         *)
(* 91-element list containing 256, so every instantiation of `mb` is an    *)
(* arbitrary extension, and breaking extensions exist.                     *)
(* ===================================================================== *)

Section CanonicalMAC.

#[local] Open Scope ring_scope.

(** THE BASE MAC — the one C1e ties to the seam. The seam at the provisioned
    key bytes, applied to the canonical decoding of a base-257 message
    integer. This is `MACb`, NOT the game's MAC. *)
Definition MACb_canonical {n : nat} (mb : byteseam_t)
    (dkey : Key n -> key_bytes) : Key n -> nat -> nat :=
  fun k => MG_of mb (dkey k).

(** THE GAME'S MAC — the base MAC at the byte-valid indexing. It is
    `Umbra_ByteSpace.MG_spread`, and the equation below is by definition; it is
    stated so that the reader can see the two names denote one function. *)
Lemma MACg_canonical_is_MG_spread :
  forall (n : nat) (mb : byteseam_t) (dkey : Key n -> key_bytes) (k : Key n),
    @MACg n (MACb_canonical mb dkey) k = MG_spread mb (dkey k).
Proof. by []. Qed.

(** Under `ArrayVectors`, the game MAC at every reachable message is an
    encoded evaluation of the concrete engine on an actual 91-byte array.
    This is the bridge needed to read the abstract inequality below as a
    statement about the implementation rather than about an arbitrary total
    extension of its byte seam. *)
Theorem canonical_game_mac_is_engine_evaluation :
  forall (n : nat) (macf : macf_t) (mb : byteseam_t)
         (dkey : Key n -> key_bytes),
    ArrayVectors ->
    ByteSeam macf mb ->
    forall (k : Key n) (m : nat),
      exists p : preimage_array_t,
        bytes91 p = canon91_of_idx m
        /\ @MACg n (MACb_canonical mb dkey) k m
           = engine_tag_nat macf (dkey k) p.
Proof.
  intros n macf mb dkey HAV Hbs k m.
  rewrite MACg_canonical_is_MG_spread.
  destruct (HAV (canon91_of_idx m) (canon91_of_idx_length m)
              (canon91_of_idx_allbytes m)) as [p Hp].
  exists p. split; [ exact Hp |].
  unfold canon91_of_idx in Hp.
  unfold MG_spread, MG_of, engine_tag_nat.
  rewrite spread_idx_val -Hp -Hbs. reflexivity.
Qed.

(** `Hfactor` IS NOT VACUOUS, AT THE TYPE THE THEOREM USES. *)
Theorem Hfactor_is_realisable :
  forall (n : nat) (macf : macf_t) (dkey : Key n -> key_bytes)
         (mb : byteseam_t),
    ByteSeam macf mb ->
    exists MAC : Key n -> nat -> nat,
      forall k : Key n, SeamC1e macf (dkey k) (MAC k).
Proof.
  move=> n macf dkey mb Hbs.
  exact: (SeamC1e_realisable_over_keymap macf dkey mb Hbs).
Qed.

(** THE BOUND, WITH THE ABSTRACT MAC REPLACED BY THE DEVICE'S SEAM AND THE
    ABSTRACT MESSAGE BOUND REPLACED BY `256^76` — the BYTE-VALID subimage,
    not the `257^76` interval of numerals it used to be. The range
    side-condition is discharged by `widx_lt_MSGB`, so it does not appear here.

    WHAT CHANGED, AND WHY IT IS NOT COSMETIC. At `257^76` this theorem was
    TRUE AND, on 25.64 % of its own message space, EMPTY: `Umbra_WireConverse.
    restricted_space_still_admits_a_broken_seam_at_MSGBn` (Qed) builds, from
    any `mb` the premise admits, another one the premise ALSO admits which
    agrees with it at every genuine byte list and collides the pinned MAC at
    two reachable messages — advantage 1. At `256^76` that construction has
    nothing to patch (`Umbra_WireConverse.msg_space256_preimages_are_bytes`,
    Qed), and under the one named premise `Umbra_ByteSpace.ArrayVectors` the
    pinned MAC is DETERMINED by the engine at every message of the space
    (`Umbra_WireConverse.msg_space256_pins_the_seam`, Qed). See the note below
    for what `ArrayVectors` costs. *)
Theorem device_forgery_le_eufcma_at_the_real_seam :
  forall (n : nat) (HS : Type) (inst : hmac_inst HS) (hs : HS) (en : list nat)
         (dkey : Key n -> key_bytes) (macf : macf_t) (mb : byteseam_t),
    SeamC1 inst hs macf ->
    ByteSeam macf mb ->
    forall LA (A : raw_package),
      ValidPackage LA (@DEV_I MSGB MSGB_positive) A_export A ->
      fdisjoint LA (EUF_locs_tt n :|: @EUF_locs_ff n MSGB MSGB_positive) ->
      Advantage
        (@DEV n MSGB MSGB_positive (MACb_canonical mb dkey) HS inst hs en dkey) A
      <= Advantage
           (@EUF_CMA n MSGB MSGB_positive (@MACg n (MACb_canonical mb dkey)))
           (A ∘ @RED_dev MSGB MSGB_positive en).
Proof.
  move=> n HS inst hs en dkey macf mb Hs Hbs LA A vA Hd.
  have Hf : forall k : Key n, SeamC1e macf (dkey k) (MACb_canonical mb dkey k).
  { move=> k. exact: (SeamC1e_canonical macf mb Hbs (dkey k)). }
  exact: (@device_forgery_le_eufcma n MSGB MSGB_positive
            (MACb_canonical mb dkey)
            HS inst hs en dkey macf Hs Hf widx_lt_MSGB LA A vA Hd).
Qed.

(** Concrete-device corollary. The first conjunct establishes that the game
    MAC is the encoded output of `macf` at every game message; the
    `ArrayVectors` premise it used to carry is now discharged by
    `Umbra_ArrayVectors.ArrayVectors_holds` (a theorem, since the array reader
    is defined). The second conjunct is the lossless EUF-CMA bound. *)
Theorem device_forgery_le_eufcma_for_the_concrete_engine :
  forall (n : nat) (HS : Type) (inst : hmac_inst HS) (hs : HS) (en : list nat)
         (dkey : Key n -> key_bytes) (macf : macf_t) (mb : byteseam_t),
    SeamC1 inst hs macf ->
    ByteSeam macf mb ->
    (forall (k : Key n) (m : nat),
       exists p : preimage_array_t,
         bytes91 p = canon91_of_idx m
         /\ @MACg n (MACb_canonical mb dkey) k m
            = engine_tag_nat macf (dkey k) p)
    /\ forall LA (A : raw_package),
      ValidPackage LA (@DEV_I MSGB MSGB_positive) A_export A ->
      fdisjoint LA (EUF_locs_tt n :|: @EUF_locs_ff n MSGB MSGB_positive) ->
      Advantage
        (@DEV n MSGB MSGB_positive (MACb_canonical mb dkey) HS inst hs en dkey) A
      <= Advantage
           (@EUF_CMA n MSGB MSGB_positive (@MACg n (MACb_canonical mb dkey)))
           (A ∘ @RED_dev MSGB MSGB_positive en).
Proof.
  intros n HS inst hs en dkey macf mb Hs Hbs. split.
  - exact (canonical_game_mac_is_engine_evaluation n macf mb dkey
             ArrayVectors_holds Hbs).
  - intros LA A vA Hd.
    exact (device_forgery_le_eufcma_at_the_real_seam
             n HS inst hs en dkey macf mb Hs Hbs LA A vA Hd).
Qed.

(** WHAT THE RIGHT-HAND SIDE NOW IS, AND WHAT IT STILL IS NOT.

    IS. An EUF-CMA advantage over the finite message space `'fin 256^76` — the
    76-byte authenticated cores, exactly — for the MAC

        MG_spread mb (dkey k)  =  mb (key bytes of k) (canonical 91 bytes of
                                     the base-257 numeral with j's digits)

    whose message encoding is injective on that space
    (`game_messages_have_distinct_preimages`) and lands, at EVERY message, in
    the set of genuine 91-byte vectors (`game_messages_decode_to_bytes`).

    IS NOT. The premise is still `ByteSeam`, which pins `mb` only on the image
    of `bytes91`. That the canonical decoding of every message of the space IS
    in that image is `Umbra_ByteSpace.ArrayVectors` — every 91-element list of
    bytes is some `array u8 91`'s read-sequence. It used to be an unprovable
    premise (the backend's `array_index_usize` was a bare axiom); with the
    reader DEFINED it is the theorem `Umbra_ArrayVectors.ArrayVectors_holds`,
    and `device_forgery_le_eufcma_for_the_concrete_engine` carries no such
    premise: it returns, at every game message, the array and its exact byte
    encoding outright. What remains outside every theorem here is the reading
    of `mb` as HMAC-SHA256 under a uniform key. *)

End CanonicalMAC.

(* ===================================================================== *)
(* MECHANISED ASSUMPTION AUDIT (see Update_Safety.v).  Compiling this     *)
(* file emits the full axiom budget of both bounds: the abstract one the  *)
(* paper's table measures, and the closed one at the real seam.  This is  *)
(* also the mechanised form of the classical-logic disclosure — the       *)
(* `boolp.*` constants inherited from mathcomp-analysis, and the          *)
(* `realsum.__admitted__interchange_psum` of finding F2, appear here.     *)
(* ===================================================================== *)
Print Assumptions device_forgery_le_eufcma.
Print Assumptions device_forgery_le_eufcma_at_the_real_seam.
Print Assumptions device_forgery_le_eufcma_for_the_concrete_engine.
