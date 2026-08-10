(** THE UNION, DETERMINISTIC HALF — an accepted package whose authenticated
    CORE was signed has the signed package's BODY.

    ------------------------------------------------------------------------
    WHAT GAP THIS CLOSES.

    `Chain_Compose.verified_update_pins_the_blob_body` (Qed, bare Coq) pins two
    accepted packages' blob bodies to each other, but its hypotheses require the
    two packages to carry THE SAME 32 TRAILING TAG BYTES. So it covers TAG
    REUSE only: "accept the same tag twice and the two bodies agree". The case a
    reader actually wants — an accepted body is the body the vendor signed, even
    when the adversary supplies a FRESH tag — is not that theorem's; it is the
    game tier's, and the game tier's conclusion is about forging the 76-byte
    authenticated core, not about the body.

    This file is the deterministic half of the bridge between them. It proves
    the statement that the two tiers were missing:

      TWO PACKAGES THE DEVICE ACCEPTS WHOSE AUTHENTICATED CORES ARE EQUAL HAVE
      EQUAL BLOB BODIES — with NO hypothesis about their tags, and with NO
      package-MAC collision disjunct.

    That is strictly stronger than `accepted_packages_pin_the_header_hmac` in
    both directions:

      * ITS HYPOTHESIS IS THE GAME'S. `Chain_Compose` needs "same length AND
        same 32 trailing bytes", which is a statement about the WIRE. Here the
        hypothesis is `msg_of_pkg pkg1 = msg_of_pkg pkg2` — equality of the
        76-byte authenticated cores, which is exactly the object the EUF-CMA
        game's message space indexes. That is what makes the union possible:
        the game's `S_loc` stores message integers, so an equation between
        message integers is the only hypothesis the game can hand over.
      * ITS CONCLUSION HAS ONE FEWER DISJUNCT. `Chain_Compose` concludes
        "bodies agree \/ chain-seam collision \/ PACKAGE-MAC collision". Equal
        tags force equal MAC outputs but not equal MAC inputs, so the package
        seam can collide. Equal CORES force equal MAC inputs outright: the
        preimage is a function of the core (six windows partition [0,91), and
        `Update_Encoding.msg_of_pre_inj` inverts the base-257 encoding on
        [15,91) while `Assembles`' label clause fixes [0,15)). So the
        package-tag seam cannot collide here — there is nothing for it to
        collide on. Only the CHAIN seam's disjunct survives.

    ------------------------------------------------------------------------
    WHAT IS STILL A DISJUNCT AND WHY. `SeamCollisionInRuns` (Chain_Body.v) is
    kept verbatim: two states reached while folding THESE blobs, with THESE
    block preimages, from THIS master key, that the chained seam sends to one
    value. It is a conclusion with pinned witnesses, not an existential over
    unrelated buffers, and it is the event an attacker must actually produce.
    Nothing here assumes it infeasible; that claim is computational and stays
    outside every statement in this development.

    ------------------------------------------------------------------------
    THE ONE AXIOM THIS FILE ADDS TO THE UPDATE-CORE BUDGET is `Chain_Value.
    array_u8_ext` (Q21) — a byte array is determined by its bytes — which
    chain-core already carries and `Chain_Model.array_ext_has_a_model`
    discharges against the concrete list model. It is used in exactly one
    place, `accepted_equal_cores_agree_on_the_preimage`, and for exactly the
    reason Chain_Body uses it: the encoding is an equation between INTEGERS, so
    it yields byte VALUES, and the window clauses of P2 are equations between
    RESULTS, which need the preimage as a TERM.

    Bare Coq 8.18 throughout — no mathcomp, no SSProve. The mathcomp half of
    the union is `Umbra_Union.v`, which does the case split on the game's query
    set and cannot be stated without SSProve.

    MEASURED AXIOM BUDGET (entries listed by `Print Assumptions`, one per line
    at column 0 of the `Axioms:` block):
      `accepted_equal_cores_pin_the_blob_body`            40
      `wire_accepted_equal_indices_pin_the_blob_body`     41
      `accepted_equal_indices_pin_the_blob_body`          41
    All Aeneas/Primitives quarantine laws plus `Chain_Value.array_u8_ext`
    (Q21). ZERO classical axioms: no `boolp.*`, no `realsum`, no `classic`. *)

Require Import Primitives.
Import Primitives.
Require Import AeneasLoopShim.
Import AeneasLoopShim.
Require Import Coq.ZArith.ZArith.
Require Import Coq.Lists.List.
Import ListNotations.
Require Import Lia.
Require Import Update_Safety.
Require Import Update_Types.
Import Update_Types.
Require Import Update_FunsExternal.
Import Update_FunsExternal.
Require Import Update_Funs.
Import Update_Funs.
Require Import Update_Crypto.
Require Import Update_Encoding.
Require Import Update_Converse.
Require Import Umbra_Wire.
Require Import Umbra_Canonical.
Require Import Umbra_ByteSpace.
Require Import Umbra_WireConverse.
Require Import Chain_Types.
Require Import Chain_FunsExternal.
Require Import Chain_Funs.
(* Chain names LAST, exactly as `Chain_Compose.v` does. (Under the v1 layout
   they had to win two collisions with `Update_Funs` — `hDR_HMAC_OFF`,
   `hDR_HMAC_LEN` — which no longer exist there in v2; the order is kept.) *)
Import Chain_Funs.
Require Import Chain_Value.
Require Import Chain_Trace.
Require Import Chain_Body.

Local Open Scope Z_scope.
Local Open Scope Primitives_scope.

(* ===================================================================== *)
(* THE TWO PREDICATES THE MATHCOMP HALF QUOTES.                           *)
(*                                                                        *)
(* Named here, in bare Coq, so that `Umbra_Union.v` can state the union    *)
(* without importing `ZArith` — whose `N_scope` would capture mathcomp's   *)
(* `%N` delimiter. This is the same discipline `Umbra_RealGame.v` follows  *)
(* for every `Z`-level fact it quotes.                                    *)
(* ===================================================================== *)

(** The folded region of the blob, byte for byte. `48` is the header length and
    `288` the block length, both read off the extracted `Chain_Funs`. *)
Definition BodiesAgree (blob1 blob2 : slice u8) (n : u32) : Prop :=
  forall k : usize, 48 <= to_Z k < 48 + 288 * to_Z n ->
    slice_index_usize blob1 k = slice_index_usize blob2 k.

(** The chained-measurement gate accepted this blob, at this block count. This
    is the FIRMWARE's second check, not the parser's: `parse_and_verify`
    performs no check on the blob body at all (`Umbra_Canonical.
    blob_body_is_not_covered_by_pkg_tag`, Qed). It is a hypothesis here for
    exactly that reason, and the fact that it is a hypothesis rather than
    something the submission oracle enforces is the obstruction reported at the
    bottom of `Umbra_Union.v`. *)
Definition ChainAccepts {CS : Type} (cinst : ChainHmac_t CS) (ch : CS)
    (master : Chain_Trace.ckey) (blob : slice u8) (n : u32) : Prop :=
  verify_blob_chain cinst ch master blob = Ok true
  /\ blob_block_count blob = Ok (Some n).

(** THE BLOCK COUNT IS NOW READ INSIDE THE AUTHENTICATED CORE — a v2 change —
    but `ChainAccepts`' shared block count is KEPT as a HYPOTHESIS of the union
    rather than derived from "the core was signed".

    `Chain_Value.blob_block_count_cong` (Qed) proves `blob_block_count` is a
    function of `blob[0,4)` (the magic) and `blob[10,14)` (`code_size`) alone.
    Under v1 the package tag authenticated only `blob[16,48)`, so those
    windows were OUTSIDE the core and the shared count was underivable in
    principle. Under v2 the tag covers the FULL header `blob[0,48)` —
    `Update_Encoding.msg_of_pkg` reads `pkg[4,32)` and `pkg[32,80)`, and the
    blob starts at `pkg[32)` — so both count windows now sit inside the
    authenticated core (the remark below is the arithmetic), and equal cores
    could IN PRINCIPLE force equal counts via `blob_block_count_cong` (which
    additionally needs the two blob lengths equal — itself available, since
    `blob_len` is in the core and the parser's guard 4 ties the blob's length
    to it). That derivation is NOT mechanised here; the theorems below keep
    the v1 statement shape, concluding about an accepted body AT THE DECLARED
    BLOCK COUNT, with the shared count as an explicit hypothesis. *)
Remark block_count_window_is_inside_the_authenticated_window :
  forall i : Z, (0 <= i < 4 \/ 10 <= i < 14) -> 0 <= i < 48.
Proof. intros i H. lia. Qed.

(* ===================================================================== *)
(* SHORT NAMES FOR THE MATHCOMP HALF.                                     *)
(*                                                                        *)
(* `Umbra_Union.v` may not import `Primitives`/`Update_Funs` unqualified   *)
(* — their notations land on top of mathcomp's — so the objects it must    *)
(* mention are aliased here. Each is a transparent `Definition`; the       *)
(* `_unfolds` lemmas below are `reflexivity`, so nothing is hidden and the *)
(* union's statement still reduces to the Aeneas-extracted bodies.         *)
(* ===================================================================== *)

Definition vupd : Type := VerifiedUpdate_t.
Definition vblob (r : vupd) : slice u8 := r.(verifiedUpdate_blob).
Definition blkcount : Type := u32.

(** "The extracted parser accepted the wire package `p` against the armed nonce
    `en` under key material `key`, returning `r`." *)
Definition Accepted {HS : Type} (inst : PkgHmac_t HS) (hs : HS)
    (key : slice u8) (en p : list nat) (r : vupd) : Prop :=
  parse_and_verify inst (wire p) (nonce16 en) hs key
  = Ok (Core_result_Result_Ok r).

Lemma Accepted_unfolds : forall {HS : Type} (inst : PkgHmac_t HS) (hs : HS)
    (key : slice u8) (en p : list nat) (r : vupd),
  Accepted inst hs key en p r
  <-> parse_and_verify inst (wire p) (nonce16 en) hs key
      = Ok (Core_result_Result_Ok r).
Proof. intros. reflexivity. Qed.

Lemma vblob_unfolds : forall r : vupd, vblob r = r.(verifiedUpdate_blob).
Proof. reflexivity. Qed.

Section UnionCore.

(* The package-tag device: one seam instance, one handle, one key. `Hseam` is
   C1 — the seam is a deterministic function of key material and preimage. The
   constant function satisfies it, so it carries no unforgeability. It is the
   same hypothesis `Update_Crypto`'s P2 and `Chain_Compose` run under. *)
Context {HS : Type}.
Variable inst : PkgHmac_t HS.
Variable hs   : HS.
Variable key  : slice u8.
Variable mac  : slice u8 -> array u8 91%usize -> array u8 32%usize.
Hypothesis Hseam :
  forall k p, inst.(PkgHmac_t_hmac_pkg) hs k p = Ok (mac k p).

(* ===================================================================== *)
(* THE PREIMAGE, PINNED TO THE CORE AND TO THE BLOB AT ONCE.              *)
(*                                                                        *)
(* `Update_Encoding.accept_encodes` already proves `msg_of_pre pre =        *)
(* msg_of_pkg pkg`, and `Update_Crypto`'s P2 already proves the            *)
(* header window `pre[43,91) = blob[0,48)`. Both are about "the"           *)
(* preimage, but each states it of its OWN existential witness, and two    *)
(* existentials cannot be identified after the fact. This lemma re-runs    *)
(* the derivation once so that a SINGLE `pre` carries both — which is what *)
(* the union needs, since it must travel from an equation between message  *)
(* integers to an equation between blob reads.                            *)
(* ===================================================================== *)

Lemma accept_pins_preimage :
  forall (pkg : slice u8) (en : array u8 16%usize) r,
    parse_and_verify inst pkg en hs key = Ok (Core_result_Result_Ok r) ->
    exists pre : array u8 91%usize,
      (* the constant domain-separation label at [0,15) *)
      (forall i j : usize, 0 <= to_Z i < 15 -> to_Z j = to_Z i ->
         array_index_usize pre j = slice_index_usize pKG_TAG_LABEL i)
      (* the 76-byte authenticated core, as the wire encodes it *)
      /\ msg_of_pre pre = msg_of_pkg pkg
      (* the full-header window [43,91) IS the returned blob's [0,48) *)
      /\ (forall i j k : usize, 0 <= to_Z i < 48 ->
            to_Z j = 43 + to_Z i -> to_Z k = to_Z i ->
            array_index_usize pre j
            = slice_index_usize r.(verifiedUpdate_blob) k).
Proof.
  intros pkg en r Hacc.
  pose proof (accept_implies_len_ge_112 inst pkg en hs key r Hacc) as Hlen.
  pose proof usize_max_bound as Hub. unfold u32_max in Hub.
  pose proof (to_Z_usize_bounds (slice_len pkg)) as Hlub.
  destruct (accept_implies_authenticated_fields inst hs key mac Hseam pkg en r Hacc)
    as [tag_off [expect [nonce [hdr [bl [pre
       [Htoff [_ [_ [HA [_ [_ [Hd [_ [He [Hf [Hg [Hblob Hh]]]]]]]]]]]]]]]]]].
  exists pre.
  destruct HA as [HL _].
  split; [ exact HL |].
  (* ---- the 76-byte core, exactly as `accept_encodes` derives it -------- *)
  assert (W1 : forall i, 0 <= i < 28 -> rdA pre (15 + i) = rdS pkg (4 + i)).
  { intros i Hi.
    assert (Hj : to_Z (uz (15 + i)) = 15 + i) by (apply to_Z_uz; lia).
    assert (Hk : to_Z (uz (4 + i)) = 4 + i) by (apply to_Z_uz; lia).
    unfold rdA, rdS.
    destruct (Z.lt_ge_cases i 16) as [Hlt|Hge].
    - assert (Hi0 : to_Z (uz i) = i) by (apply to_Z_uz; lia).
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
  exact Hh.
Qed.

(* ===================================================================== *)
(* EQUAL CORES ⟹ EQUAL PREIMAGES, AS TERMS.                              *)
(*                                                                        *)
(* This is where the package-MAC collision disjunct disappears. Equal      *)
(* TAGS give `mac key p1 = mac key p2` and leave `p1 <> p2` open — the     *)
(* collision. Equal CORES give `p1 = p2` outright, so there is nothing to  *)
(* collide.                                                               *)
(* ===================================================================== *)

Lemma accepted_equal_cores_agree_on_the_preimage :
  forall (pkg1 pkg2 : slice u8) (en : array u8 16%usize) r1 r2,
    parse_and_verify inst pkg1 en hs key = Ok (Core_result_Result_Ok r1) ->
    parse_and_verify inst pkg2 en hs key = Ok (Core_result_Result_Ok r2) ->
    msg_of_pkg pkg1 = msg_of_pkg pkg2 ->
    exists pre : array u8 91%usize,
      (forall i j k : usize, 0 <= to_Z i < 48 ->
         to_Z j = 43 + to_Z i -> to_Z k = to_Z i ->
         array_index_usize pre j
         = slice_index_usize r1.(verifiedUpdate_blob) k)
      /\ (forall i j k : usize, 0 <= to_Z i < 48 ->
         to_Z j = 43 + to_Z i -> to_Z k = to_Z i ->
         array_index_usize pre j
         = slice_index_usize r2.(verifiedUpdate_blob) k).
Proof.
  intros pkg1 pkg2 en r1 r2 A1 A2 Hmsg.
  pose proof usize_max_bound as Hub. unfold u32_max in Hub.
  destruct (accept_pins_preimage pkg1 en r1 A1) as [p1 [HL1 [Hm1 Hw1]]].
  destruct (accept_pins_preimage pkg2 en r2 A2) as [p2 [HL2 [Hm2 Hw2]]].
  (* the two preimages encode to the same integer … *)
  assert (Hpre : msg_of_pre p1 = msg_of_pre p2)
    by (rewrite Hm1, Hm2; exact Hmsg).
  (* … hence agree at every read: [15,91) by base-257 injectivity, [0,15)
     because `Assembles` pins both to the same constant label. *)
  assert (Hall : forall i, 0 <= i < 91 -> rdA p1 i = rdA p2 i).
  { intros i Hi.
    destruct (Z.lt_ge_cases i 15) as [Hlt | Hge].
    - assert (Hu : to_Z (uz i) = i) by (apply to_Z_uz; lia).
      unfold rdA.
      rewrite (HL1 (uz i) (uz i) ltac:(lia) ltac:(lia)).
      rewrite (HL2 (uz i) (uz i) ltac:(lia) ltac:(lia)).
      reflexivity.
    - exact (msg_of_pre_inj p1 p2 Hpre i ltac:(lia)). }
  (* … and a byte array is determined by its bytes (Q21). *)
  assert (Hp : p1 = p2).
  { apply (array_u8_ext 91%usize). intros i Hi.
    assert (H91 : to_Z (91%usize) = 91) by reflexivity.
    assert (Hi' : 0 <= to_Z i < 91) by (rewrite <- H91; exact Hi).
    pose proof (to_Z_usize_bounds i) as Hib.
    destruct (array_index_usize_ok p1 i Hi) as [x Hx].
    destruct (array_index_usize_ok p2 i Hi) as [y Hy].
    exists x, y. split; [ exact Hx |]. split; [ exact Hy |].
    specialize (Hall (to_Z i) Hi').
    rewrite (rdA_at p1 i ltac:(lia)), (rdA_at p2 i ltac:(lia)) in Hall.
    rewrite Hx, Hy in Hall. exact Hall. }
  subst p2. exists p1. split; [ exact Hw1 | exact Hw2 ].
Qed.

(** … and therefore the two blobs carry the same FULL 48-byte header window
    `blob[0,48)` — its 32-byte `header.hmac` field, the chained-measurement
    gate's reference value, included. NO tag hypothesis, NO collision
    disjunct. (Under v1 only `blob[16,48)` was pinned; v2 covers the whole
    header, so the window here starts at 0.) *)
Lemma accepted_equal_cores_pin_the_header_window :
  forall (pkg1 pkg2 : slice u8) (en : array u8 16%usize) r1 r2,
    parse_and_verify inst pkg1 en hs key = Ok (Core_result_Result_Ok r1) ->
    parse_and_verify inst pkg2 en hs key = Ok (Core_result_Result_Ok r2) ->
    msg_of_pkg pkg1 = msg_of_pkg pkg2 ->
    forall q : usize, 0 <= to_Z q < 48 ->
      slice_index_usize r1.(verifiedUpdate_blob) q
      = slice_index_usize r2.(verifiedUpdate_blob) q.
Proof.
  intros pkg1 pkg2 en r1 r2 A1 A2 Hmsg q Hq.
  pose proof cu32max_big as Hbig.
  destruct (accepted_equal_cores_agree_on_the_preimage pkg1 pkg2 en r1 r2 A1 A2 Hmsg)
    as [pre [Hw1 Hw2]].
  destruct (cexists_usize (43 + to_Z q) ltac:(lia)) as [j Hj].
  rewrite <- (Hw1 q j q ltac:(lia) ltac:(lia) ltac:(lia)).
  rewrite <- (Hw2 q j q ltac:(lia) ltac:(lia) ltac:(lia)).
  reflexivity.
Qed.

(* ===================================================================== *)
(* THE DETERMINISTIC UNION THEOREM.                                       *)
(* ===================================================================== *)

(** Two packages the device accepts whose AUTHENTICATED CORES are equal, and
    whose blobs both pass the chained-measurement gate with one block count
    under one master key, have blob bodies that agree byte for byte — unless
    the CHAIN seam collided, and then the colliding pair is exhibited.

    Compare `Chain_Compose.verified_update_pins_the_blob_body`: that theorem
    needs the two packages to be the same length and to carry the same 32
    trailing TAG bytes, and it carries a second disjunct for a collision of the
    PACKAGE-tag seam. Both are gone here. The price is that the hypothesis is
    now about the authenticated core rather than about the wire — which is
    exactly the object the EUF-CMA game speaks about, and is what lets
    `Umbra_Union.v` discharge it from membership in the game's query set. *)
Theorem accepted_equal_cores_pin_the_blob_body :
  forall {CS : Type} (cinst : ChainHmac_t CS) (ch : CS)
         (master : Chain_Trace.ckey)
         (pkg1 pkg2 : slice u8) (en : array u8 16%usize) r1 r2 (n : u32),
    parse_and_verify inst pkg1 en hs key = Ok (Core_result_Result_Ok r1) ->
    parse_and_verify inst pkg2 en hs key = Ok (Core_result_Result_Ok r2) ->
    msg_of_pkg pkg1 = msg_of_pkg pkg2 ->
    ChainAccepts cinst ch master r1.(verifiedUpdate_blob) n ->
    ChainAccepts cinst ch master r2.(verifiedUpdate_blob) n ->
    BodiesAgree r1.(verifiedUpdate_blob) r2.(verifiedUpdate_blob) n
    \/ SeamCollisionInRuns cinst ch master
         r1.(verifiedUpdate_blob) r2.(verifiedUpdate_blob).
Proof.
  intros CS cinst ch master pkg1 pkg2 en r1 r2 n A1 A2 Hmsg [Hv1 Hn1] [Hv2 Hn2].
  (* v2 pins the whole header blob[0,48); the chain gate only needs its
     `header.hmac` field blob[16,48), so restrict the window. *)
  assert (Hwin : forall q : usize, 16 <= to_Z q < 48 ->
            slice_index_usize r1.(verifiedUpdate_blob) q
            = slice_index_usize r2.(verifiedUpdate_blob) q).
  { intros q Hq.
    apply (accepted_equal_cores_pin_the_header_window pkg1 pkg2 en r1 r2
             A1 A2 Hmsg). lia. }
  exact (chain_accept_pins_the_blob_body cinst ch master
           r1.(verifiedUpdate_blob) r2.(verifiedUpdate_blob) n Hv1 Hv2 Hn1 Hn2
           Hwin).
Qed.

(* ===================================================================== *)
(* THE SAME, AT THE WIRE AND AT THE GAME'S OWN MESSAGE INDEX.             *)
(*                                                                        *)
(* The game does not store `msg_of_pkg`; it stores `widx`, the index of    *)
(* the message in the byte-valid subimage `256^76`. On packages the        *)
(* structural guards accept the two agree (`widx_spreads_back`, Qed), so   *)
(* an equation between game indices is an equation between authenticated   *)
(* cores. This is the form `Umbra_Union.v` consumes.                       *)
(* ===================================================================== *)

(** Acceptance implies the key-free structural guards, as a boolean of the wire
    bytes — `Update_Converse.accept_implies_struct` transported by
    `Umbra_WireConverse.wstruct_ok_iff`. No seam, no key. *)
Lemma wire_accept_implies_wstruct_ok :
  forall (en p : list nat) r,
    parse_and_verify inst (wire p) (nonce16 en) hs key
      = Ok (Core_result_Result_Ok r) ->
    wstruct_ok en p = true.
Proof.
  intros en p r Hacc. apply wstruct_ok_iff.
  exact (accept_implies_struct inst (wire p) (nonce16 en) hs key r Hacc).
Qed.

(** Equal game indices ARE equal authenticated cores, on accepted packages. *)
Lemma wire_equal_indices_are_equal_cores :
  forall (en p1 p2 : list nat) r1 r2,
    parse_and_verify inst (wire p1) (nonce16 en) hs key
      = Ok (Core_result_Result_Ok r1) ->
    parse_and_verify inst (wire p2) (nonce16 en) hs key
      = Ok (Core_result_Result_Ok r2) ->
    widx p1 = widx p2 ->
    msg_of_pkg (wire p1) = msg_of_pkg (wire p2).
Proof.
  intros en p1 p2 r1 r2 A1 A2 Hidx.
  pose proof (wire_accept_implies_wstruct_ok en p1 r1 A1) as S1.
  pose proof (wire_accept_implies_wstruct_ok en p2 r2 A2) as S2.
  pose proof (widx_spreads_back en p1 S1) as R1.
  pose proof (widx_spreads_back en p2 S2) as R2.
  (* `spread_idx (widx p) = wmsg p` on both, and the indices agree *)
  assert (Hw : wmsg p1 = wmsg p2) by (rewrite <- R1, <- R2, Hidx; reflexivity).
  unfold wmsg in Hw.
  pose proof (msg_of_pkg_nonneg (wire p1)) as N1.
  pose proof (msg_of_pkg_nonneg (wire p2)) as N2.
  lia.
Qed.

(** THE WIRE-LEVEL UNION CORE. Everything `Umbra_Union.v` needs from the
    deterministic tier, in one statement whose hypotheses are all either
    equations between wire objects or the firmware's chain-gate verdicts. *)
Theorem wire_accepted_equal_indices_pin_the_blob_body :
  forall {CS : Type} (cinst : ChainHmac_t CS) (ch : CS)
         (master : Chain_Trace.ckey) (en p1 p2 : list nat) r1 r2 (n : u32),
    parse_and_verify inst (wire p1) (nonce16 en) hs key
      = Ok (Core_result_Result_Ok r1) ->
    parse_and_verify inst (wire p2) (nonce16 en) hs key
      = Ok (Core_result_Result_Ok r2) ->
    widx p1 = widx p2 ->
    ChainAccepts cinst ch master r1.(verifiedUpdate_blob) n ->
    ChainAccepts cinst ch master r2.(verifiedUpdate_blob) n ->
    BodiesAgree r1.(verifiedUpdate_blob) r2.(verifiedUpdate_blob) n
    \/ SeamCollisionInRuns cinst ch master
         r1.(verifiedUpdate_blob) r2.(verifiedUpdate_blob).
Proof.
  intros CS cinst ch master en p1 p2 r1 r2 n A1 A2 Hidx C1 C2.
  exact (accepted_equal_cores_pin_the_blob_body cinst ch master
           (wire p1) (wire p2) (nonce16 en) r1 r2 n A1 A2
           (wire_equal_indices_are_equal_cores en p1 p2 r1 r2 A1 A2 Hidx)
           C1 C2).
Qed.

(** THE SAME THEOREM AT THE SHORT NAMES, which is the form `Umbra_Union.v`
    consumes. `Accepted` and `vblob` are transparent, so this is the statement
    above with three abbreviations expanded — `exact` closes it by conversion,
    which is the proof that nothing was smuggled into the abbreviations. *)
Theorem accepted_equal_indices_pin_the_blob_body :
  forall {CS : Type} (cinst : ChainHmac_t CS) (ch : CS)
         (master : Chain_Trace.ckey) (en p1 p2 : list nat)
         (r1 r2 : vupd) (n : blkcount),
    Accepted inst hs key en p1 r1 ->
    Accepted inst hs key en p2 r2 ->
    widx p1 = widx p2 ->
    ChainAccepts cinst ch master (vblob r1) n ->
    ChainAccepts cinst ch master (vblob r2) n ->
    BodiesAgree (vblob r1) (vblob r2) n
    \/ SeamCollisionInRuns cinst ch master (vblob r1) (vblob r2).
Proof.
  intros CS cinst ch master en p1 p2 r1 r2 n A1 A2 Hidx C1 C2.
  exact (wire_accepted_equal_indices_pin_the_blob_body cinst ch master
           en p1 p2 r1 r2 n A1 A2 Hidx C1 C2).
Qed.

(** THE HYPOTHESIS OF THE THEOREM ABOVE *IS* THE ORACLE'S `true`, in both
    directions. Stated so that no theorem has to carry both `accepts p = true`
    and the parse equation: the second implies the first, so carrying both
    would be decoration. `Umbra_Wire.accepts_true` is the converse. *)
Lemma parse_ok_iff_accepts :
  forall (en p : list nat),
    accepts inst hs key en p = true
    <-> exists r, parse_and_verify inst (wire p) (nonce16 en) hs key
                  = Ok (Core_result_Result_Ok r).
Proof.
  intros en p. split.
  - intro H. exact (accepts_true inst hs key en p H).
  - intros [r Hr]. unfold accepts. rewrite Hr. reflexivity.
Qed.

End UnionCore.
