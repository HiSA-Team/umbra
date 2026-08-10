(** THE COMPOSITION — B1, end to end.

    `Update_Crypto.accept_implies_authenticated_fields` (P2, pkg-tag v2)
    authenticates a 76-byte core of an update package — including the blob's
    FULL 48-byte header `blob[0,48)` — and, as
    `Umbra_Canonical.blob_body_is_not_covered_by_pkg_tag` proves, NOTHING of the
    blob body. `Chain_Body.chain_accept_pins_the_blob_body` pins the body to the
    32-byte `header.hmac` window at `blob[16,48)`. This file joins them at that
    window — under v2 a sub-window of what the tag pins.

    The joint says: two update packages accepted under one armed nonce and one
    key, carrying the same 32 trailing tag bytes, whose blobs both pass the
    chained-measurement gate with the same block count, have blob bodies that
    agree byte for byte — unless one of the two seams collided, and in that case
    the collision is exhibited.

    That is the sentence "verified secure enclave update" was standing in for.
    What it still is not: neither seam is assumed hard, so this is a REDUCTION.
    Both disjuncts are events an adversary must produce; the claim that they are
    infeasible is computational and is not stated in Coq. *)

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
Require Import Chain_Types.
Require Import Chain_FunsExternal.
Require Import Chain_Funs.
(* Chain names LAST. (Historical note: pre-v2 this resolved two name
   collisions with Update_Funs' hDR_HMAC_OFF/hDR_HMAC_LEN, which no longer
   exist there — v2's constant is hDR_LEN. Order kept for stability.) *)
Import Chain_Funs.
Require Import Chain_Value.
Require Import Chain_Trace.
Require Import Chain_Body.
Local Open Scope Z_scope.
Local Open Scope Primitives_scope.

(** `PreimageOf p pkg blob` — every one of the 91 bytes of `p` pinned to a byte
    of `pkg` or of `blob`, or to the constant label.

    THIS REPLACES AN EARLIER `Assembles`-BASED FORMULATION THAT WAS VACUOUS.
    `Update_Crypto.Assembles pre n au ve bl hh` relates the preimage to the
    SEAM'S ARGUMENTS. Those arguments were existentially quantified at the use
    site, and `Assembles` is a plain conjunction of byte-window equalities, so
    ANY label-prefixed 91-byte buffer assembled SOME tuple: the disjunct read
    "two distinct label-prefixed buffers collide", 2^608 preimages into 2^256
    tags, TRUE BY PIGEONHOLE for every concrete `mac`. The composed theorem was
    therefore provable with all of its hypotheses deleted. (Found by adversarial
    audit; the earlier `34825b1` pinning fixed the chain disjunct and only
    appeared to fix this one.)

    `PreimageOf` takes the PACKAGE and the BLOB, not the fields. Combined with
    [preimage_of_determines] below, `p` is then a function of `(pkg, blob)`, so
    the disjunct names ONE pair of buffers — the ones the adversary's own two
    submissions induce — and a pigeonhole collision elsewhere does not discharge
    it. *)
Definition PreimageOf (p : array u8 91%usize) (pkg blob : slice u8) : Prop :=
  (* [0,15) — the constant domain-separation label *)
  (forall i j : usize, 0 <= to_Z i < 15 -> to_Z j = to_Z i ->
     array_index_usize p j = slice_index_usize pKG_TAG_LABEL i)
  (* [15,31) — pkg[4,20), the nonce field, as terms *)
  /\ (forall i j k : usize, 0 <= to_Z i < 16 ->
     to_Z j = 15 + to_Z i -> to_Z k = 4 + to_Z i ->
     array_index_usize p j = slice_index_usize pkg k)
  (* [31,35) — pkg[20,24), author_id *)
  /\ (forall i j k : usize, 0 <= to_Z i < 4 ->
     to_Z j = 31 + to_Z i -> to_Z k = 20 + to_Z i ->
     exists x y, array_index_usize p j = Ok x
              /\ slice_index_usize pkg k = Ok y /\ to_Z x = to_Z y)
  (* [35,39) — pkg[24,28), version *)
  /\ (forall i j k : usize, 0 <= to_Z i < 4 ->
     to_Z j = 35 + to_Z i -> to_Z k = 24 + to_Z i ->
     exists x y, array_index_usize p j = Ok x
              /\ slice_index_usize pkg k = Ok y /\ to_Z x = to_Z y)
  (* [39,43) — pkg[28,32), blob_len *)
  /\ (forall i j k : usize, 0 <= to_Z i < 4 ->
     to_Z j = 39 + to_Z i -> to_Z k = 28 + to_Z i ->
     exists x y, array_index_usize p j = Ok x
              /\ slice_index_usize pkg k = Ok y /\ to_Z x = to_Z y)
  (* [43,91) — blob[0,48), the FULL UMBR header (pkg-tag v2) *)
  /\ (forall i j k : usize, 0 <= to_Z i < 48 ->
     to_Z j = 43 + to_Z i -> to_Z k = to_Z i ->
     array_index_usize p j = slice_index_usize blob k).

(** `PreimageOf` DETERMINES the preimage: the six windows partition [0,91), so a
    package and its blob have at most one preimage. This is what makes the
    collision disjunct a statement about one specific pair of buffers. *)
Lemma preimage_of_determines :
  forall (p q : array u8 91%usize) (pkg blob : slice u8),
    PreimageOf p pkg blob -> PreimageOf q pkg blob -> p = q.
Proof.
  intros p q pkg blob HP HQ. pose proof cu32max_big as Hbig.
  destruct HP as [P0 [P1 [P2 [P3 [P4 P5]]]]].
  destruct HQ as [Q0 [Q1 [Q2 [Q3 [Q4 Q5]]]]].
  assert (H91 : to_Z (91%usize) = 91) by reflexivity.
  apply (array_u8_ext 91%usize). intros j Hj. rewrite H91 in Hj.
  (* a read that succeeds in `p` and agrees as a RESULT with `q`'s *)
  assert (Hsame : array_index_usize p j = array_index_usize q j ->
                  exists x y, array_index_usize p j = Ok x
                           /\ array_index_usize q j = Ok y /\ to_Z x = to_Z y).
  { intro E. destruct (array_index_usize_ok p j ltac:(lia)) as [x Hx].
    exists x, x. split; [ exact Hx |]. split; [ rewrite <- E; exact Hx | reflexivity ]. }
  destruct (Z_lt_le_dec (to_Z j) 15) as [H15 | H15].
  { apply Hsame. destruct (cexists_usize (to_Z j) ltac:(lia)) as [i Hi].
    rewrite (P0 i j ltac:(lia) ltac:(lia)), (Q0 i j ltac:(lia) ltac:(lia)).
    reflexivity. }
  destruct (Z_lt_le_dec (to_Z j) 31) as [H31 | H31].
  { apply Hsame. destruct (cexists_usize (to_Z j - 15) ltac:(lia)) as [i Hi].
    destruct (cexists_usize (4 + to_Z i) ltac:(lia)) as [k Hk].
    rewrite (P1 i j k ltac:(lia) ltac:(lia) ltac:(lia)),
            (Q1 i j k ltac:(lia) ltac:(lia) ltac:(lia)). reflexivity. }
  destruct (Z_lt_le_dec (to_Z j) 35) as [H35 | H35].
  { destruct (cexists_usize (to_Z j - 31) ltac:(lia)) as [i Hi].
    destruct (cexists_usize (20 + to_Z i) ltac:(lia)) as [k Hk].
    destruct (P2 i j k ltac:(lia) ltac:(lia) ltac:(lia)) as [x [y [Hx [Hy Hv]]]].
    destruct (Q2 i j k ltac:(lia) ltac:(lia) ltac:(lia)) as [x' [y' [Hx' [Hy' Hv']]]].
    exists x, x'. split; [ exact Hx |]. split; [ exact Hx' |].
    rewrite Hy in Hy'. injection Hy' as Hy'. subst y'. lia. }
  destruct (Z_lt_le_dec (to_Z j) 39) as [H39 | H39].
  { destruct (cexists_usize (to_Z j - 35) ltac:(lia)) as [i Hi].
    destruct (cexists_usize (24 + to_Z i) ltac:(lia)) as [k Hk].
    destruct (P3 i j k ltac:(lia) ltac:(lia) ltac:(lia)) as [x [y [Hx [Hy Hv]]]].
    destruct (Q3 i j k ltac:(lia) ltac:(lia) ltac:(lia)) as [x' [y' [Hx' [Hy' Hv']]]].
    exists x, x'. split; [ exact Hx |]. split; [ exact Hx' |].
    rewrite Hy in Hy'. injection Hy' as Hy'. subst y'. lia. }
  destruct (Z_lt_le_dec (to_Z j) 43) as [H43 | H43].
  { destruct (cexists_usize (to_Z j - 39) ltac:(lia)) as [i Hi].
    destruct (cexists_usize (28 + to_Z i) ltac:(lia)) as [k Hk].
    destruct (P4 i j k ltac:(lia) ltac:(lia) ltac:(lia)) as [x [y [Hx [Hy Hv]]]].
    destruct (Q4 i j k ltac:(lia) ltac:(lia) ltac:(lia)) as [x' [y' [Hx' [Hy' Hv']]]].
    exists x, x'. split; [ exact Hx |]. split; [ exact Hx' |].
    rewrite Hy in Hy'. injection Hy' as Hy'. subst y'. lia. }
  { apply Hsame. destruct (cexists_usize (to_Z j - 43) ltac:(lia)) as [i Hi].
    rewrite (P5 i j i ltac:(lia) ltac:(lia) ltac:(lia)),
            (Q5 i j i ltac:(lia) ltac:(lia) ltac:(lia)). reflexivity. }
Qed.

(** A collision of the PACKAGE-TAG seam **on the two packages' own preimages**.
    No existential over protocol fields: the two buffers are the ones `pkg1` and
    `pkg2` induce, and by [preimage_of_determines] there is at most one of each. *)
Definition MacCollisionOnPackages
  (mac : slice u8 -> array u8 91%usize -> array u8 32%usize) (key : slice u8)
  (pkg1 blob1 pkg2 blob2 : slice u8) : Prop :=
  exists p1 p2 : array u8 91%usize,
    p1 <> p2
    /\ mac key p1 = mac key p2
    /\ PreimageOf p1 pkg1 blob1
    /\ PreimageOf p2 pkg2 blob2.

Section Composed.

(* The package-tag device: one seam instance, one handle, one key — and C1, the
   same functionality assumption P2 runs under. *)
Context {PS : Type}.
Variable pinst : PkgHmac_t PS.
Variable ph : PS.
Variable key : slice u8.
Variable mac : slice u8 -> array u8 91%usize -> array u8 32%usize.
Hypothesis Hseam :
  forall k p, pinst.(PkgHmac_t_hmac_pkg) ph k p = Ok (mac k p).

(* The chained-measurement device: no assumption at all. *)
Context {CS : Type}.
Variable cinst : Chain_Types.ChainHmac_t CS.
Variable ch : CS.
Variable master : Chain_Trace.ckey.

(** Two accepted packages of equal length with equal trailing tag bytes carry the
    same `header.hmac` window in their blobs — unless the package-tag seam
    collided. This is the only step that needs C1: without naming the tag as a
    function of (key, preimage) there is no preimage to compare. *)
Lemma accepted_packages_pin_the_header_hmac :
  forall (pkg1 pkg2 : slice u8) (en : array u8 16%usize) r1 r2,
    parse_and_verify pinst pkg1 en ph key = Ok (Core_result_Result_Ok r1) ->
    parse_and_verify pinst pkg2 en ph key = Ok (Core_result_Result_Ok r2) ->
    to_Z (slice_len pkg1) = to_Z (slice_len pkg2) ->
    (forall j : usize,
       to_Z (slice_len pkg1) - 32 <= to_Z j < to_Z (slice_len pkg1) ->
       slice_index_usize pkg1 j = slice_index_usize pkg2 j) ->
    (forall q : usize, 16 <= to_Z q < 48 ->
       slice_index_usize r1.(verifiedUpdate_blob) q
       = slice_index_usize r2.(verifiedUpdate_blob) q)
    \/ MacCollisionOnPackages mac key
         pkg1 r1.(verifiedUpdate_blob) pkg2 r2.(verifiedUpdate_blob).
Proof.
  intros pkg1 pkg2 en r1 r2 A1 A2 Hlen Htagb.
  pose proof cu32max_big as Hbig.
  destruct (accept_implies_authenticated_fields pinst ph key mac Hseam pkg1 en r1 A1)
    as [t1 [e1 [n1 [hh1 [bl1 [p1 P1]]]]]].
  destruct (accept_implies_authenticated_fields pinst ph key mac Hseam pkg2 en r2 A2)
    as [t2 [e2 [n2 [hh2 [bl2 [p2 P2]]]]]].
  (* keep only the three clauses this proof consumes: the tag offset, the tag
     bytes, the C1 factorisation, and the header-hmac window *)
  destruct P1 as [Ht1 P1]. destruct P1 as [_ P1]. destruct P1 as [He1 P1].
  destruct P1 as [HA1 P1]. destruct P1 as [Hb1 P1].
  destruct P1 as [_ P1]. destruct P1 as [Hnw1 P1]. destruct P1 as [_ P1].
  destruct P1 as [Hau1 P1]. destruct P1 as [Hve1 P1]. destruct P1 as [Hbl1 P1].
  destruct P1 as [_ Hw1].
  destruct P2 as [Ht2 P2]. destruct P2 as [_ P2]. destruct P2 as [He2 P2].
  destruct P2 as [HA2 P2]. destruct P2 as [Hb2 P2].
  destruct P2 as [_ P2]. destruct P2 as [Hnw2 P2]. destruct P2 as [_ P2].
  destruct P2 as [Hau2 P2]. destruct P2 as [Hve2 P2]. destruct P2 as [Hbl2 P2].
  destruct P2 as [_ Hw2].
  (* the label clause is the first conjunct of `Assembles` *)
  destruct HA1 as [HL1 _]. destruct HA2 as [HL2 _].
  (* the two tag ARRAYS agree, because their bytes are the package's, and the
     packages' trailing bytes were assumed equal *)
  assert (He : e1 = e2).
  { apply (array_u8_ext 32%usize). intros i Hi. rewrite ctz32 in Hi.
    pose proof (to_Z_usize_bounds (slice_len pkg1)) as Hl1.
    pose proof (to_Z_usize_bounds t1) as Ht1b.
    pose proof (to_Z_usize_bounds t2) as Ht2b.
    destruct (cexists_usize_full (to_Z t1 + to_Z i) ltac:(lia)) as [j Hj].
    destruct (Hb1 i j ltac:(lia) ltac:(lia)) as [x1 [y1 [Hx1 [Hy1 Hv1]]]].
    destruct (Hb2 i j ltac:(lia) ltac:(lia)) as [x2 [y2 [Hx2 [Hy2 Hv2]]]].
    exists x1, x2. repeat split; [ exact Hx1 | exact Hx2 |].
    rewrite (Htagb j ltac:(lia)) in Hy1. rewrite Hy1 in Hy2.
    injection Hy2 as Hy2. subst y2. lia. }
  (* … so `mac key` took p1 and p2 to the same tag *)
  assert (Hmac : mac key p1 = mac key p2) by (rewrite <- He1, <- He2, He; reflexivity).
  destruct (array_u8_eq_dec 91%usize p1 p2) as [Hp | Hp].
  2:{ right. exists p1, p2. split; [ exact Hp |]. split; [ exact Hmac |].
      split; unfold PreimageOf; repeat apply conj;
        first [ exact HL1 | exact HL2 | exact Hnw1 | exact Hnw2
              | exact Hau1 | exact Hau2 | exact Hve1 | exact Hve2
              | exact Hbl1 | exact Hbl2 | exact Hw1 | exact Hw2 ]. }
  subst p2. left.
  (* equal preimages ⇒ equal header windows; the chain joint needs only the
     header.hmac sub-window [16,48) of the [0,48) the v2 tag pins *)
  intros q Hq.
  destruct (cexists_usize (43 + to_Z q) ltac:(lia)) as [j Hj].
  rewrite <- (Hw1 q j q ltac:(lia) ltac:(lia) ltac:(lia)).
  rewrite <- (Hw2 q j q ltac:(lia) ltac:(lia) ltac:(lia)).
  reflexivity.
Qed.

(* ===================================================================== *)
(* THE COMPOSED THEOREM.                                                  *)
(* ===================================================================== *)

Theorem verified_update_pins_the_blob_body :
  forall (pkg1 pkg2 : slice u8) (en : array u8 16%usize) r1 r2 (n : u32),
    (* (1) both packages authenticate against the SAME armed nonce and key … *)
    parse_and_verify pinst pkg1 en ph key = Ok (Core_result_Result_Ok r1) ->
    parse_and_verify pinst pkg2 en ph key = Ok (Core_result_Result_Ok r2) ->
    (* … are the same length and carry the same 32 trailing tag bytes … *)
    to_Z (slice_len pkg1) = to_Z (slice_len pkg2) ->
    (forall j : usize,
       to_Z (slice_len pkg1) - 32 <= to_Z j < to_Z (slice_len pkg1) ->
       slice_index_usize pkg1 j = slice_index_usize pkg2 j) ->
    (* (2) … and both blobs pass the chained-measurement gate with one block
       count, under one master key. *)
    verify_blob_chain cinst ch master r1.(verifiedUpdate_blob) = Ok true ->
    verify_blob_chain cinst ch master r2.(verifiedUpdate_blob) = Ok true ->
    blob_block_count r1.(verifiedUpdate_blob) = Ok (Some n) ->
    blob_block_count r2.(verifiedUpdate_blob) = Ok (Some n) ->
    (* THEN the two blob BODIES agree on every folded byte … *)
    (forall k : usize, 48 <= to_Z k < 48 + 288 * to_Z n ->
       slice_index_usize r1.(verifiedUpdate_blob) k
       = slice_index_usize r2.(verifiedUpdate_blob) k)
    (* … or one of the two seams collided. *)
    \/ SeamCollisionInRuns cinst ch master
         r1.(verifiedUpdate_blob) r2.(verifiedUpdate_blob)
    \/ MacCollisionOnPackages mac key
         pkg1 r1.(verifiedUpdate_blob) pkg2 r2.(verifiedUpdate_blob).
Proof.
  intros pkg1 pkg2 en r1 r2 n A1 A2 Hlen Htagb Hv1 Hv2 Hn1 Hn2.
  destruct (accepted_packages_pin_the_header_hmac pkg1 pkg2 en r1 r2 A1 A2 Hlen Htagb)
    as [Hhdr | Hmc]; [| right; right; exact Hmc ].
  destruct (chain_accept_pins_the_blob_body cinst ch master
              r1.(verifiedUpdate_blob) r2.(verifiedUpdate_blob) n
              Hv1 Hv2 Hn1 Hn2 Hhdr) as [Hbody | Hsc];
    [ left; exact Hbody | right; left; exact Hsc ].
Qed.

End Composed.
