(** THE CONVERSE PARSER — the obligation `Umbra_RealGame.v` used to assume.

    WHAT WAS MISSING. Every earlier revision of the crypto layer proved only
    the FORWARD half of the device's acceptance test:

        the parser accepted  ==>  the tag on the wire is the abstract MAC of
                                  the message on the wire

    (`Umbra_Wire.wire_accept_implies_submit_true`, Qed). A reduction to EUF-CMA
    holds no key and must SIMULATE the device's `submit` oracle, so it needs the
    equivalence, factored so that everything key-dependent sits in a single tag
    check:

        accepts key p  =  struct_ok p  &&  (tag on the wire = MAC k (msg))   (F)

    with `struct_ok` key-free. `Umbra_RealGame.v` carried (F) as the section
    hypothesis `Hfactorise`. This file discharges it, by proving both halves
    over the verbatim Aeneas-extracted body:

      [accept_implies_struct]  acceptance implies the five key-free guards —
          the length guard, the magic guard, the two blob-length guards and the
          nonce comparison — each stated as an equation on the PACKAGE BYTES
          (`Update_Encoding.rdS`), not on the parser's internal `usize`s;

      [parse_walk]  conversely, those five guards drive the extracted body all
          the way to the tag comparison: the parse is shown to REDUCE to
          `ct_eq32 expect got >>= …`, with `expect` the seam's output on a
          preimage that `AssemblesF` the package's fields and encodes to
          `msg_of_pkg pkg`, and `got` the package's own trailing 32 bytes.

    Composed with `tag_gate_iff` (the tag comparison holds exactly when the two
    32-byte windows have the same base-257 encoding), they give
    `accept_factorises`: acceptance holds exactly when the guards hold and the
    wire's tag is the abstract MAC of the wire's message. That is (F);
    `Umbra_WireConverse.v` transports it across the `list nat` marshalling and
    exhibits the concrete `struct_ok`.

    THE GUARDS ARE THE CODE'S, NOT A CONVENIENT SUBSET. `parse_and_verify` has
    exactly six rejecting branches (Update_Funs.v): `len < 112`, bad magic,
    `blob_len < MIN_BLOB`, `tag_off - FIXED_PREFIX <> blob_len`, nonce
    mismatch, tag mismatch. `StructOk` below is branches 1–5 verbatim; branch 6
    is the tag check that (F) exposes. Nothing is dropped and nothing is added.

    WHAT IT COSTS. No new axiom. `ct_eq16_complete` / `ct_eq32_complete`
    (Update_Value.v, added for this file) are ordinary loop inductions; the walk
    uses the SAME twenty quarantined array/slice laws that `Update_Safety.v`
    already enumerates and `Update_Model.v` already discharges against a
    concrete list model. Bare Coq 8.18 — no mathcomp, no SSProve. *)

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
Require Import Update_Value.
Require Import Update_Auth.
Require Import Update_Crypto.
Require Import Update_Forgery.
Require Import Update_Encoding.
Local Open Scope Z_scope.
Local Open Scope Primitives_scope.

(* ===================================================================== *)
(* THE KEY-FREE GUARDS                                                    *)
(* ===================================================================== *)

(** The little-endian reading of four bytes of a total byte reader. The parser
    computes the same number with `u32::from_le_bytes`; `dec32_val`
    (Update_Crypto, Qed from the codec's digit spec) is what identifies the
    two. *)
Definition ldec (f : Z -> Z) (off : Z) : Z :=
  f off + 256 * f (off + 1) + 65536 * f (off + 2) + 16777216 * f (off + 3).

(** BRANCHES 1–5 OF THE EXTRACTED PARSER, OVER THE PACKAGE BYTES AND THE ARMED
    NONCE. Every clause is a function of the wire and the device's provisioned
    nonce ONLY: no key appears, which is precisely what makes a key-less
    reduction able to evaluate it. *)
Definition StructOk (pkg : slice u8) (en : array u8 16%usize) : Prop :=
  112 <= to_Z (slice_len pkg)
  /\ ldec (rdS pkg) 0 = to_Z uPDATE_MAGIC
  /\ 48 <= ldec (rdS pkg) 28
  /\ to_Z (slice_len pkg) - 64 = ldec (rdS pkg) 28
  /\ (forall i, 0 <= i < 16 -> rdS pkg (4 + i) = rdA en i).

(* --------------------------------------------------------------------- *)
(* Reading a byte at a literal offset, as `rdS`/`rdA` see it.             *)
(* --------------------------------------------------------------------- *)

Lemma rdS_ok : forall (s : slice u8) (i : usize) (b : u8),
  0 <= to_Z i <= usize_max -> slice_index_usize s i = Ok b ->
  rdS s (to_Z i) = to_Z b.
Proof.
  intros s i b Hi H. rewrite (rdS_at s i Hi), H. reflexivity.
Qed.

Lemma rdA_ok : forall {n : usize} (a : array u8 n) (i : usize) (b : u8),
  0 <= to_Z i <= usize_max -> array_index_usize a i = Ok b ->
  rdA a (to_Z i) = to_Z b.
Proof.
  intros n a i b Hi H. rewrite (rdA_at a i Hi), H. reflexivity.
Qed.

(* ===================================================================== *)
(* FORWARD — acceptance implies the five guards.                          *)
(* ===================================================================== *)

(* One monadic step of the extracted body, in a HYPOTHESIS. The subterm is
   taken FROM the hypothesis rather than written out, because the extracted
   range/index literals carry `%return` proof terms and are only CONVERTIBLE
   to a hand-written copy — the same reason Update_Safety's `pv_range` has to
   bridge with `exact` (see its comment). *)
Ltac ac_bind Ht c Hc :=
  lazymatch type of Ht with
  | bind ?e _ = _ =>
    destruct e as [c|] eqn:Hc; cbn [bind] in Ht; try discriminate Ht
  end.

(* One rejecting guard: the `true` branch returns an `Err`, which contradicts
   the assumed `Ok (Ok r)`. *)
Ltac ac_guard Ht Hg :=
  lazymatch type of Ht with
  | (if ?b then _ else _) = _ => destruct b eqn:Hg; try discriminate Ht
  end.

Lemma accept_implies_guard_values :
  forall {HS : Type} (inst : PkgHmac_t HS) (pkg : slice u8)
         (en : array u8 16%usize) (h : HS) (key : slice u8) r,
    parse_and_verify inst pkg en h key = Ok (Core_result_Result_Ok r) ->
    exists b0 b1 b2 b3 c28 c29 c30 c31 : u8,
      slice_index_usize pkg 0%usize = Ok b0
      /\ slice_index_usize pkg 1%usize = Ok b1
      /\ slice_index_usize pkg 2%usize = Ok b2
      /\ slice_index_usize pkg 3%usize = Ok b3
      /\ slice_index_usize pkg 28%usize = Ok c28
      /\ slice_index_usize pkg 29%usize = Ok c29
      /\ slice_index_usize pkg 30%usize = Ok c30
      /\ slice_index_usize pkg 31%usize = Ok c31
      /\ to_Z (dec32 b0 b1 b2 b3) = to_Z uPDATE_MAGIC
      /\ 48 <= to_Z (dec32 c28 c29 c30 c31)
      /\ to_Z (slice_len pkg) - 64 = to_Z (dec32 c28 c29 c30 c31).
Proof.
  intros HS inst pkg en h key r Hacc.
  unfold parse_and_verify in Hacc. cbv zeta in Hacc.
  ac_bind Hacc i1 E1. ac_bind Hacc i2 E2.
  ac_guard Hacc G0.
  ac_bind Hacc b0 R0. ac_bind Hacc b1 R1.
  ac_bind Hacc b2 R2. ac_bind Hacc b3 R3.
  ac_guard Hacc GM.
  cbn [array_to_slice_mut] in Hacc.
  ac_bind Hacc nsrc HN. ac_bind Hacc ncpy HC.
  ac_bind Hacc c20 R20. ac_bind Hacc c21 R21.
  ac_bind Hacc c22 R22. ac_bind Hacc c23 R23.
  ac_bind Hacc c24 R24. ac_bind Hacc c25 R25.
  ac_bind Hacc c26 R26. ac_bind Hacc c27 R27.
  ac_bind Hacc c28 R28. ac_bind Hacc c29 R29.
  ac_bind Hacc c30 R30. ac_bind Hacc c31 R31.
  ac_bind Hacc bl HCa. ac_bind Hacc toff HT.
  ac_guard Hacc GMin.
  ac_bind Hacc i23 H23.
  ac_guard Hacc GOff.
  (* --- the guards, converted from `usize` comparisons to plain values --- *)
  unfold scalar_cast in HCa. apply mk_scalar_to_Z in HCa.
  unfold usize_sub, scalar_sub in HT.  apply mk_scalar_to_Z in HT.
  unfold usize_sub, scalar_sub in H23. apply mk_scalar_to_Z in H23.
  rewrite tz32 in HT. rewrite tz_fixed in H23.
  unfold scalar_neqb, scalar_eqb in GM, GOff.
  apply negb_false_iff in GM. apply Z.eqb_eq in GM.
  apply negb_false_iff in GOff. apply Z.eqb_eq in GOff.
  unfold scalar_ltb in GMin. apply Z.ltb_ge in GMin. rewrite tz_min in GMin.
  exists b0, b1, b2, b3, c28, c29, c30, c31.
  unfold dec32.
  (* NB: `destruct … eqn:` abstracted each read in the GOAL as well as in the
     hypothesis, so the eight read clauses have already become reflexive. *)
  split; [ first [ exact R0 | reflexivity ] |].
  split; [ first [ exact R1 | reflexivity ] |].
  split; [ first [ exact R2 | reflexivity ] |].
  split; [ first [ exact R3 | reflexivity ] |].
  split; [ first [ exact R28 | reflexivity ] |].
  split; [ first [ exact R29 | reflexivity ] |].
  split; [ first [ exact R30 | reflexivity ] |].
  split; [ first [ exact R31 | reflexivity ] |].
  split; [ exact GM |].
  split; [ rewrite <- HCa; exact GMin | rewrite <- HCa; lia ].
Qed.

Theorem accept_implies_struct :
  forall {HS : Type} (inst : PkgHmac_t HS) (pkg : slice u8)
         (en : array u8 16%usize) (h : HS) (key : slice u8) r,
    parse_and_verify inst pkg en h key = Ok (Core_result_Result_Ok r) ->
    StructOk pkg en.
Proof.
  intros HS inst pkg en h key r Hacc.
  pose proof usize_max_bound as Hub. pose proof u32max_big as Hbig.
  pose proof (accept_implies_len_ge_112 inst pkg en h key r Hacc) as Hlen.
  destruct (accept_implies_guard_values inst pkg en h key r Hacc)
    as [b0 [b1 [b2 [b3 [c28 [c29 [c30 [c31
       [R0 [R1 [R2 [R3 [R28 [R29 [R30 [R31 [GM [GMin GOff]]]]]]]]]]]]]]]]]].
  (* the four magic bytes and the four length bytes, as `rdS` sees them *)
  assert (D0 : rdS pkg 0 = to_Z b0)
    by (rewrite <- tz0 at 1; apply rdS_ok; [ rewrite tz0; lia | exact R0 ]).
  assert (D1 : rdS pkg 1 = to_Z b1)
    by (rewrite <- tz1 at 1; apply rdS_ok; [ rewrite tz1; lia | exact R1 ]).
  assert (D2 : rdS pkg 2 = to_Z b2)
    by (rewrite <- tz2 at 1; apply rdS_ok; [ rewrite tz2; lia | exact R2 ]).
  assert (D3 : rdS pkg 3 = to_Z b3)
    by (rewrite <- tz3 at 1; apply rdS_ok; [ rewrite tz3; lia | exact R3 ]).
  assert (E28 : rdS pkg 28 = to_Z c28)
    by (rewrite <- tz28 at 1; apply rdS_ok; [ rewrite tz28; lia | exact R28 ]).
  assert (E29 : rdS pkg 29 = to_Z c29)
    by (rewrite <- tz29 at 1; apply rdS_ok; [ rewrite tz29; lia | exact R29 ]).
  assert (E30 : rdS pkg 30 = to_Z c30)
    by (rewrite <- tz30 at 1; apply rdS_ok; [ rewrite tz30; lia | exact R30 ]).
  assert (E31 : rdS pkg 31 = to_Z c31)
    by (rewrite <- tz31 at 1; apply rdS_ok; [ rewrite tz31; lia | exact R31 ]).
  rewrite (dec32_val b0 b1 b2 b3) in GM.
  rewrite (dec32_val c28 c29 c30 c31) in GMin, GOff.
  unfold StructOk, ldec.
  split; [ exact Hlen |].
  split. { replace (0 + 1) with 1 by lia. replace (0 + 2) with 2 by lia.
           replace (0 + 3) with 3 by lia.
           rewrite D0, D1, D2, D3. exact GM. }
  split. { replace (28 + 1) with 29 by lia. replace (28 + 2) with 30 by lia.
           replace (28 + 3) with 31 by lia.
           rewrite E28, E29, E30, E31. exact GMin. }
  split. { replace (28 + 1) with 29 by lia. replace (28 + 2) with 30 by lia.
           replace (28 + 3) with 31 by lia.
           rewrite E28, E29, E30, E31. exact GOff. }
  (* the nonce gate, already pushed to package bytes by P1 *)
  intros i Hi.
  destruct (exists_usize i ltac:(lia)) as [ii Hii].
  destruct (exists_usize (4 + i) ltac:(lia)) as [jj Hjj].
  destruct (accept_implies_nonce_equal inst pkg en h key r Hacc ii jj
              ltac:(lia) ltac:(lia)) as [x [y [Hx [Hy Hxy]]]].
  rewrite <- Hjj, <- Hii.
  rewrite (rdS_ok pkg jj x ltac:(lia) Hx), (rdA_ok en ii y ltac:(lia) Hy).
  exact Hxy.
Qed.

(* ===================================================================== *)
(* TACTICS FOR THE CONVERSE WALK                                          *)
(* ===================================================================== *)

(* `to_Z` of the literal offsets, in the GOAL only. Update_Safety's `tza` does
   the same `in *`, which here would traverse the (very large) residual body at
   every bound obligation. *)
Ltac tzg := rewrite ?tz0, ?tz1, ?tz2, ?tz3, ?tz4, ?tz15, ?tz16, ?tz20, ?tz21,
  ?tz22, ?tz23, ?tz24, ?tz25, ?tz26, ?tz27, ?tz28, ?tz29, ?tz30, ?tz31, ?tz32,
  ?tz35, ?tz39, ?tz43, ?tz48, ?tz91, ?tz_fixed, ?tz_min, ?tz_hdr.

(* One in-bounds read, with the index term taken FROM the residual so that it
   matches the extracted one exactly. *)
Ltac wread Ht v Hv :=
  match type of Ht with
  | context [ slice_index_usize ?s ?k ] =>
    destruct (slice_index_usize_ok s k) as [v Hv];
    [ split; tzg; lia | rewrite Hv in Ht; cbn [bind] in Ht ]
  end.

(* One valid sub-slice. The `%return` proof terms inside the range literals make
   `slice_index_range_ok`'s conclusion only CONVERTIBLE to the residual's
   subterm, so it is bridged with `exact` before rewriting (cf. Update_Safety's
   `pv_range`). *)
Ltac wrange Ht sub Hs Hl :=
  match type of Ht with
  | context [ core_slice_index_Slice_index ?I ?s
      {| core_ops_range_Range_start := ?a; core_ops_range_Range_end_ := ?b |} ] =>
    destruct (slice_index_range_ok s a b ltac:(tzg; lia) ltac:(tzg; lia)
                ltac:(tzg; lia)) as [sub [Hs Hl]];
    let E := fresh "E" in
    assert (E : core_slice_index_Slice_index I s
      {| core_ops_range_Range_start := a; core_ops_range_Range_end_ := b |}
      = Ok sub) by exact Hs;
    rewrite E in Ht; clear E; cbn [bind] in Ht
  end.

(* ===================================================================== *)
(* CONVERSE, PART 1 — the two facts the walk needs about the scratch      *)
(* buffers, stated over ABSTRACT buffers.                                 *)
(*                                                                        *)
(* WHY ABSTRACT. The extracted body builds its scratch as                 *)
(* `array_repeat 16%usize 0%u8`, whose element type elaborates to         *)
(* `scalar U8`, while every hand-written occurrence elaborates to the     *)
(* (definitionally equal, syntactically different) `u8`. `rewrite` keys on *)
(* the head symbol and then matches arguments up to unification, and that  *)
(* difference defeats it. Quantifying the buffer and using `apply` — which *)
(* unifies up to conversion — removes the problem instead of papering over *)
(* it with `change`.                                                       *)
(* ===================================================================== *)

(** THE NONCE GATE PASSES. If the parser's 16-byte scratch holds `pkg[4..20)`
    and those bytes are the armed nonce's, the constant-time comparator returns
    `true`. This is `ct_eq16_complete` transported through the copy and the
    write-back. *)
Lemma nonce_gate_passes :
  forall (nb : array u8 16%usize) (nsrc : slice u8)
         (en : array u8 16%usize) (pkg : slice u8),
    to_Z (slice_len nsrc) = to_Z (16%usize) ->
    (forall i j : usize, 0 <= to_Z i < 16 -> to_Z j = 4 + to_Z i ->
       slice_index_usize nsrc i = slice_index_usize pkg j) ->
    (forall i, 0 <= i < 16 -> rdS pkg (4 + i) = rdA en i) ->
    ct_eq16 (array_from_slice nb nsrc) en = Ok true.
Proof.
  intros nb nsrc en pkg Hnl Rn Hnon.
  pose proof usize_max_bound as Hub. pose proof u32max_big as Hbig.
  apply ct_eq16_complete. intros k Hk x y Hx Hy.
  rewrite (array_from_slice_val nb nsrc k Hnl) in Hx.
  destruct (exists_usize (4 + to_Z k) ltac:(lia)) as [kk Hkk].
  rewrite (Rn k kk Hk ltac:(lia)) in Hx.
  pose proof (Hnon (to_Z k) ltac:(lia)) as Hn.
  rewrite <- Hkk in Hn.
  rewrite (rdS_at pkg kk ltac:(lia)), Hx in Hn.
  rewrite (rdA_at en k ltac:(lia)), Hy in Hn.
  exact Hn.
Qed.

(** THE PREIMAGE THE SEAM IS FED ENCODES TO THE WIRE'S MESSAGE. The same
    computation as `Update_Encoding.accept_encodes`'s `W1`/`W2`, but taking the
    window facts as hypotheses instead of deriving them from acceptance — which
    is exactly what makes it usable in the converse direction. *)
Lemma msg_pre_eq_pkg :
  forall (pkg : slice u8) (pre : array u8 91%usize)
         (nb : array u8 16%usize) (hb : array u8 48%usize)
         (nsrc hsrc : slice u8) (au ve bl : u32)
         (c20 c21 c22 c23 c24 c25 c26 c27 c28 c29 c30 c31 : u8),
    Assembles pre (array_from_slice nb nsrc) au ve bl (array_from_slice hb hsrc) ->
    to_Z (slice_len nsrc) = to_Z (16%usize) ->
    to_Z (slice_len hsrc) = to_Z (48%usize) ->
    (forall i j : usize, 0 <= to_Z i < 16 -> to_Z j = 4 + to_Z i ->
       slice_index_usize nsrc i = slice_index_usize pkg j) ->
    (forall i j : usize, 0 <= to_Z i < 48 -> to_Z j = 32 + to_Z i ->
       slice_index_usize hsrc i = slice_index_usize pkg j) ->
    slice_index_usize pkg 20%usize = Ok c20 ->
    slice_index_usize pkg 21%usize = Ok c21 ->
    slice_index_usize pkg 22%usize = Ok c22 ->
    slice_index_usize pkg 23%usize = Ok c23 ->
    slice_index_usize pkg 24%usize = Ok c24 ->
    slice_index_usize pkg 25%usize = Ok c25 ->
    slice_index_usize pkg 26%usize = Ok c26 ->
    slice_index_usize pkg 27%usize = Ok c27 ->
    slice_index_usize pkg 28%usize = Ok c28 ->
    slice_index_usize pkg 29%usize = Ok c29 ->
    slice_index_usize pkg 30%usize = Ok c30 ->
    slice_index_usize pkg 31%usize = Ok c31 ->
    to_Z au = to_Z (dec32 c20 c21 c22 c23) ->
    to_Z ve = to_Z (dec32 c24 c25 c26 c27) ->
    to_Z bl = to_Z (dec32 c28 c29 c30 c31) ->
    msg_of_pre pre = msg_of_pkg pkg.
Proof.
  intros pkg pre nb hb nsrc hsrc au ve bl
         c20 c21 c22 c23 c24 c25 c26 c27 c28 c29 c30 c31
         HAsm Hnl Hhl Rn Rh
         R20 R21 R22 R23 R24 R25 R26 R27 R28 R29 R30 R31 Vau Vve Vbl.
  pose proof usize_max_bound as Hub. pose proof u32max_big as Hbig.
  pose proof HAsm as HAsm'.
  destruct HAsm' as [_ [ANon [AAu [AVe [ABl AHh]]]]].
  assert (DNon : forall i j k : usize, 0 <= to_Z i < 16 ->
            to_Z j = 15 + to_Z i -> to_Z k = 4 + to_Z i ->
            array_index_usize pre j = slice_index_usize pkg k).
  { intros i j k Hi Hj Hk.
    rewrite (ANon i j Hi Hj), (array_from_slice_val nb nsrc i Hnl).
    exact (Rn i k Hi ltac:(lia)). }
  assert (DHdr : forall i j k : usize, 0 <= to_Z i < 48 ->
            to_Z j = 43 + to_Z i -> to_Z k = 32 + to_Z i ->
            array_index_usize pre j = slice_index_usize pkg k).
  { intros i j k Hi Hj Hk.
    rewrite (AHh i j Hi Hj), (array_from_slice_val hb hsrc i Hhl).
    exact (Rh i k Hi ltac:(lia)). }
  assert (W1 : forall i, 0 <= i < 28 -> rdA pre (15 + i) = rdS pkg (4 + i)).
  { intros i Hi.
    assert (Hj : to_Z (uz (15 + i)) = 15 + i) by (apply to_Z_uz; lia).
    assert (Hk : to_Z (uz (4 + i)) = 4 + i) by (apply to_Z_uz; lia).
    unfold rdA, rdS.
    destruct (Z.lt_ge_cases i 16) as [Hlt|Hge].
    - assert (Hi0 : to_Z (uz i) = i) by (apply to_Z_uz; lia).
      rewrite (DNon (uz i) (uz (15 + i)) (uz (4 + i)) ltac:(lia) ltac:(lia)
                 ltac:(lia)). reflexivity.
    - destruct (Z.lt_ge_cases i 20) as [Hlt2|Hge2].
      + assert (Hi0 : to_Z (uz (i - 16)) = i - 16) by (apply to_Z_uz; lia).
        destruct (u32_window_is_pkg_bytes pkg pre au
                    c20 c21 c22 c23 20%usize 21%usize 22%usize 23%usize 31 20
                    AAu Vau ltac:(tzg; lia) ltac:(tzg; lia) ltac:(tzg; lia)
                    ltac:(tzg; lia) R20 R21 R22 R23
                    (uz (i - 16)) (uz (15 + i)) (uz (4 + i))
                    ltac:(lia) ltac:(lia) ltac:(lia)) as [x [y [Hx [Hy Hxy]]]].
        rewrite Hx, Hy. exact Hxy.
      + destruct (Z.lt_ge_cases i 24) as [Hlt3|Hge3].
        * assert (Hi0 : to_Z (uz (i - 20)) = i - 20) by (apply to_Z_uz; lia).
          destruct (u32_window_is_pkg_bytes pkg pre ve
                      c24 c25 c26 c27 24%usize 25%usize 26%usize 27%usize 35 24
                      AVe Vve ltac:(tzg; lia) ltac:(tzg; lia) ltac:(tzg; lia)
                      ltac:(tzg; lia) R24 R25 R26 R27
                      (uz (i - 20)) (uz (15 + i)) (uz (4 + i))
                      ltac:(lia) ltac:(lia) ltac:(lia)) as [x [y [Hx [Hy Hxy]]]].
          rewrite Hx, Hy. exact Hxy.
        * assert (Hi0 : to_Z (uz (i - 24)) = i - 24) by (apply to_Z_uz; lia).
          destruct (u32_window_is_pkg_bytes pkg pre bl
                      c28 c29 c30 c31 28%usize 29%usize 30%usize 31%usize 39 28
                      ABl Vbl ltac:(tzg; lia) ltac:(tzg; lia) ltac:(tzg; lia)
                      ltac:(tzg; lia) R28 R29 R30 R31
                      (uz (i - 24)) (uz (15 + i)) (uz (4 + i))
                      ltac:(lia) ltac:(lia) ltac:(lia)) as [x [y [Hx [Hy Hxy]]]].
          rewrite Hx, Hy. exact Hxy. }
  assert (W2 : forall i, 0 <= i < 48 -> rdA pre (43 + i) = rdS pkg (32 + i)).
  { intros i Hi.
    assert (Hi0 : to_Z (uz i) = i) by (apply to_Z_uz; lia).
    assert (Hj : to_Z (uz (43 + i)) = 43 + i) by (apply to_Z_uz; lia).
    assert (Hk : to_Z (uz (32 + i)) = 32 + i) by (apply to_Z_uz; lia).
    unfold rdA, rdS.
    rewrite (DHdr (uz i) (uz (43 + i)) (uz (32 + i)) ltac:(lia) ltac:(lia)
               ltac:(lia)). reflexivity. }
  unfold msg_of_pre, msg_of_pkg. f_equal.
  - apply (enc_from_shift 28 (rdA pre) (rdS pkg) 15 4).
    intros i Hi. apply W1. simpl in Hi. lia.
  - f_equal. apply (enc_from_shift 48 (rdA pre) (rdS pkg) 43 32).
    intros i Hi. apply W2. simpl in Hi. lia.
Qed.

Lemma Assembles_AssemblesF : forall pre n au ve bl hh,
  Assembles pre n au ve bl hh -> AssemblesF pre (mkFields n au ve bl hh).
Proof. intros pre n au ve bl hh H. exact H. Qed.

(* ===================================================================== *)
(* CONVERSE, PART 2 — THE WALK.                                           *)
(* ===================================================================== *)

Section Walk.

Context {HS : Type}.
Variable inst : PkgHmac_t HS.
Variable h    : HS.
Variable key  : slice u8.
Variable mac  : slice u8 -> array u8 91%usize -> array u8 32%usize.

(** C1 — the seam is a deterministic keyed function of (key, preimage).
    Inherited verbatim from `Update_Crypto`; it carries no unforgeability (the
    constant function satisfies it). *)
Hypothesis Hseam :
  forall k p, inst.(PkgHmac_t_hmac_pkg) h k p = Ok (mac k p).

Lemma seam_total : forall k p, exists t, inst.(PkgHmac_t_hmac_pkg) h k p = Ok t.
Proof. intros k p. exists (mac k p). apply Hseam. Qed.

(** THE WALK. Under the five key-free guards the extracted body reduces to a
    SINGLE tag comparison, and everything that comparison is made of is pinned:
    `expect` is the seam's output on a preimage that assembles this package's
    fields and encodes to `msg_of_pkg pkg`, and `got` is this package's own
    trailing 32 bytes. Nothing here mentions the tag's VALUE — this is precisely
    what is left of the parser once the tag check is factored out.

    ON THE `forall PV, parse_and_verify … = PV -> … /\ PV = …` SHAPE. It is a
    proof convenience and NOTHING MORE: it is logically identical to stating the
    equation about `parse_and_verify … ` directly, and it should not be read as
    making the statement self-checking or otherwise stronger. What DOES make the
    statement strong is the proof: it rewrites the extracted term step by step —
    every `bind`, every axiomatic read, every guard — and closes with
    `symmetry; exact Hpv`, so the right-hand side above is the FULL residual of
    the extracted body and not a sub-expression selected from it. Had anything
    been dropped, that final step would not typecheck. *)
Theorem parse_walk :
  forall (pkg : slice u8) (en : array u8 16%usize)
         (PV : result (core_result_Result_t VerifiedUpdate_t UpdateError_t)),
    parse_and_verify inst pkg en h key = PV ->
    StructOk pkg en ->
    exists (expect : array u8 32%usize) (got : slice u8)
           (pre : array u8 91%usize) (f : Fields) (r : VerifiedUpdate_t),
      AssemblesF pre f
      /\ expect = mac key pre
      /\ msg_of_pre pre = msg_of_pkg pkg
      /\ to_Z (slice_len got) = 32
      /\ (forall i j : usize, 0 <= to_Z i < 32 ->
            to_Z j = to_Z (slice_len pkg) - 32 + to_Z i ->
            slice_index_usize got i = slice_index_usize pkg j)
      /\ PV = bind (ct_eq32 expect got)
                (fun b1 => if b1
                           then Ok (Core_result_Result_Ok r)
                           else Ok (Core_result_Result_Err UpdateError_TagInvalid)).
Proof.
  intros pkg en PV Hpv HSk.
  destruct HSk as [Hlen [Hmag [Hmin [Hoff Hnon]]]].
  pose proof usize_max_bound as Hub. pose proof u32max_big as Hbig.
  pose proof (to_Z_usize_bounds (slice_len pkg)) as Hlub.
  unfold parse_and_verify in Hpv. cbv zeta in Hpv.
  (* ---- branch 1: the length guard ------------------------------------ *)
  destruct (usize_add_ok' fIXED_PREFIX mIN_BLOB) as [i1 [E1 V1]]; [ tzg; lia | ].
  rewrite tz_fixed, tz_min in V1.
  rewrite E1 in Hpv; cbn [bind] in Hpv.
  destruct (usize_add_ok' i1 32%usize) as [i2 [E2 V2]]; [ rewrite V1; tzg; lia | ].
  rewrite V1, tz32 in V2.
  rewrite E2 in Hpv; cbn [bind] in Hpv.
  assert (G0 : (slice_len pkg s< i2) = false)
    by (unfold scalar_ltb; apply Z.ltb_ge; lia).
  rewrite G0 in Hpv; cbv beta iota in Hpv.
  (* ---- branch 2: the magic guard ------------------------------------- *)
  wread Hpv b0 R0. wread Hpv b1 R1. wread Hpv b2 R2. wread Hpv b3 R3.
  assert (D0 : rdS pkg 0 = to_Z b0)
    by (rewrite <- tz0 at 1; apply rdS_ok; [ rewrite tz0; lia | exact R0 ]).
  assert (D1 : rdS pkg 1 = to_Z b1)
    by (rewrite <- tz1 at 1; apply rdS_ok; [ rewrite tz1; lia | exact R1 ]).
  assert (D2 : rdS pkg 2 = to_Z b2)
    by (rewrite <- tz2 at 1; apply rdS_ok; [ rewrite tz2; lia | exact R2 ]).
  assert (D3 : rdS pkg 3 = to_Z b3)
    by (rewrite <- tz3 at 1; apply rdS_ok; [ rewrite tz3; lia | exact R3 ]).
  assert (GM : (core_num_U32_from_le_bytes (mk_array4 b0 b1 b2 b3)
                s<> uPDATE_MAGIC) = false).
  { unfold scalar_neqb, scalar_eqb. apply negb_false_iff. apply Z.eqb_eq.
    change (core_num_U32_from_le_bytes (mk_array4 b0 b1 b2 b3))
      with (dec32 b0 b1 b2 b3).
    rewrite dec32_val. unfold ldec in Hmag.
    replace (0 + 1) with 1 in Hmag by lia. replace (0 + 2) with 2 in Hmag by lia.
    replace (0 + 3) with 3 in Hmag by lia.
    rewrite D0, D1, D2, D3 in Hmag. lia. }
  rewrite GM in Hpv; cbv beta iota in Hpv.
  (* ---- the nonce scratch --------------------------------------------- *)
  cbn [array_to_slice_mut] in Hpv.
  wrange Hpv nsrc Hns Hnl. rewrite tz4, tz20 in Hnl.
  assert (Hnl16 : to_Z (slice_len nsrc) = to_Z (16%usize))
    by (rewrite Hnl, tz16; reflexivity).
  assert (Rn : forall i j : usize, 0 <= to_Z i < 16 -> to_Z j = 4 + to_Z i ->
                 slice_index_usize nsrc i = slice_index_usize pkg j).
  { intros i j Hi Hj.
    apply (slice_index_range_val _ _ _ _ i j Hns);
      [ lia | tzg; lia | tzg; lia ]. }
  match type of Hpv with
  | context [ core_slice_Slice_copy_from_slice ?m ?dst ?src ] =>
    destruct (copy_from_slice_ok m dst src
      ltac:(rewrite slice_len_array_to_slice, Hnl; tzg; lia)) as [ncpy Hnc];
    rewrite Hnc in Hpv; cbn [bind] in Hpv
  end.
  apply copy_from_slice_val in Hnc. subst ncpy.
  (* ---- the twelve field bytes ---------------------------------------- *)
  wread Hpv c20 R20. wread Hpv c21 R21. wread Hpv c22 R22. wread Hpv c23 R23.
  wread Hpv c24 R24. wread Hpv c25 R25. wread Hpv c26 R26. wread Hpv c27 R27.
  wread Hpv c28 R28. wread Hpv c29 R29. wread Hpv c30 R30. wread Hpv c31 R31.
  assert (E28 : rdS pkg 28 = to_Z c28)
    by (rewrite <- tz28 at 1; apply rdS_ok; [ rewrite tz28; lia | exact R28 ]).
  assert (E29 : rdS pkg 29 = to_Z c29)
    by (rewrite <- tz29 at 1; apply rdS_ok; [ rewrite tz29; lia | exact R29 ]).
  assert (E30 : rdS pkg 30 = to_Z c30)
    by (rewrite <- tz30 at 1; apply rdS_ok; [ rewrite tz30; lia | exact R30 ]).
  assert (E31 : rdS pkg 31 = to_Z c31)
    by (rewrite <- tz31 at 1; apply rdS_ok; [ rewrite tz31; lia | exact R31 ]).
  assert (Hbv : ldec (rdS pkg) 28 = to_Z (dec32 c28 c29 c30 c31)).
  { unfold ldec. rewrite dec32_val.
    replace (28 + 1) with 29 by lia. replace (28 + 2) with 30 by lia.
    replace (28 + 3) with 31 by lia. rewrite E28, E29, E30, E31. lia. }
  (* ---- branches 3 and 4: the two blob-length guards ------------------- *)
  destruct (cast_u32_usize_ok (dec32 c28 c29 c30 c31)) as [bl [Ec Vc]].
  change (core_num_U32_from_le_bytes (mk_array4 c28 c29 c30 c31))
    with (dec32 c28 c29 c30 c31) in Hpv.
  rewrite Ec in Hpv; cbn [bind] in Hpv.
  destruct (usize_sub_ok' (slice_len pkg) 32%usize) as [toff [Et Vt]];
    [ tzg; lia | ].
  rewrite tz32 in Vt.
  rewrite Et in Hpv; cbn [bind] in Hpv.
  assert (Gmin : (bl s< mIN_BLOB) = false).
  { unfold scalar_ltb. apply Z.ltb_ge. rewrite tz_min, Vc. lia. }
  rewrite Gmin in Hpv; cbv beta iota in Hpv.
  destruct (usize_sub_ok' toff fIXED_PREFIX) as [i23 [E23 V23]];
    [ rewrite Vt; tzg; lia | ].
  rewrite tz_fixed in V23.
  rewrite E23 in Hpv; cbn [bind] in Hpv.
  assert (Goff : (i23 s<> bl) = false).
  { unfold scalar_neqb, scalar_eqb. apply negb_false_iff. apply Z.eqb_eq.
    rewrite V23, Vt, Vc. lia. }
  rewrite Goff in Hpv; cbv beta iota in Hpv.
  (* ---- the blob ------------------------------------------------------ *)
  wrange Hpv blob Hblob Hbl. rewrite tz_fixed, Vt in Hbl.
  (* ---- branch 5: the nonce gate -------------------------------------- *)
  match type of Hpv with
  | context [ ct_eq16 ?A ?B ] =>
    assert (Hct16 : ct_eq16 A B = Ok true)
      by (apply (nonce_gate_passes _ nsrc en pkg Hnl16 Rn Hnon))
  end.
  rewrite Hct16 in Hpv; cbn [bind] in Hpv; cbv beta iota in Hpv.
  (* ---- the header scratch: the FULL 48-byte header blob[0,48) --------- *)
  cbn [array_to_slice_mut] in Hpv.
  wrange Hpv hsrc Hhs Hhl. rewrite tz_hdr, tz0 in Hhl.
  assert (Hhl48 : to_Z (slice_len hsrc) = to_Z (48%usize))
    by (rewrite Hhl, tz48; reflexivity).
  assert (Rh : forall i j : usize, 0 <= to_Z i < 48 -> to_Z j = 32 + to_Z i ->
                 slice_index_usize hsrc i = slice_index_usize pkg j).
  { intros i j Hi Hj.
    rewrite (slice_index_range_val _ _ _ _ i i Hhs);
      [| lia | rewrite tz_hdr, tz0; lia | rewrite tz0; lia ].
    apply (slice_index_range_val _ _ _ _ i j Hblob);
      [ lia | rewrite Vt; tzg; lia | rewrite tz_fixed; lia ]. }
  match type of Hpv with
  | context [ core_slice_Slice_copy_from_slice ?m ?dst ?src ] =>
    destruct (copy_from_slice_ok m dst src
      ltac:(rewrite slice_len_array_to_slice, Hhl; tzg; lia)) as [hcpy Hhc];
    rewrite Hhc in Hpv; cbn [bind] in Hpv
  end.
  apply copy_from_slice_val in Hhc. subst hcpy.
  destruct (cast_usize_u32_ok bl ltac:(rewrite Vc; apply to_Z_u32_bounds))
    as [blu [Ecu Vcu]].
  rewrite Ecu in Hpv; cbn [bind] in Hpv.
  (* ---- the seam ------------------------------------------------------ *)
  match type of Hpv with
  | context [ compute_pkg_tag ?I ?N ?AU ?VE ?BL ?HH ?H2 ?K ] =>
    destruct (compute_pkg_tag_total I N AU VE BL HH H2 K seam_total)
      as [expect Hcpt];
    rewrite Hcpt in Hpv; cbn [bind] in Hpv
  end.
  (* ---- the tag window ------------------------------------------------ *)
  destruct (usize_add_ok' toff 32%usize) as [i26 [E26 V26]];
    [ rewrite Vt; tzg; lia | ].
  rewrite tz32, Vt in V26.
  rewrite E26 in Hpv; cbn [bind] in Hpv.
  wrange Hpv got Hgot Hgl. rewrite V26, Vt in Hgl.
  (* ===================================================================== *)
  (* what the walk produced                                                *)
  (* ===================================================================== *)
  destruct (compute_pkg_tag_assembles inst h key _ _ _ _ _ _ Hcpt)
    as [pre [Hmacpre HAsm]].
  rewrite Hseam in Hmacpre. injection Hmacpre as Hmacpre.
  pose proof (Assembles_AssemblesF _ _ _ _ _ _ HAsm) as HAF.
  match type of HAF with
  | AssemblesF _ ?F => exists expect, got, pre, F
  end.
  eexists.
  split. { exact HAF. }
  split. { symmetry. exact Hmacpre. }
  split.
  { eapply msg_pre_eq_pkg.
    - exact HAsm.
    - exact Hnl16.
    - exact Hhl48.
    - exact Rn.
    - exact Rh.
    - exact R20. - exact R21. - exact R22. - exact R23.
    - exact R24. - exact R25. - exact R26. - exact R27.
    - exact R28. - exact R29. - exact R30. - exact R31.
    - reflexivity.
    - reflexivity.
    - rewrite Vcu, Vc. reflexivity. }
  split. { rewrite Hgl. lia. }
  split.
  { intros i j Hi Hj.
    apply (slice_index_range_val _ _ _ _ i j Hgot);
      [ lia | rewrite V26, Vt; lia | rewrite Vt; lia ]. }
  symmetry. exact Hpv.
Qed.

(* ===================================================================== *)
(* CONVERSE, PART 3 — the tag gate IS the encoded-tag equation.           *)
(* ===================================================================== *)

Lemma tag_of_arr_nonneg : forall t : array u8 32%usize, 0 <= tag_of_arr t.
Proof.
  intro t. unfold tag_of_arr.
  pose proof (enc_from_bound 32 (rdA t) 0 (fun j _ => rdA_digit t (0 + j))). lia.
Qed.

Lemma tag_of_pkg_nonneg : forall pkg : slice u8, 0 <= tag_of_pkg pkg.
Proof.
  intro pkg. unfold tag_of_pkg.
  pose proof (enc_from_bound 32 (rdS pkg) (to_Z (slice_len pkg) - 32)
                (fun j _ => rdS_digit pkg (to_Z (slice_len pkg) - 32 + j))). lia.
Qed.

(** BOTH DIRECTIONS OF THE 32-BYTE GATE, AT THE ENCODING. Soundness is
    `ct_eq32_sound` composed with `enc_from_shift`; completeness is
    `enc_from_inj` (base-257 digit recovery) composed with `ct_eq32_complete`.
    This is the step at which the game's `nat`-valued tag equation becomes the
    parser's byte comparison. *)
Lemma tag_gate_iff :
  forall (pkg : slice u8) (expect : array u8 32%usize) (got : slice u8),
    112 <= to_Z (slice_len pkg) ->
    to_Z (slice_len got) = 32 ->
    (forall i j : usize, 0 <= to_Z i < 32 ->
       to_Z j = to_Z (slice_len pkg) - 32 + to_Z i ->
       slice_index_usize got i = slice_index_usize pkg j) ->
    (ct_eq32 expect got = Ok true <-> tag_of_arr expect = tag_of_pkg pkg).
Proof.
  intros pkg expect got Hlen Hgl Rgot.
  pose proof usize_max_bound as Hub. pose proof u32max_big as Hbig.
  pose proof (to_Z_usize_bounds (slice_len pkg)) as Hlub.
  split.
  - (* the comparator passed, so the two 32-byte windows encode alike *)
    intro Hct. destruct (ct_eq32_sound _ _ Hct) as [_ Htag].
    unfold tag_of_arr, tag_of_pkg.
    apply (enc_from_shift 32 (rdA expect) (rdS pkg) 0
             (to_Z (slice_len pkg) - 32)).
    intros i Hi. cbn in Hi.
    assert (Hii : to_Z (uz i) = i) by (apply to_Z_uz; lia).
    assert (Hjj : to_Z (uz (to_Z (slice_len pkg) - 32 + i))
                  = to_Z (slice_len pkg) - 32 + i) by (apply to_Z_uz; lia).
    destruct (Htag (uz i) ltac:(lia)) as [x [y [Hx [Hy Hxy]]]].
    rewrite (Rgot (uz i) (uz (to_Z (slice_len pkg) - 32 + i))
               ltac:(lia) ltac:(lia)) in Hy.
    unfold rdA, rdS. replace (0 + i) with i by lia.
    rewrite Hx, Hy. exact Hxy.
  - (* the encodings agree, so every byte pair agrees, so it passes *)
    intro Heq.
    apply ct_eq32_complete; [ exact Hgl |].
    unfold tag_of_arr, tag_of_pkg in Heq.
    pose proof (enc_from_inj 32 (rdA expect) (rdS pkg) 0
                  (to_Z (slice_len pkg) - 32)
                  (fun j _ => rdA_digit expect (0 + j))
                  (fun j _ => rdS_digit pkg (to_Z (slice_len pkg) - 32 + j))
                  Heq) as Hdig.
    intros k Hk x y Hx Hy.
    assert (Hjj : to_Z (uz (to_Z (slice_len pkg) - 32 + to_Z k))
                  = to_Z (slice_len pkg) - 32 + to_Z k) by (apply to_Z_uz; lia).
    pose proof (Hdig (to_Z k) ltac:(cbn; lia)) as Hd.
    replace (0 + to_Z k) with (to_Z k) in Hd by lia.
    rewrite (rdA_at expect k ltac:(lia)), Hx in Hd.
    rewrite (Rgot k (uz (to_Z (slice_len pkg) - 32 + to_Z k))
               ltac:(lia) ltac:(lia)) in Hy.
    rewrite <- Hjj in Hd.
    rewrite (rdS_at pkg (uz (to_Z (slice_len pkg) - 32 + to_Z k)) ltac:(lia)),
            Hy in Hd.
    exact Hd.
Qed.

(* ===================================================================== *)
(* THE FACTORISATION — (F), with the abstract MAC.                        *)
(* ===================================================================== *)

Context (K : Type).
Variable MACg : K -> nat -> nat.
Variable k0 : K.

(** C1e — verbatim from `Umbra_DeviceLink`, including the `AssemblesF` guard
    that keeps it satisfiable at a real HMAC seam (see that file for why the
    unguarded form is FALSE). Not a cryptographic assumption. *)
Hypothesis Hfactor :
  forall (pre : array u8 91%usize) (f : Fields),
    AssemblesF pre f ->
    MACg k0 (Z.to_nat (msg_of_pre pre))
    = Z.to_nat (tag_of_arr (mac key pre)).

(** (F). ACCEPTANCE IS EXACTLY "THE KEY-FREE GUARDS HOLD AND THE WIRE'S TAG IS
    THE MAC OF THE WIRE'S MESSAGE". The left-to-right direction is the old
    `device_accept_implies_submit_true` plus `accept_implies_struct`; the
    right-to-left direction is `parse_walk` plus `tag_gate_iff`, and is what no
    earlier revision had. Everything key-dependent now sits in the second
    conjunct, which is the single `checktag` query a key-less reduction can
    make. *)
Theorem accept_factorises :
  forall (pkg : slice u8) (en : array u8 16%usize),
    (exists r, parse_and_verify inst pkg en h key = Ok (Core_result_Result_Ok r))
    <-> (StructOk pkg en
         /\ Z.to_nat (tag_of_pkg pkg) = MACg k0 (Z.to_nat (msg_of_pkg pkg))).
Proof.
  intros pkg en. split.
  - intros [r Hacc]. split.
    + exact (accept_implies_struct inst pkg en h key r Hacc).
    + destruct (accept_encodes inst h key mac Hseam pkg en r Hacc)
        as [f [pre [t [HA [Ht [_ [_ [Hm Htg]]]]]]]].
      rewrite <- Hm, <- Htg, Ht. symmetry. exact (Hfactor pre f HA).
  - intros [HS0 Htag].
    pose proof HS0 as HS1. destruct HS1 as [Hlen _].
    destruct (parse_walk pkg en _ eq_refl HS0)
      as [expect [got [pre [f [r [HA [Hex [Hmsg [Hgl [Rgot Hres]]]]]]]]]].
    assert (Htg2 : tag_of_arr expect = tag_of_pkg pkg).
    { apply Z2Nat.inj;
        [ apply tag_of_arr_nonneg | apply tag_of_pkg_nonneg |].
      rewrite Htag, <- Hmsg, Hex. symmetry. exact (Hfactor pre f HA). }
    assert (Hct : ct_eq32 expect got = Ok true)
      by (apply (proj2 (tag_gate_iff pkg expect got Hlen Hgl Rgot)); exact Htg2).
    exists r. rewrite Hres, Hct. reflexivity.
Qed.

End Walk.
