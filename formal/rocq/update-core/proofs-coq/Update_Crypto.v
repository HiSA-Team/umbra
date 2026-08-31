(** THE COMPOSED SECURITY STATEMENT — acceptance ⇒ authenticated fields, and
    activation ⇒ strictly newer.

    P1/P3/P4 are each about one piece of the parser. None of them is a SECURITY
    theorem, because the HMAC seam is assumed only TOTAL: "authenticated" is not
    even expressible against a seam that may return anything. This file makes it
    expressible, by naming the cryptographic idealization explicitly and then
    proving what follows from it.

    HOW THE IDEALIZATION IS INTRODUCED. Everything below lives inside a `Section`
    with `Variable`/`Hypothesis`, so the assumptions become explicit PARAMETERS of
    every theorem — they are never global axioms, they never leak into any other
    file's `Print Assumptions`, and a reader can see, in each theorem's type,
    exactly which idealization it consumed.

      (C1) `Hseam` — the seam IS a keyed function: `hmac_pkg h k p = Ok (mac k p)`
           for some `mac : key -> preimage -> tag`. This is strictly stronger than
           P3's totality premise: it also says the tag depends on nothing but the
           key and the 91-byte preimage (no state, no nondeterminism, no clock).
           On the N657 the seam is `hw_hmac_single`, a call into the HASH engine;
           C1 is the standard "the hardware computes HMAC-SHA256" abstraction.

           WHAT C1 IS NOT. C1 is a FUNCTIONALITY assumption: determinism plus
           dependence on nothing outside (key, preimage). It carries no
           unforgeability, no collision resistance, no pseudorandomness — the
           constant function `fun _ _ => zeros` satisfies it. Nothing proved in
           this file may therefore be read as "an attacker cannot produce this
           tag"; what C1 buys is the ability to NAME the tag as a function of
           the key and of the assembled preimage, which is what lets the
           assembly result below be about `mac key` alone.

           C2 (previously: "for a fixed key the tag determines the five fields")
           has been REMOVED. It was an assumption that is false of any concrete
           32-byte-output function on a 91-byte domain, and it silently absorbed
           a structural fact — that the five fields land in disjoint windows of
           the preimage — that is now PROVED here (`assembly_injective`) rather
           than assumed.

    WHAT IS PROVED (all `Qed`, no admits):

      [accept_implies_authenticated_fields] — the composed theorem. If
        `parse_and_verify` accepts `pkg` against the armed nonce `en`, then
          (a) the tag field sits at `len − 32` and its 32 bytes ARE, byte for
              byte, the value the device's own `compute_pkg_tag` produces over
              exactly this package's (nonce, author_id, version, blob_len,
              header) — with author_id and version being the very fields
              handed back to the caller in the `VerifiedUpdate` record;
          (b) that value is `mac key pre` (C1) for a 91-byte preimage `pre` that
              is EXHIBITED and that PROVABLY carries those same fields at their
              fixed offsets — `Assembles pre nonce author version blob_len
              header`, i.e. the constant label at [0,15), nonce at [15,31),
              author_id at [31,35), version at [35,39), blob_len at [39,43),
              header at [43,91). This is the clause iteration 1 left bare
              (`exists p, expect = mac key p`, with `p` formally unrelated to
              the fields); it is what makes `assembly_injective` /
              `compute_pkg_tag_assembles` load-bearing for the headline result
              rather than a side artifact. It does NOT say the value is hard to
              obtain: C1 has no unforgeability content (see above);
          (c) the package's nonce field equals the armed nonce, byte for byte
              (Update_Auth.accept_implies_nonce_equal) — anti-replay at the level
              of bytes rather than of a boolean;
          (d)-(h) EVERY BYTE OF THE PREIMAGE IS PINNED. `Assembles` relates
              `pre` to the SEAM'S ARGUMENTS; of those, only author_id and
              version were tied to anything the caller can see. `nonce`, `bl`
              and `hdr` were LOOSE EXISTENTIALS, so the statement read "the tag
              covers SOME nonce" — the deleted C2's shape, one field over, and
              the freshness-critical one. The theorem now also carries:
                pre[15,31) = pkg[4..20)   AND equals the ARMED nonce `en`;
                pre[31,35) = pkg[20..24)  (author_id, at to_Z level);
                pre[35,39) = pkg[24..28)  (version);
                pre[39,43) = pkg[28..32)  (blob_len, through the
                                           u32->usize->u32 round-trip);
                pre[43,91) = blob[0..48), with `blob` proved to BE the
                                           sub-slice pkg[32..len-32) returned
                                           to the caller (v2: full UMBR header);
                pre[0,15)  = PKG_TAG_LABEL (from `Assembles`).
              So the sentence the result supports is "the tag is the device's
              MAC over the armed nonce and this package's bytes", not "over
              something containing the returned version".

      [compute_pkg_tag_assembles] / [assembly_injective] — the preimage assembly
        is a THEOREM, not an assumption: over the verbatim extracted body, the
        91-byte preimage carries the nonce at bytes 15..31, author_id at 31..35,
        version at 35..39, blob_len at 39..43 and header at 43..91, and two
        preimages that agree bytewise force all five fields to agree. This is the
        `assemble`-injectivity step C2 used to hide.

      [accepted_stale_update_is_not_activated] / [activation_implies_strictly_newer]
        — the P4 half of the composition, stated about a version field that
        reached the caller through the tag gate: slot B is activated iff its
        version strictly exceeds the active one.

        READ THESE TWO AS WEAKER THAN THEY LOOK. Both carry the acceptance
        hypothesis in their STATEMENT, but both PROOFS DISCARD IT (`intros pkg
        en r va _ Hle`), and `Print Assumptions` reports ZERO quarantine axioms
        for either. That is not sloppiness that can be tightened away here:
        `select_active_slot` is a pure function of two `option u32`s, and
        acceptance constrains it in no way whatsoever. They are therefore
        corollaries of the PURE selector lemmas `Update_Props.stale_update_
        not_selected` / `select_both_picks_strictly_greater`, with an INERT
        premise that only documents where the `u32` came from. Anyone quoting
        them as "an ACCEPTED stale package cannot be activated" is quoting the
        premise, not the proof.

        The premise becomes LOAD-BEARING one theorem down, in
        `activation_implies_package_version_strictly_newer`: there acceptance
        is what identifies `r.(verifiedUpdate_version)` with the four package
        bytes `pkg[24..28]`, so the conclusion is about the wire format and
        cannot be obtained from the selector lemmas alone. That is the P4
        statement to quote.

      [accept_implies_version_is_package_bytes] /
      [activation_implies_package_version_strictly_newer] — the same two results
        stated over the WIRE FORMAT instead of over a decoded `u32`. The decoder
        `u32::from_le_bytes` used to have no law at all, so `r.(version)` was
        formally an arbitrary function of four attacker-supplied bytes. With Q19
        (the decoder digit spec, the mirror of Q18) and Q20 (the read law for the
        4-byte `mk_array` literal the parser decodes), both discharged in
        Update_Model.v, these say: `pkg[24..28]` read little-endian IS the
        version handed back and compared by `select_active_slot`, those same four
        bytes are the ones inside the MAC'd preimage at [35,39), and activation
        implies that reading strictly exceeds the active slot's version.
        Round-trip, congruence and injectivity of the codec are DERIVED from Q19
        (`from_le_bytes_to_le_bytes`, `to_le_bytes_from_le_bytes`,
        `from_le_bytes_cong`, `from_le_bytes_inj`), not assumed.

    WHAT IS STILL OUTSIDE — do not read this as end-to-end device security:
      * the NONCE ARMING STATE MACHINE. `attest_imp.rs` keeps `nonce_armed` /
        `last_nonce` in kernel state, arms it on a quote and clears it on every
        update path. (c) says the package matches WHATEVER `en` the caller passed;
        that this `en` is fresh, single-use and unpredictable is a property of
        that handler, and it is not verified.
      * the A/B FLASH WRITE. Everything after `parse_and_verify` returns —
        erase/program of the inactive slot, the re-measurement probe, the
        TAMP anti-rollback floor, the reset — is unverified C/Rust.
      * `authenticated_version_at`, the flash scan feeding P4's inputs, and the
        boot-fail counter that can mask a slot. P4 characterises the SELECTION
        FUNCTION; the provenance of its two arguments is unverified.
      * the seam implementation. C1 says "the HW computes a keyed function"; that
        `hw_hmac_single` really computes HMAC-SHA256, that the key is the device
        key, and that the HASH engine is not sharable with NS code are all
        outside.
      * side channels, fault injection, and the `#[no_mangle] extern "C"` ABI
        boundary the NS relay crosses.
      * the extraction itself: Charon/Aeneas are trusted, unverified translators
        (see REPORT §7 item 5). *)

Require Import Primitives.
Import Primitives.
Require Import AeneasLoopShim.
Import AeneasLoopShim.
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
Require Import Update_Props.
Require Import Update_Safety.
Require Import Update_Value.
Require Import Update_Auth.
Local Open Scope Z_scope.
Local Open Scope Primitives_scope.

(* ===================================================================== *)
(* PREIMAGE ASSEMBLY — proved, not assumed.                               *)
(*                                                                        *)
(* `compute_pkg_tag` builds a 91-byte buffer and copies six things into    *)
(* six FIXED, DISJOINT windows:                                           *)
(*                                                                        *)
(*     [ 0,15)  PKG_TAG_LABEL  (a constant)                               *)
(*     [15,31)  nonce                                                     *)
(*     [31,35)  author_id  (u32, little endian)                           *)
(*     [35,39)  version    (u32, little endian)                           *)
(*     [39,43)  blob_len   (u32, little endian)                           *)
(*     [43,91)  header (full 48-byte UMBR header)                        *)
(*                                                                        *)
(* `Assembles pre n au ve bl hh` below says exactly that, at the level of  *)
(* individual byte reads of the assembled array. Two facts are proved      *)
(* about it, both over the VERBATIM extracted body, both `Qed`, and — this *)
(* is the point — WITHOUT the C1 hypothesis: they are statements about the *)
(* buffer arithmetic, not about the MAC.                                   *)
(*                                                                        *)
(*   [compute_pkg_tag_assembles]  every successful call feeds the seam a   *)
(*       preimage that `Assembles` the five fields;                        *)
(*   [assembly_injective]         two preimages that agree byte for byte   *)
(*       force all five fields to agree.                                   *)
(*                                                                        *)
(* This is the step the deleted C2 hypothesis used to absorb. With it, the *)
(* only thing still missing for "a tag pins the fields" is a property of   *)
(* `mac key` ALONE — see `tag_reuse_implies_same_fields_under_injective_mac` *)
(* at the end of this file, where that property is an EXPLICIT PREMISE of  *)
(* the statement rather than a standing hypothesis.                        *)
(*                                                                        *)
(* Equality strength. Byte conclusions are TERM equalities of `result u8`  *)
(* (`array_index_usize p j = array_index_usize n i`) — stronger than the   *)
(* `to_Z`-level house style, and obtainable here because every step is an  *)
(* equation between reads. The two u32 fields go through the opaque        *)
(* `u32::to_le_bytes`, so they land at `to_Z` level (`to_Z au1 = to_Z au2`)*)
(* via `to_le_bytes_inj`, itself PROVED from the codec's digit spec (Q18)  *)
(* rather than assumed.                                                    *)
(* ===================================================================== *)

(** The fixed prefix P3 refers to is concretely the ASCII byte string
    `umbra-update-v2`, not merely an opaque fifteen-byte slice. *)
Theorem pkg_tag_label_is_update_v2 :
  slice_index_usize pKG_TAG_LABEL 0%usize = Ok 117%u8
  /\ slice_index_usize pKG_TAG_LABEL 1%usize = Ok 109%u8
  /\ slice_index_usize pKG_TAG_LABEL 2%usize = Ok 98%u8
  /\ slice_index_usize pKG_TAG_LABEL 3%usize = Ok 114%u8
  /\ slice_index_usize pKG_TAG_LABEL 4%usize = Ok 97%u8
  /\ slice_index_usize pKG_TAG_LABEL 5%usize = Ok 45%u8
  /\ slice_index_usize pKG_TAG_LABEL 6%usize = Ok 117%u8
  /\ slice_index_usize pKG_TAG_LABEL 7%usize = Ok 112%u8
  /\ slice_index_usize pKG_TAG_LABEL 8%usize = Ok 100%u8
  /\ slice_index_usize pKG_TAG_LABEL 9%usize = Ok 97%u8
  /\ slice_index_usize pKG_TAG_LABEL 10%usize = Ok 116%u8
  /\ slice_index_usize pKG_TAG_LABEL 11%usize = Ok 101%u8
  /\ slice_index_usize pKG_TAG_LABEL 12%usize = Ok 45%u8
  /\ slice_index_usize pKG_TAG_LABEL 13%usize = Ok 118%u8
  /\ slice_index_usize pKG_TAG_LABEL 14%usize = Ok 50%u8.
Proof.
  unfold pKG_TAG_LABEL.
  repeat rewrite slice_index_array_to_slice.
  exact (mk_array15_val 117%u8 109%u8 98%u8 114%u8 97%u8 45%u8 117%u8
           112%u8 100%u8 97%u8 116%u8 101%u8 45%u8 118%u8 50%u8).
Qed.

Definition Assembles (pre : array u8 91%usize) (n : array u8 16%usize)
    (au ve bl : u32) (hh : array u8 48%usize) : Prop :=
  (forall i j : usize, 0 <= to_Z i < 15 -> to_Z j = to_Z i ->
     array_index_usize pre j = slice_index_usize pKG_TAG_LABEL i)
  /\ (forall i j : usize, 0 <= to_Z i < 16 -> to_Z j = 15 + to_Z i ->
     array_index_usize pre j = array_index_usize n i)
  /\ (forall i j : usize, 0 <= to_Z i < 4 -> to_Z j = 31 + to_Z i ->
     array_index_usize pre j = array_index_usize (core_num_U32_to_le_bytes au) i)
  /\ (forall i j : usize, 0 <= to_Z i < 4 -> to_Z j = 35 + to_Z i ->
     array_index_usize pre j = array_index_usize (core_num_U32_to_le_bytes ve) i)
  /\ (forall i j : usize, 0 <= to_Z i < 4 -> to_Z j = 39 + to_Z i ->
     array_index_usize pre j = array_index_usize (core_num_U32_to_le_bytes bl) i)
  /\ (forall i j : usize, 0 <= to_Z i < 48 -> to_Z j = 43 + to_Z i ->
     array_index_usize pre j = array_index_usize hh i).

(* --- little-endian codec: injectivity, PROVED from the digit spec ------- *)

Lemma tz2u : to_Z (2%usize) = 2. Proof. reflexivity. Qed.
Lemma tz3u : to_Z (3%usize) = 3. Proof. reflexivity. Qed.

Lemma z_four_digits : forall a, 0 <= a < 4294967296 ->
  a = a mod 256 + 256 * ((a / 256) mod 256)
      + 65536 * ((a / 65536) mod 256) + 16777216 * ((a / 16777216) mod 256).
Proof.
  intros a Ha.
  pose proof (Z.div_mod a 256 ltac:(lia)) as H0.
  pose proof (Z.div_mod (a / 256) 256 ltac:(lia)) as H1.
  pose proof (Z.div_mod (a / 65536) 256 ltac:(lia)) as H2.
  assert (D1 : a / 256 / 256 = a / 65536) by (rewrite Z.div_div by lia; reflexivity).
  assert (D2 : a / 65536 / 256 = a / 16777216)
    by (rewrite Z.div_div by lia; reflexivity).
  rewrite D1 in H1. rewrite D2 in H2.
  assert (H3 : (a / 16777216) mod 256 = a / 16777216).
  { apply Z.mod_small. split.
    - apply Z.div_pos; lia.
    - apply Z.div_lt_upper_bound; lia. }
  lia.
Qed.

(* Four agreeing base-256 digits pin a u32. Shared by the encoder and the
   decoder results below; nothing here is specific to either codec. *)
Lemma digits_determine : forall x y : u32,
  (forall k : usize, 0 <= to_Z k < 4 ->
     (to_Z x / 256 ^ to_Z k) mod 256 = (to_Z y / 256 ^ to_Z k) mod 256) ->
  to_Z x = to_Z y.
Proof.
  intros x y D.
  pose proof (D 0%usize ltac:(rewrite tz0; lia)) as D0.
  pose proof (D 1%usize ltac:(rewrite tz1; lia)) as D1.
  pose proof (D 2%usize ltac:(rewrite tz2u; lia)) as D2.
  pose proof (D 3%usize ltac:(rewrite tz3u; lia)) as D3.
  rewrite tz0 in D0. rewrite tz1 in D1. rewrite tz2u in D2. rewrite tz3u in D3.
  replace (256 ^ 0) with 1 in D0 by reflexivity.
  replace (256 ^ 1) with 256 in D1 by reflexivity.
  replace (256 ^ 2) with 65536 in D2 by reflexivity.
  replace (256 ^ 3) with 16777216 in D3 by reflexivity.
  rewrite !Z.div_1_r in D0.
  pose proof (to_Z_u32_bounds x) as Hx. pose proof (to_Z_u32_bounds y) as Hy.
  unfold u32_max in Hx, Hy.
  pose proof (z_four_digits (to_Z x) ltac:(lia)) as Ex.
  pose proof (z_four_digits (to_Z y) ltac:(lia)) as Ey.
  (* `lia` treats the digits as opaque atoms but will not close this; rewrite
     the two decompositions and the four digit equalities by hand. *)
  rewrite Ex at 1. rewrite Ey at 1.
  rewrite D0, D1, D2, D3. reflexivity.
Qed.

Lemma to_le_bytes_inj : forall x y : u32,
  (forall i : usize, 0 <= to_Z i < 4 ->
     array_index_usize (core_num_U32_to_le_bytes x) i
     = array_index_usize (core_num_U32_to_le_bytes y) i) ->
  to_Z x = to_Z y.
Proof.
  intros x y H. apply digits_determine. intros k Hk.
  destruct (u32_to_le_bytes_val x k Hk) as [bx [Hbx Hvx]].
  destruct (u32_to_le_bytes_val y k Hk) as [bz [Hbz Hvz]].
  rewrite <- Hvx, <- Hvz. f_equal.
  rewrite (H k Hk) in Hbx. rewrite Hbx in Hbz. injection Hbz as E. exact E.
Qed.

(* --- the DECODER, from Q19 alone (nothing below is assumed) ------------- *)

(** Digit i of the decoded value is byte i — the named-byte form of Q19. *)
Lemma from_le_bytes_digit : forall (a : array u8 4%usize) (i : usize) (b : u8),
  0 <= to_Z i < 4 -> array_index_usize a i = Ok b ->
  (to_Z (core_num_U32_from_le_bytes a) / 256 ^ to_Z i) mod 256 = to_Z b.
Proof.
  intros a i b Hi Hb.
  destruct (u32_from_le_bytes_val a i Hi) as [bv [Hbv Hd]].
  rewrite Hb in Hbv. injection Hbv as E. subst bv. exact Hd.
Qed.

(** ROUND-TRIP: decoding what the encoder produced gives the value back. *)
Lemma from_le_bytes_to_le_bytes : forall x : u32,
  to_Z (core_num_U32_from_le_bytes (core_num_U32_to_le_bytes x)) = to_Z x.
Proof.
  intros x. apply digits_determine. intros k Hk.
  destruct (u32_to_le_bytes_val x k Hk) as [b [Hb Hv]].
  rewrite (from_le_bytes_digit _ k b Hk Hb). exact Hv.
Qed.

(** ROUND-TRIP, the other way: re-encoding a decoded array reproduces its
    bytes. This is the direction the preimage windows need. *)
Lemma to_le_bytes_from_le_bytes : forall (a : array u8 4%usize) (i : usize),
  0 <= to_Z i < 4 ->
  exists x y,
    array_index_usize
      (core_num_U32_to_le_bytes (core_num_U32_from_le_bytes a)) i = Ok x
    /\ array_index_usize a i = Ok y
    /\ to_Z x = to_Z y.
Proof.
  intros a i Hi.
  destruct (u32_to_le_bytes_val (core_num_U32_from_le_bytes a) i Hi)
    as [x [Hx Hvx]].
  destruct (u32_from_le_bytes_val a i Hi) as [y [Hy Hvy]].
  exists x, y. split; [ exact Hx |]. split; [ exact Hy |].
  rewrite Hvx. exact Hvy.
Qed.

(** CONGRUENCE: byte-equal arrays decode to the same value. *)
Lemma from_le_bytes_cong : forall a b : array u8 4%usize,
  (forall i : usize, 0 <= to_Z i < 4 ->
     array_index_usize a i = array_index_usize b i) ->
  to_Z (core_num_U32_from_le_bytes a) = to_Z (core_num_U32_from_le_bytes b).
Proof.
  intros a b H. apply digits_determine. intros k Hk.
  destruct (u32_from_le_bytes_val a k Hk) as [x [Hx Hdx]].
  destruct (u32_from_le_bytes_val b k Hk) as [y [Hy Hdy]].
  rewrite Hdx, Hdy. f_equal.
  rewrite (H k Hk) in Hx. rewrite Hx in Hy. injection Hy as E. exact E.
Qed.

(** INJECTIVITY: two 4-byte arrays that decode to the same u32 agree byte for
    byte. The decoder loses nothing — there is no second wire encoding of an
    accepted version number. *)
Lemma from_le_bytes_inj : forall a b : array u8 4%usize,
  to_Z (core_num_U32_from_le_bytes a) = to_Z (core_num_U32_from_le_bytes b) ->
  forall i : usize, 0 <= to_Z i < 4 ->
    exists x y, array_index_usize a i = Ok x
             /\ array_index_usize b i = Ok y
             /\ to_Z x = to_Z y.
Proof.
  intros a b Heq i Hi.
  destruct (u32_from_le_bytes_val a i Hi) as [x [Hx Hdx]].
  destruct (u32_from_le_bytes_val b i Hi) as [y [Hy Hdy]].
  exists x, y. split; [ exact Hx |]. split; [ exact Hy |].
  rewrite <- Hdx, <- Hdy, Heq. reflexivity.
Qed.

(* --- the decoder as the extracted body applies it: to a 4-byte literal --- *)

Definition pick4 (b0 b1 b2 b3 : u8) (k : Z) : u8 :=
  if Z.eqb k 0 then b0 else if Z.eqb k 1 then b1
  else if Z.eqb k 2 then b2 else b3.

Lemma mk_array4_at : forall (b0 b1 b2 b3 : u8) (i : usize), 0 <= to_Z i < 4 ->
  array_index_usize (mk_array4 b0 b1 b2 b3) i
  = Ok (pick4 b0 b1 b2 b3 (to_Z i)).
Proof.
  intros b0 b1 b2 b3 i Hi.
  destruct (mk_array4_val b0 b1 b2 b3) as [A0 [A1 [A2 A3]]].
  assert (Hc : to_Z i = 0 \/ to_Z i = 1 \/ to_Z i = 2 \/ to_Z i = 3) by lia.
  unfold pick4.
  destruct Hc as [E|[E|[E|E]]]; rewrite E; cbn [Z.eqb].
  - rewrite (array_index_usize_ext _ i 0%usize) by (rewrite tz0; exact E).
    exact A0.
  - rewrite (array_index_usize_ext _ i 1%usize) by (rewrite tz1; exact E).
    exact A1.
  - rewrite (array_index_usize_ext _ i 2%usize) by (rewrite tz2u; exact E).
    exact A2.
  - rewrite (array_index_usize_ext _ i 3%usize) by (rewrite tz3u; exact E).
    exact A3.
Qed.

(** The value equation for the decoder the parser actually runs: the field IS
    the little-endian reading of its four package bytes. *)
Lemma dec32_val : forall b0 b1 b2 b3 : u8,
  to_Z (dec32 b0 b1 b2 b3)
  = to_Z b0 + 256 * to_Z b1 + 65536 * to_Z b2 + 16777216 * to_Z b3.
Proof.
  intros b0 b1 b2 b3.
  destruct (mk_array4_val b0 b1 b2 b3) as [A0 [A1 [A2 A3]]].
  unfold dec32.
  pose proof (from_le_bytes_digit _ 0%usize b0 ltac:(rewrite tz0; lia) A0) as D0.
  pose proof (from_le_bytes_digit _ 1%usize b1 ltac:(rewrite tz1; lia) A1) as D1.
  pose proof (from_le_bytes_digit _ 2%usize b2 ltac:(rewrite tz2u; lia) A2) as D2.
  pose proof (from_le_bytes_digit _ 3%usize b3 ltac:(rewrite tz3u; lia) A3) as D3.
  rewrite tz0 in D0. rewrite tz1 in D1. rewrite tz2u in D2. rewrite tz3u in D3.
  replace (256 ^ 0) with 1 in D0 by reflexivity.
  replace (256 ^ 1) with 256 in D1 by reflexivity.
  replace (256 ^ 2) with 65536 in D2 by reflexivity.
  replace (256 ^ 3) with 16777216 in D3 by reflexivity.
  rewrite Z.div_1_r in D0.
  pose proof (to_Z_u32_bounds
    (core_num_U32_from_le_bytes (mk_array4 b0 b1 b2 b3))) as Hb.
  unfold u32_max in Hb.
  pose proof (z_four_digits
    (to_Z (core_num_U32_from_le_bytes (mk_array4 b0 b1 b2 b3)))
    ltac:(lia)) as Ev.
  rewrite Ev at 1.
  rewrite D0, D1, D2, D3. reflexivity.
Qed.

(** Byte i of the RE-ENCODING of a decoded literal is byte i of the literal —
    i.e. the four bytes the encoder puts into the MAC preimage window are the
    four package bytes the field was decoded from. *)
Lemma dec32_le_byte : forall (b0 b1 b2 b3 : u8) (i : usize), 0 <= to_Z i < 4 ->
  exists x, array_index_usize
              (core_num_U32_to_le_bytes (dec32 b0 b1 b2 b3)) i = Ok x
         /\ to_Z x = to_Z (pick4 b0 b1 b2 b3 (to_Z i)).
Proof.
  intros b0 b1 b2 b3 i Hi. unfold dec32.
  destruct (to_le_bytes_from_le_bytes (mk_array4 b0 b1 b2 b3) i Hi)
    as [x [y [Hx [Hy Hxy]]]].
  rewrite (mk_array4_at b0 b1 b2 b3 i Hi) in Hy. injection Hy as Ey. subst y.
  exists x. split; [ exact Hx | exact Hxy ].
Qed.

Lemma exists_usize : forall z, 0 <= z <= u32_max -> exists j : usize, to_Z j = z.
Proof.
  intros z Hz. destruct (mk_usize_ok z Hz) as [s [_ Hs]]. exists s. exact Hs.
Qed.

(** Byte i of `to_le_bytes` depends only on the VALUE, not on the `u32` TERM.
    Needed because `blob_len` reaches the preimage after a `u32`→`usize`→`u32`
    round-trip, which changes the term (a different in-bounds proof) but not the
    number. *)
Lemma to_le_bytes_val_cong : forall (x y : u32) (i : usize), 0 <= to_Z i < 4 ->
  to_Z x = to_Z y ->
  exists bx byy,
    array_index_usize (core_num_U32_to_le_bytes x) i = Ok bx
    /\ array_index_usize (core_num_U32_to_le_bytes y) i = Ok byy
    /\ to_Z bx = to_Z byy.
Proof.
  intros x y i Hi Hxy.
  destruct (u32_to_le_bytes_val x i Hi) as [bx [Hbx Hvx]].
  destruct (u32_to_le_bytes_val y i Hi) as [byy [Hby Hvy]].
  exists bx, byy. split; [ exact Hbx |]. split; [ exact Hby |].
  rewrite Hvx, Hvy, Hxy. reflexivity.
Qed.

(** ONE u32 WINDOW OF THE PREIMAGE, PINNED TO FOUR PACKAGE BYTES.

    Given (i) an `Assembles` clause saying the preimage window at
    [base, base+4) holds `to_le_bytes v`, (ii) that `v` represents the
    little-endian reading of four bytes `c0..c3`, and (iii) that those four
    bytes were read out of `pkg` at `poff .. poff+4`, the window's bytes ARE the
    package's bytes. Applied three times below — author_id, version, blob_len —
    so that no `u32` field of the MAC'd preimage is left as a value of
    unexplained provenance. *)
Lemma u32_window_is_pkg_bytes :
  forall (pkg : slice u8) (pre : array u8 91%usize) (v : u32)
         (c0 c1 c2 c3 : u8) (k0 k1 k2 k3 : usize) (base poff : Z),
    (forall i j : usize, 0 <= to_Z i < 4 -> to_Z j = base + to_Z i ->
       array_index_usize pre j
       = array_index_usize (core_num_U32_to_le_bytes v) i) ->
    to_Z v = to_Z (dec32 c0 c1 c2 c3) ->
    to_Z k0 = poff -> to_Z k1 = poff + 1 ->
    to_Z k2 = poff + 2 -> to_Z k3 = poff + 3 ->
    slice_index_usize pkg k0 = Ok c0 -> slice_index_usize pkg k1 = Ok c1 ->
    slice_index_usize pkg k2 = Ok c2 -> slice_index_usize pkg k3 = Ok c3 ->
    forall i j k : usize, 0 <= to_Z i < 4 ->
      to_Z j = base + to_Z i -> to_Z k = poff + to_Z i ->
      exists x y, array_index_usize pre j = Ok x
               /\ slice_index_usize pkg k = Ok y
               /\ to_Z x = to_Z y.
Proof.
  intros pkg pre v c0 c1 c2 c3 k0 k1 k2 k3 base poff HW Hv
         E0 E1 E2 E3 R0 R1 R2 R3 i j k Hi Hj Hk.
  rewrite (HW i j Hi Hj).
  destruct (to_le_bytes_val_cong v (dec32 c0 c1 c2 c3) i Hi Hv)
    as [x [z [Hx [Hz Hxz]]]].
  destruct (dec32_le_byte c0 c1 c2 c3 i Hi) as [z' [Hz' Hv']].
  assert (Ez : z = z') by (rewrite Hz in Hz'; injection Hz' as E'; exact E').
  exists x, (pick4 c0 c1 c2 c3 (to_Z i)).
  split; [ exact Hx |]. split.
  - assert (Hc : to_Z i = 0 \/ to_Z i = 1 \/ to_Z i = 2 \/ to_Z i = 3) by lia.
    unfold pick4.
    destruct Hc as [E|[E|[E|E]]]; rewrite E; cbn [Z.eqb].
    + rewrite (slice_index_usize_ext _ k k0) by lia. exact R0.
    + rewrite (slice_index_usize_ext _ k k1) by lia. exact R1.
    + rewrite (slice_index_usize_ext _ k k2) by lia. exact R2.
    + rewrite (slice_index_usize_ext _ k k3) by lia. exact R3.
  - rewrite Hxz, Ez. exact Hv'.
Qed.

(* --- the walk over the extracted body ---------------------------------- *)

Ltac step_pair Ht Hm w b :=
  lazymatch type of Ht with
  | bind ?e _ = _ => destruct e as [[w b]|] eqn:Hm; cbn [bind] in Ht;
                     try discriminate Ht
  end.
Ltac step_copy Ht Hc c :=
  lazymatch type of Ht with
  | bind ?e _ = _ => destruct e as [c|] eqn:Hc; cbn [bind] in Ht;
                     try discriminate Ht
  end.

Section Composed.

(* The device: one seam instance, one handle, one key. *)
Context {HS : Type}.
Variable inst : PkgHmac_t HS.
Variable h : HS.
Variable key : slice u8.

(* ---- C1: the seam is a keyed function of (key, preimage). ---- *)
Variable mac : slice u8 -> array u8 91%usize -> array u8 32%usize.
Hypothesis Hseam :
  forall k p, inst.(PkgHmac_t_hmac_pkg) h k p = Ok (mac k p).

(* ===================================================================== *)
(* Under C1 every tag the device produces is `mac key` of the assembled   *)
(* preimage — walked over the verbatim extracted body of compute_pkg_tag. *)
(* ===================================================================== *)

Lemma compute_pkg_tag_assembles :
  forall n au ve bl hh t,
    compute_pkg_tag inst n au ve bl hh h key = Ok t ->
    exists pre : array u8 91%usize,
      inst.(PkgHmac_t_hmac_pkg) h key pre = Ok t /\ Assembles pre n au ve bl hh.
Proof.
  intros n au ve bl hh t Ht.
  unfold compute_pkg_tag in Ht. cbv zeta in Ht.
  step_pair Ht M0 w0 b0. step_copy Ht C0 c0.
  step_pair Ht M1 w1 b1. step_copy Ht C1 c1.
  step_pair Ht M2 w2 b2. step_copy Ht C2 c2.
  step_pair Ht M3 w3 b3. step_copy Ht C3 c3.
  step_pair Ht M4 w4 b4. step_copy Ht C4 c4.
  step_pair Ht M5 w5 b5. step_copy Ht C5 c5.
  apply copy_from_slice_val in C0. apply copy_from_slice_val in C1.
  apply copy_from_slice_val in C2. apply copy_from_slice_val in C3.
  apply copy_from_slice_val in C4. apply copy_from_slice_val in C5.
  subst c0 c1 c2 c3 c4 c5.
  (* the six windows have exactly the lengths the ranges ask for *)
  assert (HL0 : to_Z (slice_len pKG_TAG_LABEL)
                = to_Z (15%usize) - to_Z (0%usize))
    by (unfold pKG_TAG_LABEL; rewrite slice_len_array_to_slice, tz15, tz0; lia).
  assert (HL1 : to_Z (slice_len (array_to_slice n))
                = to_Z (31%usize) - to_Z (15%usize))
    by (rewrite slice_len_array_to_slice, tz16, tz31, tz15; lia).
  assert (HL2 : to_Z (slice_len (array_to_slice (core_num_U32_to_le_bytes au)))
                = to_Z (35%usize) - to_Z (31%usize))
    by (rewrite slice_len_array_to_slice, tz4, tz35, tz31; lia).
  assert (HL3 : to_Z (slice_len (array_to_slice (core_num_U32_to_le_bytes ve)))
                = to_Z (39%usize) - to_Z (35%usize))
    by (rewrite slice_len_array_to_slice, tz4, tz39, tz35; lia).
  assert (HL4 : to_Z (slice_len (array_to_slice (core_num_U32_to_le_bytes bl)))
                = to_Z (43%usize) - to_Z (39%usize))
    by (rewrite slice_len_array_to_slice, tz4, tz43, tz39; lia).
  assert (HL5 : to_Z (slice_len (array_to_slice hh))
                = to_Z (91%usize) - to_Z (43%usize))
    by (rewrite slice_len_array_to_slice, tz48, tz91, tz43; lia).
  (* OUT: a later window's write-back leaves earlier bytes alone *)
  assert (OUT5 : forall j : usize, to_Z j < 43 ->
     array_index_usize (b5 (array_to_slice hh)) j
     = array_index_usize (b4 (array_to_slice (core_num_U32_to_le_bytes bl))) j).
  { intros j Hj. apply (array_index_mut_range_val_out _ _ _ _ _ _ _ M5 HL5).
    left. rewrite tz43. exact Hj. }
  assert (OUT4 : forall j : usize, to_Z j < 39 ->
     array_index_usize (b4 (array_to_slice (core_num_U32_to_le_bytes bl))) j
     = array_index_usize (b3 (array_to_slice (core_num_U32_to_le_bytes ve))) j).
  { intros j Hj. apply (array_index_mut_range_val_out _ _ _ _ _ _ _ M4 HL4).
    left. rewrite tz39. exact Hj. }
  assert (OUT3 : forall j : usize, to_Z j < 35 ->
     array_index_usize (b3 (array_to_slice (core_num_U32_to_le_bytes ve))) j
     = array_index_usize (b2 (array_to_slice (core_num_U32_to_le_bytes au))) j).
  { intros j Hj. apply (array_index_mut_range_val_out _ _ _ _ _ _ _ M3 HL3).
    left. rewrite tz35. exact Hj. }
  assert (OUT2 : forall j : usize, to_Z j < 31 ->
     array_index_usize (b2 (array_to_slice (core_num_U32_to_le_bytes au))) j
     = array_index_usize (b1 (array_to_slice n)) j).
  { intros j Hj. apply (array_index_mut_range_val_out _ _ _ _ _ _ _ M2 HL2).
    left. rewrite tz31. exact Hj. }
  assert (OUT1 : forall j : usize, to_Z j < 15 ->
     array_index_usize (b1 (array_to_slice n)) j
     = array_index_usize (b0 pKG_TAG_LABEL) j).
  { intros j Hj. apply (array_index_mut_range_val_out _ _ _ _ _ _ _ M1 HL1).
    left. rewrite tz15. exact Hj. }
  (* IN: each window reads back the slice that was copied into it *)
  assert (IN0 : forall ia js : usize, 0 <= to_Z ia -> to_Z ia < 15 ->
     to_Z js = to_Z ia ->
     array_index_usize (b0 pKG_TAG_LABEL) ia
     = slice_index_usize pKG_TAG_LABEL js).
  { intros ia js H1 H2 H3.
    apply (array_index_mut_range_val_in _ _ _ _ _ _ _ _ M0 HL0);
      [ rewrite tz0; lia | rewrite tz15; lia | rewrite tz0; lia ]. }
  assert (IN1 : forall ia js : usize, 15 <= to_Z ia -> to_Z ia < 31 ->
     to_Z js = to_Z ia - 15 ->
     array_index_usize (b1 (array_to_slice n)) ia
     = slice_index_usize (array_to_slice n) js).
  { intros ia js H1 H2 H3.
    apply (array_index_mut_range_val_in _ _ _ _ _ _ _ _ M1 HL1);
      [ rewrite tz15; lia | rewrite tz31; lia | rewrite tz15; lia ]. }
  assert (IN2 : forall ia js : usize, 31 <= to_Z ia -> to_Z ia < 35 ->
     to_Z js = to_Z ia - 31 ->
     array_index_usize (b2 (array_to_slice (core_num_U32_to_le_bytes au))) ia
     = slice_index_usize (array_to_slice (core_num_U32_to_le_bytes au)) js).
  { intros ia js H1 H2 H3.
    apply (array_index_mut_range_val_in _ _ _ _ _ _ _ _ M2 HL2);
      [ rewrite tz31; lia | rewrite tz35; lia | rewrite tz31; lia ]. }
  assert (IN3 : forall ia js : usize, 35 <= to_Z ia -> to_Z ia < 39 ->
     to_Z js = to_Z ia - 35 ->
     array_index_usize (b3 (array_to_slice (core_num_U32_to_le_bytes ve))) ia
     = slice_index_usize (array_to_slice (core_num_U32_to_le_bytes ve)) js).
  { intros ia js H1 H2 H3.
    apply (array_index_mut_range_val_in _ _ _ _ _ _ _ _ M3 HL3);
      [ rewrite tz35; lia | rewrite tz39; lia | rewrite tz35; lia ]. }
  assert (IN4 : forall ia js : usize, 39 <= to_Z ia -> to_Z ia < 43 ->
     to_Z js = to_Z ia - 39 ->
     array_index_usize (b4 (array_to_slice (core_num_U32_to_le_bytes bl))) ia
     = slice_index_usize (array_to_slice (core_num_U32_to_le_bytes bl)) js).
  { intros ia js H1 H2 H3.
    apply (array_index_mut_range_val_in _ _ _ _ _ _ _ _ M4 HL4);
      [ rewrite tz39; lia | rewrite tz43; lia | rewrite tz39; lia ]. }
  assert (IN5 : forall ia js : usize, 43 <= to_Z ia -> to_Z ia < 91 ->
     to_Z js = to_Z ia - 43 ->
     array_index_usize (b5 (array_to_slice hh)) ia
     = slice_index_usize (array_to_slice hh) js).
  { intros ia js H1 H2 H3.
    apply (array_index_mut_range_val_in _ _ _ _ _ _ _ _ M5 HL5);
      [ rewrite tz43; lia | rewrite tz91; lia | rewrite tz43; lia ]. }
  exists (b5 (array_to_slice hh)). split; [ exact Ht |].
  unfold Assembles. repeat apply conj.
  - (* [0,15) — the constant PKG_TAG_LABEL *)
    intros i j Hi Hj.
    rewrite (OUT5 j ltac:(lia)), (OUT4 j ltac:(lia)), (OUT3 j ltac:(lia)),
            (OUT2 j ltac:(lia)), (OUT1 j ltac:(lia)).
    exact (IN0 j i ltac:(lia) ltac:(lia) ltac:(lia)).
  - intros i j Hi Hj.
    rewrite (OUT5 j ltac:(lia)), (OUT4 j ltac:(lia)), (OUT3 j ltac:(lia)),
            (OUT2 j ltac:(lia)).
    rewrite (IN1 j i ltac:(lia) ltac:(lia) ltac:(lia)).
    apply slice_index_array_to_slice.
  - intros i j Hi Hj.
    rewrite (OUT5 j ltac:(lia)), (OUT4 j ltac:(lia)), (OUT3 j ltac:(lia)).
    rewrite (IN2 j i ltac:(lia) ltac:(lia) ltac:(lia)).
    apply slice_index_array_to_slice.
  - intros i j Hi Hj.
    rewrite (OUT5 j ltac:(lia)), (OUT4 j ltac:(lia)).
    rewrite (IN3 j i ltac:(lia) ltac:(lia) ltac:(lia)).
    apply slice_index_array_to_slice.
  - intros i j Hi Hj.
    rewrite (OUT5 j ltac:(lia)).
    rewrite (IN4 j i ltac:(lia) ltac:(lia) ltac:(lia)).
    apply slice_index_array_to_slice.
  - intros i j Hi Hj.
    rewrite (IN5 j i ltac:(lia) ltac:(lia) ltac:(lia)).
    apply slice_index_array_to_slice.
Qed.

(** Two assembled preimages that agree byte for byte have the same five fields.
    No cryptographic hypothesis is used: this is arithmetic about disjoint
    windows of a 91-byte buffer. *)
Theorem assembly_injective :
  forall (pre1 pre2 : array u8 91%usize)
         (n1 : array u8 16%usize) (au1 ve1 bl1 : u32) (hh1 : array u8 48%usize)
         (n2 : array u8 16%usize) (au2 ve2 bl2 : u32) (hh2 : array u8 48%usize),
    Assembles pre1 n1 au1 ve1 bl1 hh1 ->
    Assembles pre2 n2 au2 ve2 bl2 hh2 ->
    (forall j : usize, 0 <= to_Z j < 91 ->
       array_index_usize pre1 j = array_index_usize pre2 j) ->
    (forall i : usize, 0 <= to_Z i < 16 ->
       array_index_usize n1 i = array_index_usize n2 i)
    /\ to_Z au1 = to_Z au2 /\ to_Z ve1 = to_Z ve2 /\ to_Z bl1 = to_Z bl2
    /\ (forall i : usize, 0 <= to_Z i < 48 ->
       array_index_usize hh1 i = array_index_usize hh2 i).
Proof.
  intros pre1 pre2 n1 au1 ve1 bl1 hh1 n2 au2 ve2 bl2 hh2 HA HB Hag.
  pose proof u32max_big as Hbig.
  destruct HA as [_ [A1 [A2 [A3 [A4 A5]]]]].
  destruct HB as [_ [B1 [B2 [B3 [B4 B5]]]]].
  repeat apply conj.
  - intros i Hi.
    destruct (exists_usize (15 + to_Z i) ltac:(lia)) as [j Hj].
    rewrite <- (A1 i j Hi Hj), <- (B1 i j Hi Hj). apply Hag. lia.
  - apply to_le_bytes_inj. intros i Hi.
    destruct (exists_usize (31 + to_Z i) ltac:(lia)) as [j Hj].
    rewrite <- (A2 i j Hi Hj), <- (B2 i j Hi Hj). apply Hag. lia.
  - apply to_le_bytes_inj. intros i Hi.
    destruct (exists_usize (35 + to_Z i) ltac:(lia)) as [j Hj].
    rewrite <- (A3 i j Hi Hj), <- (B3 i j Hi Hj). apply Hag. lia.
  - apply to_le_bytes_inj. intros i Hi.
    destruct (exists_usize (39 + to_Z i) ltac:(lia)) as [j Hj].
    rewrite <- (A4 i j Hi Hj), <- (B4 i j Hi Hj). apply Hag. lia.
  - intros i Hi.
    destruct (exists_usize (43 + to_Z i) ltac:(lia)) as [j Hj].
    rewrite <- (A5 i j Hi Hj), <- (B5 i j Hi Hj). apply Hag. lia.
Qed.

(* ===================================================================== *)
(* THE COMPOSED THEOREM.                                                  *)
(*                                                                        *)
(* Clause (b) is the one that consumes the assembly work: the preimage is *)
(* EXHIBITED and shown to carry the six windows at their fixed offsets.   *)
(* An earlier revision stopped at `exists pre, expect = mac key pre`,     *)
(* which is satisfied by ANY 91-byte array and therefore said nothing     *)
(* about the fields at all.                                              *)
(*                                                                        *)
(* WHAT CLAUSES (d)-(h) ADD, AND WHY. `Assembles` relates the preimage to *)
(* the SEAM'S ARGUMENTS. Of those six, only `author_id` and `version` were *)
(* pinned to anything the caller can see (the returned record); `nonce`,   *)
(* `blob_len` and `hdr` (the header) were LOOSE EXISTENTIALS, so statement *)
(* read "the tag covers SOME nonce" — the same shape of hole the deleted   *)
(* C2 hypothesis had, one field over, and the freshness-critical one: a    *)
(* reader could not conclude that the MAC'd nonce is the ARMED nonce.      *)
(* Clauses (d)-(h) close all three, and (i) — inside `Assembles` — pins    *)
(* the remaining 15 bytes to the constant domain-separation label, so ALL  *)
(* 91 preimage bytes are now accounted for: 15 constant label, 16 armed    *)
(* nonce (= pkg[4..20)), 4+4+4 package bytes pkg[20..32), 48 header bytes  *)
(* of the returned blob (blob[0..48)). Nothing in the preimage is free.    *)
(* ===================================================================== *)

Theorem accept_implies_authenticated_fields :
  forall (pkg : slice u8) (en : array u8 16%usize) r,
    parse_and_verify inst pkg en h key = Ok (Core_result_Result_Ok r) ->
    exists (tag_off : usize) (expect : array u8 32%usize)
           (nonce : array u8 16%usize) (hdr : array u8 48%usize) (bl : u32)
           (pre : array u8 91%usize),
      (* (a) the tag field is the last 32 bytes … *)
      to_Z tag_off = to_Z (slice_len pkg) - 32
      (* … and it is the device's own tag over EXACTLY this package's fields,
         including the author_id / version handed back to the caller … *)
      /\ compute_pkg_tag inst nonce
           r.(verifiedUpdate_author_id) r.(verifiedUpdate_version) bl hdr h key
         = Ok expect
      (* (b) … which, by C1, is the value of `mac key` on a preimage that
         PROVABLY carries exactly those six windows, each at its own offset.
         Still a functionality statement, NOT an unforgeability one: C1 says
         the seam is deterministic in (key, preimage), no more. *)
      /\ expect = mac key pre
      /\ Assembles pre nonce
           r.(verifiedUpdate_author_id) r.(verifiedUpdate_version) bl hdr
      (* … and the package really carries those tag bytes. *)
      /\ (forall i j : usize, 0 <= to_Z i < 32 -> to_Z j = to_Z tag_off + to_Z i ->
            exists x y, array_index_usize expect i = Ok x
                     /\ slice_index_usize pkg j = Ok y
                     /\ to_Z x = to_Z y)
      (* (c) anti-replay, at byte level: the nonce field IS the armed nonce. *)
      /\ (forall i j : usize, 0 <= to_Z i < 16 -> to_Z j = to_Z i + 4 ->
            exists x y, slice_index_usize pkg j = Ok x
                     /\ array_index_usize en i = Ok y
                     /\ to_Z x = to_Z y)
      (* (d) NONCE WINDOW [15,31) — the MAC'd nonce bytes ARE this package's
         bytes pkg[4..20), as terms, not merely "some" 16 bytes. *)
      /\ (forall i j k : usize, 0 <= to_Z i < 16 ->
            to_Z j = 15 + to_Z i -> to_Z k = 4 + to_Z i ->
            array_index_usize pre j = slice_index_usize pkg k)
      (* … and, composing with (c), they are the ARMED nonce `en`. This is the
         clause that makes the headline read "the tag is a MAC over the ARMED
         nonce", rather than over a nonce of unexplained provenance. *)
      /\ (forall i j : usize, 0 <= to_Z i < 16 -> to_Z j = 15 + to_Z i ->
            exists x y, array_index_usize pre j = Ok x
                     /\ array_index_usize en i = Ok y
                     /\ to_Z x = to_Z y)
      (* (e) AUTHOR_ID WINDOW [31,35) holds pkg[20..24). *)
      /\ (forall i j k : usize, 0 <= to_Z i < 4 ->
            to_Z j = 31 + to_Z i -> to_Z k = 20 + to_Z i ->
            exists x y, array_index_usize pre j = Ok x
                     /\ slice_index_usize pkg k = Ok y
                     /\ to_Z x = to_Z y)
      (* (f) VERSION WINDOW [35,39) holds pkg[24..28). *)
      /\ (forall i j k : usize, 0 <= to_Z i < 4 ->
            to_Z j = 35 + to_Z i -> to_Z k = 24 + to_Z i ->
            exists x y, array_index_usize pre j = Ok x
                     /\ slice_index_usize pkg k = Ok y
                     /\ to_Z x = to_Z y)
      (* (g) BLOB_LEN WINDOW [39,43) holds pkg[28..32) — the length field, whose
         only other appearance is the two structural guards. *)
      /\ (forall i j k : usize, 0 <= to_Z i < 4 ->
            to_Z j = 39 + to_Z i -> to_Z k = 28 + to_Z i ->
            exists x y, array_index_usize pre j = Ok x
                     /\ slice_index_usize pkg k = Ok y
                     /\ to_Z x = to_Z y)
      (* (h) the blob handed back to the caller IS the sub-slice
         pkg[32 .. len−32) … *)
      /\ core_slice_index_Slice_index
           (core_slice_index_SliceIndexRangeUsizeSliceInst u8) pkg
           {| core_ops_range_Range_start := fIXED_PREFIX;
              core_ops_range_Range_end_ := tag_off |}
         = Ok r.(verifiedUpdate_blob)
      (* … and the HEADER WINDOW [43,91) holds that blob's FULL 48-byte
         header blob[0,48), as terms. *)
      /\ (forall i j k : usize, 0 <= to_Z i < 48 ->
            to_Z j = 43 + to_Z i -> to_Z k = to_Z i ->
            array_index_usize pre j
            = slice_index_usize r.(verifiedUpdate_blob) k).
Proof.
  intros pkg en r Hacc.
  pose proof (accept_implies_nonce_equal inst pkg en h key r Hacc) as Hnon.
  pose proof (accept_implies_auth_gates inst pkg en h key r Hacc) as HG.
  destruct HG as [nsrc [ncpy [c20 [c21 [c22 [c23 [c24 [c25 [c26 [c27
    [c28 [c29 [c30 [c31 [toff [blus [blu32 [blob [hsrc [hcpy
    [i26 [expect [got HG]]]]]]]]]]]]]]]]]]]]]]].
  destruct HG as [Hns  HG]. destruct HG as [Hncpy HG]. destruct HG as [Hct16 HG].
  destruct HG as [H20  HG]. destruct HG as [H21   HG].
  destruct HG as [H22  HG]. destruct HG as [H23   HG].
  destruct HG as [H24  HG]. destruct HG as [H25   HG].
  destruct HG as [H26  HG]. destruct HG as [H27   HG].
  destruct HG as [H28  HG]. destruct HG as [H29   HG].
  destruct HG as [H30  HG]. destruct HG as [H31   HG].
  destruct HG as [Hcst1 HG]. destruct HG as [Htoff HG].
  destruct HG as [Hblob HG].
  destruct HG as [Hhsrc HG]. destruct HG as [Hhcpy HG].
  destruct HG as [Hcst2 HG]. destruct HG as [Hcpt  HG].
  destruct HG as [Hi26  HG]. destruct HG as [Hgot  HG].
  destruct HG as [Hct32 Hr].
  (* the two copies handed back their source sub-slices *)
  apply copy_from_slice_val in Hncpy. subst ncpy.
  apply copy_from_slice_val in Hhcpy. subst hcpy.
  subst r.
  cbn [verifiedUpdate_author_id verifiedUpdate_version verifiedUpdate_blob].
  (* numeric values of tag_off and tag_off+32 *)
  unfold usize_sub, scalar_sub in Htoff. apply mk_scalar_to_Z in Htoff.
  unfold usize_add, scalar_add in Hi26.  apply mk_scalar_to_Z in Hi26.
  rewrite tz32 in Htoff, Hi26.
  (* blob_len reaches the seam as u32 -> usize -> u32; only the VALUE survives *)
  unfold scalar_cast in Hcst1, Hcst2.
  apply mk_scalar_to_Z in Hcst1. apply mk_scalar_to_Z in Hcst2.
  assert (Hblv : to_Z blu32 = to_Z (dec32 c28 c29 c30 c31))
    by (rewrite Hcst2; exact Hcst1).
  (* the two scratch windows have the lengths their write-backs need *)
  pose proof (slice_index_range_len _ _ _ _ Hns) as Hnlen.
  rewrite tz4, tz20 in Hnlen.
  pose proof (slice_index_range_len _ _ _ _ Hhsrc) as Hhlen.
  rewrite tz_hdr, tz0 in Hhlen.
  (* the tag gate is a byte equality on the last 32 bytes *)
  destruct (ct_eq32_sound _ _ Hct32) as [_ Htag].
  (* the preimage the seam was actually fed, and what it carries *)
  destruct (compute_pkg_tag_assembles _ _ _ _ _ _ Hcpt) as [pre [Hmac HAsm]].
  rewrite Hseam in Hmac. injection Hmac as Hmac.
  pose proof HAsm as HAsm'.
  destruct HAsm' as [_ [ANon [AAu [AVe [ABl AHh]]]]].
  (* the nonce window, at the level of package bytes — reused twice below *)
  assert (DNon : forall i j k : usize, 0 <= to_Z i < 16 ->
            to_Z j = 15 + to_Z i -> to_Z k = 4 + to_Z i ->
            array_index_usize pre j = slice_index_usize pkg k).
  { intros i j k Hi Hj Hk.
    rewrite (ANon i j Hi Hj).
    rewrite (array_from_slice_val nonce_buf nsrc i)
      by (rewrite Hnlen, tz16; reflexivity).
    apply (slice_index_range_val _ _ _ _ i k Hns);
      [ lia | rewrite tz4, tz20; lia | rewrite tz4; lia ]. }
  exists toff, expect, (array_from_slice nonce_buf nsrc),
         (array_from_slice hdr_buf hsrc), blu32, pre.
  (* NB: not `repeat split` / `repeat apply conj` — `Assembles` is a transparent
     conjunction and either would break it open and shift every later goal. *)
  split. { exact Htoff. }
  split. { exact Hcpt. }
  split. { symmetry. exact Hmac. }
  split. { exact HAsm. }
  split.
  { intros i j Hi Hj.
    destruct (Htag i Hi) as [x [y [Hx [Hy Hxy]]]].
    exists x, y. split; [ exact Hx |]. split; [| exact Hxy ].
    rewrite <- (slice_index_range_val _ _ _ _ i j Hgot);
      [ exact Hy | lia | lia | lia ]. }
  split. { exact Hnon. }
  split. { exact DNon. }
  split.
  { (* the MAC'd nonce is the ARMED nonce: (d) composed with (c) *)
    intros i j Hi Hj.
    destruct (exists_usize (4 + to_Z i) ltac:(pose proof u32max_big; lia))
      as [k Hk].
    destruct (Hnon i k Hi ltac:(lia)) as [x [y [Hx [Hy Hxy]]]].
    exists x, y. split; [| split; [ exact Hy | exact Hxy ]].
    rewrite (DNon i j k Hi Hj Hk). exact Hx. }
  split.
  { apply (u32_window_is_pkg_bytes pkg pre (dec32 c20 c21 c22 c23)
             c20 c21 c22 c23 20%usize 21%usize 22%usize 23%usize 31 20
             AAu eq_refl ltac:(tza; lia) ltac:(tza; lia) ltac:(tza; lia)
             ltac:(tza; lia) H20 H21 H22 H23). }
  split.
  { apply (u32_window_is_pkg_bytes pkg pre (dec32 c24 c25 c26 c27)
             c24 c25 c26 c27 24%usize 25%usize 26%usize 27%usize 35 24
             AVe eq_refl ltac:(tza; lia) ltac:(tza; lia) ltac:(tza; lia)
             ltac:(tza; lia) H24 H25 H26 H27). }
  split.
  { apply (u32_window_is_pkg_bytes pkg pre blu32
             c28 c29 c30 c31 28%usize 29%usize 30%usize 31%usize 39 28
             ABl Hblv ltac:(tza; lia) ltac:(tza; lia) ltac:(tza; lia)
             ltac:(tza; lia) H28 H29 H30 H31). }
  split. { exact Hblob. }
  { intros i j k Hi Hj Hk.
    rewrite (AHh i j Hi Hj).
    rewrite (array_from_slice_val hdr_buf hsrc i)
      by (rewrite Hhlen, tz48; reflexivity).
    apply (slice_index_range_val _ _ _ _ i k Hhsrc);
      [ lia | rewrite tz_hdr, tz0; lia | rewrite tz0; lia ]. }
Qed.

(* ===================================================================== *)
(* … AND THE SAME STATEMENT AT THE LEVEL OF THE WIRE FORMAT.              *)
(*                                                                        *)
(* `accept_implies_authenticated_fields` talks about `r.(version)` — a     *)
(* DECODED `u32`. Until Q19/Q20 the decoder had no law at all, so that     *)
(* `u32` was formally an arbitrary function of four attacker-supplied      *)
(* bytes and neither P2 nor P4 said anything about the package as it       *)
(* travels on the wire. The theorem below closes that: it names the four   *)
(* bytes, gives the version's VALUE as their little-endian reading, and    *)
(* shows that those very bytes are the ones sitting in the MAC'd preimage  *)
(* at [35,39).                                                             *)
(* ===================================================================== *)

Theorem accept_implies_version_is_package_bytes :
  forall (pkg : slice u8) (en : array u8 16%usize) r,
    parse_and_verify inst pkg en h key = Ok (Core_result_Result_Ok r) ->
    exists (b24 b25 b26 b27 : u8) (expect : array u8 32%usize)
           (pre : array u8 91%usize) (nonce : array u8 16%usize)
           (hdr : array u8 48%usize) (bl : u32),
      (* the package's four version bytes … *)
      slice_index_usize pkg 24%usize = Ok b24
      /\ slice_index_usize pkg 25%usize = Ok b25
      /\ slice_index_usize pkg 26%usize = Ok b26
      /\ slice_index_usize pkg 27%usize = Ok b27
      (* … read little-endian, ARE the version the caller is handed (and the
         one `select_active_slot` compares) … *)
      /\ to_Z r.(verifiedUpdate_version)
         = to_Z b24 + 256 * to_Z b25 + 65536 * to_Z b26 + 16777216 * to_Z b27
      (* … and the device's tag is `mac key` of a preimage whose version
         window [35,39) holds those same four package bytes. *)
      /\ compute_pkg_tag inst nonce r.(verifiedUpdate_author_id)
           r.(verifiedUpdate_version) bl hdr h key = Ok expect
      /\ expect = mac key pre
      /\ (forall i j k : usize, 0 <= to_Z i < 4 ->
            to_Z j = 35 + to_Z i -> to_Z k = 24 + to_Z i ->
            exists x y, array_index_usize pre j = Ok x
                     /\ slice_index_usize pkg k = Ok y
                     /\ to_Z x = to_Z y).
Proof.
  intros pkg en r Hacc.
  pose proof (accept_implies_auth_gates inst pkg en h key r Hacc) as HG.
  destruct HG as [nsrc [ncpy [c20 [c21 [c22 [c23 [c24 [c25 [c26 [c27
    [c28 [c29 [c30 [c31 [toff [blus [blu32 [blob [hsrc [hcpy
    [i26 [expect [got HG]]]]]]]]]]]]]]]]]]]]]]].
  do 7 (destruct HG as [_ HG]).
  destruct HG as [H24 HG]. destruct HG as [H25 HG].
  destruct HG as [H26 HG]. destruct HG as [H27 HG].
  do 10 (destruct HG as [_ HG]).
  destruct HG as [Hcpt HG].
  do 3 (destruct HG as [_ HG]).
  subst r.
  destruct (compute_pkg_tag_assembles _ _ _ _ _ _ Hcpt) as [pre [Hmac HAsm]].
  rewrite Hseam in Hmac. injection Hmac as Hmac.
  destruct HAsm as [_ [_ [_ [AVer _]]]].
  exists c24, c25, c26, c27, expect, pre.
  do 3 eexists.
  cbn [verifiedUpdate_author_id verifiedUpdate_version].
  split; [ exact H24 |]. split; [ exact H25 |].
  split; [ exact H26 |]. split; [ exact H27 |].
  split; [ apply dec32_val |].
  split; [ exact Hcpt |].
  split; [ symmetry; exact Hmac |].
  intros i j k Hi Hj Hk.
  (* the preimage's version window reads the RE-ENCODING of the decoded field *)
  rewrite (AVer i j Hi Hj).
  destruct (dec32_le_byte c24 c25 c26 c27 i Hi) as [x [Hx Hvx]].
  exists x, (pick4 c24 c25 c26 c27 (to_Z i)).
  split; [ exact Hx |]. split; [| exact Hvx ].
  (* … and that byte is the package byte at 24 + i *)
  assert (Hc : to_Z i = 0 \/ to_Z i = 1 \/ to_Z i = 2 \/ to_Z i = 3) by lia.
  unfold pick4.
  destruct Hc as [E|[E|[E|E]]]; rewrite E; cbn [Z.eqb].
  - rewrite (slice_index_usize_ext _ k 24%usize) by (rewrite tz24; lia).
    exact H24.
  - rewrite (slice_index_usize_ext _ k 25%usize) by (rewrite tz25; lia).
    exact H25.
  - rewrite (slice_index_usize_ext _ k 26%usize) by (rewrite tz26; lia).
    exact H26.
  - rewrite (slice_index_usize_ext _ k 27%usize) by (rewrite tz27; lia).
    exact H27.
Qed.

(** The two facts composed, in the form a future unforgeability argument needs:
    every tag the device produces is `mac key` of a preimage that determines the
    five fields. Uses C1 (to name the tag as `mac key _`) and nothing else. *)
Theorem compute_pkg_tag_preimage_injective :
  forall n1 au1 ve1 bl1 hh1 t1 n2 au2 ve2 bl2 hh2 t2,
    compute_pkg_tag inst n1 au1 ve1 bl1 hh1 h key = Ok t1 ->
    compute_pkg_tag inst n2 au2 ve2 bl2 hh2 h key = Ok t2 ->
    exists pre1 pre2 : array u8 91%usize,
      t1 = mac key pre1 /\ t2 = mac key pre2
      /\ ((forall j : usize, 0 <= to_Z j < 91 ->
             array_index_usize pre1 j = array_index_usize pre2 j) ->
          (forall i : usize, 0 <= to_Z i < 16 ->
             array_index_usize n1 i = array_index_usize n2 i)
          /\ to_Z au1 = to_Z au2 /\ to_Z ve1 = to_Z ve2 /\ to_Z bl1 = to_Z bl2
          /\ (forall i : usize, 0 <= to_Z i < 48 ->
             array_index_usize hh1 i = array_index_usize hh2 i)).
Proof.
  intros n1 au1 ve1 bl1 hh1 t1 n2 au2 ve2 bl2 hh2 t2 H1 H2.
  destruct (compute_pkg_tag_assembles _ _ _ _ _ _ H1) as [p1 [Hm1 HA1]].
  destruct (compute_pkg_tag_assembles _ _ _ _ _ _ H2) as [p2 [Hm2 HA2]].
  exists p1, p2.
  rewrite Hseam in Hm1, Hm2.
  injection Hm1 as Hm1. injection Hm2 as Hm2.
  split; [ symmetry; exact Hm1 |]. split; [ symmetry; exact Hm2 |].
  intros Hag. exact (assembly_injective p1 p2 _ _ _ _ _ _ _ _ _ _ HA1 HA2 Hag).
Qed.

(** A CONDITIONAL WHOSE CONDITION IS KNOWN FALSE. Read the framing before the
    statement.

    `Hinj` below says `mac key` is injective: distinct 91-byte preimages give
    distinct 32-byte tags. That is FALSE by pigeonhole of any concrete
    32-byte-output function on a 91-byte domain, exactly as the deleted C2 was.
    It is NOT "the standard idealization of a MAC" — the standard idealizations
    are EUF-CMA or a random oracle, neither of which is perfect injectivity of a
    compressing function — and this corollary is therefore NOT a step toward
    unforgeability. It is kept OUT of the `Section` and written as an explicit
    premise so that no theorem picks it up silently, and so that a reader sees
    the whole assumption in the statement.

    What changed with respect to C2 is WHERE the assumption sits. C2 assumed
    injectivity of `mac key ∘ assemble` — the composition, so it also swallowed
    the (true, and now proved) fact that the assembly loses no information.
    `Hinj` is about `mac key` ALONE. The gap between the two is
    `assembly_injective`, which is a `Qed` above. That is what makes this
    corollary's proof carry content rather than permute a conjunction. *)
Corollary tag_reuse_implies_same_fields_under_injective_mac :
  (forall p q : array u8 91%usize, mac key p = mac key q ->
     forall j : usize, 0 <= to_Z j < 91 ->
       array_index_usize p j = array_index_usize q j) ->
  forall n1 au1 ve1 bl1 hh1 n2 au2 ve2 bl2 hh2 (t : array u8 32%usize),
    compute_pkg_tag inst n1 au1 ve1 bl1 hh1 h key = Ok t ->
    compute_pkg_tag inst n2 au2 ve2 bl2 hh2 h key = Ok t ->
    (forall i : usize, 0 <= to_Z i < 16 ->
       array_index_usize n1 i = array_index_usize n2 i)
    /\ to_Z au1 = to_Z au2 /\ to_Z ve1 = to_Z ve2 /\ to_Z bl1 = to_Z bl2
    /\ (forall i : usize, 0 <= to_Z i < 48 ->
       array_index_usize hh1 i = array_index_usize hh2 i).
Proof.
  intros Hinj n1 au1 ve1 bl1 hh1 n2 au2 ve2 bl2 hh2 t H1 H2.
  destruct (compute_pkg_tag_preimage_injective n1 au1 ve1 bl1 hh1 t
              n2 au2 ve2 bl2 hh2 t H1 H2) as [p1 [p2 [E1 [E2 Himp]]]].
  apply Himp. apply Hinj. rewrite <- E1, <- E2. reflexivity.
Qed.

(* ===================================================================== *)
(* … AND THE ANTI-ROLLBACK HALF (P4), over the AUTHENTICATED version.     *)
(* ===================================================================== *)

(** An accepted package whose version does not strictly exceed the active slot's
    version is never selected: selection returns slot A.

    INERT PREMISE — see the file header. The acceptance hypothesis is stated but
    NOT USED (`intros … _ Hle`); this is `Update_Props.stale_update_not_selected`
    with a documentary premise, and `Print Assumptions` shows zero quarantine
    axioms. The version-provenance content lives in
    `activation_implies_package_version_strictly_newer`. *)
Corollary accepted_stale_update_is_not_activated :
  forall (pkg : slice u8) (en : array u8 16%usize) r (va : u32),
    parse_and_verify inst pkg en h key = Ok (Core_result_Result_Ok r) ->
    (r.(verifiedUpdate_version) s> va) = false ->
    select_active_slot (Some va) (Some r.(verifiedUpdate_version)) = Ok (Some 0%usize).
Proof.
  intros pkg en r va _ Hle. apply stale_update_not_selected, Hle.
Qed.

(** Conversely, if the update slot IS activated, the version strictly exceeded
    the active one. Together with the previous corollary this is the "activate
    iff strictly newer" statement.

    INERT PREMISE — same caveat: the acceptance hypothesis is discarded
    (`intros … _ Hsel`), so this is `Update_Props.select_both_picks_strictly_
    greater` with a documentary premise. It is used below, where acceptance
    DOES do work. *)
Corollary activation_implies_strictly_newer :
  forall (pkg : slice u8) (en : array u8 16%usize) r (va : u32),
    parse_and_verify inst pkg en h key = Ok (Core_result_Result_Ok r) ->
    select_active_slot (Some va) (Some r.(verifiedUpdate_version)) = Ok (Some 1%usize) ->
    (r.(verifiedUpdate_version) s> va) = true.
Proof.
  intros pkg en r va _ Hsel.
  rewrite select_both_picks_strictly_greater in Hsel.
  destruct (r.(verifiedUpdate_version) s> va) eqn:Hgt; [ reflexivity |].
  exfalso.
  assert (Hz : to_Z (0%usize) = to_Z (1%usize)) by congruence.
  pose proof tz0. pose proof tz1. lia.
Qed.

(** P4, OVER THE PACKAGE BYTES. Activating the update slot implies that the
    little-endian reading of `pkg[24..28]` — the four bytes the version field
    is decoded from, and the four bytes that sit inside the MAC'd preimage at
    [35,39) by `accept_implies_version_is_package_bytes` — strictly exceeds
    the active slot's version. This is the anti-rollback statement about the
    WIRE FORMAT rather than about a `u32` of unexplained provenance.

    Still outside: where `va` comes from (the flash scan) and everything after
    `parse_and_verify` returns. See the file header. *)
Corollary activation_implies_package_version_strictly_newer :
  forall (pkg : slice u8) (en : array u8 16%usize) r (va : u32),
    parse_and_verify inst pkg en h key = Ok (Core_result_Result_Ok r) ->
    select_active_slot (Some va) (Some r.(verifiedUpdate_version))
      = Ok (Some 1%usize) ->
    exists b24 b25 b26 b27 : u8,
      slice_index_usize pkg 24%usize = Ok b24
      /\ slice_index_usize pkg 25%usize = Ok b25
      /\ slice_index_usize pkg 26%usize = Ok b26
      /\ slice_index_usize pkg 27%usize = Ok b27
      /\ to_Z b24 + 256 * to_Z b25 + 65536 * to_Z b26 + 16777216 * to_Z b27
         > to_Z va.
Proof.
  intros pkg en r va Hacc Hsel.
  pose proof (activation_implies_strictly_newer pkg en r va Hacc Hsel) as Hgt.
  unfold scalar_gtb in Hgt. apply Z.gtb_lt in Hgt.
  destruct (accept_implies_version_is_package_bytes pkg en r Hacc)
    as [b24 [b25 [b26 [b27 [expect [pre [nonce [hdr [bl
       [H24 [H25 [H26 [H27 [Hval _]]]]]]]]]]]]]].
  exists b24, b25, b26, b27.
  split; [ exact H24 |]. split; [ exact H25 |].
  split; [ exact H26 |]. split; [ exact H27 |].
  lia.
Qed.

End Composed.

Print Assumptions pkg_tag_label_is_update_v2.
