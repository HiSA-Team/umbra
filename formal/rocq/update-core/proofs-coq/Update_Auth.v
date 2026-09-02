(** P1 — AUTHENTICATION / ANTI-REPLAY GATE of parse_and_verify, proved over the
    verbatim Aeneas-extracted body (Update_Funs.v).

    P3 (Update_Safety.v) says the parser never traps. P1 says the parser never
    ACCEPTS without having passed both authentication gates:

      - the NONCE gate: the 16 bytes at pkg[4..20] were copied into the parser's
        scratch and that scratch was compared, with the constant-time comparator
        `ct_eq16`, against the caller's armed `expected_nonce`, returning `true`.
        Since the armed nonce is single-use (the N657 handler disarms on every
        path), this is the code-level anti-replay statement: a package built for
        an earlier nonce cannot be accepted.
      - the TAG gate: the trailing 32 bytes pkg[len-32..len] were compared, with
        `ct_eq32`, against a tag produced by the HMAC seam, and that comparison
        returned `true`.

    FIELD BINDING. An earlier revision of this theorem existentially quantified
    the seam's arguments (`exists n1 au ve bl hh, compute_pkg_tag inst n1 au ve bl
    hh h key = Ok expect`), which proves only "SOME seam call produced expect" —
    strictly weaker than the prose claim that the tag covers the package fields,
    and satisfied by a seam call on unrelated data. The statement below quantifies
    only over the RAW BYTES READ OUT OF `pkg` and then writes the seam's arguments
    as the decoding functions applied to exactly those bytes:

      nonce       = array_from_slice nonce_buf (copy_from_slice … pkg[4..20])
      author_id   = u32_from_le_bytes [pkg[20]; pkg[21]; pkg[22]; pkg[23]]
      version     = u32_from_le_bytes [pkg[24]; pkg[25]; pkg[26]; pkg[27]]
      blob_len    = usize->u32 (u32->usize (u32_from_le_bytes [pkg[28..32]]))
      header      = array_from_slice hdr_buf (copy_from_slice … blob[0..48)),
                    blob = pkg[32..len-32]   (v2: the FULL 48-byte UMBR header)

    so there is no slack left for the seam to have been called on anything else.
    The theorem additionally pins the RETURNED record: the `author_id`/`version`
    handed back to the caller are the same decodes that went into the tag, and
    the returned `blob` is the same sub-slice whose header_hmac was covered.

    THE NONCE GATE IS A BYTE EQUALITY. `accept_implies_nonce_equal` (bottom of
    this file) pushes "ct_eq16 returned true" all the way down to the package
    bytes: on acceptance, `pkg[4+j]` equals byte j of the caller's armed nonce,
    for every j < 16. It composes P1 with `Update_Value.ct_eq16_sound` and the
    VALUE half of Update_Safety's quarantine (`copy_from_slice_val`,
    `array_from_slice_val`, `slice_index_range_len/val`), all of which
    are now LEMMAS over the concrete Primitives (Update_Safety.v). Unlike
    `accept_implies_auth_gates`, it therefore DOES rest on quarantine axioms —
    see the assumption table in REPORT §7.

    WHAT IS STILL NOT PROVED HERE. The seam itself is uninterpreted: P1 says
    WHICH bytes were fed to it, not that its output is unforgeable. The
    cryptographic composition is `Update_Crypto.v`.

    `Print Assumptions accept_implies_auth_gates` reports only the Aeneas
    backend's own opaque symbols and ZERO of Update_Safety's quarantine axioms.
    (P3 needs them because it must prove the opaque ops SUCCEED; P1 is a forward
    implication from an assumed success, so it does not.) *)

Require Import Primitives.
Import Primitives.
Require Import AeneasLoopShim.
Import AeneasLoopShim.
Require Import Coq.ZArith.ZArith.
Require Import List.
Import ListNotations.
Require Import Update_Types.
Import Update_Types.
Require Import Update_FunsExternal.
Import Update_FunsExternal.
Require Import Update_Funs.
Import Update_Funs.
Require Import Lia.
Require Import Update_Safety.
Require Import Update_Value.
Local Open Scope Z_scope.
Local Open Scope Primitives_scope.

(* The zeroed scratch buffers the parser copies pkg[4..20] / blob[0..48) into. *)
Definition nonce_buf : array u8 16%usize := array_repeat 16%usize 0%u8.
Definition hdr_buf : array u8 48%usize := array_repeat 48%usize 0%u8.

(* The little-endian u32 decoder the extracted body applies to four pkg bytes. *)
Definition dec32 (b0 b1 b2 b3 : u8) : u32 :=
  core_num_U32_from_le_bytes (mk_array4 b0 b1 b2 b3).

Notation rng a b :=
  {| core_ops_range_Range_start := a; core_ops_range_Range_end_ := b |}.

Notation subslice s a b :=
  (core_slice_index_Slice_index
     (core_slice_index_SliceIndexRangeUsizeSliceInst u8) s (rng a b)).

(* Walk one monadic / branching step of the extracted body, killing every
   non-accepting continuation by discrimination against `Ok (Ok r)`. *)
Ltac auth_step H :=
  first
    [ lazymatch type of H with
      | bind ?e _ = _ => destruct e eqn:?; cbn [bind] in H; try discriminate H
      end
    | lazymatch type of H with
      | (if ?b then _ else _) = _ => destruct b eqn:?; try discriminate H
      end
    | progress cbn [array_to_slice_mut] in H ].

Theorem accept_implies_auth_gates :
  forall {H} (inst : PkgHmac_t H) (pkg : slice u8) (en : array u8 16%usize)
         (h : H) (key : slice u8) r,
    parse_and_verify inst pkg en h key = Ok (Core_result_Result_Ok r) ->
    exists (nsrc ncpy : slice u8)
           (b20 b21 b22 b23 b24 b25 b26 b27 b28 b29 b30 b31 : u8)
           (tag_off : usize) (bl_us : usize) (bl_u32 : u32)
           (blob hsrc hcpy : slice u8) (i26 : usize)
           (expect : array u8 32%usize) (got : slice u8),
      (* ---- NONCE GATE: pkg[4..20] copied into the scratch, then compared ---- *)
      subslice pkg 4%usize 20%usize = Ok nsrc
      /\ core_slice_Slice_copy_from_slice core_marker_CopyU8
           (array_to_slice nonce_buf) nsrc = Ok ncpy
      /\ ct_eq16 (array_from_slice nonce_buf ncpy) en = Ok true
      (* ---- FIELD BYTES: every byte the seam's arguments are decoded from ---- *)
      /\ slice_index_usize pkg 20%usize = Ok b20
      /\ slice_index_usize pkg 21%usize = Ok b21
      /\ slice_index_usize pkg 22%usize = Ok b22
      /\ slice_index_usize pkg 23%usize = Ok b23
      /\ slice_index_usize pkg 24%usize = Ok b24
      /\ slice_index_usize pkg 25%usize = Ok b25
      /\ slice_index_usize pkg 26%usize = Ok b26
      /\ slice_index_usize pkg 27%usize = Ok b27
      /\ slice_index_usize pkg 28%usize = Ok b28
      /\ slice_index_usize pkg 29%usize = Ok b29
      /\ slice_index_usize pkg 30%usize = Ok b30
      /\ slice_index_usize pkg 31%usize = Ok b31
      /\ scalar_cast U32 Usize (dec32 b28 b29 b30 b31) = Ok bl_us
      /\ usize_sub (slice_len pkg) 32%usize = Ok tag_off
      (* ---- BLOB and its full-header window blob[0..48) ---- *)
      /\ subslice pkg fIXED_PREFIX tag_off = Ok blob
      /\ subslice blob 0%usize hDR_LEN = Ok hsrc
      /\ core_slice_Slice_copy_from_slice core_marker_CopyU8
           (array_to_slice hdr_buf) hsrc = Ok hcpy
      /\ scalar_cast Usize U32 bl_us = Ok bl_u32
      (* ---- TAG GATE: the seam was applied to EXACTLY these decoded fields ---- *)
      /\ compute_pkg_tag inst
           (array_from_slice nonce_buf ncpy)   (* nonce   = pkg[4..20]   *)
           (dec32 b20 b21 b22 b23)             (* author  = pkg[20..24]  *)
           (dec32 b24 b25 b26 b27)             (* version = pkg[24..28]  *)
           bl_u32                              (* blob_len= pkg[28..32]  *)
           (array_from_slice hdr_buf hcpy)     (* header  = blob[0..48)  *)
           h key = Ok expect
      /\ usize_add tag_off 32%usize = Ok i26
      /\ subslice pkg tag_off i26 = Ok got
      /\ ct_eq32 expect got = Ok true
      (* ---- and the record handed back carries those same fields ---- *)
      /\ r = {| verifiedUpdate_author_id := dec32 b20 b21 b22 b23;
                verifiedUpdate_version := dec32 b24 b25 b26 b27;
                verifiedUpdate_blob := blob |}.
Proof.
  intros HH inst pkg en h key r Hacc.
  unfold parse_and_verify in Hacc. cbv zeta in Hacc.
  repeat auth_step Hacc.
  injection Hacc as Hr.
  unfold nonce_buf, hdr_buf, dec32.
  do 23 eexists.
  repeat apply conj; try eassumption.
  all: try reflexivity.
  all: try (symmetry; exact Hr).
Qed.

(* =====================================================================
   THE NONCE GATE, AT THE LEVEL OF PACKAGE BYTES.

   `accept_implies_auth_gates` ends at "ct_eq16 returned true", which is a
   statement about a boolean. This composes it with `ct_eq16_sound` and the
   value laws to reach the only formulation that means anything to an
   attacker: on acceptance, the package's nonce field IS the armed nonce.

   Chain:  pkg[4..20] --(slice_index_range_val)--> the parser's source slice
        --(copy_from_slice_val)--> the 16-byte scratch
        --(array_from_slice_val)--> the array ct_eq16 compared
        --(ct_eq16_sound)--> equal, byte by byte, to `en`.

   The conclusion is at the level of REPRESENTED VALUES (`to_Z x = to_Z y`)
   rather than `x = y`: `u8` is a sigma type over a `Prop`, so byte equality as
   Coq terms would need proof irrelevance, which is not provable without an
   extra axiom. See Update_Value.v's header. *)

Theorem accept_implies_nonce_equal :
  forall {H} (inst : PkgHmac_t H) (pkg : slice u8) (en : array u8 16%usize)
         (h : H) (key : slice u8) r,
    parse_and_verify inst pkg en h key = Ok (Core_result_Result_Ok r) ->
    forall i j : usize, 0 <= to_Z i < 16 -> to_Z j = to_Z i + 4 ->
      exists x y, slice_index_usize pkg j = Ok x
               /\ array_index_usize en i = Ok y
               /\ to_Z x = to_Z y.
Proof.
  intros HH inst pkg en h key r Hacc i j Hi Hj.
  pose proof (accept_implies_auth_gates inst pkg en h key r Hacc) as HG.
  do 23 (let w := fresh "w" in destruct HG as [w HG]).
  destruct HG as [Hns [Hcpy [Hct16 _]]].
  (* the copy handed back the source sub-slice … *)
  apply copy_from_slice_val in Hcpy. subst.
  (* … whose length is 20 - 4 = 16 *)
  pose proof (slice_index_range_len _ _ _ _ Hns) as Hlen.
  rewrite tz4, tz20 in Hlen.
  (* the comparator returning true is a byte equality on that 16-byte window *)
  destruct (ct_eq16_sound _ _ Hct16 i Hi) as [x [y [Hx [Hy Hxy]]]].
  rewrite (array_from_slice_val nonce_buf _ i) in Hx by (rewrite Hlen, tz16; reflexivity).
  rewrite (slice_index_range_val _ _ _ _ i j Hns) in Hx;
    [ | lia | rewrite tz4, tz20; lia | rewrite tz4; lia ].
  exists x, y. repeat split; assumption.
Qed.
