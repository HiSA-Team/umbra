(** THE HONEST NEGATIVE — what the chain still does not cover.

    `Umbra_Canonical.blob_body_is_not_covered_by_pkg_tag` (Qed) says the package
    package tag historically missed `blob[0,16)` and still misses
    `blob[48,blob_len)`. Pkg-tag v2 now covers the full header; `Chain_Body`
    closes the second range only for the part the fold actually walks.
    This file states, machine-checked, exactly what is left, in the same style:
    an INVARIANCE, i.e. a proof that the gate cannot separate two blobs which
    differ where nothing looks.

    THE RESIDUE, for a blob of `n` blocks:

      R1  `blob[4,10)` and `blob[14,16)` — `trust_level`, `reserved0`,
          `efbc_size`, `ess_blocks`, `reloc_count`. In no chain preimage, but
          covered by the v2 package tag. Locally to the chain,
          [verdict_ignores_the_unauthenticated_header_bytes] below proves it: the
          gate's verdict does not depend on those bytes at all.

      R2  `blob[0,4)` and `blob[10,14)` — `magic` and `code_size`. The chain
          reads them, and the v2 package tag authenticates them. `magic` is
          checked against a constant and `code_size` fixes `n`;
          [count_ignores_the_unread_header_bytes] states the exact dependency.

      R3  `blob[48 + 288·n, blob_len)` — the relocation table
          `protect_enclave.py` appends after the blocks: `reloc_count` u32
          entries, each a plaintext-relative offset of a 32-bit word a loader
          REWRITES after decryption. In no preimage of either kind.

    WHAT R1 IS WORTH TO THE CHAIN ALONE: it identifies bytes the chain ignores.
    The update tag now covers them. `trust_level` was the alarming
    one, because `UmbraEnclaveHeader::is_trusted()` reads it. That method has
    ZERO call sites in the repository — `EnclaveTrustLevel` occurs only in its own
    declaration and in the one comparison inside `is_trusted`
    (`src/kernel/src/common/enclave.rs:17-20,53,81-83`), and nothing calls
    `is_trusted`. `efbc_size` and `ess_blocks` have zero field reads anywhere;
    N657 ESS sizing comes from `code_size` (`stm32n657/boot/src/api_impl.rs:347`)
    and the EFBC window is a compile-time constant. The only unauthenticated
    field the N657 reads at all is `code_size`, and every use is bounds-checked
    (`api_impl.rs:152-155`, `339-350`). So R1 is a latent hole in the FORMAT, not
    a live hole in the product: it becomes exploitable exactly when someone gives
    one of those five bytes a consumer outside the authenticated update path.

    R3 IS LATENT TOO, AND FAIL-CLOSED — an earlier revision of this comment
    called it a live gap, which overstated it. It is a real asymmetry:
    `stm32l552/boot/src/api_impl/enclave_create.rs:282-291` folds the reloc bytes
    into the chain, `riscv32/boot/src/secure_kernel/create.rs:130-136` folds
    them, and `stm32n657/boot/src/api_impl.rs` does not. But (i) NO N657 code
    reads `reloc_count` or the table — `apply_relocs_to_block` exists only at
    `stm32l552/boot/src/secure_kernel/init.rs:101`, with a separate RISC-V
    equivalent and no N657 one — so on that platform the table is inert data
    nothing consumes; and (ii) the divergence fails CLOSED, because
    `tools/protect_enclave.py:852-857` folds the table offline whenever
    `chained_mode and reloc_count > 0`, so an N657 blob carrying relocations
    produces a root the N657's own fold cannot reproduce and is REJECTED. In
    practice N657 blobs must have `reloc_count == 0`. The gap becomes real the
    day the N657 gains reloc support — which it would need to run the static-PIE
    applications the L552 runs — and L552's own comment
    (`enclave_create.rs:250-257`) says the fold is exactly what catches on-flash
    tampering of those offsets. The crate README carries the proposed change. *)

Require Import Primitives.
Import Primitives.
Require Import AeneasLoopShim.
Import AeneasLoopShim.
Require Import Coq.ZArith.ZArith.
Require Import Coq.Lists.List.
Import ListNotations.
Require Import Lia.
Require Import Update_Safety.
Require Import Chain_Types.
Import Chain_Types.
Require Import Chain_FunsExternal.
Import Chain_FunsExternal.
Require Import Chain_Funs.
Import Chain_Funs.
Require Import Chain_Value.
Require Import Chain_Trace.
Local Open Scope Z_scope.
Local Open Scope Primitives_scope.

(* ===================================================================== *)
(* The fold's view of a block is exactly that block.                      *)
(* ===================================================================== *)

(** Two blobs agreeing on the whole of block `blk` have IDENTICAL preimages for
    it, whatever they do outside. `Chain_Value.preimage_pins_block` is the
    converse; together they say the preimage is a faithful — and exactly
    faithful — view of `blob[48+288·blk, 48+288·blk+288)`.

    The two block-index arguments are allowed to be different TERMS of the same
    value, because that is what the trace hands over: `chain_root_trace` produces
    an index per run, pinned by its value. *)
Theorem preimages_see_only_the_block_region :
  forall (blob1 blob2 : slice u8) (blk1 blk2 : u32) (pre1 pre2 : array u8 292%usize),
    block_preimage blob1 blk1 = Ok (Some pre1) ->
    block_preimage blob2 blk2 = Ok (Some pre2) ->
    to_Z blk1 = to_Z blk2 ->
    (forall k : usize,
       48 + 288 * to_Z blk1 <= to_Z k < 48 + 288 * to_Z blk1 + 288 ->
       slice_index_usize blob1 k = slice_index_usize blob2 k) ->
    pre1 = pre2.
Proof.
  intros blob1 blob2 blk1 blk2 pre1 pre2 H1 H2 Hbe Hag.
  pose proof cu32max_big as Hbig. pose proof (to_Z_u32_bounds blk1) as Hblk.
  destruct (preimage_windows blob1 blk1 pre1 H1) as [b1 [Hb1 [L1 [X1 [C1 M1]]]]].
  destruct (preimage_windows blob2 blk2 pre2 H2) as [b2 [Hb2 [L2 [X2 [C2 M2]]]]].
  pose proof (to_Z_usize_bounds (slice_len blob1)) as Hsl.
  pose proof (to_Z_usize_bounds b1) as Hb1b.
  apply (array_u8_ext_res 292%usize). intros j Hj. rewrite ctz292 in Hj.
  destruct (Z.lt_ge_cases (to_Z j) 4) as [Hlo | H4].
  - (* [0,4) — the block index. The two runs hold separately-built index terms
       of the same value, and the encoder is a function of the value (Q18+Q21). *)
    rewrite (X1 j j ltac:(lia) ltac:(lia)), (X2 j j ltac:(lia) ltac:(lia)).
    rewrite (to_le_bytes_val_cong_arr blk1 blk2 Hbe). reflexivity.
  - destruct (Z.lt_ge_cases (to_Z j) 260) as [Hmid | H260].
    + (* [4,260) — the code half *)
      destruct (cexists_usize (to_Z j - 4) ltac:(lia)) as [i Hi].
      destruct (cexists_usize_full (to_Z b1 + 32 + to_Z i) ltac:(lia)) as [k Hk].
      rewrite (C1 i j k ltac:(lia) ltac:(lia) ltac:(lia)).
      rewrite (C2 i j k ltac:(lia) ltac:(lia) ltac:(lia)).
      apply Hag. lia.
    + (* [260,292) — the meta half *)
      destruct (cexists_usize (to_Z j - 260) ltac:(lia)) as [i Hi].
      destruct (cexists_usize_full (to_Z b1 + to_Z i) ltac:(lia)) as [k Hk].
      rewrite (M1 i j k ltac:(lia) ltac:(lia) ltac:(lia)).
      rewrite (M2 i j k ltac:(lia) ltac:(lia) ltac:(lia)).
      apply Hag. lia.
Qed.

(* ===================================================================== *)
(* THE SHARP FORM OF R1 AND R3.                                           *)
(* ===================================================================== *)

(** The chain root is a function of `blob[48, 48+288·n)` and of NOTHING else in
    the blob. Two blobs agreeing there produce the same root, however they differ
    in the header metadata or in everything appended after the blocks — which is
    where the relocation table lives.

    Together with the accept gate reading `blob[16,48)` and the count reading
    `blob[0,4)` and `blob[10,14)`, this pins the gate's ENTIRE view of a blob to
    `blob[0,4) ∪ blob[10,14) ∪ blob[16, 48+288·n)`. The complement —
    `blob[4,10)`, `blob[14,16)` and `blob[48+288·n, blob_len)` — is invisible to
    it, and therefore authenticated by nothing in `formal/`.

    This is `blob_body_is_not_covered_by_pkg_tag` one layer down: same shape,
    smaller residue. *)
Theorem chain_root_ignores_everything_outside_the_blocks :
  forall {HS : Type} (inst : ChainHmac_t HS) (h : HS)
         (master : ckey) (blob1 blob2 : slice u8) (n : u32) (r1 r2 : ckey),
    chain_root inst h master blob1 n = Ok (Some r1) ->
    chain_root inst h master blob2 n = Ok (Some r2) ->
    (forall k : usize, 48 <= to_Z k < 48 + 288 * to_Z n ->
       slice_index_usize blob1 k = slice_index_usize blob2 k) ->
    r1 = r2.
Proof.
  intros HS inst h master blob1 blob2 n r1 r2 H1 H2 Hag.
  pose proof cu32max_big as Hbig. pose proof (to_Z_u32_bounds n) as Hnb.
  destruct (chain_root_trace inst h master blob1 n r1 H1) as [ms1 [T1 [L1 I1]]].
  destruct (chain_root_trace inst h master blob2 n r2 H2) as [ms2 [T2 [L2 I2]]].
  assert (Hlen : length ms1 = length ms2) by (apply Nat2Z.inj; lia).
  assert (Hms : ms1 = ms2).
  { apply nth_error_list_eq. intro k.
    destruct (nth_error ms1 k) as [p|] eqn:E1.
    - assert (Hk1 : (k < length ms1)%nat)
        by (apply nth_error_Some; rewrite E1; discriminate).
      destruct (nth_error ms2 k) as [q|] eqn:E2;
        [| exfalso; apply nth_error_None in E2; lia ].
      destruct (I1 k p E1) as [b1 [Hb1 Hp1]].
      destruct (I2 k q E2) as [b2 [Hb2 Hp2]].
      assert (Hkn : Z.of_nat k < to_Z n) by (apply Nat2Z.inj_lt in Hk1; lia).
      f_equal.
      apply (preimages_see_only_the_block_region blob1 blob2 b1 b2 p q Hp1 Hp2
               ltac:(lia)).
      intros kk Hkk. apply Hag. lia.
    - assert (E2 : nth_error ms2 k = None).
      { apply nth_error_None. apply nth_error_None in E1. lia. }
      rewrite E2. reflexivity. }
  rewrite Hms in T1. exact (trace_det (seam_of inst h) ms2 master r1 r2 T1 T2).
Qed.

(* ===================================================================== *)
(* R2 — what the count depends on.                                        *)
(* ===================================================================== *)

(** `blob_block_count` reads `blob[0,4)` (magic) and `blob[10,14)` (`code_size`)
    and consults `slice_len`, and nothing else. So `blob[4,10)` and
    `blob[14,16)` do not reach it either. *)
Theorem count_ignores_the_unread_header_bytes :
  forall blob1 blob2 : slice u8,
    to_Z (slice_len blob1) = to_Z (slice_len blob2) ->
    (forall i : usize, 0 <= to_Z i < 4 ->
       slice_index_usize blob1 i = slice_index_usize blob2 i) ->
    (forall i : usize, 10 <= to_Z i < 14 ->
       slice_index_usize blob1 i = slice_index_usize blob2 i) ->
    blob_block_count blob1 = blob_block_count blob2.
Proof. exact blob_block_count_cong. Qed.

(** And the accept condition is evaluated at the count the blob's own header
    yields — the gate cannot be run at any other. This is why `Chain_Body` may
    take "same block count" as a local hypothesis. The update composition uses
    [successful_blob_block_counts_agree] to derive it from the authenticated
    header and two successful parses. What is NOT proved, and must not be read
    in, is that two chain-accepted blobs with DIFFERENT `code_size` have related
    bodies. They do not, and no theorem here says otherwise. *)
Theorem accept_is_evaluated_at_the_header_count :
  forall {HS : Type} (inst : ChainHmac_t HS) (h : HS)
         (master : ckey) (blob : slice u8) (n : u32),
    verify_blob_chain inst h master blob = Ok true ->
    blob_block_count blob = Ok (Some n) ->
    exists r : ckey,
      chain_root inst h master blob n = Ok (Some r)
      /\ ct_eq32_at r blob hDR_HMAC_OFF = Ok true.
Proof.
  intros HS inst h master blob n Hv Hn.
  unfold verify_blob_chain in Hv. rewrite Hn in Hv. cbn [bind] in Hv.
  destruct (chain_root inst h master blob n) as [o|] eqn:Hc;
    [ cbn [bind] in Hv | cbn [bind] in Hv; discriminate ].
  destruct o as [r|]; [| discriminate ].
  exists r. split; [ reflexivity | exact Hv ].
Qed.

(* ===================================================================== *)
(* THE VERDICT ITSELF IGNORES THEM.                                       *)
(* ===================================================================== *)

(** The compare loop is a function of the 32 blob bytes it reads. *)
Lemma ct_eq32_at_loop_cong :
  forall (fuel : nat) (a : array u8 32%usize) (blob1 blob2 : slice u8)
         (off : usize) (d : u8) (i : usize),
    to_Z (slice_len blob1) = to_Z (slice_len blob2) ->
    (forall q : usize, to_Z off <= to_Z q < to_Z off + 32 ->
       slice_index_usize blob1 q = slice_index_usize blob2 q) ->
    0 <= to_Z i ->
    loop_fuel fuel (fun '(d1, i1) => ct_eq32_at_loop_body a blob1 off d1 i1) (d, i)
    = loop_fuel fuel (fun '(d1, i1) => ct_eq32_at_loop_body a blob2 off d1 i1) (d, i).
Proof.
  induction fuel as [| n IH]; intros a blob1 blob2 off d i Hlen Hag Hi.
  - reflexivity.
  - rewrite !loop_step. cbn beta iota. unfold ct_eq32_at_loop_body.
    destruct (i s< 32%usize) eqn:Hlt; [| reflexivity ].
    apply sltb_true in Hlt. rewrite ctz32 in Hlt.
    destruct (array_index_usize a i) as [x|]; [ cbn [bind] | reflexivity ].
    destruct (usize_add off i) as [q0|] eqn:Eq; [ cbn [bind] | reflexivity ].
    unfold usize_add, scalar_add in Eq. apply mk_scalar_to_Z in Eq.
    rewrite (Hag q0 ltac:(lia)).
    destruct (slice_index_usize blob2 q0) as [y|]; [ cbn [bind] | reflexivity ].
    destruct (usize_add i 1%usize) as [i2|] eqn:Ei; [ cbn [bind] | reflexivity ].
    unfold usize_add, scalar_add in Ei. apply mk_scalar_to_Z in Ei.
    rewrite tz1 in Ei.
    apply IH; [ exact Hlen | exact Hag | lia ].
Qed.

Lemma ct_eq32_at_cong :
  forall (a : array u8 32%usize) (blob1 blob2 : slice u8) (off : usize),
    to_Z (slice_len blob1) = to_Z (slice_len blob2) ->
    (forall q : usize, to_Z off <= to_Z q < to_Z off + 32 ->
       slice_index_usize blob1 q = slice_index_usize blob2 q) ->
    ct_eq32_at a blob1 off = ct_eq32_at a blob2 off.
Proof.
  intros a blob1 blob2 off Hlen Hag. unfold ct_eq32_at.
  (* every failure branch closes with `cbn [bind]` FIRST. A bare `reflexivity`
     on `bind (Fail_ e) f1 = bind (Fail_ e) f2` invites conversion to unfold
     `ct_eq32_at_loop -> loop -> loop_fuel 1000000` inside f1/f2, and normalising
     a 10^6 `nat` literal to unary does not come back. *)
  destruct (usize_add off 32%usize) as [e|]; cbn [bind]; [| reflexivity ].
  assert (Hc : (slice_len blob1 s< e) = (slice_len blob2 s< e))
    by (unfold scalar_ltb; rewrite Hlen; reflexivity).
  rewrite Hc. destruct (slice_len blob2 s< e); [ reflexivity |].
  (* Prove the loop equality FIRST and rewrite with it. Unfolding `loop` in the
     main goal instead leaves two `loop_fuel 1000000` terms for `reflexivity` to
     convert, and converting a 10^6 `nat` literal to unary does not terminate in
     any useful time. Inside the `assert` the literal is only ever unified, never
     evaluated. *)
  assert (E : ct_eq32_at_loop a blob1 off 0%u8 0%usize
              = ct_eq32_at_loop a blob2 off 0%u8 0%usize).
  { unfold ct_eq32_at_loop, loop.
    apply (ct_eq32_at_loop_cong 1000000 a blob1 blob2 off 0%u8 0%usize);
      [ exact Hlen | exact Hag | rewrite ctz0; lia ]. }
  rewrite E. reflexivity.
Qed.

(** **THE RESIDUAL WITH TEETH, in the sharpest form this development can state.**

    When both measurements complete, the gate's VERDICT is a function of

        `slice_len blob`, `blob[0,4)`, `blob[10,14)`, `blob[16,48)`
        and `blob[48, 48+288*n)`

    and of nothing else. So `blob[4,10)` and `blob[14,16)` —
    `trust_level`, `reserved0`, `efbc_size`, `ess_blocks`, `reloc_count` — and
    everything at or beyond `48+288*n` can be set to anything at all without
    changing whether the blob is accepted BY THE CHAIN. This theorem is about the
    chain gate ALONE.

    Whether the PACKAGE TAG covers them is a separate matter, and it changed:
    under pkg-tag v2 the tag's core is `pkg[4,32)` and the FULL header
    `blob[0,48)` (76 bytes), so `blob[4,10)` and `blob[14,16)` ARE now
    tag-authenticated for any blob arriving through the signed update path. What
    remains outside BOTH the chain and the v2 tag is only everything at or beyond
    `48+288*n` (the reloc table), plus — for blobs written out-of-band, never
    through the update path — the header bytes this theorem shows the chain
    ignores. (Under pkg-tag v1 the tag core was `pkg[4,32)` and `blob[16,48)`
    only, and those header bytes were authenticated by nothing;
    `Umbra_Canonical.blob_body_is_not_covered_by_pkg_tag` still bounds what the
    tag does NOT reach — the body.)

    WHETHER THAT IS EXPLOITABLE IS A QUESTION ABOUT THE CONSUMERS, NOT ABOUT
    THIS THEOREM, and on the N657 the answer is no — see the header comment. *)
Theorem verdict_ignores_the_unauthenticated_header_bytes :
  forall {HS : Type} (inst : ChainHmac_t HS) (h : HS)
         (master : ckey) (blob1 blob2 : slice u8) (n : u32) (r1 r2 : ckey),
    to_Z (slice_len blob1) = to_Z (slice_len blob2) ->
    (* the count's inputs … *)
    (forall i : usize, 0 <= to_Z i < 4 ->
       slice_index_usize blob1 i = slice_index_usize blob2 i) ->
    (forall i : usize, 10 <= to_Z i < 14 ->
       slice_index_usize blob1 i = slice_index_usize blob2 i) ->
    (* … the compared window … *)
    (forall i : usize, 16 <= to_Z i < 48 ->
       slice_index_usize blob1 i = slice_index_usize blob2 i) ->
    (* … and the folded region. NOTHING is assumed about blob[4,10),
       blob[14,16) or anything at or beyond 48+288*n. *)
    (forall k : usize, 48 <= to_Z k < 48 + 288 * to_Z n ->
       slice_index_usize blob1 k = slice_index_usize blob2 k) ->
    blob_block_count blob1 = Ok (Some n) ->
    chain_root inst h master blob1 n = Ok (Some r1) ->
    chain_root inst h master blob2 n = Ok (Some r2) ->
    verify_blob_chain inst h master blob1 = verify_blob_chain inst h master blob2.
Proof.
  intros HS inst h master blob1 blob2 n r1 r2 Hlen H04 H1014 H1648 Hbody Hn Hc1 Hc2.
  assert (Hn2 : blob_block_count blob2 = Ok (Some n))
    by (rewrite <- (blob_block_count_cong blob1 blob2 Hlen H04 H1014); exact Hn).
  assert (Hr : r1 = r2)
    by exact (chain_root_ignores_everything_outside_the_blocks
                inst h master blob1 blob2 n r1 r2 Hc1 Hc2 Hbody).
  subst r2.
  unfold verify_blob_chain. rewrite Hn, Hn2. cbn [bind].
  rewrite Hc1, Hc2. cbn [bind].
  apply ct_eq32_at_cong; [ exact Hlen |].
  intros q Hq. apply H1648. rewrite c_hmoff in Hq. lia.
Qed.
