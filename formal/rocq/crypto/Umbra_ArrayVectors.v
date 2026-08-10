(** `ArrayVectors` IS EXACTLY THE RIGHT PREMISE — satisfiable, and necessary.

    WHY THIS FILE EXISTS. `Umbra_ByteSpace` re-indexes the game's message space
    at `256^76` and proves that on that space any two seams satisfying
    `ByteSeam` agree — but only under one named model-level premise,
    `ArrayVectors`: every 91-element list of bytes is the read-sequence
    (`bytes91`) of some `array u8 91`. That premise is true of Rust and is not
    provable against the Aeneas backend, whose `Primitives.array_index_usize`
    is a bare axiom with no law relating any constructor to indexing. Asserting
    such a premise without checking it is how a development quietly becomes
    inconsistent, and asserting more than the result needs is how a development
    quietly becomes unfalsifiable. This file rules out both.

    WHAT IS PROVED, AND WHY THE PAIR MATTERS.

    * SUFFICIENT AND CONSISTENT — `ArrayVectors_holds_in_the_list_model`.
      `ArrayVectors` holds under `ModelIndex`, the statement that
      `array_index_usize` is interpreted by `Update_Model.model_array_index`.
      That function is not a fresh model invented for this file: it is
      literally the `op_array_index` field of `Update_Model.model_ops`, the
      witness of `Update_Model.quarantine_has_a_model`. So the SAME
      interpretation of the SAME symbol satisfies all twenty quarantine laws
      AND `ArrayVectors` simultaneously — adding the premise cannot have made
      the axiom set inconsistent, and it cannot have silently displaced any of
      the twenty. The proof is constructive: it BUILDS the array (clamp each
      `Z` into `u8`) and computes its read-sequence.

    * NECESSARY — `the_counterexample_rebuilds_without_ArrayVectors` and its
      contrapositive `pinning_forces_ArrayVectors_on_the_reachable_messages`.
      If at even ONE message of the new space the canonical preimage failed to
      be `bytes91` of some array, the dead-zone counterexample rebuilds at that
      message: `point_patch` bumps the seam there, and both seams still satisfy
      `ByteSeam` while disagreeing. Hence the pinning theorem IMPLIES the
      `ArrayVectors` instances it quantifies over.

    Together: the fix is EXACTLY `ArrayVectors` on the reachable messages —
    necessary and sufficient, no slack, nothing displaced. Nothing here weakens
    the honest statement that the premise is unprovable against the backend's
    uninterpreted `array_index_usize`; it establishes that the premise is the
    right one to be stuck on. *)

Require Import Primitives.
Import Primitives.
Require Import Coq.ZArith.ZArith.
Require Import Lia.
Require Import List.
Import ListNotations.
Require Import Update_Types.
Require Import Update_Safety.
Require Import Update_Model.
Require Import Update_Encoding.
Require Import Umbra_Canonical.
Require Import Umbra_ByteSpace.

Local Open Scope Z_scope.
Local Open Scope Primitives_scope.

(* ===================================================================== *)
(** * 1. Satisfiability, in the model that already discharges the quarantine *)
(* ===================================================================== *)

(** The model's interpretation of the ONE opaque symbol `bytes91` depends on,
    verbatim from `Update_Model.model_array_index` — which is the
    `op_array_index` field of `model_ops`, the witness of
    `Update_Model.quarantine_has_a_model`. *)
Definition ModelIndex : Prop :=
  forall (T : Type) (n : usize) (a : array T n) (i : usize),
    @array_index_usize T n a i = model_array_index T n a i.

(* ---- a TOTAL clamp Z -> u8; `scalar` is a sigma over Z, so this is direct ---- *)
Definition clampZ (z : Z) : Z := Z.max 0 (Z.min z 255).

Lemma clampZ_ok : forall z, scalar_min U8 <= clampZ z <= scalar_max U8.
Proof.
  intro z. cbn [scalar_min scalar_max]. unfold u8_min, u8_max, clampZ.
  pose proof (Z.le_max_l 0 (Z.min z 255)).
  pose proof (Z.le_min_r z 255).
  pose proof (Z.le_max_r 0 (Z.min z 255)).
  lia.
Qed.

Definition mkbyte (z : Z) : u8 := exist _ (clampZ z) (clampZ_ok z).

Lemma to_Z_mkbyte : forall z, 0 <= z <= 255 -> to_Z (mkbyte z) = z.
Proof.
  intros z Hz. unfold to_Z, mkbyte, clampZ. cbn [proj1_sig]. lia.
Qed.

Lemma map_to_Z_mkbyte : forall b, allbytes b = true -> map to_Z (map mkbyte b) = b.
Proof.
  intros b Hb. rewrite map_map.
  rewrite <- (map_id b) at 2. apply map_ext_in.
  intros z Hz. apply to_Z_mkbyte. exact (proj1 (allbytes_spec b) Hb z Hz).
Qed.

(** The check the re-indexing had assumed rather than performed. *)
Theorem ArrayVectors_holds_in_the_list_model : ModelIndex -> ArrayVectors.
Proof.
  intros HM b Hlen Hb.
  assert (Hl : Z.of_nat (length (map mkbyte b)) = to_Z 91%usize).
  { rewrite map_length, Hlen. reflexivity. }
  exists (exist _ (map mkbyte b) Hl).
  unfold bytes91, rdA.
  (* every read of the constructed array is the corresponding element of `b` *)
  assert (Hstep : forall i : nat, (i < 91)%nat ->
    match @array_index_usize u8 91%usize (exist _ (map mkbyte b) Hl)
                             (uz (Z.of_nat i)) with
    | Ok v => to_Z v | _ => 256 end
    = nth i b 0).
  { intros i Hi. rewrite HM. unfold model_array_index, opt_result.
    cbn [proj1_sig].
    assert (Hrange : 0 <= Z.of_nat i <= usize_max).
    { pose proof usize_max_bound as Hu. unfold u32_max in Hu. lia. }
    rewrite (to_Z_uz (Z.of_nat i) Hrange), Nat2Z.id.
    rewrite (@nth_error_nth' u8 (map mkbyte b) i (mkbyte 0))
      by (rewrite map_length, Hlen; lia).
    rewrite (@map_nth Z u8 mkbyte b 0 i).
    apply to_Z_mkbyte.
    apply (proj1 (allbytes_spec b) Hb). apply nth_In. lia. }
  apply nth_error_ext. intro k.
  destruct (Nat.ltb_spec k 91) as [Hk | Hk].
  - rewrite nth_error_map.
    assert (Hs : nth_error (seq 0 91) k = Some k).
    { rewrite (@nth_error_nth' nat (seq 0 91) k 0%nat)
        by (rewrite seq_length; lia).
      rewrite seq_nth by lia. reflexivity. }
    rewrite Hs. cbn [option_map].
    rewrite Hstep by lia.
    symmetry. apply (@nth_error_nth' Z b k 0). lia.
  - assert (H1 : nth_error (map (fun i : nat =>
        match @array_index_usize u8 91%usize (exist _ (map mkbyte b) Hl)
                                 (uz (Z.of_nat i)) with
        | Ok bb => to_Z bb | _ => 256 end) (seq 0 91)) k = None).
    { apply nth_error_None. rewrite map_length, seq_length. lia. }
    rewrite H1. symmetry. apply nth_error_None. lia.
Qed.

(* ===================================================================== *)
(** * 2. Necessity: without it, the dead-zone counterexample rebuilds *)
(* ===================================================================== *)

(** If, at even ONE message of the new space, the canonical preimage fails to
    be `bytes91` of some array, then the counterexample REBUILDS: two seams
    both satisfying `ByteSeam`, disagreeing at that message. So the residual
    is exactly `ArrayVectors` restricted to the image of `canon91 . spread`,
    and not one bit less. *)

Definition lst_eq_dec : forall l l' : list Z, {l = l'} + {l <> l'} :=
  list_eq_dec Z.eq_dec.

(** The patch that fires at ONE list, chosen by decidable list equality. *)
Definition point_patch (mb0 : byteseam_t) (b0 : list Z) : byteseam_t :=
  fun kb b => if lst_eq_dec b b0 then mb0 kb b + 1 else mb0 kb b.

Theorem the_counterexample_rebuilds_without_ArrayVectors :
  forall (macf : slice u8 -> array u8 91%usize -> array u8 32%usize)
         (mb0 : byteseam_t) (j : Z),
    ByteSeam macf mb0 ->
    (* the ONLY thing ArrayVectors buys, denied at a single message: *)
    (forall p : array u8 91%usize, bytes91 p <> canon91 (spread j)) ->
    exists mb : byteseam_t,
      ByteSeam macf mb
      /\ (forall kb : slice u8,
            mb (kbytes kb) (canon91 (spread j))
            <> mb0 (kbytes kb) (canon91 (spread j))).
Proof.
  intros macf mb0 j Hbs Hmiss.
  exists (point_patch mb0 (canon91 (spread j))).
  split.
  - intros kb p. unfold point_patch.
    destruct (lst_eq_dec (bytes91 p) (canon91 (spread j))) as [He | _].
    + exfalso. exact (Hmiss p He).
    + apply Hbs.
  - intro kb. unfold point_patch.
    destruct (lst_eq_dec (canon91 (spread j)) (canon91 (spread j)))
      as [_ | Hne]; [ lia | congruence ].
Qed.

(** Contrapositive, stated the way the verdict needs it: the pinning theorem
    on the new space IMPLIES the `ArrayVectors` instances it quantifies over.
    So `ArrayVectors` is not a convenience — it is equivalent to the result. *)
Theorem pinning_forces_ArrayVectors_on_the_reachable_messages :
  (forall (macf : slice u8 -> array u8 91%usize -> array u8 32%usize)
          (mb mb' : byteseam_t),
      ByteSeam macf mb -> ByteSeam macf mb' ->
      forall (kb : slice u8) (j : Z),
        mb (kbytes kb) (canon91 (spread j))
        = mb' (kbytes kb) (canon91 (spread j))) ->
  forall (macf : slice u8 -> array u8 91%usize -> array u8 32%usize)
         (mb0 : byteseam_t) (j : Z),
    ByteSeam macf mb0 ->
    ~ (forall p : array u8 91%usize, bytes91 p <> canon91 (spread j)).
Proof.
  intros Hpin macf mb0 j Hbs Hmiss.
  destruct (the_counterexample_rebuilds_without_ArrayVectors
              macf mb0 j Hbs Hmiss) as [mb [Hmb Hdiff]].
  (* a slice u8 to instantiate the key at: the empty one *)
  assert (Hk : Z.of_nat (length (@nil u8)) <= usize_max).
  { cbn. pose proof usize_max_bound as Hu. unfold u32_max in Hu. lia. }
  exact (Hdiff (exist _ (@nil u8) Hk)
           (Hpin macf mb mb0 Hmb Hbs (exist _ (@nil u8) Hk) j)).
Qed.

Print Assumptions ArrayVectors_holds_in_the_list_model.
Print Assumptions the_counterexample_rebuilds_without_ArrayVectors.
Print Assumptions pinning_forces_ArrayVectors_on_the_reachable_messages.
