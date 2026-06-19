(** BRIDGE — the extracted `create_from_range` computes the T5 model (issue #58).

    T5 (Mem_Region.v) proved region coverage over a faithful Coq model `cfr`. This
    file closes the gap to the REAL extracted code: it proves the
    Aeneas-generated `memoryBlockList_create_from_range` (Mem_Funs.v) returns
    exactly the `cfr` base-block index and size. So T5's coverage holds of the
    shipping function, not just a model.

    Supporting theory supplied (the Coq backend omits it):
      - `mk_scalar` `to_Z` lemmas (the scalar wrapper is defined but unspecified);
      - `scalar_and_spec`: the Coq backend ships `scalar_and` as an *axiom marked
        TODO* (Primitives.v:260) with no semantics. We supply its obvious bitwise
        meaning. (This is the `& 0xff` mask — load-bearing for the T5 finding.) *)

Require Import Coq.ZArith.ZArith.
Require Import Coq.Bool.Bool.
Require Import Coq.micromega.Lia.
Require Import Coq.Bool.Sumbool.
Require Import Primitives. Import Primitives.
Require Import Mem_Types. Import Mem_Types.
Require Import Mem_Funs. Import Mem_Funs.
Local Open Scope Z_scope.

(* --- Missing scalar theory ------------------------------------------------- *)

(* scalar_min/scalar_max for U32 are the concrete u32 bounds. *)
Lemma u32_min_eq : scalar_min U32 = 0. Proof. reflexivity. Qed.
Lemma u32_max_eq : scalar_max U32 = u32_max. Proof. reflexivity. Qed.

(* Every u32 value is within the concrete u32 range. *)
Lemma to_Z_u32_bounds : forall x : u32, 0 <= to_Z x <= u32_max.
Proof.
  intro x. destruct x as [z Hb]. unfold to_Z; simpl.
  rewrite u32_min_eq, u32_max_eq in Hb. exact Hb.
Qed.

(* mk_scalar succeeds in-range and round-trips through to_Z. *)
Lemma mk_scalar_u32_ok :
  forall z, 0 <= z <= u32_max ->
            exists s, mk_scalar U32 z = Ok s /\ to_Z s = z.
Proof.
  intros z Hz. unfold mk_scalar.
  assert (Hb : scalar_in_bounds U32 z = true).
  { unfold scalar_in_bounds. apply andb_true_intro. split.
    - unfold scalar_ge_min. apply orb_true_intro. right.
      apply Z.leb_le. rewrite u32_min_eq. lia.
    - unfold scalar_le_max. apply orb_true_intro. right.
      apply Z.leb_le. rewrite u32_max_eq. lia. }
  destruct (sumbool_of_bool (scalar_in_bounds U32 z)) as [H|H].
  - eexists. split; [ reflexivity |]. unfold to_Z; reflexivity.
  - rewrite Hb in H. discriminate.
Qed.

(* The backend's `scalar_and` is an unspecified axiom (Primitives.v:260, "TODO").
   Supply its bitwise meaning. *)
Axiom scalar_and_spec :
  forall (x y : u32), to_Z (scalar_and x y) = Z.land (to_Z x) (to_Z y).

(* The size knob the extracted code uses (256, the `& 0xff` block). *)
Lemma to_Z_block_size : to_Z mEMORY_BLOCK_SIZE = 256.
Proof. reflexivity. Qed.

(* --- Scalar op specs (success + to_Z), from the definitions + mk_scalar. ---- *)

Lemma u32_div_ok : forall a b : u32, to_Z b <> 0 ->
  exists s, u32_div a b = Ok s /\ to_Z s = to_Z a / to_Z b.
Proof.
  intros a b Hb. unfold u32_div, scalar_div.
  destruct (to_Z b =? 0) eqn:Ez; [ apply Z.eqb_eq in Ez; contradiction |].
  pose proof (to_Z_u32_bounds a) as [Ha0 Ha1].
  pose proof (to_Z_u32_bounds b) as [Hb0 Hb1].
  assert (Hq : 0 <= to_Z a / to_Z b <= u32_max).
  { split; [ apply Z.div_pos; lia |].
    apply Z.le_trans with (to_Z a); [ apply Z.div_le_upper_bound; nia | lia ]. }
  destruct (mk_scalar_u32_ok _ Hq) as [s [Hmk Hto]]. eauto.
Qed.

Lemma u32_sub_ok : forall a b : u32, to_Z b <= to_Z a ->
  exists s, u32_sub a b = Ok s /\ to_Z s = to_Z a - to_Z b.
Proof.
  intros a b Hba. unfold u32_sub, scalar_sub.
  pose proof (to_Z_u32_bounds a) as [Ha0 Ha1]. pose proof (to_Z_u32_bounds b) as [Hb0 Hb1].
  assert (Hq : 0 <= to_Z a - to_Z b <= u32_max) by lia.
  destruct (mk_scalar_u32_ok _ Hq) as [s [Hmk Hto]]. eauto.
Qed.

Lemma u32_add_ok : forall a b : u32, to_Z a + to_Z b <= u32_max ->
  exists s, u32_add a b = Ok s /\ to_Z s = to_Z a + to_Z b.
Proof.
  intros a b Hab. unfold u32_add, scalar_add.
  pose proof (to_Z_u32_bounds a) as [Ha0 Ha1]. pose proof (to_Z_u32_bounds b) as [Hb0 Hb1].
  assert (Hq : 0 <= to_Z a + to_Z b <= u32_max) by lia.
  destruct (mk_scalar_u32_ok _ Hq) as [s [Hmk Hto]]. eauto.
Qed.

Lemma to_Z_255 : to_Z (255%u32) = 255. Proof. reflexivity. Qed.
Lemma to_Z_0   : to_Z (0%u32) = 0.     Proof. reflexivity. Qed.
Lemma to_Z_1   : to_Z (1%u32) = 1.     Proof. reflexivity. Qed.

(* --- THE BRIDGE: the extracted create_from_range computes the T5 cfr model. --- *)

(** Under no-underflow (base <= limit), the extracted
    `memoryBlockList_create_from_range` succeeds, records base block `base/256`,
    and a size of `(limit-base)/256` rounded up exactly when `limit & 0xff != 0`
    — i.e. the `cfr` model T5 reasons about. So T5's region coverage holds of the
    real shipping function. (The `& 0xff` and the 256 are the hardcoded block the
    T5 finding flags.) *)
Theorem create_from_range_bridge :
  forall base limit : u32,
    to_Z base <= to_Z limit ->
    exists bl,
      memoryBlockList_create_from_range base limit = Ok bl /\
      to_Z (memoryBlock_block_base_address (memoryBlockList_memory_block bl))
        = to_Z base / 256 /\
      to_Z (memoryBlockList_memory_block_list_size bl)
        = (to_Z limit - to_Z base) / 256
          + (if Z.land (to_Z limit) 255 =? 0 then 0 else 1).
Proof.
  intros base limit Hle.
  pose proof to_Z_block_size as Hbs.
  (* div by block size: base/256 *)
  destruct (u32_div_ok base mEMORY_BLOCK_SIZE ltac:(rewrite Hbs; lia))
    as [q [Hq_eq Hq_to]].
  (* limit - base (no underflow) *)
  destruct (u32_sub_ok limit base Hle) as [d [Hd_eq Hd_to]].
  (* d / 256 *)
  destruct (u32_div_ok d mEMORY_BLOCK_SIZE ltac:(rewrite Hbs; lia))
    as [sz [Hsz_eq Hsz_to]].
  unfold memoryBlockList_create_from_range, memoryBlock_new,
         memoryBlock_set_block_base_address.
  cbn [bind].
  rewrite Hq_eq. cbn [bind].
  rewrite Hd_eq. cbn [bind].
  rewrite Hsz_eq. cbn [bind].
  (* the round-up flag: i2 = limit & 255, branch on i2 <> 0 *)
  unfold scalar_neqb.
  rewrite scalar_and_spec, to_Z_255, to_Z_0.
  destruct (Z.land (to_Z limit) 255 =? 0) eqn:Eland.
  - (* aligned: negb true = false -> else branch, no +1 *)
    cbn [negb]. eexists. split; [ reflexivity |]. cbn. split.
    + rewrite Hq_to, Hbs. reflexivity.
    + rewrite Hsz_to, Hd_to, Hbs. lia.
  - (* unaligned: negb false = true -> then branch, +1 *)
    cbn [negb].
    (* sz = d/256 < 2^24, so sz + 1 cannot overflow u32. *)
    assert (Hszbound : to_Z sz + to_Z (1%u32) <= u32_max).
    { rewrite to_Z_1, Hsz_to, Hbs.
      pose proof (to_Z_u32_bounds d) as [Hd0 Hd1].
      assert (to_Z d / 256 < 16777216)
        by (apply Z.div_lt_upper_bound; unfold u32_max in Hd1; lia).
      unfold u32_max; lia. }
    destruct (u32_add_ok sz (1%u32) Hszbound) as [szp [Hszp_eq Hszp_to]].
    rewrite Hszp_eq. cbn [bind].
    eexists. split; [ reflexivity |]. cbn. split.
    + rewrite Hq_to, Hbs. reflexivity.
    + rewrite Hszp_to, to_Z_1, Hsz_to, Hd_to, Hbs. lia.
Qed.
