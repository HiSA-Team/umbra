(** T5 — Memory-region coverage of `create_from_range` (issue #58).

    [umbra_mem_core::MemoryBlockList::create_from_range] turns an address range
    `[base, limit)` into a block list: base block index `base / BS`, size
    `(limit - base) / BS` rounded up when the limit is not block-aligned. We
    prove it COVERS the requested range — every byte of `[base, limit)` falls in
    the produced block span.

    The proof EXPOSES two load-bearing assumptions the code relies on implicitly:
      (1) the round-up test is `limit_addr & 0xff` — it hardcodes a 256-byte
          block, so the model fixes BS = 256 (matching the mask). For any other
          `UMBRA_SLOT_SIZE_BYTES`, the ceiling is wrong and coverage can fail.
      (2) `base` must be block-aligned (`base mod 256 = 0`). The size is ceiled
          on `limit mod 256`, not `(limit - base) mod 256`; with an unaligned
          base the two differ and the region can under-cover.
    Both are stated as hypotheses below — that is the finding. *)

Require Import Coq.NArith.NArith.
Require Import Coq.micromega.Lia.
Local Open Scope N_scope.

(* The block size the `& 0xff` mask hardcodes. *)
Definition BS : N := 256.

(* Faithful model of create_from_range's two outputs. *)
Definition cfr_base_block (base : N) : N := base / BS.
Definition cfr_size (base limit : N) : N :=
  ((limit - base) / BS) + (if (N.land limit 255 =? 0)%N then 0 else 1).

(* The hardware `& 0xff` is exactly `mod 256`. *)
Lemma land_255_is_mod_256 : forall x, N.land x 255 = x mod 256.
Proof.
  intro x. change 255%N with (N.ones 8). rewrite N.land_ones.
  change (2 ^ 8)%N with 256%N. reflexivity.
Qed.

(** T5 — COVERAGE. Under a block-aligned base (and the hardcoded 256-byte block),
    the region `[base_block * BS, (base_block + size) * BS)` covers `[base,
    limit)`: its low edge is exactly `base` and its high edge reaches `limit`. *)
Theorem create_from_range_covers :
  forall base limit,
    base mod BS = 0 ->
    base <= limit ->
    cfr_base_block base * BS = base /\
    limit <= (cfr_base_block base + cfr_size base limit) * BS.
Proof.
  intros base limit Halign Hle. unfold cfr_base_block, cfr_size, BS in *.
  (* div/mod identities as plain facts for lia. *)
  assert (Hdm_base : base = 256 * (base / 256) + base mod 256) by apply N.Div0.div_mod.
  rewrite Halign in Hdm_base.
  (* low edge: base is block-aligned, so (base / 256) * 256 = base. *)
  assert (Hbase : base / 256 * 256 = base) by lia.
  split; [ exact Hbase |].
  set (d := limit - base).
  assert (Hlimit : limit = base + d) by (unfold d; lia).
  (* the round-up flag equals (d mod 256 =? 0), because base ≡ 0 (mod 256). *)
  rewrite land_255_is_mod_256.
  assert (Hmod : limit mod 256 = d mod 256).
  { rewrite Hlimit. rewrite <- N.Div0.add_mod_idemp_l. rewrite Halign.
    rewrite N.add_0_l. reflexivity. }
  rewrite Hmod.
  rewrite N.mul_add_distr_r. rewrite Hbase.
  assert (Hdm_d : d = 256 * (d / 256) + d mod 256) by apply N.Div0.div_mod.
  assert (Hmlt : d mod 256 < 256) by (apply N.mod_lt; lia).
  destruct (d mod 256 =? 0)%N eqn:Hz.
  - apply N.eqb_eq in Hz. rewrite N.mul_add_distr_r. lia.
  - rewrite N.mul_add_distr_r. lia.
Qed.
