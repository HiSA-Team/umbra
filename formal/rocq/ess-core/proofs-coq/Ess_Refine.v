(** LAYER 3 — refinement: the EXTRACTED allocator computes the Layer-1 model
    (issue #58).

    The definitions `enclaveSwapSpace_mark_slots_used` etc. below are copied
    VERBATIM from the Aeneas-generated `Ess_Funs.v` (which does not compile
    standalone — it `Include`s an unfilled externals template; this is the same
    reason `Ess_Guard.v` copies its loop body rather than importing it). Each copy
    is annotated with its source. We then prove these real functions REFINE the
    clean model of `Ess_Model.v`, through the representation relation of
    `Ess_Rep.v`. All bit/array reasoning bottoms out in Layer 2's axioms — Layer 3
    introduces NONE of its own. *)

Require Import Coq.ZArith.ZArith.
Require Import Coq.micromega.Lia.
Require Import Coq.Bool.Bool.
Require Import Coq.Bool.Sumbool.
Require Import Primitives. Import Primitives.
Require Import AeneasLoopShim. Import AeneasLoopShim.
Require Import Ess_Types. Import Ess_Types.
Require Import Ess_Model.
Require Import Ess_Rep.
Local Open Scope Z_scope.
Local Open Scope Primitives_scope.

(* ── Scalar success helpers (usize), in the style of Mem_Bridge.v ─────── *)

Lemma usize_min_eq : scalar_min Usize = 0.    Proof. reflexivity. Qed.
Lemma usize_max_eq : scalar_max Usize = usize_max. Proof. reflexivity. Qed.

Lemma to_Z_usize_bounds : forall x : usize, 0 <= to_Z x <= usize_max.
Proof.
  intro x. destruct x as [z Hb]. unfold to_Z; simpl.
  rewrite usize_min_eq, usize_max_eq in Hb. exact Hb.
Qed.

Lemma usize_nonneg : forall x : usize, 0 <= to_Z x.
Proof. intro x. apply to_Z_usize_bounds. Qed.

(* u32_max is a concrete literal; anything tiny fits. *)
Lemma small_le_u32max : forall z, z <= 257 -> z <= u32_max.
Proof. intros z H. unfold u32_max. lia. Qed.

Lemma u32max_le_usizemax : u32_max <= usize_max.
Proof. exact usize_max_bound. Qed.

(* mk_scalar Usize succeeds for any value within the (conservative) u32 range. *)
Lemma mk_usize_ok : forall z, 0 <= z <= u32_max ->
  exists s : usize, mk_scalar Usize z = Ok s /\ to_Z s = z.
Proof.
  intros z Hz. unfold mk_scalar.
  assert (Hb : scalar_in_bounds Usize z = true).
  { unfold scalar_in_bounds. apply andb_true_intro. split.
    - unfold scalar_ge_min. apply orb_true_intro. left.
      apply Z.leb_le. unfold scalar_min_cons, u32_min. lia.
    - unfold scalar_le_max. apply orb_true_intro. left.
      apply Z.leb_le. unfold scalar_max_cons. lia. }
  destruct (sumbool_of_bool (scalar_in_bounds Usize z)) as [H|H].
  - eexists. split; [ reflexivity |]. unfold to_Z; reflexivity.
  - rewrite Hb in H. discriminate.
Qed.

Lemma usize_add_ok : forall a b : usize, to_Z a + to_Z b <= u32_max ->
  exists s, usize_add a b = Ok s /\ to_Z s = to_Z a + to_Z b.
Proof.
  intros a b Hab. unfold usize_add, scalar_add.
  pose proof (usize_nonneg a). pose proof (usize_nonneg b).
  apply mk_usize_ok. lia.
Qed.

Lemma usize_div_ok : forall a b : usize, to_Z b <> 0 -> to_Z a <= u32_max ->
  exists s, usize_div a b = Ok s /\ to_Z s = to_Z a / to_Z b.
Proof.
  intros a b Hb Ha. unfold usize_div, scalar_div.
  destruct (to_Z b =? 0) eqn:E; [ apply Z.eqb_eq in E; contradiction |].
  pose proof (usize_nonneg a). pose proof (usize_nonneg b).
  apply mk_usize_ok. split.
  - apply Z.div_pos; lia.
  - apply Z.le_trans with (to_Z a); [ apply Z.div_le_upper_bound; nia | lia ].
Qed.

Lemma usize_rem_ok : forall a b : usize, 0 < to_Z b -> to_Z b <= u32_max ->
  exists s, usize_rem a b = Ok s /\ to_Z s = Z.rem (to_Z a) (to_Z b).
Proof.
  intros a b Hb Hbu. unfold usize_rem, scalar_rem.
  pose proof (usize_nonneg a) as Ha. pose proof (usize_nonneg b).
  assert (Hr : 0 <= Z.rem (to_Z a) (to_Z b) < to_Z b)
    by (apply Z.rem_bound_pos; lia).
  apply mk_usize_ok. lia.
Qed.

(* Constants the extracted body mentions. *)
Lemma to_Z_usize32 : to_Z (32%usize) = 32. Proof. reflexivity. Qed.
Lemma to_Z_usize8  : to_Z (8%usize)  = 8.  Proof. reflexivity. Qed.
Lemma to_Z_usize1  : to_Z (1%usize)  = 1.  Proof. reflexivity. Qed.

(* For nonneg dividend, Z.rem agrees with Z.modulo. *)
Lemma rem_eq_mod_nonneg : forall a b, 0 <= a -> 0 < b -> Z.rem a b = a mod b.
Proof.
  intros a b Ha Hb. rewrite Z.rem_mod_nonneg by lia. reflexivity.
Qed.

(* ── VERBATIM extraction (from Ess_Funs.v, `mark_slots_used`) ─────────── *)

(** [umbra_ess_core::{EnclaveSwapSpace}::mark_slots_used]: loop body 0 — copied
    verbatim from the Aeneas-generated Ess_Funs.v. *)
Definition enclaveSwapSpace_mark_slots_used_loop_body
  (start : usize) (count : usize) (self : EnclaveSwapSpace_t) (k : usize) :
  result (control_flow (EnclaveSwapSpace_t * usize) EnclaveSwapSpace_t)
  :=
  if k s< count
  then (
    idx <- usize_add start k;
    i <- usize_rem idx 32%usize;
    i1 <- u32_shl 1%u32 i;
    i2 <- usize_div idx 32%usize;
    i3 <- array_index_usize self.(enclaveSwapSpace_bitmap) i2;
    let i4 := u32_or i3 i1 in
    a <- array_update_usize self.(enclaveSwapSpace_bitmap) i2 i4;
    k1 <- usize_add k 1%usize;
    Ok (Cont
      ({|
         enclaveSwapSpace_base_address := self.(enclaveSwapSpace_base_address);
         enclaveSwapSpace_size := self.(enclaveSwapSpace_size);
         enclaveSwapSpace_loaded_enclaves :=
           self.(enclaveSwapSpace_loaded_enclaves);
         enclaveSwapSpace_bitmap := a
       |}, k1)))
  else Ok (Done self).

Definition enclaveSwapSpace_mark_slots_used_loop
  (self : EnclaveSwapSpace_t) (start : usize) (count : usize) (k : usize) :
  result EnclaveSwapSpace_t
  :=
  loop
    (fun '((self1, k1) : (EnclaveSwapSpace_t * usize)) =>
      enclaveSwapSpace_mark_slots_used_loop_body start count self1 k1)
    (self, k).

Definition enclaveSwapSpace_mark_slots_used
  (self : EnclaveSwapSpace_t) (start : usize) (count : usize) :
  result EnclaveSwapSpace_t
  :=
  enclaveSwapSpace_mark_slots_used_loop self start count 0%usize.

(* ── represents respects extensional equality / the empty mark ───────── *)

Lemma represents_ext : forall bm (s s' : Slots),
  (forall z, s z = s' z) -> represents bm s -> represents bm s'.
Proof.
  intros bm s s' Heq Hrep widx bidx w Hw Hb Hidx.
  rewrite <- Heq. apply Hrep; assumption.
Qed.

Lemma mark_zero : forall (s : Slots) start z, mark s start 0 z = s z.
Proof.
  intros s start z. unfold mark.
  destruct (in_run z start 0) eqn:E; [| reflexivity].
  apply in_run_bounds in E. lia.
Qed.

(* ── The body step: one iteration sets exactly slot (start+k) ─────────── *)

(** One loop iteration of `mark_slots_used` (when k < count): it sets the bit for
    slot [start+k] and leaves every other bit untouched, so the bitmap advances
    from representing `mark s0 start k` to representing `mark s0 start (k+1)`.
    This is where the extracted bitmap arithmetic (word = idx/32, bit = idx%32,
    OR in 1<<bit, store) is shown to implement the model's `mark`, using ONLY the
    Layer-2 axioms. *)
Lemma mark_body_step :
  forall start count self k s0,
    0 <= to_Z k ->
    to_Z k < to_Z count ->
    to_Z start + to_Z count <= 256 ->
    represents self.(enclaveSwapSpace_bitmap) (mark s0 (to_Z start) (to_Z k)) ->
    exists (self' : EnclaveSwapSpace_t) (k1 : usize),
      enclaveSwapSpace_mark_slots_used_loop_body start count self k
        = Ok (Cont (self', k1)) /\
      to_Z k1 = to_Z k + 1 /\
      represents self'.(enclaveSwapSpace_bitmap) (mark s0 (to_Z start) (to_Z k + 1)).
Proof.
  intros start count self k s0 Hk0 Hkc Hsc Hrep.
  pose proof (usize_nonneg start) as Hs0.
  set (sidx := to_Z start + to_Z k).
  assert (Hsidx : 0 <= sidx <= 255) by (unfold sidx; lia).
  (* idx = start + k *)
  assert (Hidxmax : to_Z start + to_Z k <= u32_max)
    by (apply small_le_u32max; unfold sidx in Hsidx; lia).
  destruct (usize_add_ok start k Hidxmax) as [idx [Hidx_eq Hidx_v]].
  (* bit = idx % 32 *)
  destruct (usize_rem_ok idx (32%usize) ltac:(rewrite to_Z_usize32; lia)
              ltac:(rewrite to_Z_usize32; apply small_le_u32max; lia))
    as [bi [Hbi_eq Hbi_v]].
  rewrite to_Z_usize32 in Hbi_v.
  assert (Hbit_v : to_Z bi = sidx mod 32).
  { rewrite Hbi_v, Hidx_v. apply rem_eq_mod_nonneg; [ lia | lia ]. }
  pose proof (Z.mod_pos_bound sidx 32 ltac:(lia)) as Hmb.
  (* mask = 1 << bit = 2^bit *)
  destruct (u32_shl_one_pow2 bi ltac:(rewrite Hbit_v; lia))
    as [mask [Hmask_eq Hmask_v]].
  (* word = idx / 32 *)
  destruct (usize_div_ok idx (32%usize) ltac:(rewrite to_Z_usize32; lia)
              ltac:(rewrite Hidx_v; apply small_le_u32max; lia))
    as [wi [Hwi_eq Hwi_v]].
  rewrite to_Z_usize32 in Hwi_v. rewrite Hidx_v in Hwi_v.
  fold sidx in Hwi_v.
  pose proof (Z.div_mod sidx 32 ltac:(lia)) as Hdm.
  assert (Hword_b : 0 <= to_Z wi < 8).
  { rewrite Hwi_v. split; [ apply Z.div_pos; lia |].
    apply Z.div_lt_upper_bound; lia. }
  (* old word at wi *)
  destruct (array_index_usize_ok self.(enclaveSwapSpace_bitmap) wi
              ltac:(rewrite to_Z_usize8; exact Hword_b)) as [w0 Hw0].
  (* store the OR'd word *)
  destruct (array_update_usize_ok self.(enclaveSwapSpace_bitmap) wi
              (u32_or w0 mask) ltac:(rewrite to_Z_usize8; exact Hword_b))
    as [a Ha].
  (* k1 = k + 1 *)
  destruct (usize_add_ok k (1%usize) ltac:(rewrite to_Z_usize1; apply small_le_u32max; lia))
    as [k1 [Hk1_eq Hk1_v]].
  rewrite to_Z_usize1 in Hk1_v.
  (* assemble *)
  exists {|
      enclaveSwapSpace_base_address := self.(enclaveSwapSpace_base_address);
      enclaveSwapSpace_size := self.(enclaveSwapSpace_size);
      enclaveSwapSpace_loaded_enclaves := self.(enclaveSwapSpace_loaded_enclaves);
      enclaveSwapSpace_bitmap := a
    |}, k1.
  split; [| split].
  - (* the body evaluates to Cont with bitmap a *)
    unfold enclaveSwapSpace_mark_slots_used_loop_body.
    assert (Hlt : (k s< count) = true) by (unfold scalar_ltb; apply Z.ltb_lt; lia).
    rewrite Hlt.
    rewrite Hidx_eq. cbn [bind].
    rewrite Hbi_eq. cbn [bind].
    rewrite Hmask_eq. cbn [bind].
    rewrite Hwi_eq. cbn [bind].
    rewrite Hw0. cbn [bind].
    rewrite Ha. cbn [bind].
    rewrite Hk1_eq. cbn [bind].
    reflexivity.
  - exact Hk1_v.
  - (* the new bitmap represents mark s0 start (k+1) *)
    simpl (enclaveSwapSpace_bitmap _).
    intros widx bidx w Hwb Hbb Hidxa.
    set (slot2 := to_Z widx * 32 + to_Z bidx).
    rewrite (mark_succ s0 (to_Z start) (to_Z k) slot2 Hk0).
    fold sidx. replace (to_Z start + to_Z k) with sidx by reflexivity.
    destruct (Z.eq_dec (to_Z widx) (to_Z wi)) as [Hww | Hww].
    + (* same word as the one we wrote *)
      assert (Hwa : array_index_usize a widx = Ok (u32_or w0 mask)).
      { assert (Hj : to_Z widx = to_Z wi) by lia.
        exact (@array_update_index_eq u32 (8%usize) (self.(enclaveSwapSpace_bitmap))
                 a wi widx (u32_or w0 mask) Ha Hj). }
      rewrite Hwa in Hidxa. injection Hidxa as <-.
      rewrite u32_or_to_Z, Hmask_v, Hbit_v.
      destruct (slot2 =? sidx) eqn:Es.
      * (* this is exactly slot start+k: bit gets set true *)
        apply Z.eqb_eq in Es.
        assert (Hbe : to_Z bidx = sidx mod 32).
        { unfold slot2 in Es. rewrite Hwi_v in Hww. lia. }
        rewrite Hbe. symmetry. apply testbit_lor_pow2_same. lia.
      * (* same word, different bit: unchanged, matches old represents *)
        apply Z.eqb_neq in Es.
        assert (Hbne : to_Z bidx <> sidx mod 32).
        { intro Hc. apply Es. unfold slot2. rewrite Hwi_v in Hww. lia. }
        rewrite testbit_lor_pow2_other by lia.
        assert (Hold : array_index_usize self.(enclaveSwapSpace_bitmap) widx = Ok w0).
        { rewrite (array_index_usize_ext _ widx wi Hww). exact Hw0. }
        specialize (Hrep widx bidx w0 Hwb Hbb Hold).
        unfold slot2. exact Hrep.
    + (* different word: array unchanged at widx *)
      assert (Hneq : array_index_usize a widx
                       = array_index_usize self.(enclaveSwapSpace_bitmap) widx).
      { assert (Hj : to_Z wi <> to_Z widx) by lia.
        exact (@array_update_index_neq u32 (8%usize) (self.(enclaveSwapSpace_bitmap))
                 a wi widx (u32_or w0 mask) Ha Hj). }
      rewrite Hneq in Hidxa.
      assert (Hsl : (slot2 =? sidx) = false).
      { apply Z.eqb_neq. unfold slot2. rewrite Hwi_v in Hww. lia. }
      rewrite Hsl.
      specialize (Hrep widx bidx w Hwb Hbb Hidxa).
      unfold slot2. exact Hrep.
Qed.

(* ── Generic one-step lemmas for the fuel loop ───────────────────────── *)

Lemma loop_fuel_cont : forall {St B} fuel (f : St -> result (control_flow St B)) s s',
  f s = Ok (Cont s') ->
  loop_fuel (Datatypes.S fuel) f s = loop_fuel fuel f s'.
Proof. intros St B fuel f s s' H. simpl. rewrite H. reflexivity. Qed.

Lemma loop_fuel_done : forall {St B} fuel (f : St -> result (control_flow St B)) s b,
  f s = Ok (Done b) ->
  loop_fuel (Datatypes.S fuel) f s = Ok b.
Proof. intros St B fuel f s b H. simpl. rewrite H. reflexivity. Qed.

Lemma to_Z_usize0 : to_Z (0%usize) = 0. Proof. reflexivity. Qed.

(* ── Loop correctness: the body, iterated, computes the model `mark` ──── *)

Lemma mark_loop_fuel_ok :
  forall (m fuel : nat) (start count k : usize) (self : EnclaveSwapSpace_t) (s0 : Slots),
    (m < fuel)%nat ->
    to_Z count = to_Z k + Z.of_nat m ->
    0 <= to_Z k ->
    to_Z start + to_Z count <= 256 ->
    represents self.(enclaveSwapSpace_bitmap) (mark s0 (to_Z start) (to_Z k)) ->
    exists self',
      loop_fuel fuel
        (fun '((self1, k1) : (EnclaveSwapSpace_t * usize)) =>
           enclaveSwapSpace_mark_slots_used_loop_body start count self1 k1)
        (self, k) = Ok self' /\
      represents self'.(enclaveSwapSpace_bitmap) (mark s0 (to_Z start) (to_Z count)).
Proof.
  induction m as [| m IH]; intros fuel start count k self s0 Hmf Hcount Hk0 Hsc Hrep.
  - (* no iterations remain: count = k *)
    destruct fuel as [| fuel']; [ inversion Hmf |].
    simpl (Z.of_nat 0) in Hcount.
    assert (Hcount' : to_Z count = to_Z k) by lia.
    exists self. split.
    + apply loop_fuel_done.
      unfold enclaveSwapSpace_mark_slots_used_loop_body.
      assert (Hge : (k s< count) = false)
        by (unfold scalar_ltb; apply Z.ltb_ge; lia).
      rewrite Hge. reflexivity.
    + rewrite Hcount'. exact Hrep.
  - (* one iteration, then recurse *)
    destruct fuel as [| fuel']; [ inversion Hmf |].
    assert (Hkc : to_Z k < to_Z count)
      by (rewrite Hcount, Nat2Z.inj_succ; lia).
    destruct (mark_body_step start count self k s0 Hk0 Hkc Hsc Hrep)
      as [self1 [k1 [Hbody [Hk1v Hrep1]]]].
    assert (Hcount1 : to_Z count = to_Z k1 + Z.of_nat m)
      by (rewrite Hcount, Hk1v, Nat2Z.inj_succ; lia).
    assert (Hk10 : 0 <= to_Z k1) by lia.
    rewrite <- Hk1v in Hrep1.
    destruct (IH fuel' start count k1 self1 s0 ltac:(lia) Hcount1 Hk10 Hsc Hrep1)
      as [self' [Hloop' Hrep']].
    exists self'. split; [| exact Hrep'].
    erewrite loop_fuel_cont; [ exact Hloop' | exact Hbody ].
Qed.

(* ── THE REFINEMENT THEOREM for mark_slots_used ──────────────────────── *)

(** The EXTRACTED `mark_slots_used` computes the model's `mark`: starting from a
    bitmap that represents [s], it ends representing [mark s start count] — every
    slot in [start, start+count) set, nothing else changed. Combined with
    Layer 1's `alloc_isolation`, this transfers the spatial-isolation guarantee to
    the real shipping function. *)
Theorem mark_slots_used_refines :
  forall (self self' : EnclaveSwapSpace_t) (start count : usize) (s : Slots),
    represents self.(enclaveSwapSpace_bitmap) s ->
    to_Z start + to_Z count <= 256 ->
    enclaveSwapSpace_mark_slots_used self start count = Ok self' ->
    represents self'.(enclaveSwapSpace_bitmap) (mark s (to_Z start) (to_Z count)).
Proof.
  intros self self' start count s Hrep Hsc Hexec.
  pose proof (usize_nonneg count) as Hc0.
  pose proof (usize_nonneg start) as Hs0.
  (* at k = 0 the bitmap represents `mark s start 0`, which is just `s` *)
  assert (Hrep0 : represents self.(enclaveSwapSpace_bitmap)
                    (mark s (to_Z start) (to_Z (0%usize)))).
  { apply (represents_ext _ s).
    - intro z. rewrite to_Z_usize0. symmetry. apply mark_zero.
    - exact Hrep. }
  (* fuel = 1000000 (the `loop` constant) is enough: count <= 256 *)
  assert (Hm : (Z.to_nat (to_Z count) < 1000000)%nat).
  { change 1000000%nat with (Z.to_nat 1000000).
    apply Z2Nat.inj_lt; lia. }
  assert (Hcm : to_Z count = to_Z (0%usize) + Z.of_nat (Z.to_nat (to_Z count))).
  { rewrite to_Z_usize0, Z2Nat.id by exact Hc0. ring. }
  destruct (mark_loop_fuel_ok (Z.to_nat (to_Z count)) 1000000 start count
              (0%usize) self s Hm Hcm ltac:(rewrite to_Z_usize0; lia) Hsc Hrep0)
    as [self'' [Hloop Hrep']].
  (* the extracted call IS this fuel loop *)
  unfold enclaveSwapSpace_mark_slots_used, enclaveSwapSpace_mark_slots_used_loop,
         loop in Hexec.
  rewrite Hexec in Hloop. injection Hloop as <-. exact Hrep'.
Qed.

(* ── More scalar helpers for find_free_run / allocate ────────────────── *)

Lemma u32_min_eq : scalar_min U32 = 0.        Proof. reflexivity. Qed.
Lemma u32_max_eq : scalar_max U32 = u32_max.  Proof. reflexivity. Qed.

Lemma to_Z_u32_bounds : forall x : u32, 0 <= to_Z x <= u32_max.
Proof.
  intro x. destruct x as [z Hb]. unfold to_Z; simpl.
  rewrite u32_min_eq, u32_max_eq in Hb. exact Hb.
Qed.

Lemma usize_sub_ok : forall a b : usize,
  to_Z b <= to_Z a -> to_Z a <= u32_max ->
  exists s, usize_sub a b = Ok s /\ to_Z s = to_Z a - to_Z b.
Proof.
  intros a b Hba Ha. unfold usize_sub, scalar_sub.
  pose proof (usize_nonneg a). pose proof (usize_nonneg b).
  apply mk_usize_ok. lia.
Qed.

Lemma cast_u32_usize_ok : forall x : u32,
  exists s : usize, scalar_cast U32 Usize x = Ok s /\ to_Z s = to_Z x.
Proof.
  intro x. unfold scalar_cast. pose proof (to_Z_u32_bounds x).
  apply mk_usize_ok. lia.
Qed.

(* ── VERBATIM extraction (from Ess_Funs.v, `find_free_run`) ───────────── *)

Definition enclaveSwapSpace_find_free_run_loop_body
  (self : EnclaveSwapSpace_t) (slots_needed : u32) (total_slots : usize)
  (found_count : u32) (i : usize) :
  result (control_flow (u32 * usize) (option usize))
  :=
  if i s< total_slots
  then (
    word_idx <- usize_div i 32%usize;
    bit_idx <- usize_rem i 32%usize;
    i1 <- array_index_usize self.(enclaveSwapSpace_bitmap) word_idx;
    i2 <- u32_shl 1%u32 bit_idx;
    let i3 := u32_and i1 i2 in
    found_count1 <-
      if i3 s= 0%u32 then u32_add found_count 1%u32 else Ok 0%u32;
    if found_count1 s= slots_needed
    then (
      i4 <- usize_add i 1%usize;
      i5 <- scalar_cast U32 Usize slots_needed;
      i6 <- usize_sub i4 i5;
      Ok (Done (Some i6)))
    else (i4 <- usize_add i 1%usize; Ok (Cont (found_count1, i4))))
  else Ok (Done None).

Definition enclaveSwapSpace_find_free_run_loop
  (self : EnclaveSwapSpace_t) (slots_needed : u32) (total_slots : usize)
  (found_count : u32) (i : usize) : result (option usize)
  :=
  loop
    (fun '((found_count1, i1) : (u32 * usize)) =>
      enclaveSwapSpace_find_free_run_loop_body self slots_needed total_slots
        found_count1 i1)
    (found_count, i).

(* ── Soundness of the first-fit search loop ──────────────────────────── *)

(** Loop invariant: `found_count` counts a run of FREE slots ending just before
    `i` (slots [i - found_count, i) are all free in the model). If the loop ever
    returns `Some start`, that start begins a run of `slots_needed` free slots —
    so the allocator only ever hands out runs that were genuinely free. The
    security-critical "no double-allocation" half of `allocate`. *)
Lemma find_free_run_loop_sound :
  forall (m fuel : nat) self s slots_needed total_slots found_count i start,
    (m < fuel)%nat ->
    to_Z total_slots = to_Z i + Z.of_nat m ->
    to_Z total_slots <= 256 ->
    0 <= to_Z i ->
    1 <= to_Z slots_needed ->
    0 <= to_Z found_count <= to_Z i ->
    (forall j, to_Z i - to_Z found_count <= j < to_Z i -> s j = false) ->
    represents self.(enclaveSwapSpace_bitmap) s ->
    loop_fuel fuel
      (fun '((fc1, i1) : (u32 * usize)) =>
        enclaveSwapSpace_find_free_run_loop_body self slots_needed total_slots fc1 i1)
      (found_count, i) = Ok (Some start) ->
    free_run s (to_Z start) (to_Z slots_needed) /\
    to_Z start + to_Z slots_needed <= to_Z total_slots.
Proof.
  induction m as [| m IH];
    intros fuel self s slots_needed total_slots found_count i start
           Hmf Htot Htot256 Hi0 Hsn Hfc Hinv Hrep Hexec.
  - (* no slots remain: i = total_slots, body returns None, contradiction *)
    destruct fuel as [| fuel']; [ inversion Hmf |].
    simpl (Z.of_nat 0) in Htot.
    assert (Hge : (i s< total_slots) = false)
      by (unfold scalar_ltb; apply Z.ltb_ge; lia).
    assert (Hbody : enclaveSwapSpace_find_free_run_loop_body self slots_needed
                      total_slots found_count i = Ok (Done None))
      by (unfold enclaveSwapSpace_find_free_run_loop_body; rewrite Hge; reflexivity).
    assert (Hl : loop_fuel (Datatypes.S fuel')
                   (fun '((fc1, i1) : (u32 * usize)) =>
                     enclaveSwapSpace_find_free_run_loop_body self slots_needed
                       total_slots fc1 i1) (found_count, i) = Ok None)
      by (apply loop_fuel_done; exact Hbody).
    rewrite Hl in Hexec. discriminate.
  - destruct fuel as [| fuel']; [ inversion Hmf |].
    assert (Hilt : to_Z i < to_Z total_slots) by (rewrite Htot, Nat2Z.inj_succ; lia).
    assert (Hi256 : 0 <= to_Z i < 256) by lia.
    (* decompose i into word/bit and read the bitmap word *)
    assert (H32max : to_Z (32%usize) <= u32_max) by (rewrite to_Z_usize32; apply small_le_u32max; lia).
    destruct (usize_div_ok i (32%usize) ltac:(rewrite to_Z_usize32; lia)
                ltac:(apply small_le_u32max; lia)) as [wi [Hwi_eq Hwi_v]].
    rewrite to_Z_usize32 in Hwi_v.
    destruct (usize_rem_ok i (32%usize) ltac:(rewrite to_Z_usize32; lia) H32max)
      as [bi [Hbi_eq Hbi_v]].
    rewrite to_Z_usize32 in Hbi_v.
    assert (Hbit_v : to_Z bi = to_Z i mod 32) by (rewrite Hbi_v; apply rem_eq_mod_nonneg; lia).
    pose proof (Z.mod_pos_bound (to_Z i) 32 ltac:(lia)) as Hmb.
    pose proof (Z.div_mod (to_Z i) 32 ltac:(lia)) as Hdm.
    assert (Hwib : 0 <= to_Z wi < 8)
      by (rewrite Hwi_v; split; [ apply Z.div_pos; lia | apply Z.div_lt_upper_bound; lia ]).
    destruct (array_index_usize_ok self.(enclaveSwapSpace_bitmap) wi
                ltac:(rewrite to_Z_usize8; exact Hwib)) as [w Hw].
    destruct (u32_shl_one_pow2 bi ltac:(rewrite Hbit_v; lia)) as [mask [Hmask_eq Hmask_v]].
    (* slot i is free iff the masked word is zero *)
    assert (Hsi : s (to_Z i) = Z.testbit (to_Z w) (to_Z bi)).
    { specialize (Hrep wi bi w Hwib ltac:(lia) Hw).
      replace (to_Z wi * 32 + to_Z bi) with (to_Z i) in Hrep by (rewrite Hwi_v, Hbit_v; lia).
      exact Hrep. }
    assert (Hmasked0 : (u32_and w mask s= 0%u32) = true <-> s (to_Z i) = false).
    { unfold scalar_eqb. change (to_Z (0%u32)) with 0.
      rewrite u32_and_to_Z, Hmask_v, Hsi.
      apply land_pow2_zero_iff. lia. }
    (* bound on the running counter so fc+1 cannot overflow *)
    assert (Hfcmax : to_Z found_count + 1 <= u32_max) by (apply small_le_u32max; lia).
    (* expose the body inside the fuel loop, in Hexec *)
    cbn [loop_fuel] in Hexec.
    unfold enclaveSwapSpace_find_free_run_loop_body in Hexec.
    assert (Hlt : (i s< total_slots) = true) by (unfold scalar_ltb; apply Z.ltb_lt; lia).
    rewrite Hlt in Hexec. cbn [bind] in Hexec.
    rewrite Hwi_eq in Hexec. cbn [bind] in Hexec.
    rewrite Hbi_eq in Hexec. cbn [bind] in Hexec.
    rewrite Hw in Hexec. cbn [bind] in Hexec.
    rewrite Hmask_eq in Hexec. cbn [bind] in Hexec.
    (* case: is slot i free? *)
    destruct (u32_and w mask s= 0%u32) eqn:Efree.
    + (* slot i free: fc1 = fc + 1.  (destruct rewrote the masked-test to `true`
         inside Hmasked0, so proj1 Hmasked0 now reads `true = true -> s i = false`.) *)
      assert (Hfree : s (to_Z i) = false) by (apply (proj1 Hmasked0); reflexivity).
      assert (Hfc1 : exists fc1, u32_add found_count 1%u32 = Ok fc1 /\ to_Z fc1 = to_Z found_count + 1).
      { unfold u32_add, scalar_add. pose proof (to_Z_u32_bounds found_count) as Hfcb.
        change (to_Z (1%u32)) with 1.
        unfold mk_scalar.
        assert (Hb : scalar_in_bounds U32 (to_Z found_count + 1) = true).
        { unfold scalar_in_bounds. apply andb_true_intro. split.
          - unfold scalar_ge_min. apply orb_true_intro. right.
            apply Z.leb_le. rewrite u32_min_eq. lia.
          - unfold scalar_le_max. apply orb_true_intro. right.
            apply Z.leb_le. rewrite u32_max_eq. lia. }
        destruct (sumbool_of_bool (scalar_in_bounds U32 (to_Z found_count + 1))) as [H|H];
          [ eexists; split; [ reflexivity | reflexivity ] | rewrite Hb in H; discriminate ]. }
      destruct Hfc1 as [fc1 [Hfc1_eq Hfc1_v]].
      rewrite Hfc1_eq in Hexec. cbn [bind] in Hexec.
      (* branch: fc1 = slots_needed ? *)
      destruct (fc1 s= slots_needed) eqn:Edone.
      * (* run complete: returns Some (i+1 - slots_needed) *)
        unfold scalar_eqb in Edone. apply Z.eqb_eq in Edone.
        rewrite Hfc1_v in Edone.   (* fc + 1 = slots_needed *)
        destruct (usize_add_ok i (1%usize) ltac:(rewrite to_Z_usize1; apply small_le_u32max; lia))
          as [ip1 [Hip1_eq Hip1_v]]. rewrite to_Z_usize1 in Hip1_v.
        destruct (cast_u32_usize_ok slots_needed) as [snc [Hsnc_eq Hsnc_v]].
        destruct (usize_sub_ok ip1 snc) as [st [Hst_eq Hst_v]];
          [ rewrite Hip1_v, Hsnc_v; lia | rewrite Hip1_v; apply small_le_u32max; lia |].
        rewrite Hip1_eq in Hexec. cbn [bind] in Hexec.
        rewrite Hsnc_eq in Hexec. cbn [bind] in Hexec.
        rewrite Hst_eq in Hexec. cbn [bind] in Hexec.
        (* loop_fuel of Done (Some st) = Ok (Some st) *)
        cbn [loop_fuel] in Hexec. injection Hexec as <-.
        rewrite Hst_v, Hip1_v, Hsnc_v.
        split.
        ++ (* free_run from the invariant + slot i free *)
           intros kk Hkk.
           set (j := to_Z i + 1 - to_Z slots_needed + kk).
           destruct (Z_lt_le_dec j (to_Z i)) as [Hjlt | Hjge].
           --- apply Hinv. unfold j. lia.
           --- assert (j = to_Z i) by (unfold j in *; lia). rewrite H. exact Hfree.
        ++ (* the run fits: start + slots_needed = i + 1 <= total_slots *)
           lia.
      * (* run not complete yet: continue with fc1, i+1 *)
        unfold scalar_eqb in Edone. apply Z.eqb_neq in Edone. rewrite Hfc1_v in Edone.
        destruct (usize_add_ok i (1%usize) ltac:(rewrite to_Z_usize1; apply small_le_u32max; lia))
          as [ip1 [Hip1_eq Hip1_v]]. rewrite to_Z_usize1 in Hip1_v.
        rewrite Hip1_eq in Hexec. cbn [bind] in Hexec.
        (* loop_fuel of Cont (fc1, ip1) recurses *)
        cbn [loop_fuel] in Hexec.
        eapply (IH fuel' self s slots_needed total_slots fc1 ip1 start);
          [ lia | rewrite Htot, Nat2Z.inj_succ, Hip1_v; lia | exact Htot256
          | lia | exact Hsn | rewrite Hfc1_v, Hip1_v; lia | | exact Hrep | exact Hexec ].
        (* invariant preserved: the free run extended by slot i *)
        intros j Hj. rewrite Hip1_v, Hfc1_v in Hj.
        destruct (Z_lt_le_dec j (to_Z i)) as [Hjlt | Hjge].
        -- apply Hinv. lia.
        -- assert (j = to_Z i) by lia. rewrite H. exact Hfree.
    + (* slot i used: fc1 = 0; cannot complete (slots_needed >= 1), continue.
         The model value of slot i is irrelevant here — the run resets to 0. *)
      cbn [bind] in Hexec. (* found_count1 <- Ok 0 *)
      destruct (0%u32 s= slots_needed) eqn:Edone.
      * unfold scalar_eqb in Edone. apply Z.eqb_eq in Edone.
        change (to_Z (0%u32)) with 0 in Edone. lia.
      * destruct (usize_add_ok i (1%usize) ltac:(rewrite to_Z_usize1; apply small_le_u32max; lia))
          as [ip1 [Hip1_eq Hip1_v]]. rewrite to_Z_usize1 in Hip1_v.
        rewrite Hip1_eq in Hexec. cbn [bind] in Hexec.
        cbn [loop_fuel] in Hexec.
        eapply (IH fuel' self s slots_needed total_slots 0%u32 ip1 start);
          [ lia | rewrite Htot, Nat2Z.inj_succ, Hip1_v; lia | exact Htot256
          | lia | exact Hsn | change (to_Z (0%u32)) with 0; lia
          | | exact Hrep | exact Hexec ].
        (* invariant trivial: run length reset to 0 *)
        intros j Hj. change (to_Z (0%u32)) with 0 in Hj. lia.
Qed.

(* The ESS sizing constants the extracted find_free_run reads (from Ess_Funs.v). *)
Definition eSS_SIZE  : u32 := 65536%u32.
Definition sLOT_SIZE : u32 := 256%u32.

(** [umbra_ess_core::{EnclaveSwapSpace}::find_free_run] — verbatim wrapper. *)
Definition enclaveSwapSpace_find_free_run
  (self : EnclaveSwapSpace_t) (slots_needed : u32) : result (option usize) :=
  i <- u32_div eSS_SIZE sLOT_SIZE;
  total_slots <- scalar_cast U32 Usize i;
  enclaveSwapSpace_find_free_run_loop self slots_needed total_slots 0%u32 0%usize.

(** TOP-LEVEL SOUNDNESS: if the extracted first-fit search returns `Some start`,
    then [start, start+slots_needed) is a run of slots that were FREE in the model
    — the allocator never returns a run that overlaps a used slot. *)
Theorem find_free_run_sound :
  forall self s slots_needed start,
    represents self.(enclaveSwapSpace_bitmap) s ->
    1 <= to_Z slots_needed ->
    enclaveSwapSpace_find_free_run self slots_needed = Ok (Some start) ->
    free_run s (to_Z start) (to_Z slots_needed) /\
    to_Z start + to_Z slots_needed <= 256.
Proof.
  intros self s slots_needed start Hrep Hsn Hexec.
  unfold enclaveSwapSpace_find_free_run in Hexec.
  change (256 : Z) with (to_Z (256%usize)).
  assert (Hdiv : u32_div eSS_SIZE sLOT_SIZE = Ok (256%u32)) by reflexivity.
  rewrite Hdiv in Hexec. cbn [bind] in Hexec.
  assert (Hcast : scalar_cast U32 Usize (256%u32) = Ok (256%usize)) by reflexivity.
  rewrite Hcast in Hexec. cbn [bind] in Hexec.
  unfold enclaveSwapSpace_find_free_run_loop, loop in Hexec.
  apply (find_free_run_loop_sound (Z.to_nat 256) 1000000 self s slots_needed
           (256%usize) 0%u32 0%usize start).
  - change 1000000%nat with (Z.to_nat 1000000). apply Z2Nat.inj_lt; lia.
  - change (to_Z (256%usize)) with 256. change (to_Z (0%usize)) with 0.
    rewrite Z2Nat.id by lia. ring.
  - change (to_Z (256%usize)) with 256. lia.
  - change (to_Z (0%usize)) with 0. lia.
  - exact Hsn.
  - change (to_Z (0%u32)) with 0. change (to_Z (0%usize)) with 0. lia.
  - intros j Hj. change (to_Z (0%usize)) with 0 in Hj.
    change (to_Z (0%u32)) with 0 in Hj. lia.
  - exact Hrep.
  - exact Hexec.
Qed.

(* ── allocate: composing the search and the mark ─────────────────────── *)

Definition eFBC_BASE : u32 := 131072%u32.

(** The SUCCESS-PATH core of the extracted `allocate`, copied verbatim from
    Ess_Funs.v lines 377–395 (the body reached once the `size.checked_add(..)?`
    overflow guard has produced `slots_needed`). The overflow guard is elided
    here: it only decides WHETHER allocate errors, never WHICH run it picks, so it
    is orthogonal to the isolation property proved below. *)
Definition enclaveSwapSpace_allocate_core
  (self : EnclaveSwapSpace_t) (slots_needed : u32) :
  result ((core_result_Result_t u32 umbra_error_UmbraError_t) * EnclaveSwapSpace_t)
  :=
  if slots_needed s= 0%u32
  then Ok (Core_result_Result_Err Umbra_error_UmbraError_LengthMismatch, self)
  else (
    o1 <- enclaveSwapSpace_find_free_run self slots_needed;
    match o1 with
    | None =>
      Ok (Core_result_Result_Err Umbra_error_UmbraError_EssRegionExhausted, self)
    | Some found_start =>
      i1 <- scalar_cast U32 Usize slots_needed;
      self1 <- enclaveSwapSpace_mark_slots_used self found_start i1;
      i2 <- scalar_cast Usize U32 found_start;
      i3 <- u32_mul i2 sLOT_SIZE;
      i4 <- u32_add eFBC_BASE i3;
      Ok (Core_result_Result_Ok i4, self1)
    end).

(** REFINEMENT: a successful allocation marks exactly a run that was FREE.
    Composes `find_free_run_sound` (the run was free) with
    `mark_slots_used_refines` (the bitmap now reflects that run marked). *)
Theorem allocate_refines :
  forall (self self' : EnclaveSwapSpace_t) (s : Slots) (slots_needed addr : u32),
    represents self.(enclaveSwapSpace_bitmap) s ->
    enclaveSwapSpace_allocate_core self slots_needed
      = Ok (Core_result_Result_Ok addr, self') ->
    exists found_start : usize,
      free_run s (to_Z found_start) (to_Z slots_needed) /\
      represents self'.(enclaveSwapSpace_bitmap)
        (mark s (to_Z found_start) (to_Z slots_needed)).
Proof.
  intros self self' s slots_needed addr Hrep Hexec.
  unfold enclaveSwapSpace_allocate_core in Hexec.
  (* success ⇒ slots_needed <> 0 *)
  destruct (slots_needed s= 0%u32) eqn:Ez; [ discriminate Hexec |].
  unfold scalar_eqb in Ez. apply Z.eqb_neq in Ez.
  change (to_Z (0%u32)) with 0 in Ez.
  pose proof (to_Z_u32_bounds slots_needed) as Hsnb.
  assert (Hsn1 : 1 <= to_Z slots_needed) by lia.
  (* success ⇒ find_free_run returned Some *)
  destruct (enclaveSwapSpace_find_free_run self slots_needed) as [o1|] eqn:Efr;
    [| discriminate Hexec ].
  cbn [bind] in Hexec.
  destruct o1 as [found_start|]; [| discriminate Hexec ].
  (* i1 = slots_needed cast to usize *)
  destruct (cast_u32_usize_ok slots_needed) as [i1 [Hi1_eq Hi1_v]].
  rewrite Hi1_eq in Hexec. cbn [bind] in Hexec.
  (* mark_slots_used must have succeeded *)
  destruct (enclaveSwapSpace_mark_slots_used self found_start i1) as [self1|] eqn:Emark;
    [| cbn [bind] in Hexec; discriminate Hexec ].
  cbn [bind] in Hexec.
  (* the address arithmetic must also have succeeded; self' = self1 regardless *)
  destruct (scalar_cast Usize U32 found_start) as [i2|] eqn:E2;
    [| cbn [bind] in Hexec; discriminate Hexec ]. cbn [bind] in Hexec.
  destruct (u32_mul i2 sLOT_SIZE) as [i3|] eqn:E3;
    [| cbn [bind] in Hexec; discriminate Hexec ]. cbn [bind] in Hexec.
  destruct (u32_add eFBC_BASE i3) as [i4|] eqn:E4;
    [| cbn [bind] in Hexec; discriminate Hexec ]. cbn [bind] in Hexec.
  injection Hexec as Haddr Hself. subst self'.
  (* the run found by find_free_run was free, and fits the bitmap *)
  destruct (find_free_run_sound self s slots_needed found_start Hrep Hsn1 Efr)
    as [Hfree Hfit].
  exists found_start. split.
  - exact Hfree.
  - (* mark_slots_used refines the model mark of that run *)
    rewrite <- Hi1_v.
    apply (mark_slots_used_refines self self1 found_start i1 s Hrep);
      [ rewrite Hi1_v; exact Hfit | exact Emark ].
Qed.

(** ISOLATION COROLLARY (issue #58): two successful allocations that are both
    live occupy DISJOINT slot ranges — the extracted allocator inherits Layer 1's
    `alloc_isolation`. This is the end-to-end statement of "an enclave's blocks
    can never alias another enclave's blocks", proved of the REAL shipping code. *)
Theorem allocate_isolation :
  forall (self self1 self2 : EnclaveSwapSpace_t) (s : Slots)
         (addr1 addr2 sn1 sn2 : u32) (fs1 fs2 : usize),
    represents self.(enclaveSwapSpace_bitmap) s ->
    enclaveSwapSpace_allocate_core self sn1
      = Ok (Core_result_Result_Ok addr1, self1) ->
    free_run s (to_Z fs1) (to_Z sn1) ->
    represents self1.(enclaveSwapSpace_bitmap) (mark s (to_Z fs1) (to_Z sn1)) ->
    enclaveSwapSpace_allocate_core self1 sn2
      = Ok (Core_result_Result_Ok addr2, self2) ->
    free_run (mark s (to_Z fs1) (to_Z sn1)) (to_Z fs2) (to_Z sn2) ->
    disjoint (to_Z fs1) (to_Z sn1) (to_Z fs2) (to_Z sn2).
Proof.
  intros. eapply alloc_isolation; eassumption.
Qed.
