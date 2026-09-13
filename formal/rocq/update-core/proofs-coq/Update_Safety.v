(** P3 — BOUNDS-SAFETY of parse_and_verify, proved over the REAL Aeneas-extracted
    code (Update_Funs.v). In the Aeneas `result` monad, `Fail` is the panic /
    out-of-bounds / arithmetic-overflow channel, so "no trap on hostile input" is

        forall pkg en h key,  parse_and_verify … pkg en h key  <>  Fail _.

    The single length guard `len(pkg) >= 112` discharges every fixed index and
    range; the guard `blob_len = tag_off - 32 >= MIN_BLOB(48)` discharges the one
    variable-offset access `blob[16..48]`. The array/slice/copy/codec ops the
    Coq backend ships as bare Axioms are DEFINED in the shared library's
    Primitives.v; the laws about them the proofs consume are LEMMAS in the
    library's Aeneas_Laws.v (re-exported from here so every downstream file
    keeps seeing them unqualified), and every theorem here is closed under the
    global context. What stays in this file is crate-specific: the literal
    helpers, the 15-byte label literal, the compare-loop totality, the
    preimage assembly and P3 itself. *)

Require Import Primitives.
Import Primitives.
Require Import AeneasLoopShim.
Import AeneasLoopShim.
Require Export Aeneas_Laws.
Require Export AeneasLoopBounds.
Require Import Coq.ZArith.ZArith.
Require Import Coq.Bool.Bool.
Require Import Coq.Lists.List.
Import ListNotations.
Require Import Coq.Bool.Sumbool.
Require Import Lia.
Require Import Update_Types.
Import Update_Types.
Require Import Update_FunsExternal.
Import Update_FunsExternal.
Require Import Update_Funs.
Import Update_Funs.
Local Open Scope Z_scope.
Local Open Scope Primitives_scope.

(* ===================================================================== *)
(* Crate literals (the generic scalar helpers and tzN lemmas are in       *)
(* Aeneas_Laws).                                                          *)
(* ===================================================================== *)
Lemma tz_fixed : to_Z fIXED_PREFIX = 32. Proof. reflexivity. Qed.
Lemma tz_min   : to_Z mIN_BLOB    = 48. Proof. reflexivity. Qed.
Lemma tz_hdr   : to_Z hDR_LEN     = 48. Proof. reflexivity. Qed.

(* --- the label literal reads back its elements ---------------------------- *)

Lemma mk_array15_val :
  forall b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14 : u8,
    array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 0%usize = Ok b0
    /\ array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 1%usize = Ok b1
    /\ array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 2%usize = Ok b2
    /\ array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 3%usize = Ok b3
    /\ array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 4%usize = Ok b4
    /\ array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 5%usize = Ok b5
    /\ array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 6%usize = Ok b6
    /\ array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 7%usize = Ok b7
    /\ array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 8%usize = Ok b8
    /\ array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 9%usize = Ok b9
    /\ array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 10%usize = Ok b10
    /\ array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 11%usize = Ok b11
    /\ array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 12%usize = Ok b12
    /\ array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 13%usize = Ok b13
    /\ array_index_usize
      (mk_array15 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14) 14%usize = Ok b14.
Proof. intros. repeat apply conj; reflexivity. Qed.

(* ===================================================================== *)
(* ct_eq loop totality — the fixed-bound compare loops always return Ok.  *)
(* The fuel constant the shim's `loop` carries is never named: each body   *)
(* is total and strictly decreases the index measure `len - i`, so         *)
(* AeneasLoopBounds gives a run with fuel `S (len - i)` that any larger    *)
(* fuel — the shim's included — reproduces (loop_fuel_stable).            *)
(* ===================================================================== *)

(* The primitives the compare loops call fail only with `Failure`. *)
Lemma bind_not_oof : forall {A B : Type} (m : result A) (k : A -> result B),
  m <> Fail_ OutOfFuel -> (forall x, k x <> Fail_ OutOfFuel) ->
  bind m k <> Fail_ OutOfFuel.
Proof.
  intros A B m k Hm Hk. destruct m as [x|e]; cbn [bind].
  - apply Hk.
  - intro K. injection K as ->. apply Hm. reflexivity.
Qed.

Lemma mk_scalar_not_oof : forall ty z, mk_scalar ty z <> Fail_ OutOfFuel.
Proof.
  intros ty z. unfold mk_scalar.
  destruct (sumbool_of_bool (scalar_in_bounds ty z)); discriminate.
Qed.

Lemma array_index_usize_not_oof : forall {T} {n} (a : array T n) (i : usize),
  array_index_usize a i <> Fail_ OutOfFuel.
Proof.
  intros T n a i. unfold array_index_usize, opt_result.
  destruct (nth_error (proj1_sig a) (Z.to_nat (to_Z i))); discriminate.
Qed.

Lemma slice_index_usize_not_oof : forall {T} (s : slice T) (i : usize),
  slice_index_usize s i <> Fail_ OutOfFuel.
Proof.
  intros T s i. unfold slice_index_usize, opt_result.
  destruct (nth_error (proj1_sig s) (Z.to_nat (to_Z i))); discriminate.
Qed.

Lemma usize_add_not_oof : forall a b : usize, usize_add a b <> Fail_ OutOfFuel.
Proof. intros a b. unfold usize_add, scalar_add. apply mk_scalar_not_oof. Qed.

(* A total body under a strictly decreasing measure returns `Ok`, not merely
   "not OutOfFuel". *)
Lemma loop_fuel_ok_of_total : forall {St B : Type}
    (f : St -> result (control_flow St B)) (n : nat) (s : St),
  (forall s, exists c, f s = Ok c) ->
  loop_fuel n f s <> Fail_ OutOfFuel ->
  exists r, loop_fuel n f s = Ok r.
Proof.
  intros St B f n. induction n as [|n IH]; intros s Htot Hne.
  - exfalso. apply Hne. reflexivity.
  - destruct (Htot s) as [c Hc]. rewrite loop_step in *. rewrite Hc in *.
    destruct c as [s'|b].
    + apply IH; assumption.
    + exists b. reflexivity.
Qed.

(* --- 16-byte / array-vs-array compare loop ------------------------------ *)

Lemma ct_eq16_body_no_oof : forall (a b : array u8 16%usize) (s : u8 * usize),
  (fun '(d1, i1) => ct_eq16_loop_body a b d1 i1) s <> Fail_ OutOfFuel.
Proof.
  intros a b [d i]. cbn beta iota. unfold ct_eq16_loop_body.
  destruct (i s< 16%usize); [| discriminate ].
  apply bind_not_oof; [ apply array_index_usize_not_oof | intro x1 ].
  apply bind_not_oof; [ apply array_index_usize_not_oof | intro x2 ].
  cbv zeta. apply bind_not_oof; [ apply usize_add_not_oof | intro i4; discriminate ].
Qed.

Lemma ct_eq16_body_dec : forall (a b : array u8 16%usize) (s s' : u8 * usize),
  (fun '(d1, i1) => ct_eq16_loop_body a b d1 i1) s = Ok (Cont s') ->
  (Z.to_nat (16 - to_Z (snd s')) < Z.to_nat (16 - to_Z (snd s)))%nat.
Proof.
  intros a b [d i] [d' i'] H. cbn beta iota in H. unfold ct_eq16_loop_body in H.
  destruct (i s< 16%usize) eqn:Hlt; [| discriminate ].
  apply Z.ltb_lt in Hlt. rewrite tz16 in Hlt.
  destruct (array_index_usize a i) as [x1|]; cbn [bind] in H; [| discriminate ].
  destruct (array_index_usize b i) as [x2|]; cbn [bind] in H; [| discriminate ].
  destruct (usize_add i 1%usize) as [i4|] eqn:Hi4; cbn [bind] in H; [| discriminate ].
  injection H as _ <-.
  unfold usize_add, scalar_add in Hi4. apply mk_scalar_to_Z in Hi4. rewrite tz1 in Hi4.
  cbn [snd]. pose proof (usize_nonneg i). lia.
Qed.

Lemma ct_eq16_body_total : forall (a b : array u8 16%usize) (s : u8 * usize),
  exists c, (fun '(d1, i1) => ct_eq16_loop_body a b d1 i1) s = Ok c.
Proof.
  intros a b [d i]. cbn beta iota. unfold ct_eq16_loop_body.
  pose proof (usize_nonneg i) as Hnn.
  destruct (Z_lt_le_dec (to_Z i) 16) as [Hlt | Hge].
  - assert (Hc : (i s< 16%usize) = true) by (apply Z.ltb_lt; rewrite tz16; lia).
    rewrite Hc.
    destruct (array_index_usize_ok a i) as [x1 Hx1]; [ rewrite tz16; lia | ].
    destruct (array_index_usize_ok b i) as [x2 Hx2]; [ rewrite tz16; lia | ].
    rewrite Hx1, Hx2. cbn beta iota.
    destruct (usize_add_ok i 1%usize) as [i4 [Hi4 Hi4v]].
    { rewrite tz1. pose proof u32max_big. lia. }
    rewrite Hi4. cbn beta iota. eexists; reflexivity.
  - assert (Hc : (i s< 16%usize) = false) by (apply Z.ltb_ge; rewrite tz16; lia).
    rewrite Hc. eexists; reflexivity.
Qed.

(* The shim's `loop` on the 16-byte body IS the run with fuel `S (16 - i)`. *)
Lemma ct_eq16_loop_bounded : forall (a b : array u8 16%usize) (d : u8) (i : usize),
  ct_eq16_loop a b d i
  = loop_fuel (Datatypes.S (Z.to_nat (16 - to_Z i)))
      (fun '(d1, i1) => ct_eq16_loop_body a b d1 i1) (d, i).
Proof.
  intros a b d i. unfold ct_eq16_loop, loop.
  apply loop_fuel_stable with (n := Datatypes.S (Z.to_nat (16 - to_Z i))).
  - reflexivity.
  - exact (loop_fuel_bound_S _ (fun s : u8 * usize => Z.to_nat (16 - to_Z (snd s))) (d, i)
            (ct_eq16_body_no_oof a b) (ct_eq16_body_dec a b)).
  - pose proof (usize_nonneg i).
    apply Nat.le_trans with (m := 17%nat);
      [ lia | apply Nat.leb_le; vm_compute; reflexivity ].
Qed.

Lemma ct_eq16_total : forall a b : array u8 16%usize, exists r, ct_eq16 a b = Ok r.
Proof.
  intros a b. unfold ct_eq16. rewrite ct_eq16_loop_bounded.
  destruct (loop_fuel_ok_of_total _ _ _ (ct_eq16_body_total a b)
             (loop_fuel_bound_S _ (fun s : u8 * usize => Z.to_nat (16 - to_Z (snd s)))
                (@pair u8 usize 0%u8 0%usize) (ct_eq16_body_no_oof a b) (ct_eq16_body_dec a b)))
    as [r Hr].
  cbn [snd] in Hr. rewrite Hr. cbn beta iota. exists (r s= 0%u8). reflexivity.
Qed.

(* --- 32-byte / array-vs-slice compare loop. Symmetric to ct_eq16, but b is a
       slice and the read is bounds-checked against its length (= 32 in the
       loop branch); the body never exhausts fuel whatever the length. -------- *)

Lemma ct_eq32_body_no_oof : forall (a : array u8 32%usize) (b : slice u8) (s : u8 * usize),
  (fun '(d1, i1) => ct_eq32_loop_body a b d1 i1) s <> Fail_ OutOfFuel.
Proof.
  intros a b [d i]. cbn beta iota. unfold ct_eq32_loop_body.
  destruct (i s< 32%usize); [| discriminate ].
  apply bind_not_oof; [ apply array_index_usize_not_oof | intro x1 ].
  apply bind_not_oof; [ apply slice_index_usize_not_oof | intro x2 ].
  cbv zeta. apply bind_not_oof; [ apply usize_add_not_oof | intro i4; discriminate ].
Qed.

Lemma ct_eq32_body_dec : forall (a : array u8 32%usize) (b : slice u8) (s s' : u8 * usize),
  (fun '(d1, i1) => ct_eq32_loop_body a b d1 i1) s = Ok (Cont s') ->
  (Z.to_nat (32 - to_Z (snd s')) < Z.to_nat (32 - to_Z (snd s)))%nat.
Proof.
  intros a b [d i] [d' i'] H. cbn beta iota in H. unfold ct_eq32_loop_body in H.
  destruct (i s< 32%usize) eqn:Hlt; [| discriminate ].
  apply Z.ltb_lt in Hlt. rewrite tz32 in Hlt.
  destruct (array_index_usize a i) as [x1|]; cbn [bind] in H; [| discriminate ].
  destruct (slice_index_usize b i) as [x2|]; cbn [bind] in H; [| discriminate ].
  destruct (usize_add i 1%usize) as [i4|] eqn:Hi4; cbn [bind] in H; [| discriminate ].
  injection H as _ <-.
  unfold usize_add, scalar_add in Hi4. apply mk_scalar_to_Z in Hi4. rewrite tz1 in Hi4.
  cbn [snd]. pose proof (usize_nonneg i). lia.
Qed.

Lemma ct_eq32_body_total : forall (a : array u8 32%usize) (b : slice u8) (s : u8 * usize),
  to_Z (slice_len b) = 32 ->
  exists c, (fun '(d1, i1) => ct_eq32_loop_body a b d1 i1) s = Ok c.
Proof.
  intros a b [d i] Hlen. cbn beta iota. unfold ct_eq32_loop_body.
  pose proof (usize_nonneg i) as Hnn.
  destruct (Z_lt_le_dec (to_Z i) 32) as [Hlt | Hge].
  - assert (Hc : (i s< 32%usize) = true) by (apply Z.ltb_lt; rewrite tz32; lia).
    rewrite Hc.
    destruct (array_index_usize_ok a i) as [x1 Hx1]; [ rewrite tz32; lia | ].
    destruct (slice_index_usize_ok b i) as [x2 Hx2]; [ rewrite Hlen; lia | ].
    rewrite Hx1, Hx2. cbn beta iota.
    destruct (usize_add_ok i 1%usize) as [i4 [Hi4 Hi4v]].
    { rewrite tz1. pose proof u32max_big. lia. }
    rewrite Hi4. cbn beta iota. eexists; reflexivity.
  - assert (Hc : (i s< 32%usize) = false) by (apply Z.ltb_ge; rewrite tz32; lia).
    rewrite Hc. eexists; reflexivity.
Qed.

(* The shim's `loop` on the 32-byte body IS the run with fuel `S (32 - i)`. *)
Lemma ct_eq32_loop_bounded : forall (a : array u8 32%usize) (b : slice u8) (d : u8) (i : usize),
  ct_eq32_loop a b d i
  = loop_fuel (Datatypes.S (Z.to_nat (32 - to_Z i)))
      (fun '(d1, i1) => ct_eq32_loop_body a b d1 i1) (d, i).
Proof.
  intros a b d i. unfold ct_eq32_loop, loop.
  apply loop_fuel_stable with (n := Datatypes.S (Z.to_nat (32 - to_Z i))).
  - reflexivity.
  - exact (loop_fuel_bound_S _ (fun s : u8 * usize => Z.to_nat (32 - to_Z (snd s))) (d, i)
            (ct_eq32_body_no_oof a b) (ct_eq32_body_dec a b)).
  - pose proof (usize_nonneg i).
    apply Nat.le_trans with (m := 33%nat);
      [ lia | apply Nat.leb_le; vm_compute; reflexivity ].
Qed.

Lemma ct_eq32_total : forall (a : array u8 32%usize) (b : slice u8),
  exists r, ct_eq32 a b = Ok r.
Proof.
  intros a b. unfold ct_eq32.
  destruct (Z.eq_dec (to_Z (slice_len b)) 32) as [Hlen | Hne].
  - (* slice_len b = 32: the s<> guard is false, run the loop *)
    assert (Hc : (slice_len b s<> 32%usize) = false).
    { unfold scalar_neqb, scalar_eqb. apply negb_false_iff. apply Z.eqb_eq.
      rewrite tz32. exact Hlen. }
    rewrite Hc. rewrite ct_eq32_loop_bounded.
    destruct (loop_fuel_ok_of_total _ _ _ (fun s => ct_eq32_body_total a b s Hlen)
               (loop_fuel_bound_S _ (fun s : u8 * usize => Z.to_nat (32 - to_Z (snd s)))
                  (@pair u8 usize 0%u8 0%usize) (ct_eq32_body_no_oof a b) (ct_eq32_body_dec a b)))
      as [r Hr].
    cbn [snd] in Hr. rewrite Hr. cbn beta iota. exists (r s= 0%u8). reflexivity.
  - (* slice_len b <> 32: returns Ok false immediately *)
    assert (Hc : (slice_len b s<> 32%usize) = true).
    { unfold scalar_neqb, scalar_eqb. apply negb_true_iff. apply Z.eqb_neq.
      rewrite tz32. exact Hne. }
    rewrite Hc. exists false. reflexivity.
Qed.

(* ===================================================================== *)
(* compute_pkg_tag totality — the fixed 91-byte preimage assembly. Every  *)
(* range and length is a compile-time constant (no attacker input); it    *)
(* traps only if the HMAC seam does, which we assume total (as T1/T2 do).  *)
(* ===================================================================== *)

(* `idx_mut91` (index_mut specialised to the 91-byte buffer) is in Aeneas_Laws. *)

(* Turn every `to_Z (n%usize)` into its plain number. NB: `vm_compute` cannot do
   this — it gets stuck on the opaque `usize_max` axiom inside `mk_scalar`; the
   `tzN` reflexivity-lemmas go through the conversion checker instead. *)
Ltac tzc := rewrite ?tz0, ?tz1, ?tz4, ?tz15, ?tz16, ?tz31, ?tz32, ?tz35, ?tz39, ?tz43, ?tz48, ?tz91.

(* One assembly step: an in-bounds mutable sub-slice of the 91-byte buffer, then a
   copy_from_slice whose source length matches the sub-slice. Bounds and the
   length equality are discharged inline (no floating goals / ordering issues). *)
(* NB: the range literals carry `%return` proof terms, so idx_mut91's conclusion
   is only CONVERTIBLE (not syntactically equal) to the goal's index_mut — a bare
   `rewrite He` can't key-match it. We re-state the goal's exact subterm and bridge
   it to He with `exact` (which is up to conversion), then rewrite that. *)
Ltac pkg_step :=
  match goal with
  | |- context [ core_array_Array_index_mut ?inst ?arr
        {| core_ops_range_Range_start := ?a; core_ops_range_Range_end_ := ?b |} ] =>
    let sub := fresh "sub" in let bk := fresh "bk" in
    let He := fresh "He" in let Hl := fresh "Hl" in let Hx := fresh "Hx" in
    destruct (idx_mut91 arr a b ltac:(tzc; lia) ltac:(tzc; lia)
                                 ltac:(tzc; lia)) as [sub [bk [He Hl]]];
    assert (Hx : core_array_Array_index_mut inst arr
        {| core_ops_range_Range_start := a; core_ops_range_Range_end_ := b |} = Ok (sub, bk))
      by exact He;
    rewrite Hx; clear Hx He; cbn [bind];
    match goal with
    | |- context [ core_slice_Slice_copy_from_slice ?m ?dst ?src ] =>
      let cs := fresh "cs" in let Hcs := fresh "Hcs" in
      destruct (copy_from_slice_ok m dst src
        ltac:(rewrite Hl; try unfold pKG_TAG_LABEL;
              rewrite ?slice_len_array_to_slice; tzc; lia)) as [cs Hcs];
      rewrite Hcs; cbn [bind]
    end
  end.

Lemma compute_pkg_tag_total :
  forall {H} (inst : PkgHmac_t H) (nonce : array u8 16%usize)
    (author version blob_len : u32) (hdr : array u8 48%usize) (h : H) (key : slice u8),
  (forall k p, exists t, inst.(PkgHmac_t_hmac_pkg) h k p = Ok t) ->
  exists t, compute_pkg_tag inst nonce author version blob_len hdr h key = Ok t.
Proof.
  intros HH inst nonce author version blob_len hdr h key Hmac.
  unfold compute_pkg_tag. cbv zeta.
  pkg_step. pkg_step. pkg_step. pkg_step. pkg_step. pkg_step.
  cbv zeta. apply Hmac.
Qed.

(* ===================================================================== *)
(* P3 — parse_and_verify never Fails, for ANY pkg / expected_nonce / key. *)
(* ===================================================================== *)

Ltac tza := rewrite ?tz0, ?tz1, ?tz2, ?tz3, ?tz4, ?tz15, ?tz16, ?tz20, ?tz21, ?tz22,
  ?tz23, ?tz24, ?tz25, ?tz26, ?tz27, ?tz28, ?tz29, ?tz30, ?tz31, ?tz32, ?tz35, ?tz39,
  ?tz43, ?tz48, ?tz91, ?tz_fixed, ?tz_min, ?tz_hdr in *.

(* One in-bounds read of pkg: 0 <= to_Z k < to_Z (slice_len pkg), from Hlen. *)
Ltac pv_idx :=
  match goal with
  | |- context [ slice_index_usize ?s ?k ] =>
    let v := fresh "v" in let Hv := fresh "Hv" in
    destruct (slice_index_usize_ok s k) as [v Hv];
    [ split; tza; lia | rewrite Hv; cbn [bind] ]
  end.

(* One valid sub-slice of pkg: bridge the %return-carrying range term with exact. *)
Ltac pv_range Hlenname :=
  match goal with
  | |- context [ core_slice_index_Slice_index ?inst ?s
        {| core_ops_range_Range_start := ?a; core_ops_range_Range_end_ := ?b |} ] =>
    let sub := fresh "sub" in let Hs := fresh "Hs" in let Hx := fresh "Hx" in
    destruct (slice_index_range_ok s a b ltac:(tza; lia) ltac:(tza; lia) ltac:(tza; lia))
      as [sub [Hx Hs]];
    let E := fresh "E" in
    assert (E : core_slice_index_Slice_index inst s
        {| core_ops_range_Range_start := a; core_ops_range_Range_end_ := b |} = Ok sub)
      by exact Hx;
    rewrite E; clear E Hx; cbn [bind]; rename Hs into Hlenname
  end.

(* One copy_from_slice with a supplied length-equality proof. *)
Ltac pv_copy tac :=
  match goal with
  | |- context [ core_slice_Slice_copy_from_slice ?m ?dst ?src ] =>
    let cs := fresh "cs" in let Hcs := fresh "Hcs" in
    destruct (copy_from_slice_ok m dst src ltac:(tac)) as [cs Hcs];
    rewrite Hcs; cbn [bind]
  end.

Lemma parse_and_verify_total :
  forall {H} (inst : PkgHmac_t H) (pkg : slice u8) (en : array u8 16%usize)
    (h : H) (key : slice u8),
  (forall k p, exists t, inst.(PkgHmac_t_hmac_pkg) h k p = Ok t) ->
  exists r, parse_and_verify inst pkg en h key = Ok r.
Proof.
  intros HH inst pkg en h key Hmac.
  unfold parse_and_verify. cbv zeta.
  (* i1 = 32+48 = 80, i2 = 112 *)
  destruct (usize_add_ok' fIXED_PREFIX mIN_BLOB) as [i1 [E1 V1]];
    [ tza; pose proof usize_max_bound; unfold u32_max in *; lia | ].
  rewrite E1; cbn [bind].
  destruct (usize_add_ok' i1 32%usize) as [i2 [E2 V2]];
    [ rewrite V1; tza; pose proof usize_max_bound; unfold u32_max in *; lia | ].
  rewrite E2; cbn [bind].
  (* length guard: len < 112 -> Malformed; else len >= 112 *)
  destruct (slice_len pkg s< i2) eqn:G.
  { exists (Core_result_Result_Err UpdateError_Malformed); reflexivity. }
  assert (Hlen : 112 <= to_Z (slice_len pkg)).
  { apply Z.ltb_ge in G. rewrite V2, V1 in G. tza. lia. }
  (* magic: read pkg[0..3], branch *)
  pv_idx. pv_idx. pv_idx. pv_idx.
  match goal with |- context [ (?m0 s<> uPDATE_MAGIC) ] =>
    destruct (m0 s<> uPDATE_MAGIC) eqn:Gm end.
  { exists (Core_result_Result_Err UpdateError_BadMagic); reflexivity. }
  (* nonce := pkg[4..20] copied into a 16-byte buffer *)
  cbn [array_to_slice_mut].
  pv_range Hnonce.
  pv_copy ltac:(rewrite slice_len_array_to_slice, Hnonce; tza; lia).
  (* author (20..23), version (24..27), i21 (28..31) *)
  pv_idx. pv_idx. pv_idx. pv_idx.
  pv_idx. pv_idx. pv_idx. pv_idx.
  pv_idx. pv_idx. pv_idx. pv_idx.
  (* blob_len = cast i21 to usize; tag_off = len - 32 *)
  match goal with |- context [ scalar_cast U32 Usize ?x ] =>
    destruct (cast_u32_usize_ok x) as [bl [Ec Vc]] end.
  rewrite Ec; cbn [bind].
  destruct (usize_sub_ok' (slice_len pkg) 32%usize) as [toff [Et Vt]]; [ tza; lia | ].
  rewrite Et; cbn [bind].
  destruct (bl s< mIN_BLOB) eqn:Gmin.
  { exists (Core_result_Result_Err UpdateError_Malformed); reflexivity. }
  destruct (usize_sub_ok' toff fIXED_PREFIX) as [i23 [E23 V23]]; [ rewrite Vt; tza; lia | ].
  rewrite E23; cbn [bind].
  destruct (i23 s<> bl) eqn:G23.
  { exists (Core_result_Result_Err UpdateError_Malformed); reflexivity. }
  (* blob := pkg[32..tag_off], length = len-64 >= 48 (from Hlen) *)
  pv_range Hblob.
  match goal with |- context [ ct_eq16 ?x ?y ] =>
    destruct (ct_eq16_total x y) as [bn Hbn]; rewrite Hbn; cbn [bind] end.
  destruct bn.
  2:{ exists (Core_result_Result_Err UpdateError_NonceMismatch); reflexivity. }
  (* header := blob[0..48) — the FULL UMBR header — copied into a 48-byte buffer *)
  cbn [array_to_slice_mut].
  pv_range Hhdr.
  pv_copy ltac:(rewrite slice_len_array_to_slice, Hhdr; tza; lia).
  (* cast blob_len back to u32 (round-trip, so <= u32_max) *)
  destruct (cast_usize_u32_ok bl ltac:(rewrite Vc; apply to_Z_u32_bounds)) as [blu [Ecu Vcu]].
  rewrite Ecu; cbn [bind].
  (* compute_pkg_tag: total (Section C) *)
  match goal with |- context [ compute_pkg_tag ?I ?n ?au ?ve ?bl2 ?hh ?hh2 ?k ] =>
    destruct (compute_pkg_tag_total I n au ve bl2 hh hh2 k Hmac) as [tg Htg];
    rewrite Htg; cbn [bind] end.
  (* got := pkg[tag_off .. tag_off+32] (= pkg[..len]) *)
  destruct (usize_add_ok' toff 32%usize) as [i26 [E26 V26]];
    [ rewrite Vt; pose proof (to_Z_usize_bounds (slice_len pkg)); tza; lia | ].
  rewrite E26; cbn [bind].
  pv_range Hgot.
  match goal with |- context [ ct_eq32 ?x ?y ] =>
    destruct (ct_eq32_total x y) as [bt Hbt]; rewrite Hbt; cbn [bind] end.
  destruct bt.
  - eexists; reflexivity.
  - exists (Core_result_Result_Err UpdateError_TagInvalid); reflexivity.
Qed.

(* ===================================================================== *)
(* MECHANISED ASSUMPTION AUDIT.  The paper's central instrument is        *)
(* `Print Assumptions`; running it must therefore be part of the build,   *)
(* not a claim about a manual session.  Compiling this file emits the     *)
(* assumption set of P3 — it must be "Closed under the global context".   *)
(* ===================================================================== *)
Print Assumptions parse_and_verify_total.
