(** Security properties of the secure-enclave-update protocol (issue #58),
    proved against the REAL Aeneas-extracted code in Update_Funs.v.

    P4 — ANTI-ROLLBACK AT SLOT SELECTION (proved, Qed; zero QUARANTINE axioms —
    `Print Assumptions` reports only the six Aeneas backend scalar-width
    parameters `usize_max`/`isize_min`/`isize_max` and their three bound
    axioms, which every theorem in this development inherits).
    `select_active_slot` boots the enclave with the highest authenticated
    version. The theorems below fully characterise it: the update slot (B) is
    chosen ONLY when its version strictly exceeds the active one — a stale or
    equal-version package can never win selection, and an empty slot is never
    chosen. This is the code-level analogue of the never-downgrade property.

    P4b — the same characterisation, under the MASKED inputs the boot path feeds
    it when a crash-looping slot is excluded (see the second half of this file).

    P3 — BOUNDS-SAFETY of parse_and_verify: PROVED in `Update_Safety.v`
    (`parse_and_verify_total`, Qed), on the six SUCCESS laws of the quarantine,
    which is declared in ONE block in that file (not here). The quarantine has
    TWENTY axioms in total: those six SUCCESS laws, plus eight VALUE laws used
    by the byte-level authentication results, plus four WRITE-BACK/ENCODER laws
    used by the preimage-assembly results, plus two DECODER laws used by the
    wire-format results. All twenty have a machine-checked model in
    `Update_Model.v`. See REPORT §7. *)

Require Import Primitives.
Import Primitives.
Require Import Coq.ZArith.ZArith.
Require Import Update_Types.
Import Update_Types.
Require Import Update_Funs.
Import Update_Funs.
Local Open Scope Primitives_scope.

(** Both slots empty → no enclave selected. *)
Theorem select_none_none : select_active_slot None None = Ok None.
Proof. reflexivity. Qed.

(** Only slot A valid → A. Only slot B valid → B. An absent slot is never picked. *)
Theorem select_only_a : forall va, select_active_slot (Some va) None = Ok (Some 0%usize).
Proof. reflexivity. Qed.
Theorem select_only_b : forall vb, select_active_slot None (Some vb) = Ok (Some 1%usize).
Proof. reflexivity. Qed.

(** THE ANTI-ROLLBACK CHARACTERISATION. With both slots valid, B (the update
    target) is selected iff its version is strictly greater; otherwise A wins
    (ties included). So a package whose version does not strictly exceed the
    active version can never take over selection. *)
Theorem select_both_picks_strictly_greater :
  forall va vb,
    select_active_slot (Some va) (Some vb)
      = Ok (Some (if vb s> va then 1%usize else 0%usize)).
Proof. intros va vb. cbn. destruct (vb s> va); reflexivity. Qed.

(** Corollary (the anti-rollback direction): if the update version does NOT
    strictly exceed the active version, selection returns the ACTIVE slot A —
    the stale/equal-version package is never activated. *)
Corollary stale_update_not_selected :
  forall va vb,
    (vb s> va) = false ->
    select_active_slot (Some va) (Some vb) = Ok (Some 0%usize).
Proof.
  intros va vb Hle.
  rewrite select_both_picks_strictly_greater, Hle. reflexivity.
Qed.

(* ==========================================================================
   P4b — ANTI-ROLLBACK UNDER MASKED INPUTS.

   The N657 boot path (`api_impl::umbra_enclave_create_imp`) adds a liveness
   fallback: a slot that has crash-looped `BOOT_FAIL_THRESHOLD` times is excluded
   by passing `None` for it. `select_active_slot` itself is untouched — exclusion
   is only a MASKED INPUT. This section proves that the masking cannot be used to
   defeat P4, so the fallback is covered by proof rather than by argument.
   ========================================================================== *)

(** Total characterisation of selection — every combination of present/absent
    (i.e. every masking) in one statement. Everything below is a corollary. *)
Theorem select_characterisation :
  forall a b,
    select_active_slot a b =
      Ok (match a, b with
          | None, None => None
          | Some _, None => Some 0%usize
          | None, Some _ => Some 1%usize
          | Some va, Some vb => Some (if vb s> va then 1%usize else 0%usize)
          end).
Proof.
  intros a b. destruct a as [va|]; destruct b as [vb|]; try reflexivity.
  apply select_both_picks_strictly_greater.
Qed.

(** Selection over masked inputs is exactly selection over the SURVIVORS: among
    the slots that survive masking, the highest version still wins, and a masked
    slot is never selected. `ma`/`mb` = "this slot is excluded". *)
Theorem select_masked_is_max_over_survivors :
  forall (ma mb : bool) (va vb : u32),
    let a' := if ma then None else Some va in
    let b' := if mb then None else Some vb in
    (ma = false -> mb = false ->
       select_active_slot a' b' = Ok (Some (if vb s> va then 1%usize else 0%usize)))
    /\ (ma = true  -> mb = false -> select_active_slot a' b' = Ok (Some 1%usize))
    /\ (ma = false -> mb = true  -> select_active_slot a' b' = Ok (Some 0%usize))
    /\ (ma = true  -> mb = true  -> select_active_slot a' b' = Ok None).
Proof.
  intros ma mb va vb a' b'. unfold a', b'.
  repeat split; intros Ha Hb; subst ma; subst mb; apply select_characterisation.
Qed.

(** THE SECURITY DIRECTION, under masking. As long as the ACTIVE slot A survives
    the mask, a stale or equal-version update in B is never selected — whatever
    B's mask is. So a crash-counter the attacker can influence for slot B buys
    nothing: masking B only makes B less likely to run, never more. *)
Corollary masked_stale_update_not_selected :
  forall (mb : bool) (va vb : u32),
    (vb s> va) = false ->
    select_active_slot (Some va) (if mb then None else Some vb) = Ok (Some 0%usize).
Proof.
  intros mb va vb Hle. destruct mb.
  - apply select_only_a.
  - apply stale_update_not_selected, Hle.
Qed.

(** Dually, masking B never promotes B either: with B excluded, A wins whatever
    the versions are. *)
Corollary masked_b_never_selected :
  forall (va vb : u32), select_active_slot (Some va) None = Ok (Some 0%usize).
Proof. intros va vb. apply select_only_a. Qed.

(** THE ONE WAY MASKING CAN LOWER THE RUNNING VERSION — stated explicitly so it
    is not mistaken for a gap. If the active slot A is excluded (A crash-looped
    `BOOT_FAIL_THRESHOLD` times), selection falls back to B even when B's version
    is lower. That is the intended liveness trade, it is gated on the physical
    boot-fail counter, and it is the ONLY combination in
    `select_masked_is_max_over_survivors` where the selected version can be below
    the maximum over all slots. *)
Corollary masked_active_slot_falls_back_to_b :
  forall (vb : u32), select_active_slot None (Some vb) = Ok (Some 1%usize).
Proof. intro vb. apply select_only_b. Qed.

(** Both slots excluded → nothing is selected; the caller must refuse to boot
    (the N657 path returns `EnclaveNotFound` rather than looping). *)
Corollary masked_both_excluded_selects_nothing :
  select_active_slot None None = Ok None.
Proof. apply select_none_none. Qed.

(* --------------------------------------------------------------------------
   P3 — parse_and_verify bounds-safety (no-Fail). DONE: proved in Update_Safety.v
   exactly in the shape sketched below; the obligation list is the quarantine
   that file declares (and Update_Model.v exhibits a model for).

     Theorem parse_and_verify_total :
       forall {H} (inst : PkgHmac_t H) pkg en (h : H) key,
         (forall k p, exists t, PkgHmac_t_hmac_pkg inst h k p = Ok t) ->   (* A1 hmac total *)
         exists r, parse_and_verify inst pkg en h key = Ok r.             (* never Fail *)

   Discharge obligations — the SUCCESS half of the quarantine (cf. Ess_Rep's 8
   axioms). The VALUE half (index extensionality, the forward range length/read
   laws, copy_from_slice's write-back value, array_from_slice's read-through,
   u8 xor/or as Z bitwise ops) is NOT used here; it is what Update_Value.v and
   Update_Auth.accept_implies_nonce_equal rest on:
     - slice_index_usize_ok : i < slice_len x  -> exists v, slice_index_usize x i = Ok v
     - array_index_usize_ok : i < n            -> exists v, array_index_usize a i = Ok v
     - copy_from_slice_ok   : slice_len s = slice_len s1 -> exists s2, ... = Ok s2
     - scalar bound         : u32_max <= usize_max   (unblocks usize_add/sub + casts)
     - ct_eq16/32 totality  : the fuel `loop` reaches Done in <=16/32 steps (Ok)
   Then the single length guard `len >= 112` discharges every index/range, and the
   guard `i23 = blob_len >= MIN_BLOB=48` discharges the blob[16..48] access.
   -------------------------------------------------------------------------- *)
