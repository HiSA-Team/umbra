(** THE WIRE — a package space that IS a `choice_type`, and the REAL
    acceptance predicate over it.

    WHAT THIS FILE IS FOR. `Umbra_Reduction.v` states, in its own header, the
    defect that disqualifies the development: its `submit` oracle returns a
    TAG-VERIFICATION verdict, not "`parse_and_verify` accepted", so `Print
    Assumptions update_forgery_le_eufcma` lists no Aeneas axiom and the file
    would compile unchanged if `parse_and_verify` did not exist. Closing that
    needs the real acceptance predicate to live inside SSProve's package
    language, which needs the adversary's submission to have a `choice_type`.

    WHY THE OBSTRUCTION IS NOT WHERE IT LOOKS. An Aeneas `slice u8` is
    `{l : list u8 | Z.of_nat (length l) <= usize_max}` over `u8 = {x : Z | ...}`
    — a sigma type over `Prop`, with no `Choice` structure and no prospect of
    one. That is TRUE and is why the old file quantified over abstract readers
    `msgN`/`tagN : nat -> nat` instead. But it is the wrong conclusion. SSProve
    never requires the oracle's SEMANTIC domain to be a `choice_type`; it
    requires the oracle's ARGUMENT to be one (`opsig := ident * (choice_type *
    choice_type)`, `Inductive raw_code (A : choiceType)`). `chList chNat` is a
    `choice_type`. So the adversary submits the WIRE BYTES — `list nat`, which
    is exactly what a real attacker puts on the UART — and the device-side
    marshalling from bytes to `slice u8` happens INSIDE the oracle body, as an
    ordinary total Coq function. That function is `wire`, below.

    WHAT `wire` IS AND IS NOT. It is total: it truncates at `MAX_PKG` and
    clamps each code into the byte range. It is the IDENTITY on genuine wire
    traffic — `to_Z_byte_of_nat` and `wire_bytes` pin the byte VALUES it
    produces — so no real package is unreachable. It is NOT claimed to be a
    bijection onto `slice u8` as a TYPE: two slices with the same byte values
    need not be equal terms (`u8` is a sigma over a `Prop`; that would need
    proof irrelevance — the same reason `Umbra_DeviceLink.v` needs C1e). The
    modelling claim is the weaker and true one: the adversary's reachable set
    is every byte string of length <= MAX_PKG, and `wire` is the device's
    marshalling of it.

    WHAT IS PROVED HERE. `wire_accept_implies_submit_true` is
    `Umbra_DeviceLink.device_accept_implies_submit_true` instantiated at the
    wire decoder: if the real, extracted `parse_and_verify` accepts the byte
    string `p`, then the integer `wtag p` read off those same bytes is the
    abstract MAC of the integer `wmsg p`. `wmsg`/`wtag` are the CONCRETE
    readers the old file left universally quantified. Everything in this file
    is bare Coq 8.18 — no mathcomp, no SSProve. *)

Require Import Primitives.
Import Primitives.
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
Require Import Update_Crypto.
Require Import Update_Forgery.
Require Import Update_Encoding.
Require Import Umbra_DeviceLink.

Open Scope Z_scope.

(* ===================================================================== *)
(* BYTES                                                                  *)
(* ===================================================================== *)

(** The longest package the model lets an adversary submit. Any concrete
    bound below `u32_max` works; the protocol's packages are 112 bytes plus
    the blob, and `usize_max` is only known to be at least `u32_max`
    (`Primitives.usize_max_bound`), so a literal is the only way to discharge
    the `slice` well-formedness obligation without assuming more. *)
Definition MAX_PKG : nat := 65536.

Lemma byte_bound : forall n : nat,
  scalar_min U8 <= Z.of_nat (Nat.min n 255) <= scalar_max U8.
Proof.
  intros n. unfold scalar_min, scalar_max, u8_min, u8_max. lia.
Qed.

(** A byte CODE becomes a byte. Codes above 255 are clamped, so the map is
    total; on the byte range it is the identity, which is what makes the
    package space faithful (see `to_Z_byte_of_nat`). *)
Definition byte_of_nat (n : nat) : u8 := exist _ (Z.of_nat (Nat.min n 255)) (byte_bound n).

Lemma to_Z_byte_of_nat : forall n : nat,
  (n <= 255)%nat -> to_Z (byte_of_nat n) = Z.of_nat n.
Proof. intros n Hn. unfold to_Z, byte_of_nat; cbn [proj1_sig]. lia. Qed.

(* ===================================================================== *)
(* THE WIRE DECODER                                                       *)
(* ===================================================================== *)

Lemma wire_bound : forall l : list nat,
  Z.of_nat (length (map byte_of_nat (firstn MAX_PKG l))) <= usize_max.
Proof.
  intros l. rewrite map_length.
  pose proof (firstn_le_length MAX_PKG l) as Hf.
  apply Nat2Z.inj_le in Hf.
  pose proof usize_max_bound as Hb.
  eapply Z.le_trans; [ exact Hf |].
  eapply Z.le_trans; [| exact Hb ].
  unfold MAX_PKG, u32_max.
  change (65536 <= 4294967295)%Z. lia.
Qed.

(** THE MARSHALLING. Wire bytes in, the device's `slice u8` out. Total. *)
Definition wire (l : list nat) : slice u8 :=
  exist _ (map byte_of_nat (firstn MAX_PKG l)) (wire_bound l).

(** FAITHFULNESS, at the level the modelling actually needs: the byte VALUES
    the device sees are the byte values the adversary sent, for every package
    of at most `MAX_PKG` genuine bytes. *)
Lemma wire_bytes : forall l : list nat,
  (length l <= MAX_PKG)%nat ->
  (forall n, In n l -> (n <= 255)%nat) ->
  map to_Z (proj1_sig (wire l)) = map Z.of_nat l.
Proof.
  intros l Hlen Hb. unfold wire; cbn [proj1_sig].
  rewrite firstn_all2 by exact Hlen.
  rewrite map_map. apply map_ext_in.
  intros a Ha. apply to_Z_byte_of_nat. apply Hb. exact Ha.
Qed.

Lemma to_Z_16 : to_Z 16%usize = 16.
Proof. reflexivity. Qed.

Lemma nonce_bound : forall l : list nat,
  Z.of_nat (length (map byte_of_nat (firstn 16 (l ++ repeat 0%nat 16))))
  = to_Z 16%usize.
Proof.
  intros l. rewrite map_length, firstn_length, app_length, repeat_length.
  rewrite to_Z_16. lia.
Qed.

(** The expected anti-rollback nonce, likewise given by its bytes. Padded so
    the map is total on every list. *)
Definition nonce16 (l : list nat) : array u8 16%usize :=
  exist _ (map byte_of_nat (firstn 16 (l ++ repeat 0%nat 16))) (nonce_bound l).

(* ===================================================================== *)
(* THE REAL ACCEPTANCE PREDICATE                                          *)
(* ===================================================================== *)

Section Accept.

Context {HS : Type}.
Variable inst : PkgHmac_t HS.
Variable hs   : HS.

(** THE DEVICE'S VERDICT, AS A `bool`. This is the whole point: acceptance is
    a TOTAL, DETERMINISTIC function of the wire bytes, the expected nonce and
    the key, so it lifts into SSProve as `ret (accepts ...)` with no
    probabilistic content at all.

    Totality is not an assumption. `Update_Safety.parse_and_verify_total`
    (Qed) proves `parse_and_verify` never returns `Fail_`; the `false` branch
    for `Fail_` below is therefore unreachable, and is present only because
    `parse_and_verify`'s Coq type is `result (...)` rather than `(...)`.

    DECIDABILITY IS NOT AN ISSUE, AND THIS IS WORTH SAYING. `result` and
    `core_result_Result_t` are ordinary inductives in `Type`; reading a `bool`
    off them is a `match`, not a decision procedure. The fact that the match
    does not REDUCE — `parse_and_verify` is built over `Primitives`' axiomatic
    array/slice operations, so `accepts` is a stuck term — is irrelevant to
    SSProve, which needs a `bool`-VALUED function, not a computable one. *)
Definition accepts (key : slice u8) (en p : list nat) : bool :=
  match parse_and_verify inst (wire p) (nonce16 en) hs key with
  | Ok (Core_result_Result_Ok _) => true
  | _ => false
  end.

Lemma accepts_true : forall key en p,
  accepts key en p = true ->
  exists r, parse_and_verify inst (wire p) (nonce16 en) hs key
            = Ok (Core_result_Result_Ok r).
Proof.
  intros key en p H. unfold accepts in H.
  destruct (parse_and_verify inst (wire p) (nonce16 en) hs key)
    as [res|e] eqn:E; [| discriminate].
  destruct res as [r|er]; [| discriminate].
  exists r. reflexivity.
Qed.

End Accept.

(** Transparent aliases. The SSProve tier must name the device's types, but
    importing `Primitives` there would drop its notations on top of
    mathcomp's. These unfold to `slice u8` / `PkgHmac_t H` definitionally, so
    they can be used interchangeably with them. *)
Definition key_bytes : Type := slice u8.
Definition hmac_inst (H : Type) : Type := PkgHmac_t H.

(* ===================================================================== *)
(* THE CONCRETE READERS                                                   *)
(* ===================================================================== *)

(** `Umbra_Reduction.v` left these universally quantified and admitted, in its
    own header, that "what the modelling actually needs is a single INJECTION
    from wire packages into `nat`, and the games instantiated at that one
    reader ... it is NOT constructed in this development". These are that
    reader: key-free functions of the WIRE BYTES alone, so a reduction holding
    no key can compute them. *)
Definition wmsg (p : list nat) : nat := Z.to_nat (msg_of_pkg (wire p)).
Definition wtag (p : list nat) : nat := Z.to_nat (tag_of_pkg (wire p)).

(* ===================================================================== *)
(* THE LINK, AT THE WIRE                                                  *)
(* ===================================================================== *)

Section WireLink.

Context {HS : Type}.
Variable inst : PkgHmac_t HS.
Variable hs   : HS.
Variable key  : slice u8.
Variable macf : slice u8 -> array u8 91%usize -> array u8 32%usize.

(** C1 — verbatim from `Umbra_DeviceLink`. Carries no unforgeability. *)
Hypothesis Hseam :
  forall k p, inst.(PkgHmac_t_hmac_pkg) hs k p = Ok (macf k p).

Context (K : Type).
Variable MACg : K -> nat -> nat.
Variable k0 : K.

(** C1e — verbatim from `Umbra_DeviceLink`. Not a cryptographic assumption;
    see that file's header for why the `AssemblesF` guard is load-bearing. *)
Hypothesis Hfactor :
  forall (pre : array u8 91%usize) (f : Fields),
    AssemblesF pre f ->
    MACg k0 (Z.to_nat (msg_of_pre pre))
    = Z.to_nat (tag_of_arr (macf key pre)).

(** The property the SSProve tier consumes, named so that the two tiers can be
    compared without restating it. *)
Definition ForwardLink {H : Type} (i : hmac_inst H) (h : H) (kb : key_bytes)
                       (en : list nat) (M : nat -> nat) : Prop :=
  forall p, accepts i h kb en p = true -> wtag p = M (wmsg p).

(** THE FORWARD LINK AT THE WIRE. Whatever the extracted parser accepts is a
    valid (message, tag) pair for the abstract MAC, at the concrete readers.

    This is the statement the SSProve layer consumes. Note what it does NOT
    say: it is an IMPLICATION, not an equivalence. The converse — structural
    guards plus a matching tag imply acceptance — is what a key-less reduction
    needs in order to SIMULATE the device's `submit` oracle. It is PROVED, in
    `Update_Converse.v` (`accept_implies_struct` + `parse_walk` +
    `tag_gate_iff`, composed as `accept_factorises`) and transported to the wire
    by `Umbra_WireConverse.wire_accept_factorises`; earlier revisions of this
    comment said it was "not proved anywhere in this development", which stopped
    being true when those files landed. This theorem is still stated as an
    implication because that is all `Umbra_RealGame`'s forward-link comparison
    needs from it. *)
Theorem wire_accept_implies_submit_true :
  forall (en p : list nat),
    accepts inst hs key en p = true ->
    wtag p = MACg k0 (wmsg p).
Proof.
  intros en p Hacc.
  destruct (accepts_true inst hs key en p Hacc) as [r Hr].
  unfold wtag, wmsg.
  exact (device_accept_implies_submit_true inst hs key macf Hseam K MACg k0
           Hfactor (wire p) (nonce16 en) r Hr).
Qed.

(** Restated as `ForwardLink`, which is what `Umbra_RealGame.v` compares its
    factorisation hypothesis against. THE POINT OF THE RESTATEMENT: the
    forward direction is FREE — it follows from C1 and C1e alone, both of
    which the development already carries. Whatever `Umbra_RealGame.v`'s
    `Hfactorise` adds, it is not this. *)
Corollary forward_link_holds : forall en : list nat,
  ForwardLink inst hs key en (MACg k0).
Proof. intros en p Hacc. exact (wire_accept_implies_submit_true en p Hacc). Qed.

End WireLink.
