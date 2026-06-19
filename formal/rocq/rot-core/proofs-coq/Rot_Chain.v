(** T2 — Tamper-evidence of Umbra's chained measurement (issue #58).

    Umbra's root of trust is the chained HMAC measurement built by streaming
    [umbra_rot_core::update_chain] one block at a time:
        M_0 = initial_key,   M_{i+1} = HMAC(M_i, block_i).
    The extracted `update_chain` computes exactly `output = HMAC(current_key,
    block)` (see Rot_Funs.v) — so the firmware's running measurement is the
    fold below, `chain`.

    We work in the standard SYMBOLIC crypto model (as ProVerif does): HMAC is an
    opaque function assumed collision-free, here as injectivity in its
    (key, block) pair. Under that single assumption we prove the chain is
    INJECTIVE in the block sequence: any change to any block — the threat
    model's CJ2 tampering, whether of flash or a DMA transfer — changes the root
    measurement. This is the mechanized form of the CJ2 property the existing
    proptests only sample. *)

Require Import Coq.Lists.List.
Import ListNotations.

Section ChainTamperEvidence.

  (* Abstract measurement keys and blocks (the extracted code uses
     [array u8 32] and [slice u8]; their concrete shape is irrelevant to the
     argument). *)
  Variable key   : Type.
  Variable block : Type.

  (* The opaque HMAC step that [update_chain] performs: next = hmac k b. *)
  Variable hmac : key -> block -> key.

  (* Idealized-HMAC assumption (symbolic model): the step is injective in its
     (key, block) pair. This is exactly the "no collisions" idealization a
     ProVerif model grants the cryptographic primitive. *)
  Hypothesis hmac_injective :
    forall k1 b1 k2 b2, hmac k1 b1 = hmac k2 b2 -> k1 = k2 /\ b1 = b2.

  (* The chained measurement: the fold the firmware computes by streaming
     [update_chain]. *)
  Fixpoint chain (k : key) (bs : list block) : key :=
    match bs with
    | []        => k
    | b :: bs'  => chain (hmac k b) bs'
    end.

  (* Strengthened invariant: generalize over BOTH anchors. Equal-length block
     sequences driving equal chains from (possibly different) anchors force both
     the anchors AND the sequences to be equal. *)
  Lemma chain_strong :
    forall bs bs' j j',
      length bs = length bs' ->
      chain j bs = chain j' bs' ->
      j = j' /\ bs = bs'.
  Proof.
    induction bs as [| b bs IH]; intros bs' j j' Hlen Hchain.
    - destruct bs' as [| b' bs']; [ simpl in Hchain; split; [exact Hchain | reflexivity]
                                  | discriminate Hlen ].
    - destruct bs' as [| b' bs']; [ discriminate Hlen |].
      simpl in Hchain, Hlen. injection Hlen as Hlen'.
      (* Hchain : chain (hmac j b) bs = chain (hmac j' b') bs' *)
      destruct (IH bs' (hmac j b) (hmac j' b') Hlen' Hchain) as [Hanchor Htail].
      apply hmac_injective in Hanchor. destruct Hanchor as [Hj Hb].
      split; [ exact Hj | rewrite Hb, Htail; reflexivity ].
  Qed.

  (** TAMPER-EVIDENCE. Two block sequences of the same length that produce the
      same root measurement from the same anchor must be identical. Contrapositive:
      tampering with any block (any flash/DMA modification) changes the root
      measurement. *)
  Theorem chain_injective :
    forall bs bs' k,
      length bs = length bs' ->
      chain k bs = chain k bs' ->
      bs = bs'.
  Proof.
    intros bs bs' k Hlen Hchain.
    destruct (chain_strong bs bs' k k Hlen Hchain) as [_ Htail]. exact Htail.
  Qed.

End ChainTamperEvidence.
