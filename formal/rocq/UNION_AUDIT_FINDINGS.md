# Adversarial audit of the Tier-D / Tier-G union

> **CORRECTION, issued against my own earlier findings.** Every axiom count I
> published before this line was **wrong and too low, by exactly 3**. My
> extraction regex was `^[A-Za-z_][A-Za-z0-9_.']*\s*$` — a name *alone* on a
> line — which silently drops the entries whose type is short enough that Coq
> prints `name : type` on one line. Those three are
> `Primitives.usize_max`, `Primitives.isize_min`, `Primitives.isize_max` (the
> backend's scalar-width constants — precisely the "3 width bounds" of Table 1).
> The Implementer's rule (count lines at column 0 inside the `Axioms:` block,
> less the header) is the correct one, and I have adopted it. See §D7 for the
> corrected figures. The classical-axiom findings are **unaffected**: that check
> was a case-insensitive grep over the whole emitted output, not over extracted
> names.

Tests pre-registered in `UNION_PREREGISTRATION.md` (commit `2388405`), written
before the union existed. Findings appended as they are confirmed.

---

## Phase 1b — audit of the *prose* union argument, at baseline `1ffa809`

The union has not been mechanised yet. This section audits whether the informal
argument residual (ii) gestures at is even *correct*, so that a hole is not
mechanised.

### F0 — The joint at `blob[16,48)` is SOUND. **CONFIRMED**

`Update_Encoding.msg_of_pkg pkg = enc_from (rdS pkg) 4 28 + 257^28 * enc_from
(rdS pkg) 48 32`. That is `pkg[4,32)` (nonce16 ‖ author4 ‖ version4 ‖ blob_len4)
together with `pkg[48,80)`. The blob starts at `pkg[32)`, so `pkg[48,80)` is
exactly `blob[16,48)`, the header-HMAC window.

This is byte-for-byte the same window set as `Chain_Compose.PreimageOf`'s five
package clauses plus its `blob[16,48)` clause. The two tiers really do read the
same 60 bytes. No gap here.

Further, `widx p = Z.to_nat (shrink (msg_of_pkg (wire p)))` and `shrink` clamps
each base-257 digit mod 256. On a package `wstruct_ok` accepts, `wlen p >= 112`,
so every read in `[4,32)` and `[48,80)` is in bounds and returns a byte
`<= 255`; the clamp is the identity and `shrink` is an injective re-encoding of
the same sixty digits. So **equal `widx` on two structurally-valid packages
implies equal 60 core bytes, hence equal `blob[16,48)`**. The joint carries.

### F1 — Equal package length is FREE through Tier G, not merely "derivable". **CONFIRMED**

`Umbra_WireConverse.wstruct_ok` clause 4 is `wlen p - 64 = ldec (rdS (wire p)) 28`,
i.e. `len = 32 + blob_len + 32`, and `blob_len` sits at `pkg[28,32)` — inside the
60-byte core. `struct_ok` is a conjunct of *both* worlds of the `DEV` game. So
Tier D's hypothesis `to_Z (slice_len pkg1) = to_Z (slice_len pkg2)` is a
consequence of "same signed core" plus structural acceptance, and so is the fact
that `wtag` reads the same offset in both packages. §V (iii)'s "though derivable,
a strengthening we did not take" understates this: on the Tier-G route it costs
nothing.

### F2 — HOLE: block count is not authenticated, and the union cannot fix it. **CONFIRMED**

`Chain_Funs.blob_block_count` reads `blob[0,4)` (magic) and `blob[10,14)`
(`code_size`). Neither lies in the 60-byte core. Therefore Tier G's "this core
was signed" does **not** deliver `blob_block_count blob_adv = blob_block_count
blob_vendor`, and `Chain_Body.chain_accept_pins_the_blob_body` requires exactly
that equality (shared `n`).

Consequence, and it is the load-bearing one: **the union cannot conclude "an
accepted body is authentic".** The strongest honest conclusion is "an accepted
body *of the vendor's declared block count* is authentic". If the revised
residual (ii) says otherwise, it overclaims.

The strengthening that would close it — *equal `blob[16,48)` + both blobs
chain-accept ⇒ equal `n`* — is not in the tree. Its failure mode is a
**cross-length** fold collision (two folds of different length reaching the same
32-byte root). `Chain_Body.SeamCollisionInRuns` does *not* constrain `ms1` and
`ms2` to equal length, so it is expressible; but no lemma proves it, and
`chain_accept_pins_the_blob_body` takes equal `n` as a hypothesis rather than
deriving it. Until proved, equal `n` must survive as a hypothesis of the union.

### F3 — HOLE: the ideal world hands back an *index*, not a second blob. **CONFIRMED — structural**

`Umbra_RealGame.DEV_pkg_ff`'s submit oracle is

    ret (struct_ok p && ((widx_ord p, wtag p) \in domm S))

`S : {fmap Msg MsgN * nat -> unit}`. Membership yields a **message index and a
tag**. `chain_accept_pins_the_blob_body` needs a **second blob** to compare
against. Nothing in `formal/rocq/crypto/` maps `S` back to packages or blobs.

Any union must therefore introduce a bridging hypothesis of roughly the shape

    forall m, m \in domm S -> exists pkg', widx pkg' = m
              /\ verify_blob_chain (blob pkg') = Ok true
              /\ blob_block_count (blob pkg') = Ok (Some n)

**This is the joint where the sixth vacuity would live.** It is precisely the
`Assembles` failure mode already fatal here once: an existential witness
supplied at the use site, over an unpinned object. Two ways it goes wrong:

- if the witness blob is existentially quantified *inside* the conclusion, the
  adversary's own blob discharges it and the conclusion degenerates to "the body
  equals itself";
- if the hypothesis quantifies over arbitrary `pkg'` with no determinacy lemma,
  the union constrains nothing about *the vendor's* package.

The required antidote is the `preimage_of_determines` discipline: the bridge
must pin `pkg'` as a function of the signed index, and the union must be stated
so that the *hypothesis*, not the conclusion, carries the existential.

### F4 — HOLE: "signed" ≠ "authentic". **CONFIRMED — already disclosed, must stay disclosed**

`DEV_pkg_ff`'s `dsign` signs an **adversary-chosen** index `m : 'fin 256^60`.
So `(widx p, wtag p) \in domm S` means *the adversary obtained a signature on
this core from the modelled signing oracle* — not *the vendor intended this
body*. §V B2 already discloses this ("the freshness seam relating the vendor's
signing service to the game's query set is assumed"). The union's honest
conclusion is at most:

> the accepted body equals the body of some core the signing oracle signed.

If the revised (ii) drops to "an accepted body is authentic" unqualified, that
qualifier has been deleted and the claim is stronger than the artefact.

### F5 — HOLE: EUF-CMA does not discharge Tier D's collision disjunct. **CONFIRMED — category check**

`Chain_Compose.MacCollisionOnPackages` is a **collision** of `mac key` at two
distinct 75-byte preimages. EUF-CMA does not bound collision-finding. The
textbook collision→forgery reduction additionally needs one of the two colliding
preimages to have been *signed* — which is exactly what the tag-reuse branch does
not know, since both packages were merely *accepted by the device*, not signed.

Diagnostic value: if the union routes purely through Tier G's ideal world,
`MacCollisionOnPackages` should **disappear** from the conclusion. Its
disappearance is the tell that the union is genuine. If it survives *alongside* a
Tier-G advantage term, the two halves have been placed side by side rather than
joined, and the union is a `\/`, not a union — verdict OPEN under T6.

### F6 — Baseline recount of Table 1. **CONFIRMED EXACT** (every figure)

Recomputed from the tree at `1ffa809`, not taken from the paper.

| Claim | Recount | Derivation |
|---|---|---|
| Tier D 8 511 L | **8 511** | update-core hand-written (`Auth 207 + Crypto 1125 + Model 1246 + Props 169 + Safety 661 + Value 329` = 3 737) + crypto non-game (`ArrayVectors 206 + ByteSpace 504 + Canonical 979 + DeviceLink 422 + Wire 272 + WireConverse 613 + Update_Converse 779 + Update_Encoding 674 + Update_Forgery 325` = 4 774) |
| Tier D 332 `Qed` | **332** | `2+25+47+11+54+14` = 153, `6+29+46+9+9+32+13+24+11` = 179 |
| Tier G 1 452 L | **1 452** | `Umbra_EUFCMA 240 + Umbra_RealGame 908 + Umbra_Reduction 304` |
| Tier G 23 `Qed` | **23** | `2 + 18 + 3` |
| chain-core 1 927 L | **1 927** | `Body 200 + Compose 288 + Model 115 + Reachable 162 + Residual 330 + Trace 271 + Value 561` |
| Backend `Primitives.v` 1 077 L | **1 077** | file length |
| Totals 9 963 L / 355 `Qed` | **9 963 / 355** | 8 511+1 452, 332+23 |
| 0 admits | **0** | `grep -rn Admitted --include='*.v'` over all three trees: empty |
| 61:1 | **61.1** | 9 963 / 163 |
| 10:1 | **9.83** | 1 927 / 196 |

Every figure in Table 1 is exact at baseline. **Any union work moves the
chain-core and/or Tier-G rows, and the Totals row with them; I will recount.**

Presentational note (not a defect): the "Totals" row does **not** sum the table —
it excludes the chain-core row's 1 927 lines and 63 `Qed`, because 61:1 is
`(TierD+TierG) / 163` and chain-core is reported separately at 10:1 over its own
196. A PC reader will read "Totals" as the column sum. One clause would fix it.

### F7 — Bare tiers are pure; page limit and double-blind hold. **CONFIRMED**

- `grep -rn -e mathcomp -e ssreflect -e Ssreflect -e ssrbool -e SSProve
  --include='*.v' update-core chain-core` → **empty**. Neither `_CoqProject`
  names mathcomp. The bare tier is bare at baseline; T8 will re-run this.
- `grep -rn Admitted --include='*.v'` over update-core, chain-core, crypto →
  **empty**.
- `main.pdf`: 7 pages, body ends on page 6, page 7 is references only. Metadata
  `Author:` empty; no author name in `pdftotext` output; title block reads
  "Anonymous submission". Compliant.
- Minor double-blind inconsistency worth one look: reference [5] (the project's
  own repository) is anonymised, while reference [4] cites a DATE 2025 paper on
  the *same named system* with its authors in full. Third-person self-citation is
  normally permitted, but anonymising one and not the other is inconsistent and
  makes the omission conspicuous rather than concealing.

### F8 — T1 calibration on the *existing* theorem: all 8 hypotheses load-bearing. **CONFIRMED**

The harness is `scratchpad/hypdel.py`: it replaces a hypothesis's *content* with
`True` (arity and intro pattern preserved) and recompiles. Run against
`Chain_Compose.verified_update_pins_the_blob_body` at `1ffa809`, coqc 8.18.0:

| Hypothesis neutralised | Result |
|---|---|
| `parse_and_verify … pkg1 … = Ok (Ok r1)` | load-bearing |
| `parse_and_verify … pkg2 … = Ok (Ok r2)` | load-bearing |
| `to_Z (slice_len pkg1) = to_Z (slice_len pkg2)` | load-bearing |
| trailing-32-tag-bytes `forall j` block | load-bearing |
| `verify_blob_chain … r1.blob = Ok true` | load-bearing |
| `verify_blob_chain … r2.blob = Ok true` | load-bearing |
| `blob_block_count r1.blob = Ok (Some n)` | load-bearing |
| `blob_block_count r2.blob = Ok (Some n)` | load-bearing |

Baseline compiles at `rc=0`; every neutralisation fails. The earlier
`Chain_Compose` vacuity (provable with every hypothesis deleted) is genuinely
fixed, and the harness gives the right answer on a known-good theorem.

Stated limitation, so it is not overread: this shows the *proof script* breaks,
not that the weakened statement is unprovable by some other script. It is the
standard mechanical test and it is what was pre-registered; a survival is
damning, a failure is evidence but not proof of necessity.

### F9 — Baseline `Print Assumptions`, run by me. **CONFIRMED**

`Print Assumptions Chain_Compose.verified_update_pins_the_blob_body` →
**37 axioms, zero classical**. Grep for `boolp | classic | propositional_ext |
functional_ext | proof_irrel | realsum | JMeq | Eqdep` over the output:
**empty**. Composition of `Primitives` bare declarations (17),
`Update_Safety` quarantine laws (16), `Update_FunsExternal` opaque codecs (3),
and `Chain_Value.array_u8_ext` (Q21, 1).

This is the number the union must be compared against. **If the mechanised
union's `Print Assumptions` acquires a single `boolp.*` or
`realsum.__admitted__interchange_psum`, the bare tier has been contaminated and
the paper must disclose it** — Table 1 currently attributes `realsum` to Tier G
alone, and the chain-core row's "Assumed" column says only "the same 20
quarantine laws, + Q21".

---

## Phase 2 — audit of the delivery

### D1 — `crypto/Umbra_UnionCore.v` (428 L), deterministic half. **CONFIRMED, and it is a real strengthening**

Compiles clean at `coqc 8.18.0`, `exit=0`, with
`-R . UmbraCrypto -R ../update-core/proofs-coq Lib -R ../chain-core/proofs-coq Lib`.
Zero `Admitted`, zero `admit`.

Headline: `accepted_equal_cores_pin_the_blob_body` and its wire form
`wire_accepted_equal_indices_pin_the_blob_body`.

**T6 — the trailing-tag hypothesis is GONE.** It is replaced by
`msg_of_pkg pkg1 = msg_of_pkg pkg2` (wire form: `widx p1 = widx p2`), an equation
between the *authenticated cores* — the object the EUF-CMA game's message space
indexes. Both the same-length and the same-32-trailing-bytes hypotheses of
`Chain_Compose` are eliminated.

**T3/F5 — the package-MAC collision disjunct is GONE, and for the right reason.**
This was my pre-registered diagnostic for "genuine union vs `\/` of two
theorems", and it passes. `accepted_equal_cores_agree_on_the_preimage` derives
`p1 = p2` *as terms*, not merely `mac key p1 = mac key p2`: `msg_of_pre` is a
60-digit base-257 numeral over `rdA pre` on `[15,75)` with every digit `<= 256`,
hence injective (`Update_Encoding.msg_of_pre_inj`), and `Assembles`' label clause
fixes `[0,15)` to the constant `pKG_TAG_LABEL` in both. Q21 (`array_u8_ext`)
converts the byte-value agreement into term equality. Equal cores force equal MAC
*inputs*, so there is nothing left for the package seam to collide on. Only
`SeamCollisionInRuns` survives — pinned, as before, to steps of the two folds.
The category error I pre-registered under F5 (discharging a *collision* by appeal
to EUF-CMA) has been avoided by making the collision impossible rather than by
assuming it away.

**T1 — every hypothesis load-bearing.** Content replaced by `True`, arity and
intro pattern preserved, recompiled:

| Hypothesis | Result |
|---|---|
| `accepted_equal_cores_pin_the_blob_body` / parse `pkg1` | load-bearing |
| … / parse `pkg2` | load-bearing |
| … / `msg_of_pkg pkg1 = msg_of_pkg pkg2` | load-bearing |
| … / `ChainAccepts … r1.blob n` | load-bearing |
| … / `ChainAccepts … r2.blob n` | load-bearing |
| `wire_accepted_equal_indices…` / parse `wire p1` | load-bearing |
| … / parse `wire p2` | load-bearing |
| … / `widx p1 = widx p2` | load-bearing |
| … / `ChainAccepts … r1.blob n` | load-bearing |
| section `Hypothesis Hseam` (C1) | load-bearing |

**T4 — it constrains the extracted bodies.** `Locate` resolves the statement's
names to `Lib.Update_Funs.Update_Funs.parse_and_verify`,
`Lib.Chain_Funs.Chain_Funs.verify_blob_chain` and
`Lib.Chain_Funs.Chain_Funs.blob_block_count` — all in Aeneas-generated files
(`Update_Funs.v` opens "THIS FILE WAS AUTOMATICALLY GENERATED BY AENEAS", 0
`Qed`). Not a re-model.

**T8 — bare, and clean.** `Print Assumptions` run by me on both theorems:
**38 axioms, zero classical.** Grep for `boolp | classic | propositional_ext |
functional_ext | proof_irrel | realsum | JMeq | Eqdep` over the emitted output:
**empty**. The set is the baseline 37 plus `Update_Safety.slice_index_usize_ok`.
`update-core/` and `chain-core/` acquire no mathcomp dependency (the new
dependency runs crypto → chain-core, one way). Every `mathcomp`/`ssreflect`
occurrence in the deterministic crypto files is inside a comment.

**T3 — the theorem is not trivially satisfied.** Two *distinct* packages can meet
every hypothesis: they may differ at `blob[4,10)` and `blob[14,16)` (residual
(iv)'s unauthenticated window), which lies in neither the 60-byte core nor the
folded region `blob[48, 48+288n)`. So the conclusion is a genuine constraint, not
an artefact of the hypotheses collapsing to `pkg1 = pkg2`.

### D2 — F2 (block count) SURVIVES into the union, exactly as predicted. **CONFIRMED**

`ChainAccepts cinst ch master blob n` is `verify_blob_chain … = Ok true /\
blob_block_count blob = Ok (Some n)`, and it is a **hypothesis on both blobs at a
shared `n`**. Both instances tested load-bearing. `blob_block_count` still reads
`blob[10,14)` (`code_size`), outside the authenticated core, so the shared `n`
cannot be derived from "the cores are equal". **The union is conditional on equal
block count, and the paper must say so.** "An accepted body is authentic" remains
an overclaim; "an accepted body *at the declared block count*" is what was proved.

### D2b — DEFECT: `Umbra_UnionCore.v` is not in the build. **CONFIRMED**

`abebf2c` touches one file. `crypto/_CoqProject` and `crypto/build.sh` are
unchanged: `INCLUDES=(-R . UmbraCrypto -R ../update-core/proofs-coq Lib)` lacks
`-R ../chain-core/proofs-coq Lib`, and `DET_FILES` does not list
`Umbra_UnionCore.v`. I had to supply the third `-R` by hand. **As committed,
`./build.sh` does not verify the union core**, and the paper's "clean sequential
rebuild" does not cover it. Secondary: `--det-only` now needs chain-core built
first, and the script's only guard is on `../update-core/proofs-coq/Update_Crypto.vo`.

### D2c — DEFECT: axiom figure drift in the commit message. **CONFIRMED**

`abebf2c` claims "39 axioms". Measured by me, per theorem:
`accepted_equal_cores_pin_the_blob_body` = **37**;
`wire_accepted_equal_indices_pin_the_blob_body` = **38**; 38 unique across both.
Small, but it is the class of drift T10 exists to catch. If 39 reaches the paper
it is refuted.

### D3 — F3 (signed-set → second package) is still open at this point

`Umbra_UnionCore.v` proves a statement about **two packages**. The reader's
question needs the second package to be *the vendor's*, and the game's ideal
oracle stores a message index, not a package. That bridge is deferred to
`Umbra_Union.v`, which does not exist yet. Everything I pre-registered under
T7.1 applies there and nowhere else: the existential over the second package must
sit in the **hypothesis**, not the conclusion, or the adversary's own blob
discharges it and the theorem says "the body equals itself".

### D4 — `crypto/Umbra_Union.v` (361 L), the game half. Statement analysis

```coq
Theorem accepted_body_is_the_signed_body_or_a_forgery :
  forall (k : Key nk) (S : qset) (p q : list nat) (rp rq : VerifiedUpdate_t) (nb : u32),
    parse_and_verify inst (wire p) (nonce16 en) hs (dkey k) = Ok (Ok rp) ->
    parse_and_verify inst (wire q) (nonce16 en) hs (dkey k) = Ok (Ok rq) ->
    (((widx_ord p, wtag p) \in domm S) -> widx_ord q = widx_ord p) ->
    ChainAccepts cinst ch master (verifiedUpdate_blob rp) nb ->
    ChainAccepts cinst ch master (verifiedUpdate_blob rq) nb ->
    BodiesAgree (verifiedUpdate_blob rp) (verifiedUpdate_blob rq) nb
    \/ SeamCollisionInRuns cinst ch master (verifiedUpdate_blob rp) (verifiedUpdate_blob rq)
    \/ ideal_verdict S p = false.
```

**The F3 discipline is respected.** The vendor's package `q` is a universally
quantified parameter; its relation to the signed set sits in **hypothesis (3)**,
never in the conclusion. My pre-registered refutation — instantiate the
conclusion's existential with the adversary's own blob and read off "the body
equals itself" — has no target. Confirmed by reading the statement.

**F2, F4 and F5 are all disclosed in the file header, explicitly and correctly**
(limits (3), (2), (4) respectively), including the observation that a surviving
`MacCollisionOnPackages` could never have been discharged by EUF-CMA. The
`OBSTRUCTION` section reports, as a negative result, why the three disjuncts do
not become one probability statement: O1, the submit oracle cannot condition on
the chain gate because `parse_and_verify` never touches the body; O2, the chained
seam has no game and no sampled `master`, so an additive `Pr[collision]` term
cannot be written down. Both are correct and both are the right reasons.

### D5 — **REFUTATION OF NOVELTY**: the union theorem is logically equivalent to the deterministic one

`accepted_body_is_the_signed_body_or_a_forgery` is `A \/ B \/ ¬C` where
`C` is `(widx_ord p, wtag p) \in domm S` (modulo `struct_ok p`, which acceptance
already supplies), and hypothesis (3) is `C -> widx_ord q = widx_ord p`. That is
propositionally `C -> (widx q = widx p)` and `C -> (A \/ B)` — i.e. exactly

    Umbra_UnionCore.accepted_equal_indices_pin_the_blob_body

with an `A \/ ¬A` wrapped around it. Both directions:

- **(⇐)** the file's own proof: case on `Hmem`; true branch applies UnionCore,
  false branch discharges the third disjunct by `andbF`. No other step.
- **(⇒)** instantiate `S := setm emptym (widx_ord p, wtag p) tt`. Then `Hmem`
  holds, `ideal_verdict S p = struct_ok p = true` (acceptance gives `struct_ok`),
  so the third disjunct is refuted, hypothesis (3) is discharged from
  `widx p = widx q`, and what remains is precisely UnionCore's conclusion.

So the game half adds **zero logical content** over the bare-Coq half. What it
adds is *vocabulary*: the third disjunct is written in the game's own terms.
That is worth something — the identification of the join point is now in a
type-checked statement rather than in prose — but it is not "the union is
mechanised" in the sense a reader will take from residual (ii).

**What actually closed part of (ii) is `Umbra_UnionCore.v`, not `Umbra_Union.v`.**
The real advance is the move from "same trailing tag bytes" to "same
authenticated core", which eliminated the package-MAC collision disjunct. The
case split on top is bookkeeping. The paper's revised wording must credit the
former and must not present the latter as more than a restatement.

**D5 IS NOW A THEOREM, NOT AN ARGUMENT.** I mechanised the (⇒) direction against
the committed artefact at `fa73231`. It closes with `Qed`, 41 axioms, zero
classical — the same budget as everything else in this family:

```coq
Theorem union_implies_unioncore :
  forall (nk : nat) (HS : Type) (inst : hmac_inst HS) (hs : HS) (en : seq nat)
         (dkey : Key nk -> key_bytes) (macf : macf_t),
    SeamC1 inst hs macf ->
    forall (CS : Type) (cinst : Chain_Funs.ChainHmac_t CS) (ch : CS)
           (master : Chain_Trace.ckey) (k : Key nk)
           (p q : seq nat) (rp rq : vupd) (nb : blkcount),
      Accepted inst hs (dkey k) en p rp ->
      Accepted inst hs (dkey k) en q rq ->
      widx p = widx q ->
      ChainAccepts cinst ch master (vblob rp) nb ->
      ChainAccepts cinst ch master (vblob rq) nb ->
      BodiesAgree (vblob rp) (vblob rq) nb
      \/ Chain_Body.SeamCollisionInRuns cinst ch master (vblob rp) (vblob rq).
Proof.
  move=> nk HS inst hs en dkey macf Hseam CS cinst ch master k p q rp rq nb
         Ap Aq Hidx Cp Cq.
  pose S := setm emptym (@widx_ord MSGB MSGB_positive p, wtag p) tt.
  have Hh : ((@widx_ord MSGB MSGB_positive p, wtag p) \in domm S ->
             @widx_ord MSGB MSGB_positive q = @widx_ord MSGB MSGB_positive p).
  { move=> _. rewrite /widx_ord. by rewrite Hidx. }
  have H := @accepted_body_is_the_signed_body_or_a_forgery
              nk HS inst hs en dkey macf Hseam CS cinst ch master k S
              p q rp rq nb Ap Aq Hh Cp Cq.
  case: H => [Hb | [Hc | Hf]].
  - by left.
  - by right.
  - exfalso.
    have Hs : struct_ok en p = true.
    { rewrite /struct_ok.
      exact: (wire_accept_implies_wstruct_ok inst hs (dkey k) en p rp Ap). }
    have Hm : (@widx_ord MSGB MSGB_positive p, wtag p) \in domm S.
    { rewrite /S domm_set in_fsetU1. by rewrite eqxx. }
    move: Hf. rewrite /ideal_verdict Hs Hm /=. by [].
Qed.
```

The forward direction is the Implementer's own proof of
`accepted_body_is_the_signed_body_or_a_forgery`, which is a `case` on `Hmem`
plus one application of UnionCore plus `andbF`. So the two theorems are
**inter-derivable**. The game half adds no logical content; the entire advance
is `Umbra_UnionCore.v`. (Kept at
`scratchpad/union_converse.v`; not left in the source tree, so it does not enter
the build or the line counts.)

### D6 — **DEFECT**: `ideal_verdict` is a transcription, not a proof

`Umbra_Union.ideal_verdict S p := struct_ok en p && ((widx_ord p, wtag p) \in domm S)`
is claimed, in a comment, to be "verbatim the body of `DEV_pkg_ff`'s `dsubmit`
oracle". **There is no lemma connecting the two.** `grep -n ideal_verdict
Umbra_Union.v` returns the definition, two uses inside the theorem and its proof,
and two comments — nothing tying it to `Umbra_RealGame.DEV_pkg_ff`.

The asymmetry is the tell. The *real* side is genuinely tied: `dev_accepts` is
the same definition `DEV_pkg_tt` invokes, and `union_hypothesis_is_the_real_oracle`
proves the union's acceptance hypothesis implies it. The *ideal* side rests on
textual inspection of two files. If `DEV_pkg_ff` is ever edited, nothing catches
the drift, and the union's third disjunct silently stops being the game's
rejection event — which is the entire load-bearing claim of the file.

Fix is cheap and should be taken: define `ideal_verdict` once (in
`Umbra_RealGame.v`) and have `DEV_pkg_ff`'s `dsubmit` return it, so the two
cannot diverge; or prove a lemma that the ideal package's `dsubmit` returns
`ideal_verdict S p`. This is the same class of gap — a claim carried by comment
rather than by the kernel — that this development has already been bitten by.

### D7 — Corrected axiom budgets, measured by me. **CONFIRMED**

Rule: entries in the `Print Assumptions` block = lines at column 0, less the
`Axioms:` header. Classical check = case-insensitive grep for
`boolp | classic | propositional_ext | functional_ext | proof_irrel | realsum |
admitted` over the whole emitted output.

| Theorem | Axioms | Classical / admitted |
|---|---|---|
| `Chain_Compose.verified_update_pins_the_blob_body` (baseline) | **40** | 0 |
| `Umbra_UnionCore.accepted_equal_cores_pin_the_blob_body` | **40** | 0 |
| `Umbra_UnionCore.wire_accepted_equal_indices_pin_the_blob_body` | **41** | 0 |
| `Umbra_UnionCore.accepted_equal_indices_pin_the_blob_body` | **41** | 0 |
| **`Umbra_Union.accepted_body_is_the_signed_body_or_a_forgery`** | **41** | **0** |
| `Umbra_Union.forgery_disjunct_is_bounded_by_eufcma` | **50** | **yes** |
| `Umbra_RealGame.device_forgery_le_eufcma` | **50** | yes |
| `Umbra_RealGame.device_forgery_le_eufcma_at_the_real_seam` | **50** | yes |

The four classical/admitted constants, listed verbatim from the emitted output
and reached only by the last three rows:
`boolp.propositional_extensionality`, `boolp.functional_extensionality_dep`,
`boolp.constructive_indefinite_description`,
`realsum.__admitted__interchange_psum`.

**Two consequences, and the second is the more important.**

1. The paper's Table 1 figure of 50 axioms for the EUF-CMA bound is confirmed,
   and the classical inheritance is real and must stay disclosed. It currently
   is (C1, "Milder, and not removable").

2. **The union theorem's axiom set is *identical* to the deterministic
   theorem's** — 41 entries, name for name, `diff` empty, zero classical. Stated
   in the SSProve tier, over the game's `fmap`-valued query set, and it inherits
   nothing from mathcomp-analysis. That is mechanical confirmation of D5: a
   statement that did any probabilistic work could not have this budget. The
   union is the deterministic theorem in game vocabulary.

   It also **refutes the `Umbra_Union.v` header as first written**, which said
   "THIS FILE IS NOT MATHCOMP-FREE, AND NEITHER IS THE UNION THEOREM … and with
   them mathcomp-analysis's `boolp.*` classical axioms". False of the union
   theorem. (The Implementer independently found this and reported it; the
   header text must be corrected to match, or the paper will inherit an
   over-disclosure that also disguises D5.)

### D8 — both defects fixed at `fa73231`. **CONFIRMED FIXED**

- **D6 (transcription).** `ideal_verdict` now lives in `Umbra_RealGame.v:542` and
  `DEV_pkg_ff`'s `dsubmit` returns it (`Umbra_RealGame.v:559`,
  `ret (ideal_verdict S p)`). The two can no longer drift, because there is only
  one of them. This is the right fix, not a lemma papering over two copies.
- **D2b (not in the build).** `crypto/_CoqProject` carries
  `-R ../chain-core/proofs-coq Lib` and lists `Umbra_UnionCore.v` (det tier) and
  `Umbra_Union.v` (game tier). `build.sh` `INCLUDES` updated, both files added to
  `DET_FILES`/`GAME_FILES`, and a second ordering guard added on
  `../chain-core/proofs-coq/Chain_Body.vo`. `.vo` count in `crypto/` after a
  clean rebuild is 14 = 10 deterministic + 4 game, matching the file lists.

### D9 — T10 recount after the union. Every Table 1 figure moves.

Measured at `fa73231` (`wc -l`, `grep -c 'Qed\.'`), same conventions as F6.

| | LOC | `Qed` |
|---|---|---|
| `Umbra_UnionCore.v` (bare Coq → Tier D) | **505** | **12** |
| `Umbra_Union.v` (SSProve → Tier G) | **403** | **4** |
| `Umbra_RealGame.v` (grew: `ideal_verdict` moved in) | 908 → **925** | 18 (unchanged) |

Consequent totals, on the paper's existing taxonomy:

| Row | Was | Now |
|---|---|---|
| Tier D | 8 511 L, 332 `Qed` | **9 016 L, 344 `Qed`** |
| Tier G | 1 452 L, 23 `Qed` | **1 872 L, 27 `Qed`** |
| chain-core | 1 927 L, 63 `Qed` | unchanged |
| Totals row (Tier D + Tier G) | 9 963 L, 355 `Qed`, 61:1 | **10 888 L, 371 `Qed`, 66.8:1** |
| admits | 0 | **0** (`grep -rn Admitted --include='*.v'` over all three trees: empty) |

**"61:1" is now wrong and must become 67:1** on the existing convention — or the
convention must change, which raises a question the paper has to answer rather
than dodge: `Umbra_UnionCore.v` and `Umbra_Union.v` are about *both* crates
jointly (they consume `update-core`'s P2 and `chain-core`'s `Chain_Body`), so
attributing them to update-core's 163 Rust lines alone is a choice. If instead
every hand-written line (8 511 + 1 452 + 1 927 + 505 + 403 = 12 798) is divided by
every verified Rust line (163 + 196 = 359), the ratio is **35.6:1** — a much more
flattering number, which is a reason to be careful, not a reason to take it.
Whichever is chosen, it must be stated, and the "Totals" row must either sum the
table or say that it does not.

**Rebuild time — I RETRACT an earlier claim of my own.** I reported that
`Umbra_Union.v` "did not finish in a 10-minute `coqc`". That observation was
contaminated: the Implementer's concurrent clean rebuild removed the `.vo` files
my run depended on. Re-measured in isolation, `Umbra_Union.v` compiles in
**6.4 s**.

Full clean sequential rebuild from **zero** `.vo`, measured by me, all three
trees, `coqc` 8.18.0, Apple M1:

| Tree | Time | Failures |
|---|---|---|
| `update-core/proofs-coq` (12 files) | 247 s | 0 |
| `chain-core/proofs-coq` (10 files) | 16 s | 0 |
| `crypto` via `build.sh` (14 files, incl. both union files) | 30 s | 0 |
| **total** | **293 s** | **0** |

The paper's "≈ 280 s … ±5 % between runs" gives 266–294 s, so **293 s is inside
the stated tolerance and the figure stands** even with the union added (~7 s).
No change required. `grep -rn Admitted --include='*.v'` over all three trees is
empty, so "0 admits" also stands after a from-scratch build.

### D10 — T1 on the union theorem, run by me. **CONFIRMED: no decoration**

Same harness, applied to `Umbra_Union.v` at `fa73231`; baseline compiles in 6 s,
each neutralisation recompiled in full.

| Hypothesis neutralised | Result |
|---|---|
| section `Hypothesis Hseam : SeamC1 inst hs macf` | load-bearing |
| `Accepted inst hs (dkey k) en p rp` | load-bearing |
| `Accepted inst hs (dkey k) en q rq` | load-bearing |
| `ChainAccepts … (vblob rp) nb` | load-bearing |
| `ChainAccepts … (vblob rq) nb` | load-bearing |
| **bridge hypothesis (3)**, `mem -> widx_ord q = widx_ord p` | load-bearing |

The Implementer's own T1 run agrees. Six for six.

### D11 — the last vacuity avenue: could the conclusion's range be empty? **CLOSED, mechanically**

`BodiesAgree blob1 blob2 n` quantifies over `48 <= k < 48 + 288 * to_Z n`. At
`n = 0` that range is empty and the conclusion would be **vacuously true** — a
textbook sixth vacuity, and the one place left where this theorem could have said
nothing. It cannot happen: `ChainAccepts` carries
`blob_block_count blob = Ok (Some n)`, and the extracted body returns `Ok None`
when the quotient is zero. I proved it rather than read it:

```coq
Lemma block_count_is_positive :
  forall (blob : slice u8) (n : u32),
    blob_block_count blob = Ok (Some n) -> 0 < to_Z n.
```

`Qed`, over `Chain_Funs.blob_block_count` (the Aeneas-generated body), by
case analysis down to the `if n s= 0%u32 then Ok None` branch. So every instance
of the union's first disjunct constrains **at least 288 bytes**. Script kept at
`scratchpad/block_count_positive.v`; not left in the tree.

Also checked: `Chain_Reachable.chain_gate_accepts_a_matching_measurement` (Qed)
shows `verify_blob_chain … = Ok true` is reachable, so `ChainAccepts` is not an
unsatisfiable premise either. T2 and T3 pass for every premise of the union.

---

## Phase 2 (cont.) — the paper

### D12 — Table 1 after the union: every figure re-derived. **CONFIRMED EXACT**

| Claim | Recount |
|---|---|
| Tier D 9 016 L / 344 `Qed` | exact |
| Tier G 1 872 L / 27 `Qed` | exact |
| chain-core 1 927 L / 63 `Qed` | exact |
| Totals 10 888 L / 371 `Qed`, 67:1 | exact (10 888/163 = 66.8) |
| "whose 908 lines consume both crates" | exact (505 + 403) |
| 12 815 L over 359 Rust = 36:1 | exact (9 016+1 872+1 927; 35.7) |
| ≈ 290 s ±5 % rebuild | my clean rebuild from zero `.vo`: **293 s**, 0 failures |
| 50 axioms | exact |
| 7 SSProve/mathcomp incl. 1 `Admitted`; 43 the extraction bill | exact — `Axioms.R`, `FunctionalExtensionality.functional_extensionality_dep`, `SPropBase.ax_proof_irrel`, `boolp.constructive_indefinite_description`, `boolp.functional_extensionality_dep`, `boolp.propositional_extensionality`, `realsum.__admitted__interchange_psum` |
| 20 quarantine laws | exact (20 `Axiom` declarations in `Update_Safety.v`) |
| 0 admits | exact |

The caption's "Totals, all measured, and *not* the column sum" answers my F6
objection. The taxonomy question is answered in the open, both ways.

### D13 — the revised residual (ii): **no overclaim**

It says, in the paper's own words: *"The advance is the first theorem's, not the
second's: the two are inter-derivable, so what closed anything is 'same
tag'→'same core', the case split supplying vocabulary."* That is D5, stated
against the author's own work, and it was written before I published the
mechanised converse. It also carries: *signed* is not *authentic* (F4); the
disjuncts do not collapse into one probability bound, with O1 and O2 named (T9);
`DEV_pkg_ff`'s own returned function rather than a transcription (D6); "deleting
any one of its six hypotheses breaks the proof" (T1, and the count of six is
right). Residual (iii) carries the block count forward as *"an accepted body at
the vendor's declared block count"* (F2). Every disclosure I logged at baseline
survives.

### D14 — **DEFECT: hard page-limit violation.** Body now runs onto page 7

`main.tex`'s own format note quotes the DATE CFP: *"Maximum number of pages: 6
pages plus one extra page exclusively for references… Body text must therefore
end within page 6, and page 7 must contain nothing but the bibliography."*

`pdftotext -layout -f 7 -l 7 main.pdf | head` returns **"VI. CONCLUSION"** in the
left column. At baseline `1ffa809` the Conclusion sat on page 6 and page 7 was
references-only; the expanded (ii) pushed it over. Roughly 10–12 body lines must
come out. This is a desk-reject risk, not a style note.

Double-blind otherwise still clean: `pdfinfo` shows empty `Author`/`Title`/
`Subject`/`Keywords`; the only author names in the extracted text are reference
[4]'s third-person self-citation, which is unchanged from baseline.

### D15 — **DEFECT: the readability edit made residual (iv) false**

Baseline (iv) was scoped and correct: *"`is_trusted()` has zero call sites,
`efbc_size` and `ess_blocks` zero field reads anywhere"* — and it did **not**
claim `reloc_count` has no reader, handling that separately under (i) with the
fails-closed argument, exactly as `Chain_Residual.v`'s header does.

The revised text compresses this to *"those fields have no reader"*, applied to a
list that includes `reloc_count`. **False.** Five readers in shipping code:

- `src/hardware/platform/stm32l552/boot/src/secure_kernel/init.rs:114` — `let n_relocs = { hdr.reloc_count } as u32;`
- `src/hardware/platform/stm32l552/boot/src/api_impl/enclave_create.rs:260` — `let n_relocs = { header.reloc_count } as u32;`
- `src/hardware/platform/riscv32/boot/src/secure_kernel/create.rs:131-136` — reads it and sizes a slice from it

and `apply_relocs_to_block` (`stm32l552/…/secure_kernel/init.rs:101`) is called at
`lifecycle.rs:344` and imported in `enter.rs`. So `reloc_count` is an
unauthenticated field that controls how many 32-bit words a loader **rewrites in
decrypted enclave code** on two of three platforms.

This is the exact failure mode the audit was told to watch for: a readability
edit deleting a careful true statement and leaving a false one. It must be
reverted to the scoped form. The cost of leaving it is not the miscounted field;
it is that a reviewer who greps the artefact refutes one of the paper's own
negative results in a single command.

### D16 — both paper defects fixed; three line counts now stale by 19

**D14 (page limit) — FIXED.** `pdftotext -layout -f 7 -l 7 main.pdf` now begins
with `R EFERENCES` at offset 0, and every non-blank line on page 7 is a reference
entry or a continuation of one. The Conclusion ends on page 6. `pdfinfo` reports
7 pages, empty `Author`.

**D15 (false residual) — FIXED, and better than the baseline.** The new (iv)
says outright that `reloc_count` *is* read, that it sizes the relocation walk on
two of three boot paths, that it is unauthenticated, and that what protects it is
(i)'s fail-closed measurement rather than the theorem. The baseline was merely
silent about `reloc_count` in (iv); this is stronger.

**Double-blind, ref [4] — COMPLIANT.** `Umbra~\cite{umbra-date25}` in both
`background.tex:5` and `introduction.tex:16` is pure third person, with no
first-person attribution anywhere. Citing one's own *published* work in the third
person is what double-blind requires; anonymising a published, citable paper
would be worse. Refs [1] and [5] (the concurrent submission and the repository)
are anonymised. No issue.

**Stale by 19 lines.** `ae21e4f` added obstruction O3 to `Umbra_Union.v` as a
comment block: 403 → 422 L, `Qed` unchanged. Re-measured at the final commit:

| Table 1 figure | Printed | Measured now |
|---|---|---|
| Tier D | 9 016 L, 344 `Qed` | **9 016**, 344 — correct |
| Tier G | 1 872 L, 27 `Qed` | **1 891**, 27 — **19 low** |
| Totals L | 10 888 | **10 907** — **19 low** |
| all-hand-written | 12 815 | **12 834** — **19 low** |
| 67:1 | — | 10 907/163 = 66.9 — **unchanged** |
| 36:1 | — | 12 834/359 = 35.75 — **unchanged** |
| ≈290 s ±5 % | — | **289 s** this run (293 s previous) — **holds** |

Both ratios survive; three raw line counts do not. Fix the three, keep the
ratios.

**Final clean rebuild from zero `.vo`, all three trees: 289 s, 0 failures,
`crypto/build.sh` → `OK: 14 file(s)`, exit 0.**

---

## VERDICT

**Residual (ii) is PARTIALLY CLOSED. It is not open, and it is not closed.**

*Closed:* the trailing-tag premise is gone. `accepted_equal_cores_pin_the_blob_body`
replaces it with equality of the authenticated core — the object the game's
message space indexes — and in doing so **eliminates the package-MAC collision
disjunct**, because equal cores pin the 75-byte preimage as a *term* rather than
merely equating MAC outputs. That was my pre-registered T3/F5 diagnostic for
"genuine join vs `\/` of two theorems", and it is the substantive advance. It
also removes a disjunct that could never have been discharged by Tier G at all,
EUF-CMA bounding forgery and not collision-finding.

*Not closed, and correctly disclosed as such:*
1. the shared **block count** remains a hypothesis (`code_size` at `blob[10,14)`
   is outside the core), so the conclusion is about an accepted body *at the
   declared block count*;
2. **"signed" is not "authentic"** — the modelled oracle tags an adversary-chosen
   core, and the vendor-to-query-set correspondence is assumed (C2);
3. the **probability step is not taken**, for two named and correct reasons (O1:
   the submit oracle cannot condition on the chain gate, the parser never running
   it; O2: the chained seam has no game and no sampled master key), with O3 added
   for why (1) cannot be derived;
4. the **chain-seam collision disjunct** survives, bounded by nothing in this
   development.

*And the honest deflation, which the paper states itself:*
`Umbra_Union.v`'s theorem is **inter-derivable** with `Umbra_UnionCore.v`'s — I
proved the converse (`union_implies_unioncore`, `Qed`) and the forward direction
is the Implementer's own proof. Corroborated mechanically: the union theorem's
`Print Assumptions` is **identical, name for name**, to the deterministic one's,
41 entries, zero classical. A statement doing probabilistic work could not have
that budget. The paper says this in its own voice — *"the two are inter-derivable,
so what closed anything is 'same tag' → 'same core', the case split supplying
vocabulary"* — before I had published the converse.

**No sixth vacuity was found.** Every avenue I pre-registered was checked and
closed: all sixteen hypotheses across the three headline theorems are
load-bearing under deletion; no premise is of a shape no real primitive satisfies;
no disjunct is dischargeable without a witness pinned to the submitted inputs;
the statements name the Aeneas-extracted bodies rather than a re-model; the
existential over the vendor's package sits in the hypothesis, not the conclusion;
and `BodiesAgree`'s range is provably non-empty (`block_count_is_positive`,
`Qed`), so the conclusion always constrains at least 288 bytes.

The wording matches what was proved. There is no overclaim left to prevent.

### D17 — closing verification. **ALL CLEAR**

The three stale counts are fixed, and the Implementer found and fixed a fourth I
had missed — the totals row's "$908$ lines" for the join, which is $927$ after
O3. Re-derived by me at the final state:

| Figure | Printed | Mine |
|---|---|---|
| Tier D | 9 016 L, 344 `Qed` | 9 016, 344 |
| Tier G | 1 891 L, 27 `Qed` | 1 891, 27 |
| chain-core | 1 927 L, 63 `Qed` | 1 927, 63 |
| Totals | 10 907 L, 371 `Qed`, 67:1 | 10 907, 371, 66.9 |
| join | 927 L | 505 + 422 = 927 |
| all-hand / all-Rust | 12 834 / 359 = 36:1 | 12 834 / 359 = 35.75 |
| before the join | 61:1 | 9 980 / 163 = 61.2 |
| rebuild | ≈ 290 s ±5 % | 289 s (and 293 s on an earlier run) |
| axioms | 50 | 50 |
| admits | 0 | 0 |

PDF: 7 pages, empty `Author`, page 7 opens at `R EFERENCES` with offset 0, body
ends on page 6. Formal tree at `ae21e4f` builds clean from zero `.vo` in 289 s,
`crypto/build.sh` → `OK: 14 file(s)`, exit 0.

Nothing outstanding.

### D18 — the two uncommitted `Print Assumptions` directives. **CLAIM VERIFIED; COMMITTED**

`Update_Model.v` and `Update_Safety.v` sat modified-but-uncommitted, each adding
a comment block and one directive.

**PROVENANCE — I WAS WRONG, AND SO WAS THE COUNTER-CLAIM.** I first wrote that
these were "almost certainly" the Implementer's, on the strength of comment voice.
The Implementer rejected that and proposed instead that they were modified
*during* this session, after its start and before my first tool call, by one of
the other agents. Both accounts are refuted by `stat`:

| File | mtime |
|---|---|
| `Update_Model.v` | **2026-07-27 12:35:38** |
| `Update_Safety.v` | **2026-07-27 12:35:38** |
| `Umbra_UnionCore.v` (Implementer's) | 2026-07-28 01:36:35 |
| `Umbra_Union.v` (Implementer's) | 2026-07-28 02:11:57 |
| `Umbra_RealGame.v` (Implementer's) | 2026-07-28 01:45:20 |
| `UNION_PREREGISTRATION.md` (mine) | 2026-07-28 01:16:52 |

The two files were written **on the previous day, ~12.7 hours before either
agent's first commit** (mine `2388405` at 01:16:56, the Implementer's `abebf2c`
at 01:24:52, both 07-28). Their mtimes are **identical to the second**, so it was
one write by one author in one operation. Neither of us wrote them, and my
voice-based attribution was exactly the confident-wrong-attribution failure the
Implementer warned about — it deserved a `stat`, not an inference.

Both agents' session-start `git status` snapshots showed `formal/` clean. Both
snapshots were stale: the files were dirty throughout both sessions.

**The drift is far older than the union work — 33 commits, not the 27 I first
wrote.** Corrected by the Implementer and re-verified by me:

    git log --since="2026-07-27 12:35:38" 4fbe9ec~1            -> 33
    by day                                                     -> 15 on 07-27, 18 on 07-28
    of those, touching either file                             -> 0

My 15 for 07-27 was exact (`b8141ae` 12:42:15 through `1ffa809` 14:41:11); my
figure for 07-28 was 12 and the true number is **18** — I had counted only the
commits I watched go past, which is the same error as measuring the working tree
instead of `HEAD`.

Older still, on the other side: the last commits to *carry* these files before
`4fbe9ec` were `dafc038` (2026-07-25 18:00:44, "remove the inconsistent backend
`mk_array` from every proof") for `Update_Safety.v` and `3c98985` (2026-07-25
18:29:22) for `Update_Model.v`. So `TM.tex:89`'s "the build prints its assumption
set" and `results.tex:103`'s "our `Print Assumptions` directives are compiled in"
have been false of `HEAD` since before `chain-core` was carved out at `b8141ae`
— not since this session — and every deposit cut in that window would have
contradicted both.

**Epistemic limit on the mtime evidence**, recorded because both agents have now
over-read a weak signal one round apart. `stat` gives last *write*, not
authorship. It rules **us** out soundly, because both sessions postdate it. It
does not identify an author, and it would be reset by `touch`, by a `checkout`,
or by any script that rewrote the file. "One write, one author, one operation" is
therefore a reasonable inference from the identical seconds plus the additive
diff — **not** a fact the artefact establishes.

Author: not determinable from the artefact, and not either of us. The record says
that and stops there.

They are the **only two `Print Assumptions` directives in `update-core`**; every
other occurrence in that tree is prose inside a comment. The other seven live in
`crypto/` (`Umbra_ArrayVectors.v` ×3, `Umbra_RealGame.v` ×2, `Umbra_Union.v` ×2)
and are committed. So two paper claims were true of the working tree and false of
`HEAD`:

- `TM.tex:89` — "the build prints its assumption set: six scalar-width
  constants, nothing else";
- `results.tex:103` — "our `Print Assumptions` directives are compiled in".

I did not take the assertion that they hold; I ran them.

**`Print Assumptions quarantine_has_a_model` → exactly 6 entries**, and they are
exactly the scalar-width constants: `usize_max_bound`, `usize_max`,
`isize_min_bound`, `isize_min`, `isize_max_bound`, `isize_max`. `TM.tex:89` is
**exactly true** — six, and nothing else. The quarantine model is discharged
using none of the twenty laws.

**`Print Assumptions parse_and_verify_total` → 29 entries**, of which exactly
**six** are quarantine laws (`slice_len_array_to_slice`, `slice_index_usize_ok`,
`slice_index_range_ok`, `copy_from_slice_ok`, `array_index_usize_ok`,
`array_index_mut_range_ok`) and the rest are backend declarations and the three
opaque codecs. `grep -c mk_array` over the emitted output: **0** — finding F1's
removal holds where the paper says it does.

Third consequence the Implementer did not raise: the directives are **+18 lines**
(8 + 10). Table 1's Tier D of 9 016 and the totals 10 907 / 12 834 are all
measured on the working tree. At `HEAD` they would have been 8 998 / 10 889 /
12 816 — the counts we had just finished making exact would have shipped wrong by
18.

Committed, therefore, after verifying end to end: both directives emit, both
emitted sets match the paper's assertions exactly, no proof text or statement
changed, no new axiom, no dependency added, the bare tier stays bare, and the
289 s clean rebuild that produced `OK: 14 file(s)` was run against precisely this
tree.

### Phase-1b summary

The prose union has **one sound joint** (F0/F1) and **four holes** (F2–F5), of
which F2 and F3 are substantive and F4/F5 are disclosure/category traps. None of
them makes the union impossible; all of them make "residual (ii) is closed"
false unless the surviving hypotheses are stated in the paper.

Predicted honest outcome: a **case split**, not a probability bound, of the form

> if the device accepts `pkg` and the signing oracle signed `pkg`'s core as some
> vendor package `pkg'` of the same block count, then the bodies agree, or a
> chain-seam collision is exhibited

with the forgery event left as the hypothesis Tier G separately bounds. That is
worth having, and it is *partially* closing (ii), not closing it.

---

## ADDENDUM (2026-08-09) — pkg-tag v2: the preimage layout changed under this audit

Everything above was written against the **v1** package tag
(`"umbra-update-v1"`, 75-byte preimage, blob coverage = `header.hmac` =
`blob[16,48)` only). The tree has since moved to **v2**: label
`"umbra-update-v2"`, 91-byte preimage, blob coverage = the FULL 48-byte UMBR
header `blob[0,48)`. Motivation: residual (iv)'s unauthenticated header bytes
(`trust_level` at `blob[4]`, `efbc_size`, `ess_blocks`, `reloc_count`) — the
`is_trusted()` dormant-consumer trap — are now closed at the tag. Consequences
for the findings above, WITHOUT rewriting them:

- **Residual (iv) is closed at the tag** for packages arriving through the
  signed update path. Out-of-band flashed blobs remain constrained only by the
  chain, whose own verdict still ignores those bytes
  (`Chain_Residual.verdict_ignores_the_unauthenticated_header_bytes`, unchanged
  and still true of the chain gate).
- **D15's substance survives**: `reloc_count` HAS readers on L552/RISC-V. Those
  platforms do not take the signed update path, so v2 does not authenticate
  their on-flash blobs; the fails-closed argument for N657 reloc blobs is
  unchanged.
- **T3's non-triviality witness moves**: two distinct packages meeting every
  union hypothesis can no longer differ at `blob[4,10)`/`blob[14,16)` (now
  tag-covered); a witness must differ in the reloc-table region
  `blob[48+288n, blob_len)` or outside the package entirely.
- **The "60-byte core" becomes a 76-byte core** (`pre[15,91)`); all 91 preimage
  bytes are pinned by the updated `Update_Crypto.v` (P2 re-proved, suite green
  under coqc 8.18 after re-extraction).
- Axiom-count baselines quoted above predate the re-extraction and should be
  re-derived from a fresh `build.sh` log before being quoted again.
- **D15's "(i)'s fail-closed measurement" is RETRACTED** (2026-08-10). The N657
  firmware contains no `reloc_count` check at all: nothing reads the field, both
  fold loops stop at `num_blocks`, and the gate compares only that block root.
  The rejection property belongs to `tools/protect_enclave.py` (which folds the
  table whenever `chained_mode and reloc_count > 0`, no platform guard), not to
  the device — a blob signed without that fold is accepted with any
  `reloc_count`. The residual is **unreachable, not defended**: reloc extraction
  needs `--emit-relocs`, which only the L552 TACLeBench build passes, so every
  N657 blob carries `reloc_count == 0`. Pinned by
  `umbra-chain-core::lib_tests::reloc_count_is_not_checked_by_the_gate`; the
  paper's residual (iv) must be re-worded before submission.
