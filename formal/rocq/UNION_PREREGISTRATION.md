# Pre-registered falsification tests for the Tier-D / Tier-G union

Written BEFORE the union theorem existed. Anything not on this list that the
union happens to satisfy is a coincidence; anything on this list that it fails
is a defect. Timestamped by its commit.

> **Note (post-hoc, 2026-08-09):** this record predates pkg-tag **v2**. Where it
> says the tag covers a "60-byte core"/`blob[16,48)`, the current tree covers a
> 76-byte core / the full header `blob[0,48)`. The text below is left VERBATIM as
> the timestamped pre-registration; do not read its byte counts as current.

Baseline commit: `1ffa809` ("verifiable core: re-measure the axiom budget after
removing classic"). At this commit the union does not exist; `results.tex`
§"Formalization boundaries" residual (ii) says "We argue that union in prose and
have not mechanised it."

## 0. What the union is supposed to say

Residual (ii) names the gap: `verified_update_pins_the_blob_body`
(`chain-core/proofs-coq/Chain_Compose.v`) requires **both packages to carry the
same 32 trailing tag bytes**, so it covers tag *reuse* only. The sentence a
reader wants is *an accepted body is authentic*. The fresh-tag half is Tier G
(`crypto/Umbra_RealGame.v`, `device_forgery_le_eufcma[_at_the_real_seam]`),
whose conclusion is a **game advantage inequality about the 60-byte core**, not
a statement about the blob body.

An honest union must therefore *transport* the Tier-G conclusion into a
statement about `blob[48, 48+288n)`. A disjunction that merely writes the two
existing conclusions side by side is not a union; it is a `\/`.

## T1 — Hypothesis deletion (mechanical)

For **every** hypothesis of the final union statement, in order: comment it out
(or replace its use by `admit`-free weakening), recompile the file, and record
whether the proof still closes. Deletion is applied one at a time.

- **PASS** = every hypothesis is load-bearing (deleting any one breaks the
  build).
- **FAIL** = at least one hypothesis survives deletion. This is the exact
  signature of the `Chain_Compose` bug already found here (provable with every
  hypothesis deleted) and of `C1e`.

Hypotheses that must be individually tested, at minimum, because they are the
ones the tag-reuse theorem carries today and any union will inherit:
`Hseam` (C1 factorisation), the two `parse_and_verify … = Ok (Ok r)` premises,
`to_Z (slice_len pkg1) = to_Z (slice_len pkg2)`, the trailing-tag-bytes premise
(if it survives at all — see T6), the two `verify_blob_chain … = Ok true`
premises, and the two `blob_block_count … = Ok (Some n)` premises with a
**shared** `n`.

Special case: if the union is stated in SSProve, `ValidPackage` and `fdisjoint`
side-conditions are exempt (they are well-formedness, not content), but
`Hfactor`/`SeamC1`/`ByteSeam`/`Hrange` are **not** exempt.

## T2 — Satisfiability of every premise by something resembling real HMAC

For each premise, exhibit (or demand the Implementer exhibit) a model in which
it holds and which is not degenerate:

- the premise must be satisfied by a seam that is a *keyed* function of
  (key bytes, 75 preimage bytes) — the constant function is allowed to satisfy
  it, but the premise must not be satisfied *only* by degenerate seams;
- **specifically**: no premise may be of the form "the tag determines the
  fields" or "the MAC is injective", both of which are false by pigeonhole for
  any 256-bit tag over a 600-bit preimage. `tag_determines_fields` was killed
  here for exactly this.
- if a premise quantifies over an existential witness supplied at the use site
  (the `Assembles` failure mode), it must be accompanied by a determinacy lemma
  in the style of `preimage_of_determines`, or it is presumed vacuous.

## T3 — Non-triviality of every disjunct

Every disjunct of the conclusion must be either
(a) a statement pinned to buffers the *adversary's own two submissions* induce
(the `PreimageOf` discipline), or
(b) a probability term.

Test: for each collision/forgery disjunct D, ask whether D can be discharged
**without exhibiting a witness derived from the inputs**. Concretely, check
whether D is provable from pigeonhole alone at a concrete seam (e.g. instantiate
the seam with a constant function and see whether D becomes trivially true). If
D is provable at the constant seam with no reference to the submitted packages,
D is decoration.

This applies with particular force to `MacCollisionOnPackages`: it must remain
pinned by `PreimageOf` to `(pkg_i, blob_i)`.

## T4 — The conclusion must constrain the EXTRACTED parser body

- The union's accept predicate must reduce to `Update_Funs.parse_and_verify`
  and `Chain_Funs.verify_blob_chain` — the Aeneas-extracted bodies — not to a
  hand-written re-model.
- Falsification test: delete `Update_Funs.v` / `Chain_Funs.v` from
  `_CoqProject` (or rename the definitions) and confirm the union statement
  ceases to typecheck. If the union statement survives with the extracted code
  removed, it is about a re-model.
- If the union is stated over the SSProve `DEV` package, the same test applies
  to `dev_accepts` → `accepts` → `parse_and_verify`.

## T5 — Does the theorem still say anything with no oracle access?

Restrict the adversary to zero `dsign` queries (or, in a bare-Rocq union, empty
the signed set `S`). The union must then say something *stronger*, not
something *empty*. If with `S = emptym` the conclusion degenerates to `True`,
or to "the device rejects everything", the statement has no content in the
interesting regime.

Conversely: if the union's conclusion is *unconditionally* true irrespective of
the adversary's queries, it is not a security statement.

## T6 — The specific gap the union claims to close

The union must **remove** the same-trailing-tag hypothesis, or explicitly say it
did not. Three verdict levels, decided mechanically by reading the final
statement:

- **CLOSED**: the trailing-tag premise is gone and the conclusion still
  constrains `blob[48, 48+288n)`.
- **PARTIAL**: the trailing-tag premise is gone but the conclusion is now a
  probability bound whose event does not mention the body, or a new premise of
  comparable strength replaced it.
- **OPEN**: the statement is a disjunction of the two existing theorems.

## T7 — The five bridging obligations I expect to be smuggled

Pre-registered because these are the joints where an unstated assumption will be
hidden. Each must appear **explicitly** in the closed type of the union, or be
disclosed in the paper as an assumption:

1. **Signed-set-to-package.** Tier G's ideal oracle
   (`DEV_pkg_ff`) accepts iff `(widx_ord p, wtag p) ∈ domm S`. Membership yields
   a *message index and a tag*, **not a second package**. Tier D's body-pinning
   step needs a *second blob*. Bridging requires an assumption of the shape
   "every element of `S` is `widx` of some package the vendor built, whose blob
   passes the chain gate". That assumption does not exist in the game. If the
   union produces a second blob without such a hypothesis, it is unsound or the
   hypothesis is hidden in a definition.
2. **Honest-signer freshness.** `dsign` signs an *adversary-chosen* message
   index. `(widx p, wtag p) ∈ domm S` therefore means "the adversary got this
   core signed", not "the vendor intended this body". §V B2 already discloses
   this as a prose assumption; the union must not quietly upgrade it.
3. **Equal block count.** `blob_block_count` reads `blob[0,4)` (magic) and
   `blob[10,14)` (`code_size`) — `code_size` is **outside** the 60-byte
   authenticated core, so a signed core does **not** determine `n`. The
   union therefore cannot derive `Hn1`/`Hn2` from Tier G. Either the premise
   survives (and the paper must say the union is conditional on it), or the
   Implementer proves the strengthening "equal `blob[16,48)` + both chain-accept
   ⇒ equal `n`" — which is a *new* theorem and must be checked separately, and
   which I expect to need a cross-block-count collision disjunct the current
   `SeamCollisionInRuns` does not express.
4. **Collision is not forgery.** Tier D's residual disjunct
   `MacCollisionOnPackages` is a **collision** of `mac key` at two distinct
   75-byte preimages. EUF-CMA does **not** bound collision-finding. If the union
   discharges `MacCollisionOnPackages` by appeal to Tier G's EUF-CMA advantage,
   that is a category error and I will refute it. A sound reduction from
   collision to forgery additionally needs one of the two colliding preimages to
   have been *signed*, which in the tag-reuse case is exactly what is not known.
5. **Encoding agreement.** `widx p = Z.to_nat (shrink (msg_of_pkg (wire p)))`
   must read the same 60 bytes that `Chain_Compose.PreimageOf` pins
   (`pkg[4,20)`, `pkg[20,24)`, `pkg[24,28)`, `pkg[28,32)`, `blob[16,48)`). If
   `msg_of_pkg` reads a different window, or if `shrink`'s `mod 256` collapses
   two reachable cores, "the same signed core" does not imply "the same
   `blob[16,48)`" and the union is broken at its joint. Test: exhibit two
   distinct 60-byte cores with equal `widx`, or prove injectivity on the
   reachable set.

## T8 — Axioms, admits, purity of the bare tier

- Run `Print Assumptions` on the final union theorem **myself**. Report the full
  list, not the Implementer's summary.
- Specifically flag `boolp.constructive_indefinite_description`,
  `boolp.propositional_extensionality`, `boolp.functional_extensionality_dep`,
  `realsum.__admitted__interchange_psum`, and any `classic`. If the union sits
  in bare Rocq but silently pulls in mathcomp-analysis classical axioms, the
  paper must disclose it; the paper currently discloses `realsum` for Tier G
  only.
- `grep -c 'Admitted\|admit\b'` over all `.v` files must stay at 0.
- `update-core/` and `chain-core/` `_CoqProject` files and imports must acquire
  **no** mathcomp / SSProve / mathcomp-analysis dependency. Test:
  `grep -rn 'mathcomp\|ssprove\|Ssreflect\|ssreflect' formal/rocq/update-core
  formal/rocq/chain-core` must stay empty, and both must still build with a Coq
  installation lacking mathcomp.
- Clean rebuild from scratch (`make clean` / removing `*.vo`) must succeed with
  zero errors and zero `Warning: … admitted`.

## T9 — If a probability bound is claimed

- The bound must not be `≤ 1` in disguise. Check the right-hand side is an
  `Advantage` of a *named* game, and that the message space is `256^60` (the
  byte-valid subimage) and **not** `257^60` (20.86 % dead zone,
  `restricted_space_still_admits_a_broken_seam_at_MSGBn`) and **not** `nat`
  (periodicity, advantage 1).
- The game's `submit` oracle must be `dev_accepts` → `parse_and_verify`, not a
  re-model.
- Any additive term on the right must be exhibited, not elided.

## T10 — Paper-level checks

- Recount from the artefact: hand-written Rocq lines, `Qed\.` count, axiom
  count from the emitted `Print Assumptions`. Table~\ref{tab:layers} currently
  claims 9 963 lines, 355 `Qed`, 0 admits, 50 axioms, 61:1 and 10:1. Every one
  of these must be re-derived.
- The revised residual (ii) wording must match what was proved, per T6's three
  levels. Specifically: if the block-count premise survives (T7.3), the paper
  may not write "an accepted body is authentic" without qualification.
- No honest disclosure deleted: diff §V against the baseline and check that
  every residual (i)–(v) and B1–B4 caveat still present at `1ffa809` is either
  still there or was removed *because it was discharged by a Qed I have seen*.
- Double-blind: `pdftotext main.pdf` must contain no author name; PDF metadata
  (`pdfinfo`) likewise.
- Page limit: body must end within page 6, page 7 references only.
