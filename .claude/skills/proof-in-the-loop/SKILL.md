---
name: proof-in-the-loop
description: >
  Extraction-and-proof methodology for Rust crates targeting Lean via
  Charon/Aeneas, in which a failed proof obligation is a design input: the
  code changes, not only the proof. Takes a source crate, extracts it,
  proposes properties across three first-class categories — functional,
  security (safety-style), and computational (game-based / reduction-style) —
  gets approval on the property set, attempts proofs, and on failure
  classifies the cause (extraction-shape limit, backend-theory gap, or a
  genuine defect in the code or in the claimed spec itself) before proposing
  a fix and restarting. Continues until every approved property is proved
  with no `sorry`, then discharges the three tool-boundary obligations.
  Trigger: "run proof-in-the-loop on <crate>", "propose properties for
  <crate>", "extract and prove <crate>", "classify this proof failure".
---

# Proof-in-the-loop

Verification as a development practice, not a post-freeze audit. A component
of the artifact under development is carved out, extracted mechanically into
Lean, and proved; when an obligation cannot be discharged, **changing the
code counts as a response alongside strengthening the proof**. The two
alternate until a guarantee and a revised artifact come out together.

Three commitments separate this from verification applied after a design
freeze:

1. **The object proved is carved from the source the artifact is built
   from** — a leaf crate the rest of the system is rewired to call, so the
   proof covers no transcription whose fidelity has to be argued separately.
   The carving is itself a modification no proof covers: it introduces
   defects of its own, counted as a cost of the practice.
2. **A failed proof is a design input.** When the extractor cannot handle an
   idiom, strengthening the proof is not available and changing the code is.
   Raised after a design freeze the same obligation would only produce a
   limitations note.
3. **Every tool boundary carries a validation obligation of its own.** A
   machine-checked theorem is silent about what happens between tools — see
   Step 8.

What leaves the loop is a pair whose halves are not independent: the
guarantee is conditional on the artifact having the shape the proof assumed,
and the artifact has that shape because the proof asked for it.

The point is the loop, not any particular resulting proof. Every
classification decision must land in the campaign log (Step 9) so someone
else could replay it without the originating conversation.

## The loop

```
input crate
  -> extract to Lean (charon + aeneas)
  -> propose properties (functional / security / computational)
  -> approve the property set
  -> attempt proofs
  -> on failure: classify -> propose fix (confirm per table) -> apply
  -> restart from extract (code changed) or attempt (only spec/proof changed)
  -> every approved property closes with no `sorry`
  -> discharge the boundary obligations O1-O3
```

## Step 1 — Input

A leaf crate, or the module it wraps if no crate exists yet. Establish two
things up front:

- **The baseline.** If the component has been through a proof loop before,
  the baseline is its state *before any proof-induced change* — which is not
  the same as a single commit. Keep legitimate architecture (crate
  boundaries); revert changes the loop itself caused. Enumerate them
  explicitly and record each with its baseline commit; a partial revert
  silently re-runs the loop on its own output.
- **The cryptographic surface.** Does the crate call a MAC/signature seam?
  That decides whether a computational property is proposed in Step 3.

## Step 2 — Extract

```
charon cargo --preset=aeneas --dest-file=<crate>.llbc
aeneas -backend lean <crate>.llbc -dest formal/lean/<Crate>/<Crate> -split-files
```

Extraction must be **one scripted, idempotent command** over pinned Charon
and Aeneas submodules, failing loudly on anything unhandled, so no later
change silently reintroduces what a patch removed. Record the pins.

Known post-generation patch: a hyphenated crate name (`my-thing-core`) emits
`import My-thing.Types`, an invalid Lean identifier. Fix the import line;
keep the fix in the extraction script, not by hand.

Count and report the split: lines emitted verbatim vs. lines that are yours
(shims, patches, external-function definitions). Ours-vs-theirs is part of
the trusted base.

## Step 3 — Propose properties, three categories

Mine existing ground truth first, in this order — the point is to avoid
inventing a spec when the project already has one:

1. The project's threat model / crown-jewel claims.
2. Any protocol- or architecture-level model already verified elsewhere
   (model checker, protocol prover); its properties are the intended spec
   even when the model is not the code.
3. Any prior verification report for the same component — its theorem
   statements are the existing functional/security spec, and its
   cryptographic write-up the existing computational spec.
4. Property tests, which encode informal invariants where no formal
   statement exists.

**Functional** — behavioral correctness ("the selector picks the strictly
greater version", "the block list covers the requested range").

**Security (safety-style)** — invariants and implications, not probabilistic
("acceptance implies the authenticator was checked against these exact
bytes", "two live allocations are disjoint").

**Computational** — only where a MAC/signature seam exists. Game-based,
reduction-style bounds (EUF-CMA-style forgery bounds and similar), built on
a Lean game-based cryptography framework (SSProve-style: packages, state
separation, pRHL). The interesting form makes the **extracted function
itself the oracle** of the experiment rather than proving a bound about a
hand-written specification — that is what extraction into a proof assistant
buys over annotation-based tools.

Do not reach for a framework's off-the-shelf catalog assumption without
checking its shape: a single-query indistinguishability game is not the
adaptive multi-query `gettag`/`checktag` oracle game a real forgery bound
needs. Author the experiment to the shape the bound requires: real/ideal
packages, a stateless reduction package, and a triangle-inequality bound.

Where a category has no existing artifact, propose candidates:
functional/security from {memory safety, isolation, anti-replay,
anti-rollback, integrity, tamper-evidence}; computational from
{EUF-CMA-style forgery bound} if a seam exists.

Write every proposed property as a Lean theorem statement with `sorry`,
committed **before** any proof attempt. These are editable at any point,
directly or inline; re-read before every attempt, never cached.

## Step 4 — Approval

Confirm/edit/reject the full proposed set (all three categories together)
before attempting any proof. Record the approved set in the campaign log.

## Step 5 — Attempt

Functional/security: `step*` / `scalar_tac` / `omega` / library search
(`lean_loogle`, `lean_local_search`), per the Aeneas tactic-guidance skills
(`aeneas-lean-core`, `aeneas-tactics-quickref`, `proof-patterns`). Loops:
`loop.spec_decr_nat` with an explicit measure and invariant; the invariant
usually needs to carry a *monotonicity* clause as well as a progress clause.

Computational: build the game and the reduction in the chosen framework;
keep the deterministic layer free of any principle the probabilistic layer
imports (build realizers constructively rather than invoking choice, even at
the price of an extra premise you then prove).

## Step 6 — On failure, classify

| Class | Meaning | Action | Auto-approve? |
|---|---|---|---|
| A — extraction-shape | the extractor/IR cannot represent the idiom | propose a behavior-preserving code refactor, re-extract | **never** — always confirm |
| B — backend-theory gap | the target library lacks a lemma or a model | supply/find it | yes (proof-side only) |
| C1 — code defect | the code actually violates the property | propose a fix | **never** — always confirm |
| C2 — spec/hypothesis defect | the claimed property, or a supporting hypothesis, is too weak, vacuous, or false | propose a spec correction | **never** — always confirm |
| C3 — implicit assumption | the code relies on a real, currently-holding, undocumented invariant | surface it as an explicit precondition | applied automatically, but **always** logged as a flagged finding |

C1–C3 are "the proof was right to fail" — a genuine defect, in the code or
in the claimed spec itself — distinct from A/B, "the tooling was the limit".
Typical instances: a refactor-introduced fail-open branch that returns a
constant compared against attacker-supplied bytes (C1); a game whose message
index admits values no execution can produce, letting an adversary win with
advantage 1 in the gap (C2); a bound the code trusts every caller to respect
and never checks (C3).

A Class-A finding is worth distinguishing further: an idiom the **frontend**
cannot lower will fail on every backend, while one that only the **target
backend's library** cannot model may extract cleanly elsewhere. Re-running
extraction under a second backend, or a newer pin, is what tells them apart
— and only the first justifies changing the code.

Where the table says "always confirm", propose the fix but follow direction
if given rather than only offering accept/reject.

## Step 7 — Restart

Re-extract (Step 2) if code changed; otherwise re-attempt (Step 5). Continue
until every approved property in every category closes: no `sorry`, and
`#print axioms` showing only foundational axioms or documented, logged
additions.

## Step 8 — Boundary obligations

The generalizable results of a loop are rarely the theorems. The failures
occur not inside a tool but at the boundaries between tools, where a
machine-checked proof has nothing to say. Discharge these explicitly, each
with the failure that motivated it:

**O1 — audit the assumptions the toolchain contributes.** A dependency
contributes obligations you did not author, so an axiom list free of *your*
axioms establishes nothing about non-vacuity: an unsound library axiom
closes theorems by `Qed`/`rfl` and leaves them vacuous. Two steps discharge
it. First, **quarantine** the postulated operations in one block and exhibit
one model satisfying them *jointly* — an inconsistent axiom set has no
model, which is how you find one. Second, **make the model the
definition**: keep the names and types, define every postulated operation,
and the laws become lemmas. That closes the logical gap only; that the
definitions model the source language faithfully stays argued, not proved.
Report the axiom list for every top-level theorem, and note that
`noncomputable` is about executability, not soundness.

**O2 — prove the implementation's image covers the model's domain.** A proof
can be correct and irrelevant. Wherever an abstract domain meets a concrete
one — a game's message space against the code's byte space, a spec's index
type against reachable states — either prove the implementation's reachable
image covers the domain, or turn an uncovered point into an adversary.
Review does not catch this; state it constructively and check that removing
one reachable vector reconstructs the counterexample.

**O3 — reconnect the refactoring to the deployed artifact.** Carving a
verifiable crate out of deployed source changes that source, and the
difference is the part no proof covers. **Proof coverage and defect coverage
are different quantities**, and refactoring for verifiability moves code out
of the second without moving it into the first — a premise of totality on a
seam is satisfied by a total but wrong implementation, and no further
proving over the crate reaches it. Evidence here is differential and
structural, not deductive: a known-answer test pinning pre-carve-out code,
shim and crate to identical outputs, plus a symbol-level check that the
deployed binary contains the crate's function monomorphized at the real
primitive (which needs an inlining barrier on the seam entry, invisible to
extraction).

## Step 9 — Campaign log

One entry per iteration in the campaign log (default
`formal/lean/CAMPAIGN.md`): crate, property and category, classification,
action taken, resulting commit, axiom accounting. This is the
reproducibility artifact — the log plus the baseline commits plus the pinned
extraction command should let a third party replay every decision.

Two disciplines make the log worth trusting:

- **Label every claim as proved, assumed, or argued.** *Proved* = a theorem
  closed over the extracted body, its scope fixed by its own hypotheses.
  *Assumed* = a named hypothesis or axiom, counted in the budget. *Argued* =
  prose not mechanized. Never let an argued claim inherit the standing of a
  proved one by adjacency.
- **Keep a cost and assumption budget.** Per layer: size, what is verified
  there, what is assumed, and which boundary obligation it raises. Report
  proof lines per source line and the axiom count of the headline theorem.
  Infrastructure reuse dominates the second crate's cost, so report per-crate
  figures separately rather than one ratio.

State where the guarantee stops as precisely as where it holds: which
transcriptions live outside the verified crate, which regions no
authenticator reaches, and which steps are tested rather than proved.
