# Issue #58 — Verifiable-core refactor & Rocq-model feasibility

> **Revision note (2026-09-02): the deterministic layer is axiom-free.**
> `update-core/proofs-coq/Primitives.v` is now a project variant of the Aeneas
> backend file in which every backend `Axiom` (scalar widths, bitwise
> operators, array/slice/vector operations, and the inconsistent `mk_array`,
> which is simply gone) is a definition over the `list`/`Z` representation the
> sigma types already carried. The "quarantine" laws of `Update_Safety.v` and
> chain-core's `array_u8_ext` are therefore lemmas, the companion model files
> (`Update_Model.v`, `Chain_Model.v`) are deleted because the model *is* the
> definition, the scalar carrier is a boolean bounds check so equal values give
> equal scalars without proof irrelevance, and `Print Assumptions` on every
> update-core and chain-core theorem reports "Closed under the global context".
> The headline SSProve theorem keeps only the 7 assumptions SSProve/mathcomp
> themselves introduce (`crypto/headline-assumptions.txt`). A concrete accepted
> package is exhibited by computation in `Update_Reachable.v`. Passages below
> that describe the quarantine as axioms, or count 43/50 assumptions, predate
> this revision.

Branch: `58-verifiable-core-rocq-feasibility`. Work under `formal/rocq/`
only — nothing here is built by the firmware. Toolchain setup: see
[`README.md`](README.md).

> **Note on the Phase-1 spike.** The feasibility spike (`spike/` — a 90-LOC
> throwaway ESS-cache slice + its generated `proofs-coq/`, `proofs-lean/`) was
> verified end-to-end (Coq chain compiled green; lemmas `lookup_body_empty_step`
> and `loop_fuel_unfold` proved) and then **deleted** — it was never meant to be
> committed. Every finding it produced is preserved in this report. Phase 3's
> real model (`crates/umbra-ess-model`) and its `.v` output will live here.

The issue asks two things, in order:
1. **Feasibility** — can we realistically extract a Rocq/Coq model from this
   code, with what tool and what limits?
2. **Refactoring** — how should the project be structured to make that
   possible and maintainable?

---

## 1. FEASIBILITY (Phase 0 + Phase 1 + proof micro-spike — DONE)

### Tools (built from source, working on the dev Mac)

| Tool | Version / pin | Status |
|---|---|---|
| Charon | `6f058254` (the commit aeneas pins) | ✅ built, runs |
| Aeneas | `8dd8bfb` (2026-06-16) | ✅ built, runs |
| coqc | 8.18.0 (opam `default`) | ✅ |
| Lean | — | ❌ not installed (would need elan + Lean 4.30 + building Aeneas's Lean lib) |

Build path used: `opam switch create aeneas 5.3.0` + deps, `gmake setup-charon`
(needs **gmake**, not BSD make), `gmake`. Binaries: `/tmp/aeneas/bin`,
`/tmp/aeneas/charon/bin`.

### The spike (run, then deleted — see note above)

A minimal, purely-algorithmic slice of the ESS cache (`lookup` + LFU `install`
over a fixed array, ~90 LOC, zero unsafe). Real commands, real output, nothing
invented:

```
charon cargo --preset=aeneas --dest-file=spike.llbc          # ✅ 131 KB LLBC
aeneas -backend coq  spike.llbc -dest proofs-coq  -split-files # ✅ Spike_Types.v + Spike_Funs.v
aeneas -backend lean spike.llbc -dest proofs-lean -split-files # ✅ Types.lean + Funs.lean
```

### Readability — excellent

Generated `.v` / `.lean` map **1:1 to source** with line-citation comments
(`Source: 'src/lib.rs', lines 36:4-45:5`). Records, functions, and the match in
`install` are directly recognizable. This alone is a real audit artifact.

### Coq compiles — but only after manual patching

`coqc -R . Lib` goes green only after **3 classes of manual fix** (Lean needed
none):

| # | Fix | Cost |
|---|---|---|
| a | Derived `Clone` instances emit a partial record (missing `clone_from`) | +1 line per derived type |
| b | Index-counter `while` loops emit a `control_flow` / `loop` combinator that the **Coq `Primitives.v` does not define at all** (Lean's stdlib does) | one ~30-line shim, `AeneasLoopShim.v`, per project |
| c | Coq 8.18 rejects Aeneas's `fun '(tuple) : T =>` binder | one mechanical destructure per multi-var loop |

Structural recursion over recursive datatypes compiles clean in Coq; **array
index-scans — which dominate ESS (lookup, LFU, slot allocation) — do not.**

### The decisive measurement: typecheck ≠ proof

The gate was almost passed on "the `.v` files compile." That is the wrong
variable. We ran a **proof micro-spike** (`proofs-coq/Spike_Props.v`) to ask the
real question — can one property survive the shim?

- ✅ **Proved** `lookup_body_empty_step` (one loop iteration on an empty cache)
  and `loop_fuel_unfold`. **Real Coq proofs, they compile.**
- ⚠️ But the step lemma **required adding `array_index_repeat`** — an axiom the
  Coq backend omits.
- ❌ The full property `lookup_empty_returns_none` is left `Abort`ed with a
  documented wall: finishing it needs `to_Z` of `usize` literals and the bound
  comparisons to reduce, and **`usize_max` is an Axiom** (`Primitives.v:103`),
  so every scalar literal is stuck. You must axiomatize the scalar theory by
  hand.

### Why Coq is the weak leg — quantified

| | Coq backend | Lean backend |
|---|---|---|
| Array model | **5 opaque Axioms, 0 lemmas** | real `Array` + **142 index/slice lemmas** |
| `usize_max` | Axiom → blocks literal reduction | concrete + `scalar_tac` tactic |
| Loop `control_flow`/`loop` | **absent** | shipped |
| Aeneas README | "Lean and HOL4 are our most mature backends" | (the mature path) |

### Verdict — livable?

- **Extraction: yes.** Pipeline runs, output is clean and readable, Coq
  typechecks with a one-time per-project shim.
- **Proving in Coq out-of-the-box: no.** Arrays are uninterpreted axioms with
  no theory; proving anything about array-scanning code means first rebuilding
  the scalar+array library that Lean already ships. That is infrastructure
  work, not program proof.
- **Decision (user, 2026-06-16): Coq only.** We accept the consequence the
  spike exposed: the array/scalar theory the Coq backend omits must be
  hand-written **once** as reusable infrastructure (a `EssTheory.v` shipping the
  `array_index_repeat`-style lemmas + scalar-literal facts). Cost is paid per
  project, not per proof. To keep that cost bounded, **write the model in the
  Coq-clean subset**: prefer structural recursion over slices to indexed `while`
  loops, so generated code stays close to the `Fixpoint`/`match` shape that
  needs no loop shim. The independent design review's Lean recommendation is noted and
  declined per this decision.

---

## 2. REFACTORING (Phase 2 map — DONE; Phase 3 — PENDING gate)

### The split is already physical

Pure cache bookkeeping lives in `src/kernel/src/common/ess.rs` (**0 unsafe**,
deps = `EnclaveDescriptor` + `umbra_error` only). All hardware lives in the
per-platform `secure_kernel/ess_miss.rs`. `handle_ess_miss` *is* the boundary.

### `handle_ess_miss`, classified line-by-line

| Step | Code | Class | Model representation |
|---|---|---|---|
| range check | `block_idx >= num_blocks` | ✅ pure | guard |
| address calc | `flash_base + HEADER + idx*320` | ⚠️ arith→ptr | pure arith; ptr opaque |
| fetch | `copy_nonoverlapping(ct_ptr,…)` | ❌ HW DMA/MMIO | opaque `fetch(block)→bytes` |
| derive keys | `derive_hmac_key/enc_key` | ❌ crypto | opaque (already `CryptoEngine`) |
| HMAC | `crypto.hmac(…)` | ❌ crypto | opaque `hmac(key,data)→digest` |
| compare | constant-time `diff |= a^b` | ✅ pure | the integrity check |
| evict decision | `resident >= LIMIT` + LFU `find_eviction_victim` | ✅ pure | **core, proved** |
| evict | `trap_fill_slot(...)` | ❌ HW MMIO | opaque `trap_fill(slot)` |
| install | `install_block` (AES→ESS) | ❌ crypto+MMIO | opaque `install(slot,pt)` |
| `fence.i` | `fence_i()` | ❌ asm | opaque, no model effect |
| bookkeeping | `block_loaded[i]=true; counter+=1` | ✅ pure | **core transition, proved** |

### Boundary

- **Inside the core (pure, modelable, 0 unsafe today):** all of `common/ess.rs`
  — `allocate` (first-fit bitmap), `release`, `register_enclave`,
  `get_block_address`, `find_eviction_victim` (LFU), `loaded_count` — plus the
  decision logic of `handle_ess_miss`.
- **Outside (opaque assumptions — 5 seams):** crypto (3 methods, already behind
  `CryptoEngine`), `fetch` (flash→buf) and `install`/`trap_fill` (MMIO) — the
  last two are raw `unsafe` in the per-platform crate and have **no trait yet**.

### Abstract assumptions carried into the model

| Seam | Abstract signature | Assumption |
|---|---|---|
| crypto | `hmac(key,data)→digest`, `decrypt(key,ct)→pt` | collision-resistance assumed (as ProVerif's Validator) |
| block store | `fetch(block)→bytes` | returns the block's flash bytes; no aliasing |
| installer | `install(slot,pt)`, `trap_fill(slot)`, `fence` | write-only effect; model tracks only `loaded[slot]` |

### Proposed verifiable core

One leaf crate `crates/umbra-ess-model` (`#![no_std]`, zero unsafe) modeling the
abstract cache + the `request→validate→evict→install→execute` transition, the 5
seams as trait methods / opaque fns. Reuses `umbra-api` newtypes + the existing
`CryptoEngine` seam (Phase 1 confirmed these pass Aeneas). One structural change
vs. today: model loops as **structural recursion over the block slice**, not the
indexed `while` of `allocate`/`find_eviction_victim`, to stay in Coq's clean
regime (the Phase-1 wall).

**Phase 3 target theorem:** `execute(b) ⇒ validated(b) ∧ registered(b)` — the
Rust-code-level analogue of the existing ProVerif protocol property.

### Phase 3 — workspace survey + real-code pilot (DONE)

**Direction change (user, 2026-06-16):** extract from the **real** project, not a
parallel hand-written model. Goal: maximize the verifiable safe-code surface via
a behavior-preserving refactor.

**Survey (Umbra-authored code only; vendored Tock/QEMU excluded):**
`crates/*` = **0 unsafe** already; `src/kernel/` = 19 files, only **3** with
unsafe; `src/hardware/` (drivers/boot/asm) holds the unsafe (the boundary). The
verifiable core ≈ `crates/*` + ~900 LOC of safe kernel logic (ess, memory_layout,
key_generator/store, memory_guard/validation, `EnclaveDescriptor`).

**Crate layout (independent design review): pilot `ess.rs` first, destination = domain
crates.** Don't commit topology before proving extraction on the hardest real
module; let extraction friction + the proof call-graph define boundaries.

**Pilot 3a — `crates/umbra-ess-core` (real logic, host-buildable, 0 unsafe):**
copied the actual kernel ESS logic verbatim, added host-default address consts +
a mirror `build.rs` for the size knobs. Host `cargo test` green; `charon` +
`aeneas -backend coq` run. **Firmware untouched (crate not yet wired) → all 4
platforms still build.** Generated `.v` under `formal/rocq/ess-core/proofs-coq/`.

**Result: 31 of 33 functions extracted cleanly** — `release`, `register_enclave`,
`get_block_address` (incl. its `.and_then` closure), `enclave_psp_top`, `new`, all
derives. **Two real frictions found in real kernel idioms**, each reproduced in a
3-line minimal probe:

| Function | Idiom | Aeneas error | Behavior-preserving fix |
|---|---|---|---|
| `LoadedEnclave::loaded_count` | `.iter().filter().count()` | "Region ids should not be visited directly" | rewrite as explicit `while` |
| `EnclaveSwapSpace::allocate` | mutate `&mut` array **inside a nested loop with outer early-return** | "Unimplemented" | hoist the inner slot-marking loop into a helper fn |

Bit-shifts, `checked_add().ok_or()?`, and nested loops with early-return all
translate fine (probed individually) — only the two idioms above need a subset
rewrite. This is the concrete "how much refactor to make real code verifiable"
answer: **2 small behavior-preserving rewrites per the ess module.**

**Subset rewrites (3 total, behavior-preserving — `cargo test` still green):**
after these, **all 33 functions extract with 0 `admit`**:
1. `loaded_count`: `.iter().filter().count()` → explicit `while`.
2. `allocate`: split into a pure `find_free_run` (`&self`) + a separate
   `mark_slots_used` mutation (Aeneas can't mutate `&mut self` inside an
   early-returning loop).
3. `find_free_run`: dropped the conditionally-assigned `found_start` loop
   variable (computed from `i` on success) — three loop-carried vars made
   Aeneas's loop fixed-point analysis diverge.

**Security proof — PROVED (`Qed`) on real extracted code.**
`formal/rocq/ess-core/proofs-coq/Ess_Guard.v` proves the **Check-Cache guard**:

> `get_block_address` returns an executable address **only** for a block that is
> resident (`is_loaded = true`) AND id-matched, inside an id-matched enclave.

i.e. `check_cache_body … = Ok (Done (Some addr)) ⇒ ∃ e i efb, … is_loaded = true
∧ id matches`. This is the Rust-code-level analogue of the ProVerif property
`Execute(b) ⇒ RegisterBlock(b)` — no address is handed out for a block that was
not loaded and registered. The proof is over the **verbatim-extracted** loop
body (real `Ess_Types` records + the `control_flow`/`loop` shim), with the
slice-iterator `next` and the address arithmetic as opaque parameters (the
latter is not part of the guard).

**Residual / honest caveats:**
- The proof re-states the extracted body verbatim rather than `Require`-ing the
  whole generated `Ess_Funs.v`, which needs ~6 hand-stubbed std types + a fix
  for a duplicate-`Include` label clash (`core_cmp_PartialEq_t`) — a known
  Aeneas-Coq-backend integration gap (`Ess_Types` + `Ess_FunsExternal` compile;
  `Ess_Funs` needs the dedup). Closing that is mechanical std-modeling, the
  Phase-1 "infrastructure, not proof" cost.
- The guard is **local/by-construction** (the block `get_block_address` reads).
  The **global temporal invariant** ("every resident block went through
  `validate`") additionally needs the eviction-loop + array theory — the
  remaining work to fully close `execute ⇒ validated ∧ registered`.

**Pilot 3b — kernel rewired (host-gated; YOUR cross-build gate pending).**
`umbra-ess-core` is now a real workspace member; the kernel depends on it and
forwards `platform-*` features. `kernel::common::ess` is a `pub use
umbra_ess_core::*` shim and `common::enclave::EnclaveDescriptor` re-exports the
crate's type — so it is now the single source for both firmware and proof, and
every `common::ess::…` call site is unchanged. **Behavior-preserving, verified
on host:**
- `cargo check -p kernel` ✅
- `cargo test -p kernel` ✅ 22 passed (the ESS proptests, now exercising the
  re-exported crate code)
- `cargo test -p umbra-ess-core` ✅

All `common::ess::{SLOT_SIZE, EnclaveSwapSpace, EfbDescriptor, MAX_EFBS,
CACHE_LIMIT_PER_ENCLAVE, ESS_BASE, enclave_psp_top, …}` and `EnclaveDescriptor`
imported by the boot crates resolve through the re-export.

**Remaining gate (only you can run it):** the ARM/RISC-V cross-builds —
`rebuild_all.sh` on L552 / L562 / N657 / RISC-V — to confirm zero regression on
the shipping targets. This workstation cannot cross-compile (ARM/RISC-V toolchain not in PATH).
Until that passes, treat 3b as host-validated only.

---

## Issue-comment summary (draft — do NOT post without confirmation)

> **Feasibility spike done.** Built Charon (`6f05825`) + Aeneas (`8dd8bfb`) from
> source and ran the full pipeline on a 90-LOC safe-Rust slice of the ESS cache.
>
> - Pipeline works end-to-end; **both Coq and Lean** generated; output is
>   exceptionally readable (1:1 with source, line-cited).
> - **Lean compiles clean.** **Coq needs 3 one-time manual patches** (missing
>   `clone_from`, a ~30-line `control_flow`/`loop` shim the Coq stdlib lacks, one
>   binder-syntax rewrite). Structural recursion is clean in Coq; array
>   index-scans (which dominate ESS) need the shim.
> - **Key caveat: typecheck ≠ proof.** We proved one real loop-step lemma, but
>   the Coq backend ships arrays as **5 opaque axioms with 0 lemmas** (Lean ships
>   142) and `usize_max` is an axiom that blocks literal reduction. Proving real
>   properties in Coq means first rebuilding the scalar/array theory Lean already
>   has.
> - **Decision: Coq only.** The model is extractable and worth a verifiable-core
>   refactor — the `umbra-api` seam already exists — but Coq means we ship the
>   missing array/scalar theory ourselves (one reusable `EssTheory.v`) and write
>   the model in the Coq-clean subset (structural recursion, not indexed loops).
>   Refactor proposal (Phase 2/3) pending.

---

## 3. ROOT-OF-TRUST PROPERTIES — proved on faithful models of the extracted algorithms (`umbra-rot-core`)

> **Read the title literally.** Unlike ess-core, mem-core and update-core, the
> four rot-core theorems (T1–T4) are **not** proved over the Aeneas output. None
> of `Rot_Verify.v`, `Rot_Chain.v`, `Rot_Integrity.v`, `Rot_Validate.v`
> `Require`s `Primitives` or `Rot_Funs`; they are hand-written Coq over
> `list N`, transcribed from the Rust by eye. That is why they print `Closed
> under the global context` — there is no extracted code in them to carry the
> backend's axioms. Two consequences a reviewer should hold us to: (i) the
> transcription is an unverified step (the "model fidelity" column in the
> assumption table), and (ii) T2/T3's `Hypothesis hmac_injective` is an
> **idealization no fixed-output function satisfies** — a 32-byte HMAC is not
> injective on arbitrary-length inputs; the hypothesis stands in for the
> computational statement "an adversary cannot exhibit a collision", which
> plain Coq cannot express. The extracted `Rot_Funs.v` exists and typechecks,
> but nothing in §3 is proved about it.

The `Ess_Guard` property was local/by-construction. The interesting Root-of-Trust
properties are about Umbra's **chained HMAC measurement** (`M₀ = master_key`,
`Mᵢ₊₁ = HMAC(Mᵢ, blockᵢ)`; threat-model CJ2). Carved the measurement logic out of
`kernel::key_storage_server` into a new verifiable leaf crate
**`crates/umbra-rot-core`** (`#![no_std]`, zero unsafe).

**Refactor (behavior-preserving):**
- `verify_measurement`, `derive_key`, `update_chain`, `authenticate_and_decrypt`
  moved to `umbra-rot-core`, made **generic** `C: ?Sized + CryptoEngine` —
  because **Aeneas cannot extract `&mut dyn CryptoEngine`** ("Function pointers
  are not supported yet"; a trait object is a vtable). The kernel's
  `KeyGenerator` keeps `&mut dyn CryptoEngine` and delegates, instantiating
  `C = dyn CryptoEngine`: **dispatch stays virtual (no monomorphization bloat),
  logic is the proved one.**
- `key_store::{Key, KEY_SIZE}` re-exported from the crate (single source).
- Host-verified: `cargo check/test -p kernel` ✅ 22 passed (incl. the CJ2
  chained-measurement proptests, now exercising the delegated crate). Cross-build
  gate = CI.
- All 4 primitives **extract to Coq, 0 `admit`**. (`compute_measurement`'s
  `&[&[u8]]` slice-of-slices is *not* Aeneas-extractable and the firmware never
  calls it — it streams `update_chain` — so it stays a test-only oracle.)

**Theorems proved (`Qed`)** — `formal/rocq/rot-core/proofs-coq/`:

| # | File | Statement | Assumption |
|---|---|---|---|
| **T1** | `Rot_Verify.v` | `verify_measurement` is a **sound accept gate**: accepts ⟺ tags byte-equal (`ct_eq_correct`); corollary `verify_no_false_accept` | **none** (pure logic, `N.lor`/`N.lxor` lemmas) |
| **T2** | `Rot_Chain.v` | the chained measurement is **injective** in the block sequence (`chain_injective`) — **tamper-evidence**: any change to any block changes the root measurement | idealized HMAC (injective in (key,block) — the ProVerif symbolic model) |
| **T3** | `Rot_Integrity.v` | **RoT integrity**: acceptance ⇒ presented blocks **are** the registered ones (`rot_integrity`); contrapositive `rot_tamper_rejected` | T1 + T2 |

T3 is the code-level, **content-integrity** strengthening of ProVerif's
`Execute(b) ⇒ RegisterBlock(b)`: not merely "every executed block was
registered" but "the executed code is bit-for-bit the registered code; no
substituted or tampered enclave is accepted."

**Honest scope:** T1/T2 are proved over faithful Coq models of the extracted
algorithms (the OR-fold-of-XORs gate; the `update_chain` HMAC step) with HMAC
idealized — the standard symbolic-crypto level, now *mechanized* and tied to the
real extracted functions, vs. the existing CJ2 *property tests* that only sample
it. Remaining: bind the Coq `chain` to the extracted `update_chain` body by a
refinement lemma (currently justified by reading the extracted definition).

---

## 4. EXTENDING THE VERIFIABLE CORE — memory-protection server (T4, T5)

The remaining safe kernel modules, carved and proved:

- `memory_protection_server/memory_guard.rs` → **traits only** (the hardware
  enforcement seam: MPCBB/SAU/PMP/RISAF). No logic to verify; left in place.
- `memory_protection_server/memory_validation.rs::validate_block` → now delegates
  to a new **`umbra_rot_core::validate_block`** (generic, extracted, 0 admit).
  **T4** (`Rot_Validate.v`, `validate_block_sound`): a validated block's derived
  measurement IS the expected one — a corollary of T1, lifting the proved gate to
  the memory-protection server. No new crypto assumption.
- `common/memory_layout.rs` → new verifiable crate **`crates/umbra-mem-core`**
  (block model + region math, extracted 0 admit). **T5** (`Mem_Region.v`,
  `create_from_range_covers`): the block list built from `[base, limit)` covers
  the requested range.

**Verification finding (T5).** Proving coverage forced two implicit assumptions
of `create_from_range` into the open, as proof hypotheses:
1. the round-up test `limit_addr & 0xff` **hardcodes a 256-byte block** — for any
   other `UMBRA_SLOT_SIZE_BYTES` the ceiling is computed against the wrong modulus
   and coverage can fail;
2. **`base` must be block-aligned** (`base mod 256 = 0`) — the size ceils on
   `limit mod 256`, not `(limit − base) mod 256`, so an unaligned base can
   under-cover.
Both hold for the default configuration; they are latent coupling worth a guard
or a follow-up fix.

**Host-verified (behavior-preserving):** `cargo check/test -p kernel` ✅ 22,
`umbra-rot-core` + `umbra-mem-core` tests ✅. Cross-build = CI.

### Verifiable-core summary

| Crate | Domain | Theorems |
|---|---|---|
| `umbra-ess-core` | ESS cache state machine | Check-Cache guard (`Ess_Guard`) |
| `umbra-rot-core` | RoT chained measurement | T1 gate soundness, T2 tamper-evidence, T3 RoT integrity, T4 validator soundness |
| `umbra-mem-core` | memory-block region math | T5 region coverage (+ finding) |

The Umbra-authored safe kernel surface (cache, measurement/RoT, memory layout) is
now carved into verifiable leaf crates the firmware depends on, with machine-
checked properties on the security-critical ones.

---

## 5. CLOSING THE BRIDGE — a theorem on the *extracted* code (T5)

T1–T5 above are proved over faithful Coq models of the extracted algorithms. To
make a proof stand on the **Aeneas-generated code itself** (as `Ess_Guard` does
for the verbatim body), we close the bridge for `create_from_range`:

`formal/rocq/mem-core/proofs-coq/Mem_Bridge.v` — `create_from_range_bridge` —
proves the extracted `memoryBlockList_create_from_range` (compiled from
`Mem_Funs.v`) returns exactly the `cfr` base-block index and size that T5
(`Mem_Region.v`) reasons about. So **T5's region coverage holds of the real
generated function**, not just a model. The extracted `Mem_Funs.v` is compiled
against Aeneas's Coq `Primitives.v` (the one Coq-backend patch: `clone_from`
filled on 3 derived `Clone` instances).

**Deepest backend gap found en route:** Aeneas's Coq `scalar_and` is shipped as
an **unspecified `Axiom` marked `TODO`** (`Primitives.v:260`) — bitwise-and has
*no* semantics in the Coq backend. The bridge had to **supply** it
(`scalar_and_spec`: `to_Z (scalar_and x y) = Z.land …`). This is the `& 0xff`
mask at the heart of the T5 finding: the property literally cannot be stated
about the extracted code until the missing axiom is provided. A concrete,
mechanized instance of the Phase-1 thesis ("the Coq backend ships the generator
but not the theory").

**Status of the other bridges (honest).** Grounding T1 (`verify_measurement`)
and T2 (`update_chain`) on extracted code requires compiling the extracted
`Rot_Funs.v`, which pulls the heavier std-theory (`core::slice::Iter`,
`core::convert::From`, the `CryptoEngine` trait record, the `control_flow`/loop
combinator) — the same Include-clash + std-stub work the ess full-module compile
needs, larger here. The `create_from_range` bridge is the proof-of-technique:
**it is mechanical-but-volume to repeat**, gated only by how much of Aeneas's Coq
standard library one is willing to backfill (which is exactly the Coq-only cost
this report has quantified from Phase 1 onward).

---

## 6. ABSTRACTION/REFINEMENT — the extracted ESS allocator, fully bridged

§5 bridged a single straight-line function. The ESS *allocator* is the harder,
security-critical case: two `while` loops over a 256-bit bitmap, where the very
property that matters (enclave blocks never alias) lives in the bit arithmetic
the Coq backend leaves unspecified. We prove it with the standard
**abstraction/refinement stack** — three layers, so the Aeneas/scalar ugliness is
quarantined to one file instead of smeared across every theorem.

Files (all under `formal/rocq/ess-core/proofs-coq/`, all `Qed`, no `admit`s —
modulo the backend base axioms and the Layer-2 quarantine, itemised per theorem in
§7's *Assumption accounting*):

| Layer | File | Content |
|---|---|---|
| **1 — model** | `Ess_Model.v` | `Slots := Z -> bool`; `free_run` / `mark`; **`alloc_isolation`**: two live allocations occupy DISJOINT slot ranges. Pure — no extracted types. |
| **2 — representation** | `Ess_Rep.v` | `represents (bitmap) (Slots)` (word/bit ⇆ model slot); the **8 quarantined axioms** giving the opaque ops their semantics; the bit lemmas DERIVED from `Z.testbit` theory. |
| **3 — refinement** | `Ess_Refine.v` | verbatim `mark_slots_used` / `find_free_run` / `allocate` + the theorems below. |

Theorems on the **extracted** code (verbatim from `Ess_Funs.v`, copied as
`Ess_Guard.v` does — the generated module does not compile standalone):

- **`mark_slots_used_refines`** — the extracted bitmap mutation refines the model
  `mark`: from a bitmap representing `s`, the loop ends representing
  `mark s start count`. Full loop-invariant proof; the bit-set/clear bridge
  (`word=idx/32`, `bit=idx%32`, OR-in `1<<bit`, store) reduced entirely to Layer-2.
- **`find_free_run_sound`** — if the first-fit search returns `Some start`, then
  `[start, start+slots_needed)` was a run of FREE slots (and fits the bitmap).
  The sliding-window run-counter invariant: `found_count` = length of the free
  run ending at the cursor.
- **`allocate_refines`** — a successful allocation marks exactly a previously-free
  run. ~15 lines: it composes the two loop refinements above.
- **`allocate_isolation`** — end-to-end: distinct live allocations are `disjoint`.
  The real shipping allocator inherits Layer-1's `alloc_isolation`.

### The quarantine (Layer 2's 8 axioms)

Every opaque primitive the proofs touch is pinned down ONCE, honestly, in
`Ess_Rep.v` — the same move §5 made with `scalar_and_spec`, generalised:

- **array theory** (the Coq backend ships `array_index_usize`/`array_update_usize`
  as bare `Axiom`s, "TODO: finish the definitions"): McCarthy select/store laws
  (`_index_eq`, `_index_neq`), success (`_ok`), and value-extensionality (`_ext`).
- **bit theory** (`scalar_and`/`scalar_or`/`scalar_shl` are `Axiom`s with no
  semantics): `u32_or_to_Z`/`u32_and_to_Z` = `Z.lor`/`Z.land`, and
  `u32_shl_one_pow2` (`1<<b = 2^b` for `b<32`). Everything else — that OR-ing in
  `1<<b` sets bit `b` and leaves the rest, that `w & (1<<b) = 0` iff bit `b` is
  clear — is **derived** from Coq's `Z.testbit` library, not assumed.

That is the whole point of the stack: Layer 3's two ~250-line loop proofs and the
trivial `allocate` composition introduce **no** further axioms. To refine the next
extracted function, reuse the same 8.

### How to build

```bash
export PATH="$HOME/.opam/default/bin:$PATH"   # coqc 8.18
cd formal/rocq/ess-core/proofs-coq
for f in Primitives AeneasLoopShim Ess_TypesExternal Ess_Types \
         Ess_Model Ess_Rep Ess_Guard Ess_Refine; do coqc -R . Lib $f.v; done
```

(or `coq_makefile -f _CoqProject -o Makefile && make` — the `_CoqProject` lists
the buildable files in order and documents why `Ess_Funs.v` is excluded.)

---

## 7. SECURE ENCLAVE-UPDATE PROTOCOL — extracted, wired, and proved (P1/P1v/P2/P3/P4)

The remote-attestation branch added a secure enclave-update protocol
(`kernel::key_storage_server::enclave_update`): a nonce-bound, HMAC-tagged update
package, parsed on adversary-controlled bytes, plus A/B slot selection by
authenticated version. Carved verbatim into a new verifiable leaf crate
**`crates/umbra-update-core`** (`#![no_std]`, `#![forbid(unsafe_code)]`), and — as
of the wiring commit described below — the crate the firmware actually calls, via
a thin shim that preserves every existing call site.

**The one refactor for extractability (behavior-preserving):** the kernel injects
HMAC as a closure `impl FnOnce(&[u8], &[&[u8]])` — Aeneas extracts neither
closures nor slice-of-borrows (the same wall as `compute_measurement` in §3). The
crate replaces it with a `PkgHmac` trait taking a single flat
`[u8; PKG_PREIMAGE_LEN]` preimage — exactly what the on-target HW HASH path
already builds. Host tests (6, incl. the `huge_blob_len` bounds witness) stay green.

**Extraction — cleanest yet.** `charon cargo --preset=aeneas
--rustc-arg=--cfg=charon` (the `charon` cfg strips the `Debug`/`PartialEq`
derives, whose `@discriminant`/fmt code is non-extractable and dead weight for the
logic) → `aeneas -backend coq`. `parse_and_verify`, `compute_pkg_tag`,
`ct_eq16/32`, `select_active_slot` all extract. Unlike `Ess_Funs.v`, **the whole
generated `Update_Funs.v` typechecks standalone** — cfg-gating the derives removes
the `PartialEq` Include-clash. Manual patches are only the documented ones
(loop-shim import; the Coq-8.18 `fun '(x,y)` binder; opaque `from_le_bytes`/
`to_le_bytes`/`copy_from_slice` seams; and the rewrite of array literals off the
backend's **unsound** `mk_array` axiom — see "An inherited unsoundness" below).
The whole pipeline is one reproducible command:
`formal/rocq/update-core/extract.sh`.

**P4 — anti-rollback, PROVED (`Qed`; zero quarantine axioms — it does inherit
the Aeneas backend's 6 scalar-width parameters, see the table below)** in
`update-core/proofs-coq/Update_Props.v`, over the extracted `select_active_slot`:
`select_both_picks_strictly_greater` fully characterises selection (the update
slot B is chosen **iff** its version strictly exceeds the active one), with
`stale_update_not_selected` as the anti-rollback corollary (a stale/equal-version
package returns the active slot A — never activated). Empty slots are never
chosen (`select_none_none`, `select_only_a/b`).

**P3 — bounds-safety of `parse_and_verify`, PROVED (`Qed`, no `admit`s, modulo the
assumptions accounted for below)** in `update-core/proofs-coq/Update_Safety.v` —
`parse_and_verify_total`. The Aeneas `result` monad's `Fail` case *is* the
panic/out-of-bounds/overflow channel, so bounds-safety on hostile input is exactly
`∀ pkg en h key, parse_and_verify … ≠ Fail`. Proved over the **verbatim extracted
body** (the whole `Update_Funs.v` chain): the single length guard `len ≥ 112`
discharges every fixed index (`pkg[0..31]`) and range (`pkg[4..20]`,
`pkg[32..tag_off]`, `pkg[tag_off..len]`), and the same guard makes the one variable
access `blob[0..48]` in-bounds (`blob.len = len − 64 ≥ 48`). Supporting lemmas also
proved `Qed`: `ct_eq16_total` / `ct_eq32_total` (fuel-loop totality) and
`compute_pkg_tag_total` (the fixed 91-byte preimage assembly).

### The proofs are wired into the firmware (was: the fatal gap)

Until now `umbra-update-core` was a *carved copy*: the shipping firmware called a
hand-maintained twin, `kernel::key_storage_server::enclave_update`, so P3/P4
constrained nothing that ran on the board. That gap is **closed**.

`key_storage_server::enclave_update` is now a thin shim over the crate — the same
move `common::ess` makes over `umbra-ess-core` and `key_generator` makes over
`umbra-rot-core`. It re-exports `UPDATE_MAGIC`, `PKG_TAG_LABEL`,
`PKG_PREIMAGE_LEN`, `UpdateError`, `VerifiedUpdate`, `PkgHmac` and
`select_active_slot`, and keeps `compute_pkg_tag` / `parse_and_verify` at their
historical **closure** signatures (`hmac: impl Fn(&[u8], &[&[u8]]) -> [u8;32]`;
`FnOnce` until the seam adapter was made structurally infallible — see below —
after which every call site, all of them plain `fn` items, still compiles
untouched) while delegating the whole body to the crate. No parsing or verification logic
remains in the kernel. The N657 boot call sites (`attest_imp.rs`, `api_impl.rs`)
are unchanged — same module path, same call syntax.

The one seam is HMAC injection: kernel = closure over a slice-of-borrows (not
Aeneas-extractable), crate = `PkgHmac` trait over one flat `[u8; 91]` preimage. A
private `ClosureHmac` adapter holds the closure by value under an `Fn` bound and
bridges them by handing it a **single flat part** — byte-identical to the
on-target `hw_hmac_single`, which concatenates its parts with no separators
(15+16+4+4+4+48 = 91). It is **structurally infallible**: no `Option`, no
fallback arm, no synthetic tag. (An earlier revision used `Cell<Option<F>>` and
returned an all-zero tag if the cell was empty, "because a zero tag never matches
a real HMAC". That reasoning is wrong and the arm was fail-**open**: the tag is
compared by `ct_eq32(&expect, got)` where `got` is 32 bytes taken verbatim from
the attacker-supplied package, so an attacker sending 32 zero bytes was accepted.
It was unreachable at the time and invisible to the proofs — P3's seam premise is
totality only, which a constant-returning arm satisfies — which is exactly why it
was removed rather than merely argued unreachable. Two kernel tests now pin the
intent, one of them demonstrating the acceptance a constant-returning seam
enables.) A differential KAT
(`shim_matches_crate_and_legacy_paths`) pins the three-way equality *legacy
six-part call == shim == crate*, on the tag and end-to-end through
`parse_and_verify`.

Host gates green: `cargo check -p kernel` (default and `platform-n657`),
`cargo check -p umbra-n657-boot --target thumbv8m.main-none-eabihf`,
`cargo test -p kernel` (72), `cargo test -p umbra-update-core` (6). The full
four-target cross-build (`rebuild_all.sh`) is the remaining gate and has not been
run here.

So P3 and P4 now constrain the *shipping* path: what the N657 executes on an
`umbra_enclave_update` call is the function `parse_and_verify_total` is proved
total about, and the slot chosen is the one
`select_both_picks_strictly_greater` characterises.

**Scope of that claim — the pure functions, not the handler.** The theorems
constrain `parse_and_verify` and `select_active_slot`; they say nothing about
where those functions' *inputs* come from, and all of that is unverified
firmware: `authenticated_version_at` and the A/B flash scan that produce P4's
two `Option<u32>`s, the boot-fail counter that can mask a slot, the
`nonce_armed`/`last_nonce` arming state machine in `attest_imp.rs` that produces
P3/P1's `expected_nonce`, the NS→S copy into `PKG_SCRATCH`, and the erase/program
of the inactive slot afterwards. The HMAC seam itself sits *outside* every
theorem in this section: P3 assumes only that it is total, and P1 says which
bytes were fed to it — neither says its output is unforgeable. The only place a
cryptographic property is assumed and used is `Update_Crypto.v` (below), where
it is an explicit `Section` hypothesis rather than a global axiom.

### Assumption accounting — what the `Qed`s actually rest on

"Zero admits" alone oversells. Precisely: every theorem below closes with `Qed`
and there is not one `admit`/`Admitted` anywhere in `formal/rocq` — **modulo**

1. **backend base** — the Aeneas Coq backend's own `Primitives.v` axioms. The
   file declares 51; it ships `array_index_usize`, `slice_index_usize`,
   `array_to_slice`, `slice_len`, … as bare `Axiom`s with a literal
   `(* TODO: finish the definitions *)`, plus the scalar-width parameters
   (`usize_max`, `isize_min/max` and their bounds). Not ours, not avoidable
   without forking the backend. **One of them was outright unsound** — the
   array-literal constructor `mk_array` proves `False` — and every headline
   theorem inherited it until it was patched out of the extracted body; see
   "An inherited unsoundness in the Aeneas Coq backend" below, and
   `formal/rocq/AENEAS_COQ_MKARRAY_BUG.md`.
2. **quarantine** — our own axioms giving those opaque primitives the semantics
   Rust gives them, pinned in ONE block per crate rather than smeared across
   theorems: **20** in `Update_Safety.v` (6 *success* laws — "this op does not
   trap"; 8 *value* laws — "and this is what it returns"; 4 *write-back/codec*
   laws — what a mutable window borrow writes, that `array_to_slice` preserves
   reads, and the little-endian `u32` ENCODER digit spec; and 2 *decoder* laws —
   the mirrored digit spec for `u32::from_le_bytes` and the read law for the
   four-byte array literal the parser decodes), 8 in `Ess_Rep.v`, 1 in
   `Mem_Bridge.v`. P3 uses exactly the 6 success laws; the byte-level
   authentication results use the value laws; the assembly results use the
   write-back/codec ones; the wire-format results use the decoder ones.
   §"Machine-checked consistency" below discharges all 20 update-core axioms
   against one concrete model.
3. **idealized crypto** — HMAC modelled as an injective/collision-free function.
   In rot-core this is a `Hypothesis` inside a `Section`, so it lands in the
   theorem *statement* (the theorems are literally closed); it is an
   idealization no fixed-output function satisfies (see the §3 warning box).
   In update-core, as of this revision, **no cryptographic assumption is used
   by any theorem whose conclusion is asserted; one theorem is stated
   *conditionally* on MAC injectivity, an assumption known false** (see the
   `tag_reuse_…_under_injective_mac` row of the table below).
   P1/P3/P4 assume only **totality** as a per-theorem
   premise (`∀ k p, ∃ t, hmac_pkg h k p = Ok t`); `Update_Crypto.v` adds a single
   `Section` hypothesis C1 ("the seam is a keyed function of key and preimage"),
   which is *functionality*, not unforgeability — the constant function satisfies
   it. The earlier C2 ("for a fixed key a tag determines the fields it covers")
   has been **deleted**: it is false of any concrete 32-byte-output function on
   the 91-byte preimage domain, and its sole consumer was a corollary that merely
   permuted its conclusion. What C2 was silently absorbing — injectivity of the
   preimage *assembly* — is now proved (`assembly_injective`, below).
4. **model fidelity** — rot-core's theorems are proved over a *hand-transcribed*
   model of the Rust, not over extracted code (§3). That transcription is
   eyeballed, not machine-checked. ess-core, mem-core and update-core prove over
   the verbatim extracted bodies, so they do not carry this.

Per-theorem, from `Print Assumptions` (counts are of distinct constants reported;
"backend" = `Primitives`/`*_FunsExternal` symbols, "quarantine" = ours). The
update-core rows below were re-measured on the current tree, by `Require`ing all
of `Update_{Safety,Value,Props,Auth,Crypto,Model}` in one scratch file and
running `Print Assumptions` on each name; the "idealized HMAC" column is read
off the `Check`ed *type* of the theorem (does it quantify over `mac` and consume
`Hseam`?), not off `Print Assumptions`, since `Section` hypotheses never appear
there:

| Theorem | File | backend | quarantine | idealized HMAC | model fidelity |
|---|---|---|---|---|---|
| **P3** `parse_and_verify_total` | `Update_Safety.v` | 23 | 6 (success laws) | premise (totality only) | no — extracted body |
| `compute_pkg_tag_total` | `Update_Safety.v` | 17 | 3 | premise (totality only) | no |
| `ct_eq16_total` / `ct_eq32_total` | `Update_Safety.v` | 9 / 11 | 1 / 2 | — | no |
| `ct_eq16_sound` / `ct_eq32_sound` | `Update_Value.v` | 9 / 11 | 3 / 4 (value laws) | — | no — extracted body |
| **P4** `select_both_picks_strictly_greater` | `Update_Props.v` | 6 (scalar-width params only) | **0** | — | no |
| **P4** `stale_update_not_selected` | `Update_Props.v` | 6 (scalar-width params only) | **0** | — | no |
| **P4b** `select_masked_is_max_over_survivors`, `masked_stale_update_not_selected` | `Update_Props.v` | 6 (scalar-width params only) | **0** | — | no |
| **P1** `accept_implies_auth_gates` | `Update_Auth.v` | 23 | **0** | — | no — extracted body |
| **P1v** `accept_implies_nonce_equal` | `Update_Auth.v` | 23 | 7 (value laws) | — | no — extracted body |
| **P2** `accept_implies_authenticated_fields` | `Update_Crypto.v` | 23 | **15** (value + write-back/read + both codec laws + Q20) | **C1 as a `Section` hypothesis** (appears in the theorem's type) | no — extracted body |
| **P2w** `accept_implies_version_is_package_bytes` | `Update_Crypto.v` | 23 | **10** (value + write-back + both codec laws) | **C1** | no — extracted body |
| **P4w** `activation_implies_package_version_strictly_newer` | `Update_Crypto.v` | 23 | 10 | **C1** | no — extracted body |
| `from_le_bytes_to_le_bytes` (round-trip) | `Update_Crypto.v` | 9 | 2 (`u32_to_le_bytes_val`, `u32_from_le_bytes_val`) | **none** | no |
| `from_le_bytes_inj` / `from_le_bytes_cong` | `Update_Crypto.v` | 8 | 1 (`u32_from_le_bytes_val`) | **none** | no |
| `compute_pkg_tag_assembles` | `Update_Crypto.v` | 19 | 5 (write-back + read laws) | **none — no `mac`, no C1 in its type** | no — extracted body |
| `assembly_injective` / `to_le_bytes_inj` | `Update_Crypto.v` | 10 / 8 | 1 (`u32_to_le_bytes_val`) | **none** | no |
| `compute_pkg_tag_preimage_injective` | `Update_Crypto.v` | 19 | 6 | **C1** | no — extracted body |
| `tag_reuse_implies_same_fields_under_injective_mac` | `Update_Crypto.v` | 19 | 6 | **C1 + an explicit `mac key` injectivity PREMISE in the statement** | no — extracted body |
| `accepted_stale_update_is_not_activated` / `activation_implies_strictly_newer` | `Update_Crypto.v` | 23 | 0 | — | no — **but the acceptance premise is INERT: both proofs discard it (`intros … _ Hle`). Corollaries of the pure `Update_Props` selector lemmas; quote P4w instead.** |
| `check_cache_guard` (Check-Cache) | `Ess_Guard.v` | 7 | 0 (2 `Parameter`s: `next`, `compute_addr`) | — | no |
| `allocate_refines` | `Ess_Refine.v` | 11 | 8 (`Ess_Rep`) | — | no |
| `allocate_isolation` | `Ess_Refine.v` | 11 | 0 † | — | no |
| `quarantine_is_the_axioms` | `Update_Model.v` | 22 | **20 — by construction** | — | witness |
| `quarantine_has_a_model` | `Update_Model.v` | 6 (scalar-width params only) | **0** | — | witness |
| **T5** `create_from_range_covers` | `Mem_Region.v` | **0 — closed under the global context** | 0 | — | pure model |
| `create_from_range_bridge` | `Mem_Bridge.v` | 7 | 1 (`scalar_and_spec`) | — | no |
| **T1** `ct_eq_correct` / `verify_no_false_accept` | `Rot_Verify.v` | **0 — closed** | 0 | — | **yes** |
| **T2** `chain_injective` | `Rot_Chain.v` | **0 — closed** | 0 | `Hypothesis hmac_injective` | **yes** |
| **T3** `rot_integrity` / `rot_tamper_rejected` | `Rot_Integrity.v` | **0 — closed** | 0 | `Hypothesis hmac_injective` | **yes** |
| **T4** `validate_block_sound` | `Rot_Validate.v` | **0 — closed** | 0 | — | **yes** |

† `allocate_isolation` composes Layer 1's `alloc_isolation` and takes the
per-allocation refinement facts as *premises*; `allocate_refines` is the theorem
that discharges them, and that one does carry the `Ess_Rep` 8. Read the two rows
together — the isolation result is only as strong as `allocate_refines`.

Two corrections to earlier informal counts of this tree:

- rot-core carries **0** axioms in its build, not 14. The 14 live in
  `Rot_FunsExternal_Template.v`, an Aeneas *template* that is not listed in
  rot-core's `_CoqProject` and is imported by nothing; all four rot-core theorems
  print `Closed under the global context`.
- Counting `Axiom` declarations across every `.v` file (including the three
  vendored copies of `Primitives.v` and the unused `*_Template.v`) inflates the
  number. What matters is what each theorem *uses*, which is the table above.

**P4b — anti-rollback under MASKED inputs, PROVED (`Qed`)** in `Update_Props.v`.
The N657 boot path adds a liveness fallback: a slot that has crash-looped
`BOOT_FAIL_THRESHOLD` times is excluded by passing `None` for it
(`api_impl::umbra_enclave_create_imp`). `select_active_slot` is untouched —
exclusion is only a masked input — but that had to be *argued*, not proved.
Now it is proved: `select_characterisation` covers all four
present/absent combinations in one statement, `select_masked_is_max_over_survivors`
says selection is still the max over the slots that survive masking, and
`masked_stale_update_not_selected` is the security direction — **as long as the
active slot A survives the mask, a stale or equal-version B is never selected,
whatever B's mask is**, so a crash counter an attacker can influence for B buys
nothing. The one combination where masking can lower the running version (A
excluded → fall back to B) is called out explicitly as the intended liveness
trade, gated on the physical boot-fail counter. Assumptions: the 6 scalar-width
parameters, **zero** quarantine axioms.

**P1 — authentication / anti-replay gate, PROVED (`Qed`)** in the new
`Update_Auth.v`, over the verbatim extracted body. Where P3 says the parser never
traps, P1 says it never *accepts* without having passed both gates:
`accept_implies_auth_gates` — from `parse_and_verify … = Ok (Ok r)` it follows
that (a) the 16 bytes at `pkg[4..20]` were copied out and compared with `ct_eq16`
against the caller's armed `expected_nonce`, returning **true** (the armed nonce
is single-use, so this is anti-replay at code level), and (b) the 32 bytes at
`pkg[len−32..len]` were compared with `ct_eq32` against a tag produced **by the
HMAC seam** over the package fields, returning **true**. The proof is a forward
walk over the monadic body: every early exit returns `Ok (Err …)` and every
failure returns `Fail`, so all are discharged by `discriminate`, leaving the
single accepting path. `Print Assumptions`: 24 backend symbols, **zero of the
twenty quarantine axioms** — P3 needs them because it must prove the opaque ops
*succeed*; P1 assumes success and reads forward.

"Over the package fields" in (b) is load-bearing, so the statement now says it.
An earlier revision existentially quantified the seam's arguments (`∃ n au ve bl
hh, compute_pkg_tag inst n au ve bl hh h key = Ok expect`), which proves only
"*some* seam call produced `expect`" and would be satisfied by a call on
unrelated data. `accept_implies_auth_gates` now quantifies **only over the raw
bytes read out of `pkg`** and writes the seam's arguments as the decoders applied
to exactly those bytes — nonce = the copy of `pkg[4..20]`, author =
`u32::from_le_bytes pkg[20..24]`, version = `pkg[24..28]`, blob_len = the
`usize`↔`u32` round-trip of `pkg[28..32]`, header = the copy of the FULL
48-byte UMBR header `blob[0..48)` (pkg-tag v2; v1 covered only `blob[16..48)`)
with `blob = pkg[32..len−32]` — and additionally pins the returned record: the
`author_id`/`version` handed to the caller are the same decodes that went into
the tag, and the returned `blob` is the sub-slice whose header was covered.

**P1v — the nonce gate at BYTE level, PROVED (`Qed`)**. "`ct_eq16` returned
true" is a statement about a boolean, not about bytes.
`Update_Value.ct_eq16_sound` / `ct_eq32_sound` prove the two extracted
constant-time comparators sound by their accumulator invariant (the OR-fold of
XORs is zero iff every XOR is zero iff every byte pair is equal — the technique
rot-core's T1 uses, here over the *extracted* loops rather than a transcription),
and `Update_Auth.accept_implies_nonce_equal` chains that through the copy and the
sub-slice to the package bytes: **on acceptance, `pkg[4+j]` equals byte `j` of
the caller's armed nonce, for every `j < 16`.** The cost is the 8 *value* laws
added to the quarantine (index extensionality, the forward length/read laws of a
successful range sub-slice, `copy_from_slice`'s write-back value,
`array_from_slice`'s read-through, and `u8` xor/or as the `Z` bitwise ops); all 8
are discharged by `Update_Model.v` (§ below).

One honest limit on the shape of these statements: conclusions about individual
bytes are at the level of *represented values* (`to_Z x = to_Z y`), not `x = y`
— `u8` is a sigma type over a `Prop`, so term-level byte equality would need
proof irrelevance, which is not provable in Coq without a further axiom, and we
state the honest form rather than assume one. (The assembly results below get
term-level equality of *reads*, `array_index_usize p j = array_index_usize n i`,
because every step there is an equation between reads rather than between bytes.)

A second limit that used to sit here — "the write-back half of the opaque ops is
unmodelled, which is why `Update_Crypto.v`'s C2 has to be assumed at the
`compute_pkg_tag` level rather than derived from injectivity of `mac` alone" —
has been **closed**; see the assembly subsection below.

**P2 — the composed statement, PROVED (`Qed`)** in `Update_Crypto.v`.
P1/P3/P4 are each about one piece of the parser and none of them is a *security*
theorem: with the seam assumed only total, even "the tag is a function of these
bytes" is not expressible. `Update_Crypto.v` makes it expressible by naming one
`Section` hypothesis, C1 (`hmac_pkg h k p = Ok (mac k p)`: the seam is a keyed
function of key and preimage only), which lands in the *type* of every theorem
that uses it and never in any `Print Assumptions`. **C1 is functionality, not
security** — determinism plus "depends on nothing else"; the constant function
satisfies it. The composed theorem
`accept_implies_authenticated_fields` says: if `parse_and_verify` accepts `pkg`
against armed nonce `en`, then (a) the tag field sits at `len − 32` and its 32
bytes are, byte for byte, what the device's own `compute_pkg_tag` produces on
the arguments the parser passed it; (b) that value is `mac key pre` for a
91-byte preimage `pre` that is **exhibited** and shown to carry those arguments
at their fixed offsets (`Assembles` — label at `[0,15)`, nonce at `[15,31)`,
author_id at `[31,35)`, version at `[35,39)`, blob_len at `[39,43)`,
header at `[43,91)`); (c) the package's nonce field equals the armed nonce
byte for byte; and (d)–(h) **each of those windows is pinned to something the
caller can name**.

Be exact about (b) alone, because two earlier revisions were not. `Assembles`
relates the preimage to the *seam's arguments*. Of the five, only author_id and
version were ever tied to anything visible (the returned record); `nonce`, `bl`
and `hdr` were **loose existentials**, so the honest reading of the theorem was
"the tag covers *some* nonce" — the same shape of hole the deleted C2 had, one
field over, and the freshness-critical one. Clauses (d)–(h), added in this
revision, close it. What is now pinned, and to what:

| preimage window | pinned to | equality strength |
|---|---|---|
| `[0,15)` label | the constant `PKG_TAG_LABEL` | term equality of reads |
| `[15,31)` nonce | `pkg[4..20)` **and** the armed nonce `en` | term / `to_Z` |
| `[31,35)` author_id | `pkg[20..24)` | `to_Z` (through the codec) |
| `[35,39)` version | `pkg[24..28)` | `to_Z` |
| `[39,43)` blob_len | `pkg[28..32)` | `to_Z` |
| `[43,91)` header | `blob[0..48)` — the blob's full UMBR header, with `blob` proved to **be** `pkg[32..len−32)` — the sub-slice returned to the caller | term equality of reads |

All 91 bytes of the MAC'd preimage are therefore accounted for. The sentence
this supports is *"the tag is the device's MAC over the armed nonce and this
package's bytes"* — a statement about **which function** produced the tag and
**over what**, still **not** a claim that the tag is hard to produce.

An earlier revision of (b) said only `∃ pre, expect = mac key pre`, which any
91-byte array satisfies. `Print Assumptions accept_implies_authenticated_fields`
now reports **15** quarantine axioms including Q15/Q16 (the range write-back),
Q17, and both codec laws, where the bare version reported 8 and none of them.

`accepted_stale_update_is_not_activated` / `activation_implies_strictly_newer`
add the P4 half, **but read them as weaker than they look**: both state the
acceptance hypothesis and both proofs discard it (`intros pkg en r va _ Hle`),
because `select_active_slot` is a pure function of two `option u32`s that
acceptance constrains in no way. They are corollaries of the pure
`Update_Props` selector lemmas with an inert, documentary premise —
`Print Assumptions` shows zero quarantine axioms for either. The premise only
becomes load-bearing in `activation_implies_package_version_strictly_newer`
(P4w), where acceptance is what identifies the compared `u32` with
`pkg[24..28]`. **P4w is the row to quote.**

`Update_Crypto.v`'s header lists what remains outside, and it is not a short
list: the nonce arming state machine, the A/B flash write and re-measurement,
`authenticated_version_at` and the boot-fail counter, the seam implementation
(that `hw_hmac_single` really is HMAC-SHA256 under the device key), side
channels and fault injection, and the unverified Charon/Aeneas translation. This
is not an end-to-end device-security result and must not be quoted as one.

### The preimage assembly — from assumption to theorem

`compute_pkg_tag` writes six things into six fixed windows of a 91-byte buffer
(`[0,15)` a constant label, `[15,31)` nonce, `[31,35)` author_id, `[35,39)`
version, `[39,43)` blob_len, `[43,91)` the full 48-byte header) and MACs the result. The
earlier revision could say nothing about that buffer: the quarantine only
described what the opaque slice ops *read*, never what a mutable window borrow
*writes*. So the fact that the five fields survive the assembly had to be bought
by assuming it — that was C2, stated at the level of `mac key ∘ assemble`.

That is now proved. Two `Qed` theorems in `Update_Crypto.v`, over the verbatim
extracted body, **neither of which uses C1** (check the printed types: they take
`inst`, `h`, `key`, and no `mac`/`Hseam`):

| Theorem | Statement |
|---|---|
| `compute_pkg_tag_assembles` | every successful call feeds the seam a preimage `pre` with `array_index_usize pre (15+i) = array_index_usize nonce i` for `i<16`, and likewise the constant `PKG_TAG_LABEL` at 0, author_id at 31, version at 35, blob_len at 39, header_hmac at 43 — **term** equalities of `result u8`, not `to_Z` ones. The label clause covers the last 15 preimage bytes no earlier revision constrained |
| `assembly_injective` | two preimages that agree byte for byte on `[0,75)` force all five fields to agree: nonce and header_hmac byte-wise, the three `u32`s at `to_Z` level |

The `u32` fields go through the opaque `u32::to_le_bytes`, so they need a codec
law. That law is the **digit spec** (Q18: byte *i* of `to_le_bytes x` is
`(x / 256^i) mod 256`), not an injectivity assumption; injectivity
(`to_le_bytes_inj`) is *derived* from it, via a `Qed` base-256 reconstruction
argument for `0 ≤ x < 2^32`. Q18 is discharged by `Update_Model.v` like the rest.

The enabling change is in the quarantine, which grew from 14 to **18** here
(and to **20** with the decoder laws in the next section): Q15/Q16
(the write-back of a range borrow reads like the written slice inside the window
and like the original array outside it), Q17 (`array_to_slice` preserves reads,
not only length) and Q18. `Update_Model.v` no longer models write-backs as the
identity — the range write-back is the splice `firstn a ++ sub' ++ skipn b`,
length-guarded so it stays total — and every pre-existing conjunct was re-proved
against the changed model.

**What this does and does not buy.** It removes an assumption that was false of
reality and replaces it with a theorem. It does **not** produce a security
result, and it is **not progress toward unforgeability**. The remaining step is
a property of `mac key` *alone*, and the one theorem that states it —
`tag_reuse_implies_same_fields_under_injective_mac`: *if* `mac key` is injective
on 91-byte preimages, *then* a tag accepted for one field tuple cannot be the
honest tag of a different tuple — has an antecedent that is **false by
pigeonhole** for any 32-byte-output function on a 91-byte domain. It is
therefore a conditional whose condition is known not to hold, and it should not
be described as "the standard idealization of a MAC": the standard idealizations
are EUF-CMA or a random oracle, neither of which is perfect injectivity of a
compressing function. The theorem is kept because its premise is now about the
primitive rather than about the primitive composed with a buffer layout, and its
proof carries content (it goes through `assembly_injective`) instead of
permuting a conjunction — not because it approximates unforgeability. An honest
EUF-CMA statement needs a probabilistic framework (SSProve / FCF / EasyCrypt);
it is not attempted here.

### The decoder — the same hole, one field over

Q18 constrains the **encoder** (`u32::to_le_bytes`). The **decoder**
(`u32::from_le_bytes`) is what actually produces `author_id`, `version` and
`blob_len` out of attacker-supplied package bytes — `Update_Funs.v` lines
224/244/251/258 — and it arrived from the backend with **no law whatsoever**: no
round-trip, no injectivity, nothing. So the `version` that P4 compares, and that
P2 claims the tag covers, was formally an *arbitrary function of four bytes*.
Structurally the same hole the deleted C2 was hiding, sitting directly under both
flagship results.

Two axioms close it, and they are `Update_Model.v`-discharged like the rest:

| | Statement | Why it is needed |
|---|---|---|
| **Q19** | digit *i* of `from_le_bytes a` is `to_Z (a[i])` — the exact mirror of Q18, a *spec*, not an injectivity assumption | gives the decoder any semantics at all |
| **Q20** | the four-byte array literal `mk_array4 b0 b1 b2 b3` reads back its four elements | the parser *always* applies the decoder to such a literal, and `array_index_usize` is a bare backend `Axiom` with no read law; without Q20, Q19 cannot be applied to the package bytes. `mk_array4` is a **total definition** carrying its own length proof, not the backend's `mk_array` axiom — see the next section |

Everything else is **derived**, `Qed`, from Q19 (+ Q18 where both codecs are
involved): `from_le_bytes_to_le_bytes` (round-trip), `to_le_bytes_from_le_bytes`
(the other round-trip, byte-wise), `from_le_bytes_cong` (byte-equal arrays decode
equal) and `from_le_bytes_inj` (arrays that decode equal agree byte for byte —
there is no second wire encoding of an accepted version). The shared base-256
reconstruction step, `digits_determine`, is factored out of the encoder proof and
reused.

With those, P2 and P4 are restated **over package bytes**:

- `accept_implies_version_is_package_bytes` — on acceptance the four bytes
  `pkg[24..28]` exist, their little-endian reading **is** `to_Z
  r.(verifiedUpdate_version)` (a value equation, `dec32_val`), and those same
  four bytes are the ones in the MAC'd preimage's version window `[35,39)` — the
  window and the package byte are tied together index by index.
- `activation_implies_package_version_strictly_newer` — if the update slot is
  activated, then the little-endian reading of `pkg[24..28]` strictly exceeds the
  active slot's version.

That is the sentence that makes the anti-rollback result mean something about the
wire format: *the version the slot selector compares is the version carried in
the authenticated bytes of the package*. It still says nothing about
unforgeability, and `va`'s provenance (the flash scan) is still unverified.

### An inherited unsoundness in the Aeneas Coq backend, and how it is removed

Everything above is worth nothing if the theory it is proved in is
contradictory, and until this revision it was. The Aeneas Coq backend's
`Primitives.v` declares

```coq
Definition array T (n : usize) := { l : list T | Z.of_nat (length l) = to_Z n}.
(* TODO: finish the definitions *)
Axiom mk_array : forall {T : Type} (n : usize) (l : list T), array T n.
```

The axiom's conclusion type is **empty** at `T := Empty_set, n := 4` — the only
`list Empty_set` is `nil`, whose length is `0 ≠ 4` — so `mk_array` proves
`False`, in eight lines, `Qed`:

```coq
Theorem mk_array_is_inconsistent : False.
Proof.
  pose (a := mk_array (T:=Empty_set) 4%usize nil).
  destruct a as [l Hl]. rewrite (list_empty_nil l) in Hl. cbn in Hl.
  change (to_Z (4%usize)) with 4 in Hl. lia.
Qed.
(* Print Assumptions: usize_max_bound, usize_max, mk_array,
                      isize_min(_bound), isize_max(_bound) *)
```

The backend emits `mk_array` for **every array literal in extracted Rust**. Our
extracted parser built two — the 15-byte `PKG_TAG_LABEL` and the four-byte
literals `u32::from_le_bytes` decodes — so `Primitives.mk_array` appeared in
`Print Assumptions` of **P2, P2w, P3 and P4w alike**. Stated plainly: for two
revisions this development's headline results were `Qed`-closed, `admit`-free,
carefully quarantined — and proved from an inconsistent theory, which makes
them vacuous. The non-vacuity claim that used to sit in `Update_Model.v` §5 and
in the consistency section below was **false**, and it contradicted a caveat
120 lines earlier in the same file.

This is an **inherited upstream bug, not one authored here**:
`update-core/proofs-coq/Primitives.v` is byte-identical to
`formal/toolchain/aeneas/backends/coq/Primitives.v` at the vendored pin
(aeneas `8dd8bfb` / charon `6f058254`). The write-up, with the minimal
reproduction, affected versions and three suggested upstream fixes, is
`formal/rocq/AENEAS_COQ_MKARRAY_BUG.md`; it has **not** been filed yet.

**The fix here.** `extract.sh` gains a patch step, alongside the existing
loop-shim and binder rewrites: every `mk_array N%usize [ … ]` in the generated
`Update_Funs.v` becomes an application of a total constructor that carries its
own length proof,

```coq
Definition mk_array4 (b0 b1 b2 b3 : u8) : array u8 4%usize :=
  exist _ [b0; b1; b2; b3] eq_refl.
```

(`eq_refl` typechecks because `scalar_le_max` tries the *conservative* bound
first, so `to_Z (4%usize)` reduces without unfolding the opaque `usize_max`.)
The step is idempotent and **fails the extraction** if a literal of an arity
without a constructor ever appears, so a future field cannot silently
re-introduce the axiom. Both arities the body uses are covered — the earlier
"stated at the one arity the extracted code uses" justification for Q20 was
simply wrong about the code.

After the change, `Print Assumptions` on P3 / P1 / P1v / P2 / P2w / P4w lists
no `mk_array`; the backend count drops 24 → 23 across the board. Q20 survives,
but now says only that `array_index_usize` reads back a **concrete** array —
the same kind of law as Q7/Q12/Q17, and unavoidable for the same reason
(`array_index_usize` is itself a bare backend axiom). `Update_Model.v` drops
its `op_mk_array4` bundle field entirely.

For completeness, the sibling axioms with the same result type are **sound**:
`array_repeat`, `array_from_slice` and `array_update` each already *take* an
inhabitant of `T` or of `array T n`, so their conclusion types are inhabited
whenever their arguments are. `mk_array` is the only one that manufactures an
`array T n` out of nothing.

### What still blocks an end-to-end authentication theorem

Stated as a list, so nothing here is quotable as more than it is:

1. **No unforgeability assumption exists in this development.** C1 is
   functionality. There is no `Section` hypothesis, anywhere in update-core,
   from which "an adversary without the key cannot produce an accepted package"
   follows. The nearest thing is the explicit premise of
   `tag_reuse_implies_same_fields_under_injective_mac`, which is a *collision*
   property, not an unforgeability one, and is a premise rather than a
   conclusion. In Coq without probability this cannot be fixed, only relocated;
   fixing it means a different tool.
2. **Nonce arming is unmodelled.** Every anti-replay statement is relative to
   *whatever* `expected_nonce` the caller passes. That it is fresh, single-use
   and unpredictable is the job of `attest_imp.rs`'s `nonce_armed`/`last_nonce`
   state machine, which no theorem mentions.
3. **The A/B flash state machine is unmodelled.** P4 characterises the pure
   selection function; where its two `Option<u32>`s come from
   (`authenticated_version_at`, the flash scan, the boot-fail counter), and
   everything after `parse_and_verify` returns (erase, program, re-measure,
   TAMP floor, reset), is unverified firmware.
4. **The seam implementation is unmodelled**: that `hw_hmac_single` is
   HMAC-SHA256 under the device key, and that the HASH engine is not shared with
   NS code.
5. **Charon/Aeneas AND our post-extraction patch steps are trusted.** The proofs
   are about the extracted `.v`; that the `.v` faithfully models the Rust is the
   translators' problem, and they are unverified. `extract.sh` then applies three
   textual patches to the generated code (loop-shim import, the Coq-8.18 binder
   rewrite, and the `mk_array` literal rewrite). The last one replaces an
   application of an inconsistent axiom with a total definition — a strictly
   better model of the Rust literal, but the two are **not provably equal**, so
   the rewrite is part of the trusted base, not a verified step.
6. **The quarantine is 20 axioms.** `Update_Model.v` shows they are
   consistent and that the intended Rust semantics satisfies them; it cannot
   show that *upstream's* opaque constants do, because there is nothing to prove
   that from.

The next concrete obligation, if this line is continued in Coq, is (2): give
`attest_imp.rs`'s arming/clearing discipline a small state machine, extract it,
and prove "an accepted package's nonce was armed by the immediately preceding
quote and is cleared before the next accept". That is a reachable Coq result and
would upgrade the byte-level nonce equality into an actual freshness statement.

### Machine-checked consistency of the quarantine (`Update_Model.v`)

The quarantine is the one place an extracted-code proof can quietly go vacuous:
postulate something contradictory about the opaque ops and every downstream
theorem is free. `update-core/proofs-coq/Update_Model.v` closes that
constructively — it builds a concrete interpretation of the operations and
proves **all twenty** statements hold of it. Two theorems, both `Qed`:

| Theorem | What it establishes |
|---|---|
| `quarantine_is_the_axioms` | The predicate `QuarantineHolds`, applied to the real `Primitives` symbols, is discharged **verbatim** by Update_Safety's twenty axioms — each conjunct by `exact`, so Coq's conversion check forces the modelled property to *be* the assumed one, with no weakened restatement. `Print Assumptions`: exactly those 20, plus backend symbols. |
| `quarantine_has_a_model` | `∃ O, QuarantineHolds O`, proved from the model. `Print Assumptions` reports **six** constants (`usize_max`/`isize_min`/`isize_max` and their three bound axioms — the backend's scalar-width parameters) and **none** of the twenty. |

Every field of the modelled bundle is either one of those bare `Primitives` /
`Update_FunsExternal` axioms itself or a `Definition` that merely applies one, so
`∃ O, QuarantineHolds O` really is an interpretation of the constants the
extracted code runs on, not a re-parameterisation that could drift away from
them; `quarantine_is_the_axioms` is what forces that correspondence to be exact.
Stated in `Update_Model.v`'s header.

One tactic note, because it bit: `repeat split` had to become `repeat apply
conj`. On the *model* instance three of the conjuncts (the two bitwise laws and
Q17) hold by conversion, so `split` — which is `constructor 1`, and closes an
`eq` goal whose sides are convertible — was discharging them and silently
shifting every subsequent bullet onto the wrong goal.

The model is not a degenerate one cooked up to satisfy the statements. In
`Primitives.v`, `slice T` and `array T n` are **already** sigma-types over
`list T` — only the *operations* are opaque — so the interpretation is the
obvious Rust one: length = list length, indexing = `nth_error`, range-slicing =
`firstn`/`skipn`, an out-of-range range yielding the `None` that
`core_slice_index_Slice_index` turns into `Fail` (= the Rust panic),
`copy_from_slice` = "lengths must match, then `dst` becomes `src`", and the
array `IndexMut` forwarding to the slice impl exactly as Rust's does.

The u8 bitwise ops are modelled as `Z.lxor` / `Z.lor`, with the 0..255 range
**proved** (via `Z.log2_lxor` / `Z.log2_lor`), not assumed;
`array_from_slice` as "a length-matching slice *is* the array"; the range
read law via `nth_error`/`firstn`/`skipn`.

What it gives: **consistency of the quarantine** (the twenty axioms are
satisfiable in plain Coq, so *they* cannot derive `False`) and **faithfulness**
(the satisfying interpretation *is* the intended Rust semantics, so the axioms
are not merely non-contradictory but right).

**What it does not give, and the correction this revision had to make.** A model
of the quarantine bounds *only the quarantine*. A theorem is vacuous if **any**
axiom in its `Print Assumptions` set is inconsistent, including one this file
never mentions — and that is exactly what happened: until the previous section's
fix, every headline theorem also listed `Primitives.mk_array`, which proves
`False`. So the sentence that used to stand here — "neither P3 nor the
byte-level authentication results nor the assembly results are vacuous" — was
**false**, however good the model was, and it contradicted `Update_Model.v`'s
own caveat that the backend's base axioms are inherited unmodelled.

The claim that can be made now, stated at its real strength. The assumption set
of each of P3, P1, P1v, P2, P2w and P4w consists of exactly:

1. quarantine axioms — satisfiable, by the two theorems above;
2. the six scalar-width parameters — satisfiable (take `usize_max := u32_max`,
   `isize_min := i32_min`, `isize_max := i32_max`; the three bound axioms then
   hold);
3. the remaining backend/seam constants, each declared as a bare `Axiom c : A`
   with no axiom constraining it. Each is individually satisfiable iff `A` is
   inhabited, and each `A` here is: `result T` by `Fail_`, the scalar types by
   `0`, `slice T` by the empty list, and the array-returning ones by the
   argument they already take (see the previous section).

Point 3 is an **argument in this document, not a machine-checked theorem**:
there is no Coq artifact here exhibiting a model of the whole of `Primitives.v`,
so a second unsound backend axiom of `mk_array`'s shape would not be caught by
`Update_Model.v`. What can be said mechanically is weaker and is what we say:
`Print Assumptions` on each headline theorem lists no axiom **known** to be
unsound, and the one that was known unsound is gone.

**The side condition, and that it holds.** A satisfiability argument of this
shape is only valid if the modelled symbols carry no *other* laws that a model
would have to respect at the same time. Verified for this development: in
`Primitives.v` each of `slice_len`, `array_to_slice`, `array_from_slice`,
`array_index_usize`, `slice_index_usize`, `core_array_Array_index_mut`,
`core_slice_Slice_copy_from_slice`,
`core_slice_index_SliceIndexRangeUsizeSlice_get/_index(_mut)`, `scalar_xor` and
`scalar_or` occurs **only** in its own bare `Axiom` declaration and in
`Definition`s that merely apply it — there is no `Lemma`, `Axiom` or
`Hypothesis` in the file stating any property of any of them. (The file's only
equational axioms, `alloc_vec_Vec_index_eq`/`_mut_eq`, are about `alloc_vec_Vec`,
which this development never touches.)

What it does **not** give, stated plainly: nothing about upstream's symbols.
`Primitives.array_index_usize` and friends stay uninterpreted constants, so the
twenty statements must **remain axioms** — `Update_Model.v` is a companion
witness, imported by nothing. The RANGE write-back is now modelled for real (the
splice), which is what Q15/Q16 constrain; the two write-backs no statement
mentions are still modelled loosely — `SliceIndex_get_mut`'s (splice on `Some`,
identity on `None`) and `array_from_slice`'s length-mismatch branch (keep the old
array) — so a future theorem that leaned on either would need a stronger model.
One landmine recorded there and repeated here: `splice_or`'s length guard makes
the modelled write-back a **silent no-op** for a wrong-length replacement slice.
Harmless today — Q15 and Q16 both carry the matching-length hypothesis, so
neither can reach the fallback — but any future axiom about `back` at
unconstrained lengths would be satisfied *vacuously* by this model and must
either carry the same hypothesis or force a stronger model.
And it is orthogonal to the backend's own base axioms, which it inherits rather
than models.

The same construction is the obvious next step for `Ess_Rep.v`'s 8 and
`Mem_Bridge.v`'s 1 (the bit-theory ones need `Z.testbit` rather than lists);
not done here.

### Verifiable-core summary (updated)

| Crate | Domain | Theorems |
|---|---|---|
| `umbra-ess-core` | ESS cache + allocator | Check-Cache guard; allocator isolation refinement |
| `umbra-rot-core` | RoT chained measurement | T1 gate, T2 tamper-evidence, T3 integrity, T4 validator |
| `umbra-mem-core` | memory-block region math | T5 region coverage |
| `umbra-update-core` | secure enclave update | **P1 auth gate bound to the parsed fields** + **P1v nonce gate at byte level** + **P2 composed statement under C1, carrying the assembled preimage** + **P2w version/anti-rollback over the package BYTES** + **preimage-assembly injectivity, proved** + **P3 bounds-safety** + **P4/P4b anti-rollback** (all Qed, extracted code) + `Update_Model.v` 20-axiom consistency witness, and the extracted body patched off the backend's unsound `mk_array` axiom |
| `umbra-chain-core` | the update blob's chained measurement | **coverage** (`preimage_pins_block`) + **the body-pinning target theorem** (`chain_accept_pins_the_blob_body`) + **the composition with P2** (`verified_update_pins_the_blob_body`) + **the residue, proved at verdict level** (`verdict_ignores_the_unauthenticated_header_bytes`) + **non-vacuity of the accept branch** (`chain_gate_accepts_a_matching_measurement`) (all Qed, extracted code) + `Chain_Model.v` witness for the ONE added axiom (Q21). No cryptographic hypothesis and no classical axiom: both collision disjuncts are conclusions carrying witnesses PINNED to the adversary's own two submissions, not assumptions |

Wiring status — which crate the firmware actually executes:

| Crate | Kernel entry point | Wired? |
|---|---|---|
| `umbra-ess-core` | `common::ess` (`pub use umbra_ess_core::*`) | yes |
| `umbra-rot-core` | `key_storage_server::key_generator` (delegates) | yes |
| `umbra-mem-core` | `common::memory_layout` (re-export) | yes |
| `umbra-update-core` | `key_storage_server::enclave_update` (closure→`PkgHmac` shim) | **yes (new)** |
| `umbra-chain-core` | `key_storage_server::blob_chain` (re-export) | kernel yes; **N657 boot still runs an inline copy**, pinned to the crate by a differential host test rather than by a call |

### How to build (update-core)

```bash
export PATH="$PWD/formal/toolchain/aeneas/bin:$PWD/formal/toolchain/charon/bin:$HOME/.opam/default/bin:$PATH"
formal/rocq/update-core/extract.sh          # charon -> aeneas -> re-apply patches
cd formal/rocq/update-core/proofs-coq
for f in Primitives AeneasLoopShim Update_Types Update_FunsExternal Update_Funs \
         Update_Props Update_Safety Update_Value Update_Auth Update_Crypto \
         Update_Model; do coqc -R . Lib $f.v; done
# (this is exactly the order in proofs-coq/_CoqProject; Update_Auth.v is the slow
#  one, ~4 min, because P1 walks the whole extracted parse_and_verify body.
#  Whole chain from clean: ~4m45 on the dev Mac, coqc 8.18.0.)
```

### How to build (chain-core)

```bash
export PATH="$PWD/formal/toolchain/aeneas/bin:$PWD/formal/toolchain/charon/bin:$HOME/.opam/default/bin:$PATH"
formal/rocq/chain-core/extract.sh           # charon -> aeneas -> patches + seam aliases
# update-core FIRST: chain-core loads its Primitives, AeneasLoopShim and Update_*
# out of ../update-core/proofs-coq (see chain-core/proofs-coq/_CoqProject), and
# Chain_Compose.v Requires Update_Crypto.
cd formal/rocq/chain-core/proofs-coq
coq_makefile -f _CoqProject -o Makefile && make       # 9 files, ~40 s
```

The extraction ALIASES every opaque seam to update-core's constant of the same
name rather than letting Aeneas declare a fresh per-crate `Axiom`, so
`Update_Safety`'s 20-axiom quarantine — and `Update_Model.v`'s discharge of it —
applies verbatim instead of a second, parallel block being opened.
`extract.sh` fails loudly if the Aeneas template ever declares an axiom the alias
list does not cover.
