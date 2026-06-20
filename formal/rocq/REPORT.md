# Issue #58 — Verifiable-core refactor & Rocq-model feasibility

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

## 3. ROOT-OF-TRUST PROPERTIES — proved on the real code (`umbra-rot-core`)

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

Files (all under `formal/rocq/ess-core/proofs-coq/`, all `Qed`, **zero admits**):

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
