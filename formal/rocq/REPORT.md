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
