# Rocq/Coq formal-model toolchain

This directory holds the Rocq (Coq) verification work for Umbra (issue #58):
extracting a machine-checked model of the ESS cache logic from the Rust source
via **Charon** (Rust → LLBC) and **Aeneas** (LLBC → Coq). Nothing here is built
by the firmware — it is an independent verification artifact.

Backend decision: **Coq only.** Aeneas also has a Lean backend (more mature),
but this project targets Coq; see [`REPORT.md`](REPORT.md) for the trade-offs.


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

## Dependencies

| Tool | Version pinned/used | Why |
|---|---|---|
| **opam** + **OCaml** | 5.3.0 (switch named `aeneas`) | Aeneas is an OCaml program |
| **Charon** | git `6f058254eb741c12e9b388df07adaf7cc8aac8ed` | Rust → LLBC frontend; commit is pinned by Aeneas in `charon-pin` |
| **Aeneas** | git `8dd8bfb` (2026-06-16) | LLBC → Coq translator |
| **Coq** (`coqc`) | 8.18.0 | typechecks the generated `.v` |
| **rustup** | any recent | Charon installs its own nightly (`nightly-2026-06-01`) |
| **GNU make** (`gmake`) | 4.x | **required** — Charon's Makefile is not BSD-make compatible |

On macOS the Homebrew tools (`gmake`, `opam`, `rustup`) live under
`/opt/homebrew/bin`; make sure that is on `PATH`.

## Install

Charon and Aeneas are **vendored as git submodules** under
[`formal/toolchain/`](../toolchain/), pinned to the known-good commits above
(previously they lived in an ephemeral `/tmp` checkout that kept vanishing).

```bash
# 1. OCaml 5.3 in a dedicated opam switch (Aeneas wants OCaml 5; 5.3.0 known-good)
opam switch create aeneas 5.3.0
eval "$(opam env --switch=aeneas)"
opam install -y ppx_deriving visitors easy_logging zarith yojson core_unix \
  odoc ocamlgraph menhir ocamlformat.0.27.0 unionFind progress domainslib

# 2. Fetch the pinned Charon + Aeneas sources
git submodule update --init formal/toolchain/aeneas formal/toolchain/charon

# 3. Build both (needs gmake, not macOS BSD make; uses the 'aeneas' opam switch).
#    Charon pulls its own Rust nightly-2026-06-01 via rustup on first build.
formal/toolchain/build.sh    # -> aeneas/bin/aeneas + charon/bin/charon

# 4. Coq, if not already present (any opam switch with coq 8.18 works)
opam install -y coq.8.18.0

# 5. Put the binaries on PATH
export PATH="$PWD/formal/toolchain/aeneas/bin:$PWD/formal/toolchain/charon/bin:$PATH"
charon --help | head -1
aeneas -version
coqc --help | head -1
```

> `make` on macOS is the antiquated BSD version and Charon's Makefile rejects it
> (`*** You seem to be using the OSX antiquated Make version`). `build.sh`
> defaults to `gmake` (`brew install make`); override with `MAKE=...`.
> The submodules are marked `ignore = dirty`, so build artifacts under them do
> not show up as changes in the parent repo's `git status`.

## Running the pipeline

From a host-buildable, `#![no_std]`, **safe-Rust** crate (no `unsafe`, no MMIO,
no `extern "C"`):

```bash
charon cargo --preset=aeneas --dest-file=model.llbc
aeneas -backend coq model.llbc -dest proofs-coq -split-files
```

## Compiling the generated Coq

Aeneas does not copy its Coq support library, and a few manual steps are needed
(documented in [`REPORT.md`](REPORT.md) §1):

1. Copy the primitives: `cp formal/toolchain/aeneas/backends/coq/Primitives.v proofs-coq/`.
2. Use a **non-empty** logical path — `coqc -R . Lib file.v`. (An empty `-R . ""`
   clashes with the `Module Primitives` wrapper inside `Primitives.v`.)
3. The Coq backend ships **no** `control_flow`/`loop` combinator and **no**
   array/scalar theory. Index-counter `while` loops therefore need a small
   hand-written shim plus added array/scalar lemmas. Prefer writing model code
   as **structural recursion over slices** to stay in Coq's clean regime and
   avoid the shim where possible.

```bash
cd proofs-coq
coqc -R . Lib Primitives.v
coqc -R . Lib <Model>_Types.v
coqc -R . Lib <Model>_Funs.v
```

The **ESS allocator** is verified with a full abstraction/refinement stack
(`ess-core/proofs-coq/`: `Ess_Model.v` → `Ess_Rep.v` → `Ess_Refine.v`), proving
the extracted `mark_slots_used` / `find_free_run` / `allocate` refine a clean
model and so inherit spatial isolation. Build order + rationale live in that
directory's `_CoqProject`; the architecture is documented in
[`REPORT.md`](REPORT.md) §6.

## Layout

```
formal/rocq/
├── README.md            # this file
├── REPORT.md            # feasibility findings + refactor proposal (issue #58)
├── AENEAS_COQ_MKARRAY_BUG.md   # the backend axiom that proves False, and the fix
├── ess-core/            # ESS cache state machine
├── rot-core/            # deprecated historical model; excluded from artifact claims
├── mem-core/            # memory-block region math
├── update-core/         # secure enclave update — the 12-file chain, P1..P4
├── chain-core/          # the update blob's chained measurement — closes B1
└── crypto/              # SSProve: EUF-CMA for the package tag
```

### Build order

`chain-core` and `crypto` both load `Primitives.v`, `AeneasLoopShim.v` and the
`Update_*` files out of `update-core/proofs-coq`, so **update-core builds first**:

```bash
cd formal/rocq/update-core/proofs-coq && coq_makefile -f _CoqProject -o Makefile && make
cd ../../chain-core && ./build.sh      # 9 files + assumption audit
cd ../crypto        && ./build.sh      # needs SSProve; --det-only for bare Coq
```

### A caveat about `rot-core`

`rot-core`'s T1–T4 are **not** over extracted code. Those files never `Require`
`Primitives` or `Rot_Funs`; they are hand-written Coq over `list N` with the real
assumptions moved into `Section` `Variable`/`Hypothesis`. Their "0 axioms" is true
and close to meaningless. Worse, `Rot_Chain.v`'s `hmac_injective` is
**unsatisfiable** by any fixed-output MAC (pigeonhole), so what it proves is
vacuous. `chain-core` is the redone version of that argument: over the verbatim
extracted body, and as a reduction rather than under a false hypothesis.
`rot-core/DEPRECATED.md` is the tombstone: submission builds and assumption
audits intentionally exclude the directory.
