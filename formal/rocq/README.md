# Rocq/Coq formal-model toolchain

This directory holds the Rocq (Coq) verification work for Umbra (issue #58):
extracting a machine-checked model of the ESS cache logic from the Rust source
via **Charon** (Rust → LLBC) and **Aeneas** (LLBC → Coq). Nothing here is built
by the firmware — it is an independent verification artifact.

Backend decision: **Coq only.** Aeneas also has a Lean backend (more mature),
but this project targets Coq; see [`REPORT.md`](REPORT.md) for the trade-offs.

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

```bash
# 1. OCaml 5.3 in a dedicated opam switch (Aeneas wants OCaml 5; 5.3.0 known-good)
opam switch create aeneas 5.3.0
eval "$(opam env --switch=aeneas)"
opam install -y ppx_deriving visitors easy_logging zarith yojson core_unix \
  odoc ocamlgraph menhir ocamlformat.0.27.0 unionFind progress domainslib

# 2. Clone Aeneas (it vendors Charon at the pinned commit)
git clone https://github.com/AeneasVerif/aeneas /tmp/aeneas
cd /tmp/aeneas

# 3. Build Charon at the pinned commit — USE gmake, not the macOS `make`
gmake setup-charon          # clones + builds ./charon at the charon-pin commit

# 4. Build Aeneas
gmake                       # produces ./bin/aeneas (+ ./charon/bin/charon)

# 5. Coq, if not already present (any opam switch with coq 8.18 works)
opam install -y coq.8.18.0

# 6. Put the binaries on PATH
export PATH="/tmp/aeneas/bin:/tmp/aeneas/charon/bin:$PATH"
charon --help | head -1
aeneas -version
coqc --help | head -1
```

> `make` on macOS is the antiquated BSD version and Charon's Makefile rejects it
> (`*** You seem to be using the OSX antiquated Make version`). Always use
> `gmake` (`brew install make`).

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

1. Copy the primitives: `cp /tmp/aeneas/backends/coq/Primitives.v proofs-coq/`.
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
└── (Phase 3) proofs-coq/ + the umbra-ess-model crate's generated .v
```
