# Guardrails

The Umbra repo enforces a fixed set of operational rules at code-review
time. Three reviewer-facing references are kept inline in this chapter. CI mechanically enforces a subset; the rest are reviewer
judgment, cited by rule number when blocking a PR.

The rule set is **closed by default** — adding a new rule requires an architectural decision record.

## The three pages

| Page | Audience | Length |
|---|---|---|
| [NEVER_DO](never-do.md) | Reviewer + CI | 12 rules — anti-patterns with the canonical bad/good shape and the lint that catches each. |
| [ALWAYS_DO](always-do.md) | Contributor | 18 rules — positive form of the same guardrails, organised by topic (memory & safety, errors, type safety, testing, style). |
| [Code review checklist](code-review-checklist.md) | Reviewer | Multi-section table: "what to look for" + "comment shortcut" rows the reviewer copy-pastes when blocking. |

## NEVER_DO — the 12 rules

A quick scan; the full text with examples lives in
[NEVER_DO](never-do.md).

| # | Rule | Crown Jewel | Enforcement |
|---|---|---|---|
| 1  | Never `.unwrap()` / `.expect()` on attacker-influenceable data | CJ4 | clippy `unwrap_used` + `expect_used` denied in CI Job 1 |
| 2  | Never `unsafe { ... }` without a real `// SAFETY:` comment | — | clippy `undocumented_unsafe_blocks` denied |
| 3  | Never `as`-cast on size or offset calculations | CJ3 | clippy `cast_possible_truncation` (warn; expected to deny once the residual call-site bucket is migrated) |
| 4  | Never `transmute` without `#[repr(C)]` on both sides | — | clippy `transmute_undefined_repr` denied |
| 5  | Never block in fault handlers without consulting the panic policy | — | Reviewer scan + `panic_policy::handle_fault()` routing |
| 6  | Never trust NS-supplied pointers in NSC veneer impls | CJ4 | Reviewer + `arg_validation::ns_slice` gate at every NSC entry |
| 7  | Never re-implement a driver per platform when a HAL trait exists | — | Reviewer (HAL trait scan before adding driver code) |
| 8  | Never use `Result<T, ()>` | — | `grep -rn 'Result<.*, *()>' src/ crates/` must return empty (CI Job 1) |
| 9  | Never reorder DMA → MPCBB / RIF operations | CJ3 | Reviewer; `handle_ess_miss` is the canonical paired-flip implementation |
| 10 | Never modify the master key as a side-effect | CJ1 | `xtask flash` auto-revert + reviewer check on `master_key.*` diffs |
| 11 | Never commit binaries | — | `find . -name '*.bin' …` CI step + `.gitignore` |
| 12 | Never invoke a `_imp` symbol from outside its NSC veneer pair | CJ4 | Linker `PROVIDE` weakening removed; cross-crate calls produce link errors |

CJ1–CJ4 are the Crown Jewels defined in
the [Threat Model (ADR 000)](../decisions/000-threat-model.md):
CJ1 master-key confidentiality, CJ2 chained-measurement integrity,
CJ3 EFB confidentiality + isolation, CJ4 NSC boundary integrity.

## ALWAYS_DO — the 18 rules

The positive form. Organised by topic in [ALWAYS_DO](always-do.md):

**Memory & safety (4 rules).** Borrow over clone (#1). Wrap MMIO in
typed register access (#2). Use `try_into()` / `checked_*` for any
computed offset or size (#3). Every `unsafe` block: minimal scope, real
`// SAFETY:` comment (#4).

**Errors (3 rules).** `UmbraError` for every fallible path (#5). `?`
propagation through all kernel and driver call chains (#6). Error
variants describe *what*, *why*, and *what to inspect* (#7).

**Type safety (3 rules).** Newtypes for distinct domains (#8). Enums
for exclusive states (#9). `PhantomData` markers for compile-time
security domains (#10) — see [Type-state](../architecture/type-state.md).

**Testing (4 rules).** TDD red-green-refactor for new kernel logic
(#11). Property tests for invariants — `proptest` host-side (#12).
`umbra-pal-test` is the host-test entry point for kernel logic (#13).
Every fix lands with a regression test (#14).

**Style & hygiene (4 rules).** `cargo fmt --check`, `cargo clippy
-D warnings`, `cargo doc --no-deps` green on every push (#15). Public
items have `///` doc with example or invariant (#16). Cross-file
hazards observed during debugging become `///` doc on the affected
item rather than tribal knowledge (#17). Conventional commit prefixes
(`feat:` / `fix:` / `refactor:` / `test:` / `docs:` / `chore:` /
`perf:`) on every commit (#18).

## Code review checklist — the reviewer walk

The [Code review checklist](code-review-checklist.md) is the
reviewer's runtime checklist. The reviewer walks five sections —
Correctness, Safety, Security (Crown Jewel), Testing, Style — and
pastes the "comment shortcut" column when a row fails.

The Crown Jewel section pairs each CJ with a concrete trigger:

| Crown Jewel | Reviewer trigger |
|---|---|
| CJ1 (master-key) | New code reading `master_key.bin` / `MASTER_KEY` static; new UART/USART print of crypto material |
| CJ2 (chained measurement) | Changes to `validator.rs`, the `Hash` driver, or boot-init ordering |
| CJ3 (EFB / memory protection) | New DMA call site; new MPCBB / RISAF / RIFSC register write |
| CJ4 (NSC) | New `*_imp` / `*_callable` symbol pair; new pointer arg through NSC |

## PR template integration

`.github/pull_request_template.md` prefixes its checklist with the
[Code review checklist](code-review-checklist.md) items so the
contributor self-checks before review. The body also requires:

- A documented-hazard reference inline (a `///` doc citation, an ADR,
  or a guardrails rule number) when the change touches code flagged
  as fragile.
- HW smoke result (`R0=0x72CA33A8` on L552 / L562 / N657) — the
  reviewer expects this for any change crossing the boot or kernel.

## Architectural decisions and supersession

Architectural decisions live in the [Design Decisions](../decisions/README.md)
section. Each ADR is immutable once **Accepted**; superseding
decisions land as new ADRs that link back to the original.

Adding a new rule to NEVER_DO / ALWAYS_DO requires an ADR if it
materially changes the security posture, or an inline entry on the
relevant guardrails page otherwise. The reviewer can trace from PR
diff back to the guardrails number back to the ADR without leaving
the book.
