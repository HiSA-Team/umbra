# Design Decisions

Architecture Decision Records (ADRs) capture **why** a load-bearing
choice was made — the alternatives that were considered, the trade-offs
that were accepted, and the consequences that follow. The
`architecture/` chapters describe **what** the system is; the ADRs in
this section describe **why** it is that way.

An ADR is **immutable once Accepted**. Superseding decisions land as
new ADRs that link back to the original. The historical record is part
of the audit trail.

## Index

| ADR | Status | Title |
|---|---|---|
| [000](000-threat-model.md) | Accepted | Umbra Threat Model (v1) — Crown Jewels CJ1–CJ4, attacker model A1–A3, NSC ABI invariants |
| [001](001-workspace-layout.md) | Accepted | Single Cargo workspace with leaf-crate dependency tree |
| [002](002-umbra-error.md) | Accepted | `UmbraError` enum as the canonical fallible-path type |
| [003](003-hal-traits.md) | Accepted | HAL trait surface in `umbra-hal`, impls in PAL crates |
| [004](004-type-state-security-domain.md) | Accepted | Type-state markers for the enclave lifecycle |
| [005](005-nsc-boundary.md) | Accepted | `*_imp` / `*_callable` veneer pair as the only NS→S entry surface |
| [006](006-master-key-chain.md) | Accepted | Build-time master key with `xtask flash` auto-revert |
| [007](007-panic-policy.md) | Accepted (implemented) | Panic policy: log + `SYSRESETREQ`, with `debug-halt` opt-in halt |

## Status values

- **Proposed** — under discussion, not load-bearing yet.
- **Accepted** — the project follows this; landed in code and CI.
- **Superseded** — replaced by a newer ADR (linked inline).
- **Rejected** — explicitly considered and turned down. Kept so the
  same proposal is not re-litigated.

## Adding a new ADR

1. Pick the next free three-digit number and a kebab-case topic
   (`007-multi-efb-sharing.md`).
2. Mirror the structure of an existing ADR — Context, Decision,
   Alternatives Considered, Consequences, Cross-references.
3. Set the status to `Proposed` while the decision is open; flip it to
   `Accepted` once the code and CI land.
4. Add a row to the index table above with a one-line title.
5. Add a corresponding entry in [SUMMARY.md](../SUMMARY.md) so the
   mdBook side panel surfaces it.
6. Reference the ADR's relative path in commit messages that depend on
   the decision.

## How ADRs relate to the rest of the documentation

- The **architecture chapters** (`architecture/*.md`) document the
  current shape of the system. They are kept up to date as code
  changes.
- The **ADRs** (this section) document the choice point that produced
  that shape. They are written once and frozen.
- The **contributor guardrails** (`contributing/guardrails.md`) are
  operational rules that derive from the accepted ADRs.

When an architectural chapter contradicts an ADR, one of them is
stale — open an issue.
