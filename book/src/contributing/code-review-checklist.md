# Code review checklist

The reviewer runs this list before approving any PR. Each box maps to
a rule in [NEVER_DO](never-do.md) or [ALWAYS_DO](always-do.md). The
"what to look for" column says how to spot a violation; the "comment
shortcut" column gives a paste-ready reviewer comment.

The PR template (`.github/pull_request_template.md`) prefixes its
checklist with these items so the contributor self-checks before the
reviewer sees the diff.

---

## Correctness

| Check | What to look for | Comment shortcut |
|---|---|---|
| All `Result` consumed; no silent `let _ =` discards | `grep -n 'let _ = ' <changed_files>` — every match must be justified | `Discarded Result here — surface via UmbraError? (ALWAYS_DO #6)` |
| All MMIO writes through typed wrapper | `core::ptr::write_volatile` / `core::ptr::read_volatile` outside `peripheral_regs::RealMmio` | `Use volatile-register / MmioAccess::write — raw write_volatile bypasses MmioMem test surface (ALWAYS_DO #2)` |
| No new `Result<T, ()>` introduced | `grep 'Result<.*, *()>' <changed_files>` | `Result<T, ()> introduces no context — return UmbraError variant (NEVER_DO #8)` |

---

## Safety

| Check | What to look for | Comment shortcut |
|---|---|---|
| Every new `unsafe { }` has a `// SAFETY:` comment | Scan diff for `unsafe {` without a preceding `// SAFETY:` line; clippy `undocumented_unsafe_blocks` should catch in CI | `Missing/empty SAFETY comment — name the invariant (NEVER_DO #2)` |
| No new `transmute` without `#[repr(C)]` on both sides | Grep for `transmute`; verify source + target types both carry `#[repr(C)]` or `#[repr(transparent)]` | `transmute requires #[repr(C)] on both sides — see NEVER_DO #4` |
| Integer arithmetic on offsets uses `checked_*` or `try_into()` | Look for `+` / `*` on `u32`/`usize` in code that computes an address or buffer length | `Use checked_add + UmbraError::OffsetOverflow — CJ3 hazard (NEVER_DO #3)` |

---

## Security (Crown Jewel checklist)

Cross-reference: [Threat Model (ADR 000)](../decisions/000-threat-model.md).

| Check | What to look for | Comment shortcut |
|---|---|---|
| **CJ1** — no path that could leak master-key bytes off-chip | New code reading `master_key.bin` or `MASTER_KEY` static; new UART/USART print of cryptographic material | `Logging or returning master-key bytes — CJ1 violation` |
| **CJ2** — chained-measurement invariants preserved | Changes to `validator.rs`, the `Hash` driver, or boot-init ordering | `Verify chained-measurement still computed BEFORE first NSC enter` |
| **CJ3** — MPCBB / RIF configuration unchanged or audited | New DMA call site; new MPCBB / RISAF / RIFSC register write | `DMA paired with MPCBB pre/post-flip? See NEVER_DO #9` |
| **CJ4** — NSC veneer arg-validation present for any new veneer | New `*_imp` / `*_callable` symbol pair; pointer arg through NSC boundary | `NS pointer needs arg_validation::ns_slice gate (NEVER_DO #6)` |

---

## Testing

| Check | What to look for | Comment shortcut |
|---|---|---|
| Host-side unit test added for new kernel logic | New function in `src/kernel/src/`; matching `#[test]` in `mod tests` of the same file or sibling | `New kernel logic without host test — add TestPlatform-backed test (ALWAYS_DO #11 + #13)` |
| MMIO test added for new driver code | New `pub fn` in `src/hardware/platform/*/drivers/src/`; matching `#[cfg(test)] mod tests` using `MmioMem` | `New driver entry without MmioMem test — add the MmioMem-recorded pattern` |
| HW smoke test green for all platforms | PR description states `R0=0x72CA33A8` on L552 (or L562) and N657 boot success | `Run cargo xtask flash <platform> on all platforms before merge` |
| Codecov `codecov/patch` check is green | PR-introduced lines must be covered at the project's patch threshold (70%) | `New code covered below the patch threshold — add a `umbra-pal-test` case before merge (see Coverage gate below)` |

### Coverage gate

CI uploads host-side coverage via `cargo-llvm-cov` to Codecov on every
push. The thresholds live in `codecov.yml` at the repo root:

- **`codecov/project`** — fails on a coverage regression vs the base
  commit (drift > 1 pp). The absolute target is `auto`, so the gate
  enforces "do not make it worse", not a fixed percentage. Once the
  baseline is established the target will flip to a concrete number.
- **`codecov/patch`** — requires the PR's own added/modified lines to
  hit **70 %** coverage. A PR that adds new logic without exercising it
  in `umbra-pal-test` fails here even if the project-wide percentage is
  unchanged.

The boot binaries (`umbra-<mcu>-boot`) and PAL drivers
(`umbra-<mcu>-drivers`) are excluded from the coverage report because
they cross-compile to `thumbv8m.main-none-eabi` and cannot run on host.
Their coverage story is the HW smoke test row above plus the per-driver
`MmioMem` recordings, neither of which Codecov measures.

If Codecov's check fails:

1. Open the PR's Codecov comment — it lists every uncovered new line.
2. Add a host-side test in the appropriate crate's `tests/` directory
   or in an inline `#[cfg(test)] mod tests`.
3. Push; the next CI run re-uploads and the gate recomputes.

---

## Style

| Check | What to look for | Comment shortcut |
|---|---|---|
| `cargo fmt --check` clean | CI Job 1 must be green | `Run cargo fmt — CI Job 1 caught the formatting drift` |
| `cargo clippy --workspace -- -D warnings` clean | CI Job 1 must be green | `` cargo clippy is denied warnings — fix the lint or `#[allow]` with justification `` |
| No file exceeds 600 LOC (hard) / 400 LOC (soft target) | `tools/check_file_size.sh` exits 0; soft warnings allowed but flagged | `File over 400 LOC soft cap — decompose or document why this module shouldn't split` |
| Conventional commit message | Commit subject starts with `feat:` / `fix:` / `refactor:` / `test:` / `docs:` / `chore:` / `perf:` | `Rewrite the commit subject per Conventional Commits — see ALWAYS_DO #18` |

---

## How to use this checklist

1. **Contributor**: self-check during PR draft. Address every "no"
   before requesting review.
2. **Reviewer**: open the diff, walk the table top-to-bottom, paste
   the comment shortcut when a row fails. Don't approve until every
   row is green or has a stated exception in the PR description.
3. **CI**: most rows in Correctness, Safety, and Style are
   mechanically enforced. The Security rows require human judgment.
