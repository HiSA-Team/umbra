# Pre-registered falsification tests — chain-core wiring into the N657 boot image

Written and committed **before** the wiring change was inspected. Baselines below
are `HEAD = aa47e0db892614b9c051d523ebddc22ea17e193c` on branch
`58-verifiable-core-rocq-feasibility`.

At the moment of writing, `git status --porcelain crates/ formal/ src/kernel/`
reported exactly one dirty path — `crates/umbra-chain-core/src/lib.rs` — so the
change was in flight but unread. Everything in `formal/rocq/chain-core/`,
`src/kernel/key_storage_server/blob_chain*.rs` and the N657 `api_impl.rs` was
still at its `HEAD` content when these baselines were taken.

## What is being claimed

The paper's residual (i), verbatim at `HEAD`:

> *(i) No firmware calls the crate*: every boot image keeps its own inline fold,
> and `nm` finds no chain-core symbol in the linked N657 image. The link is a
> differential host test plus a drift guard pinning the transcribed *constants*
> and `cfg` — not the fold body, and not execution: materially weaker than
> update-core, whose firmware runs the proved function.

The change under test inverts the dependency in
`crates/umbra-chain-core/src/lib.rs` so that `block_preimage` is defined via a
new `block_preimage_of_block(blk, &[u8; 288])`, re-extracts, repairs the proofs,
and changes the N657 call site to call the crate.

## The overclaim this document exists to prevent

The firmware obtains the 288 block bytes by computing an address into the
memory-mapped XSPI2 window and issuing 288 `core::ptr::read_volatile`s. The
proved function consumes an already-materialised `&[u8; 288]`. Therefore even a
flawless refactor leaves **the address computation and the volatile reads
outside the proof**, and leaves the *boundary* — not the *fold* — as the new
residual. Residual (i) **shrinks; it does not vanish.** Any revised wording of
the form "residual (i) is closed", "the firmware executes the proved code", or
"the fold is now fully verified" is false as stated and must be marked REFUTED.

Softer variants that are equally false and must also be caught:

- "the proved function is what runs on the device" (the *proved* function is one
  callee of what runs on the device);
- "the inline fold is gone" (the byte-transport loop is still inline and still
  `unsafe`);
- dropping residual (i) from the residual list entirely rather than rewording it;
- silently recategorising it under residual (iv)/(v) so the count "Five residuals
  remain" stays constant while (i) is quietly deleted.

## Baselines (all at `HEAD`, recorded before inspection)

`git rev-parse HEAD:<path>` blob hashes:

| path | HEAD blob |
|---|---|
| `crates/umbra-chain-core/src/lib.rs` | `f44a0ed60fb4ef35b30d8cf2f95f51bd4377b5c4` |
| `crates/umbra-chain-core/src/lib_tests.rs` | `87bfe6e074326ce0a655fae83a900f92c69ff9e1` |
| `formal/rocq/chain-core/proofs-coq/Chain_Types.v` | `ce7d96bc68eb404c491c717d01323a4c4c37cc57` |
| `formal/rocq/chain-core/proofs-coq/Chain_FunsExternal.v` | `58835494d7e356423548ac2481e75770fe0e9b8b` |
| `formal/rocq/chain-core/proofs-coq/Chain_Funs.v` | `f84ccd93cdb90cb808dc18cf85bc0dae54de3ae1` |
| `formal/rocq/chain-core/proofs-coq/Chain_Value.v` | `ee164abee0fbd45456c505cb6e66881174c9811e` |
| `formal/rocq/chain-core/proofs-coq/Chain_Trace.v` | `f00aa4b1ea65e1d48d67c85b8dc595cb13cb2c49` |
| `formal/rocq/chain-core/proofs-coq/Chain_Body.v` | `7b7aa3a87fde18d9fb292ca620c92768af117408` |
| `formal/rocq/chain-core/proofs-coq/Chain_Compose.v` | `318bee950a4232101a384075d9458445fd12103e` |
| `formal/rocq/chain-core/proofs-coq/Chain_Residual.v` | `822bc79af26a6c33e9e2dc013b0a3a3c568004e9` |
| `formal/rocq/chain-core/proofs-coq/Chain_Reachable.v` | `2755187c9353e3d338eefe613e32dea99423b65a` |
| `src/hardware/platform/stm32n657/boot/src/api_impl.rs` | `6196dbf0403e43b6f24412054e1b3a8c1c189d94` |
| `src/kernel/src/key_storage_server/blob_chain.rs` | `dea7074f3929d4ebf66ccae7eddc3cf10efe52e6` |
| `src/kernel/src/key_storage_server/blob_chain_tests.rs` | `1c5e4cb086a4de9e0967598b94fab6f22c7fdc26` |

`formal/rocq/chain-core/chain.llbc` is **untracked** (`.gitignore:1: *.llbc`), so
git cannot witness whether the extraction re-ran. T3 below therefore keys on the
tracked `.v` files, not the `.llbc`.

Note for both agents: the N657 `api_impl.rs` is **dirty against `HEAD`** already
(`+36 −2`, unrelated A/B-probe work). Any statement about "the firmware fold" must
say which of the two it measured. Last round the same trap was fallen into twice.

### Axiom-count baseline and the counting method

Counting method, fixed here so it cannot be tuned after the fact. `Print
Assumptions` in Coq 8.18 emits section headers (`Axioms:`, `Section Variables:`,
`Opaque constants:`) and then one entry per assumption whose **name starts at
column 0**; the type is either on the same line after ` : ` or on following
indented lines. So:

```
count = (# lines matching ^[^ ]) − (# lines matching ^[A-Za-z ]+:$)
```

The subtrahend removes only the headers. A regex that requires a dotted name
would miss `array_u8_ext`, which prints **unqualified** — this is exactly the
class of mistake that undercounted last round.

Baseline measured with
`coqc -R . Lib -R ../../update-core/proofs-coq Lib` on a file that
`Print Assumptions Chain_Body.chain_accept_pins_the_blob_body`:

- **36 assumptions** (37 column-0 lines − 1 `Axioms:` header).

Any post-delivery figure must be produced by the same command and the same
formula, and any *increase* must be named and justified, not netted out.

## The tests

### T1 — Is the proved function the one the firmware calls?

The whole point of the task. PASS requires **all** of:

1. `crates/umbra-chain-core/src/lib.rs` exports `block_preimage_of_block` (or
   equivalent) taking `&[u8; 288]`, and `block_preimage` is *defined in terms of
   it*, not merely alongside it.
2. The N657 call site actually calls into `umbra_chain_core` — reachable by a
   real Rust path, not a doc comment. Evidence: the boot crate's `Cargo.toml`
   gains the dependency (directly or via `kernel`), and `api_impl.rs` names the
   symbol.
3. The Rocq theorems **constrain the callee**. Either (a) the headline theorems
   are restated over `block_preimage_of_block`, or (b) a `Qed` factoring lemma of
   the shape `block_preimage blob blk = Ok pre → ∃ b, block_preimage_of_block blk
   b = pre ∧ b = <the 288 bytes at 48+288·blk>` exists and is *used*. A lemma
   that exists but is `Admitted`, or that exists and is never referenced by any
   headline theorem, is FAIL for this sub-item.

FAIL mode I expect to have to check hardest: the extracted `Chain_Funs.v` gains
`block_preimage_of_block` but every theorem in `Chain_Body/Compose/Residual/
Reachable` still quantifies only over `block_preimage`/`verify_blob_chain`, while
the firmware calls the new leaf. That is a *strictly worse* position than `HEAD`,
because it would look wired while proving about the wrapper the device does not
call.

### T2 — Byte-exact preimage layout, by test not by reading

The shipping firmware assembles `verify_buf = [blk_le(4) | code(256) | meta(32)]`
where `code` is at `block_base + BLOCK_HEADER_SIZE` and `meta` at `block_base +
BLOCK_META_OFFSET`, i.e. the on-flash block is `[meta(32) | code(256)]` and the
preimage reverses the halves. A silent reordering breaks chained measurement for
every already-signed enclave and for `tools/protect_enclave.py`'s offline stamp,
and would surface only on hardware.

PASS requires an executed test — I will write and run my own, independent of
whatever the Wirer ships — showing, for a blob with distinguishable bytes:

- `pre[0..4] == blk.to_le_bytes()`;
- `pre[4..260] == blob[48+288k+32 .. 48+288k+288]`;
- `pre[260..292] == blob[48+288k .. 48+288k+32]`;
- and that `block_preimage(blob, k) == block_preimage_of_block(k, &blob[48+288k
  .. 48+288k+288])` for several `k`, byte for byte.

`BLOCK_PREIMAGE_LEN` must stay `292` and `BLOCK_LEN` `288`.

### T3 — Did the extraction actually re-run?

The highest-value failure available here is a **stale extraction with
repaired-looking proofs**: hand-edited `.v` files that mention the new function
while `Chain_Funs.v` was never regenerated from the new Rust.

PASS requires:

1. `formal/rocq/chain-core/proofs-coq/Chain_Funs.v` blob differs from
   `f84ccd93cdb90cb808dc18cf85bc0dae54de3ae1`, **and** its new content defines
   `block_preimage_of_block` with a body that corresponds to the new Rust
   (checked by reading the extracted body against `lib.rs`, arm by arm — the
   guard, the two `copy_from_slice` windows, the index arithmetic).
2. `Chain_Funs.v` is *not* hand-edited beyond the documented `extract.sh`
   patches. Evidence: the diff against `HEAD` in the untouched regions is empty,
   and the patch markers `extract.sh` re-applies (loop-shim import, 8.18 binder
   rewrite, opaque u32 codecs, `mk_array4`) are present exactly once each.
3. If `Chain_Funs.v` is **unchanged** while `lib.rs` changed, that is an
   immediate REFUTED for the whole task: the model no longer corresponds to the
   crate.

Since `chain.llbc` is untracked I will additionally check its mtime against the
`lib.rs` mtime and against the `.v` mtimes; an `.llbc` older than `lib.rs` is
positive evidence the extraction did not re-run.

### T4 — Proof integrity

PASS requires, measured by me:

- every headline theorem closes with `Qed`, none with `Admitted`;
- zero occurrences of the *tactics* `admit`/`give_up` and zero `Admitted.` in
  `formal/rocq/chain-core/proofs-coq/*.v`. Counting rule: match `\badmit\b`,
  `\bgive_up\b`, `^Admitted\.` — and then **subtract nothing**, but read every
  hit, because `realsum.__admitted__interchange_psum` is an inherited axiom
  *name* occurring in prose in the crypto tree and is not a tactic. It must not
  be counted as one, and equally must not be used to explain away a real hit in
  chain-core;
- the whole `chain-core` `Makefile` target rebuilds from clean (`.vo` deleted)
  with `coqc` exit 0;
- `Print Assumptions` on `Chain_Body.chain_accept_pins_the_blob_body`,
  `Chain_Compose.verified_update_pins_the_blob_body`,
  `Chain_Reachable.chain_gate_accepts_a_matching_measurement`, and the four
  `Chain_Residual` theorems, counted by the formula above, with any new axiom
  named. Baseline for the first is 36.

### T5 — Purity

- `crates/umbra-chain-core/src/lib.rs` keeps `#![no_std]` and
  `#![forbid(unsafe_code)]` (grep, first 100 lines);
- `crates/umbra-chain-core/Cargo.toml` and `crates/umbra-update-core/Cargo.toml`
  acquire **no** `mathcomp`/`ssreflect`-adjacent dependency and no new
  `[dependencies]` entry at all beyond what `HEAD` had;
- `formal/rocq/chain-core/proofs-coq/_CoqProject` gains no `-R` into
  `formal/rocq/crypto` or any mathcomp path;
- no `From mathcomp` / `Require Import ssreflect` appears in
  `formal/rocq/chain-core/proofs-coq/*.v` or `formal/rocq/update-core/proofs-coq/*.v`.

### T6 — Is the differential test still falsifying, or now circular?

`src/kernel/src/key_storage_server/blob_chain_tests.rs` holds
`firmware_replica_preimage`, a hand transcription of the N657 fold, and asserts
the crate agrees with it. Two guards sit on top:
`the_firmware_still_uses_the_configuration_we_transcribed` reads the firmware's
own source and `Cargo.toml` at compile time, and `the_crates_constants_are_the_firmwares`.

After the wiring, the firmware calls the crate. The *replica* is still an
independent transcription, so `crate_preimage_matches_the_firmware_replica`
retains falsifying power **only if the replica is still transcribed from
firmware source that still contains the arithmetic**. The failure mode to catch:
the wiring deletes `fold_block_from_flash`'s preimage assembly from
`api_impl.rs`, the compile-time source-reading guard silently matches nothing (or
is edited to point at the crate), and the "differential" test degenerates into
`crate == crate`.

PASS requires: (a) the source-reading guard still reads a firmware file and
would still *fail* if that file drifted — demonstrated by me mutating the read
file and observing the test fail; (b) if the firmware arithmetic moved, the guard
moved with it and now pins the *remaining* firmware-side arithmetic (address
computation, `BLOCK_HEADER_SIZE`/`BLOCK_META_OFFSET`), not the crate's. If
neither holds, I will say plainly that the differential test has become a
tautology.

### T7 — `HEAD` vs working tree

Every number either agent reports must state which tree it was measured on. I
will re-measure any figure I repeat. Specifically flagged: `api_impl.rs` is
already `+36 −2` dirty against `HEAD` for unrelated reasons, and `chain.llbc` is
untracked, so "the extracted model changed" cannot be read off `git status`.

## What neither agent can verify — the silicon-only list

Neither the Wirer nor I have an ARM toolchain. The following are **not** settled
by anything in this repository and are exactly what a board run tests:

1. **That the boot image compiles at all** for `thumbv8m.main-none-eabi` with the
   new dependency edge. A `no_std` leaf pulled into the boot crate can fail on
   feature unification, `panic_handler` duplication, or a `libcore` symbol the
   linker script does not place.
2. **That `nm` now finds a chain-core symbol in the linked image** — the paper's
   own stated evidence for residual (i). LTO/inlining may leave *no* symbol even
   when the code does run, so a naive `nm` check can produce a false negative;
   and `--gc-sections` may leave a symbol that is never called, a false positive.
   Only a disassembly of the call site, or an on-device trace, settles it.
3. **Flash/ROM budget.** The boot image is size-constrained; a non-inlined 292-byte
   stack buffer plus a second copy of the fold could overflow the FSBL region or
   blow the stack. `[u8; 292]` on the secure stack is not free.
4. **That the refactor is behaviour-preserving on device.** The host test uses a
   contiguous `&[u8]`; the device reads a memory-mapped XSPI2 window whose reads
   must be `volatile` and whose alignment/burst behaviour is not modelled. If the
   wiring materialises `[u8; 288]` from flash and then hands it to the crate, the
   288-byte copy is new code on the device that no test here exercises.
5. **That chained measurement still accepts already-signed enclaves.** The only
   real regression oracle is booting an existing signed blob (the `0x72CA33A8`
   liveness value) on N657 and observing accept, plus a tampered blob and
   observing reject.
6. **Timing.** The fold runs per block at create time; an extra full-block copy
   per block is measurable and is a claim the paper may make.
7. **The `unsafe` byte transport itself.** `#![forbid(unsafe_code)]` in the crate
   guarantees nothing about the `unsafe` block that remains in `api_impl.rs`; its
   address arithmetic is checked only by the `checked_mul`/`checked_add` chain and
   by MPU/RISAF at runtime.

## The judgement this document commits me to in advance

If T1 passes in full, the honest statement is:

> The device now executes the proved fold **body**; what remains outside the
> proof is the address computation and the volatile byte transport that
> materialise the block. Residual (i) narrows from "no firmware calls the crate"
> to "the firmware calls the crate across a `&[u8; 288]` boundary it fills with
> unverified volatile reads."

If T1 fails at sub-item 3 (theorems still only about the wrapper), the honest
statement is that the wiring is cosmetic and residual (i) has *not* materially
changed, only moved.

---

# RESULTS — measured after delivery

Delivery measured at `fafd2ac` plus the then-uncommitted working-tree changes to
`api_impl.rs` and `blob_chain_tests.rs`. Where a figure could differ between
`HEAD` and the working tree, both are stated.

## T1 — is the proved function the one the firmware calls? **CONFIRMED, with a bounded scope**

1. `block_preimage_of_block(blk, &[u8; BLOCK_LEN])` exists and `block_preimage`
   is *defined through it* (`crates/umbra-chain-core/src/lib.rs`) — not added
   alongside. CONFIRMED.
2. The firmware calls it, at two sites:
   `api_impl.rs:126` inside `update_chain` (the **real create** fold) and
   `api_impl.rs:278` inside `fold_block_from_flash` (the probe). Both are real
   Rust call edges through the kernel re-export. CONFIRMED.
3. The theorems constrain the callee. Tested by **axiomatisation**, not by
   reading: in an isolated copy of the proof tree, `preimage_of_block_windows`
   and `preimage_factors_through_block` were rewritten from `Lemma … Qed` into
   `Axiom` with identical statements, the tree rebuilt from clean, and
   `Print Assumptions Chain_Body.chain_accept_pins_the_blob_body` then **lists
   both names** (assumption count moves 35 → 30 as the two axioms subsume seven
   lower-level ones). A proof term that did not route through the leaf lemmas
   could not list them. CONFIRMED.

## T2 — byte-exact preimage layout **CONFIRMED**

Run from a standalone crate with a path dependency on the real crate, against a
re-derivation of the layout written from the on-flash spec rather than from the
crate source. For blobs with non-uniform bytes: `pre[0..4]` is `blk` little-endian
(checked at `blk = 39`, a multi-byte index), `pre[4..260]` is
`blob[48+288k+32 .. +288]`, `pre[260..292]` is `blob[48+288k .. +32]`;
`block_preimage_of_block` and `block_preimage` agree byte for byte on every
block; a marked block with meta `0xA5` and code `0x5C` lands code-first. Both
guards survive, including the exact-fit and one-short blob lengths.
`BLOCK_LEN = 288`, `BLOCK_PREIMAGE_LEN = 292`. The layout did not move.

## T3 — did the extraction re-run? **CONFIRMED**

`Chain_Funs.v` changed from `f84ccd93…`. Its `block_preimage_of_block` body is
Aeneas output, not a hand edit: every unrelated source-line comment in the file
shifted consistently with the new `lib.rs` (`100→130`, `121→147`, `129→155`,
`143→169`, `168→194`, `181→207`, `187→213`), which a hand edit would not produce.
`block_preimage` now genuinely ends in `a <- block_preimage_of_block blk block1`.
mtimes order correctly: `lib.rs` 07:07:29 → `chain.llbc` 07:07:30 → `Chain_Funs.v`
07:07:31. `chain.llbc` is untracked (`.gitignore: *.llbc`), so git alone could not
have witnessed this.

## T4 — proof integrity **CONFIRMED**

Built **from clean** in an isolated copy of `formal/rocq/{update-core,chain-core}`
containing only tracked `.v` and `_CoqProject`, so no stale `.vo` could mask a
break. Gate is per-file `.vo` existence, not `make`'s exit status — `make` was
observed returning 0 while compiling nothing, so exit status alone is not evidence.

- update-core and chain-core both build; 0 missing `.vo`.
- `grep -nE '\badmit\b|\bgive_up\b|Admitted'` over `chain-core/proofs-coq/*.v`:
  **zero hits**. 48 `Qed.`, 0 `Defined.`. The three new lemmas each close `Qed.`.
- `Print Assumptions`, counted as `(col-0 lines) − (header lines)`:

  | theorem | assumptions |
  |---|---|
  | `Chain_Body.chain_accept_pins_the_blob_body` | 35 |
  | `Chain_Compose.verified_update_pins_the_blob_body` | 40 |
  | `Chain_Reachable.chain_gate_accepts_a_matching_measurement` | 26 |
  | `Chain_Value.preimage_pins_block` | 26 |

  **CORRECTION — my own number was wrong.** I first reported the pre-refactor
  figure as **36**. It is **35**. The 36 came from running `Print Assumptions`
  against the `.vo` files sitting in the repo working tree, built 2026-07-27 from
  a state that is not `aa47e0d` — a stale-artifact measurement, the same family
  of error as measuring the working tree instead of `HEAD`, which this document
  was written to avoid and which its own harness was built to prevent. I took the
  baseline before I built the harness.

  Re-derived properly: `aa47e0d`'s tracked `.v` extracted with `git show` into a
  fresh directory, both proof trees rebuilt from clean, same theorem, same
  formula → **35**. And the assumption *name sets* at `aa47e0d` and at the
  delivery are **identical** — `diff` is empty. So the correct statement is not
  "35, down from 36" but **35 → 35, no axiom added and none removed**. The
  refactor is axiom-neutral.

  The Implementer declined to repeat my 36 without measuring it, which is what
  forced this re-derivation. A regex requiring a dotted name would separately have
  missed `array_u8_ext`, which prints unqualified — the undercount trap named in
  advance, and avoided.

## T5 — purity **CONFIRMED**

`#![no_std]` and `#![forbid(unsafe_code)]` both still present. `[dependencies]`
is empty in both `umbra-chain-core` and `umbra-update-core`. No `mathcomp`,
`ssreflect` or `ssrbool` anywhere in `chain-core/proofs-coq` or
`update-core/proofs-coq`. `_CoqProject` still has exactly two `-R`, neither into
`formal/rocq/crypto`.

## T6 — is the differential test still falsifying? **PARTLY — one real blind spot**

Not circular overall. `firmware_replica_accept` still transcribes the firmware's
*own* header parse, block-count derivation, `MAX_EFBS` guard, fold loop and
constant-time compare, and `crate_verdict_matches_the_firmware_replica_on_tampering`
compares that against the crate's `verify_blob_chain` across single-byte flips.
That comparison is exactly what covers the parts of the chain the firmware does
*not* take from the crate, so it retains falsifying power.

Two mutation tests, run against the firmware source:

- **Fires.** Replacing `update_chain`'s call to the proved assembly with an
  inline buffer makes `the_firmware_calls_the_proved_assembly` FAIL
  (`blob_chain_tests.rs:217`). The wiring cannot silently rot.
- **Does not fire — a genuine gap.** Swapping the *destination offsets* of the
  two `read_volatile` loops in `fold_block_from_flash` (code to `block[0..256]`,
  meta to `block[256..288]`, constants untouched, still exactly two
  `read_volatile`, still calling the proved function) leaves **all 7 kernel tests
  green**. That mutation inverts the code/meta halves and would reject every
  already-signed enclave on hardware. The source-reading guard checks the
  constants, the presence of the call, and the *count* of volatile reads — not
  where the bytes land.

  So `the_replica_block_is_the_blobs_block` pins the **replica's** offsets
  against the crate's `base` arithmetic, not the **firmware's**. The README
  sentence "pins the firmware's offsets against the crate's own base arithmetic"
  overstates it by one level of indirection. The gap sits inside the residual the
  wiring commit itself declares (address arithmetic and the reads), so it is not
  an undisclosed class of failure — but it is not tested either, and only silicon
  or a stricter source guard closes it.

## T7 — `HEAD` vs working tree **noted throughout**

At the time of measurement `api_impl.rs` and `blob_chain_tests.rs` were dirty
against `fafd2ac`; all firmware figures above are working-tree. The Coq figures
are from tracked `.v` copied out of the tree. `chain.llbc` is untracked, so "the
extraction re-ran" was established from content and mtime, not from git.

One disclosure about this document: it was committed at `ae1823e`, 88 seconds
*after* the Wirer's first commit `a8f5e18` landed. Its baselines were read while
`HEAD` was still `aa47e0d` and its predictions were written without reading
`a8f5e18`'s diff — but the commit is a descendant of it, and anyone weighing the
pre-registration should know that.

---

# The overclaim, refuted

Two committed files say the theorems reach further than they do.

- `src/kernel/src/key_storage_server/blob_chain.rs:38-39` — "the shipping folds
  execute the proved code from the block onwards: assembly, ordering, **fold,
  gate**."
- `crates/umbra-chain-core/README.md:105-108` — "**The theorems constrain
  everything downstream of those reads** — preimage assembly, the code/meta
  ordering, **the fold, the accept gate** — **and nothing upstream of them.** The
  boundary runs exactly at the end of the read loops."

"the fold" and "the accept gate" are **false**. The firmware executes exactly one
of the crate's six entry points:

| crate entry point | call sites in `stm32n657/boot/` |
|---|---|
| `block_preimage_of_block` | **2** (`api_impl.rs:126`, `api_impl.rs:278`) |
| `block_preimage` | 0 |
| `chain_root` | 0 |
| `blob_block_count` | 0 |
| `verify_blob_chain` | 0 |
| `ct_eq32_at` | 0 |

What the firmware still does itself, and no theorem touches:

- **the block count** — `header.code_size / TOTAL_BLOCK_SIZE` with its own
  `num_blocks == 0 || > MAX_EFBS` guard (`api_impl.rs:165-166`, `:391`), which is
  `blob_block_count`'s job, magic check included;
- **the fold loop** — `while blk < num_blocks { … }` (`api_impl.rs:174`, `:471`),
  which is `chain_root`'s job, including the accumulator threading;
- **the accept gate** — `Kernel::finalize_measurement`
  (`secure_kernel.rs:190-202`), a *separately written* constant-time compare
  against `header.hmac` (`api_impl.rs:181`, `:494`), which is `verify_blob_chain`
  / `ct_eq32_at`'s job; under `enclave_version_bind` it is `search_version`
  instead, further still from the modelled gate.

The boundary therefore does **not** run "exactly at the end of the read loops".
It closes again at the end of `block_preimage_of_block` and re-opens for the
count, the loop and the gate. The proved region is a 292-byte per-block
assembly; the surrounding control flow that decides whether an enclave runs is
firmware-only, related to the theorems by transcription in
`firmware_replica_accept` — the same kind of link the paper's residual (i)
already calls "materially weaker".

Accurate replacement wording: *the shipping folds execute the proved preimage
assembly; the block count, the fold loop and the accept gate remain firmware
transcriptions of the modelled ones.*

# Paper wording

`_DATE27_/sections/results.tex:166` still reads "*(i) No firmware calls the
crate*: every boot image keeps its own inline fold, and `nm` finds no chain-core
symbol in the linked N657 image." As of this delivery that is **false** and must
be rewritten. The `nm` clause was never checkable here and is now doubly
unsafe — see the silicon list above. "Every boot image" is still true of L552 and
RISC-V, which were not wired.

---

# Re-verification after the corrections

Delivery re-measured at `2840743`.

- The "fold, gate" sentence is gone from all four files that carried it
  (`blob_chain.rs`, `crates/umbra-chain-core/README.md`,
  `formal/rocq/chain-core/README.md`, and the `api_impl.rs` doc comment — the
  last two I had not found; the Implementer located them). Each now carries the
  one-entry-point-of-six census and the count/loop/gate table.
- **The mutation now fails.** Re-applying the destination-offset swap (code into
  `block[0..256]`, meta into `block[256..288]`, constants untouched, both
  `read_volatile` loops intact, proved call intact) makes
  `the_firmware_calls_the_proved_assembly` FAIL at `blob_chain_tests.rs:249`.
  Restored, it passes. The blind spot I found is closed, verified by me, not
  taken on report.
- Both proof trees rebuild from clean, 0 missing `.vo`; 7/7 kernel tests, 16/16
  chain-core tests, and my own independent layout test all pass.
- Independent cross-check of the layout against the *offline signer*:
  `tools/protect_enclave.py:701` builds `binding_input = block_id_le(4) +
  ciphertext + meta` and folds exactly that (`:753`). Signer, crate and firmware
  agree on `[blk_le | code | meta]`. Three parties, one order.
- `stm32l552` and `riscv32` reference no chain-core symbol at all: their folds
  remain entirely inline. Any sentence about "the firmware" must name N657.

---

# Paper figures invalidated by the change — independent re-derivation

The Implementer reported six figures its change falsified. None were in my
pre-registration; I had checked the *claims* about the wiring and not the
*measurements* that the wiring moved. Verified here by re-deriving each counting
rule from scratch and requiring it to reproduce the paper's `aa47e0d` number
exactly before applying it to `HEAD` — a rule that cannot reproduce the base is
not the rule the paper used.

| figure | rule I derived | `aa47e0d` | `HEAD` |
|---|---|---|---|
| chain-core hand-written `.v` | all `chain-core/proofs-coq/*.v` minus the four extraction outputs (`Chain_Types`, `Chain_Funs`, `Chain_FunsExternal`, `Chain_FunsExternal_Template`): `2279 − 22 − 270 − 37 − 23` | **1 927** ✓ | **2 059** |
| verified Rust | `wc -l` of the two crates' `src/lib.rs` | **359** = 163+196 ✓ | **392** = 163+229 |
| chain-core `Qed` | `^(Lemma\|Theorem\|Corollary\|Proposition\|Fact)` | **63** ✓ | **66** |
| chain-core tests | `^#[test]` in `lib_tests.rs` | **13** ✓ | **16** |
| all hand-written | Tier D + Tier G + chain-core | **12 834** ✓ | **12 966** |
| global ratio | hand-written / verified Rust | 12834/359 = 35.75 → **36:1** ✓ | 12966/392 = 33.08 → **33:1** |
| marginal ratio | chain-core `.v` / chain-core Rust | 1927/196 = 9.83 → **10:1** ✓ | 2059/229 = 8.99 → **9:1** |

The tier decomposition also reproduces exactly, which is what makes the
"unchanged" half credible rather than asserted: crypto's four `GAME_FILES`
(`Umbra_EUFCMA` 240 + `Umbra_Reduction` 304 + `Umbra_RealGame` 925 +
`Umbra_Union` 422) = **1 891** = Tier G; update-core hand-written + crypto's ten
deterministic files = **9 016** = Tier D; 9016 + 1891 = **10 907** = "update-core's
two tiers"; 10907 + 1927 = **12 834**. Every one is the paper's printed figure.

Unchanged and re-verified as unchanged at `HEAD`: 9 016, 1 891, 10 907, 371 `Qed`,
163 L Rust, 67:1 (10907/163 = 66.91), 61:1 (9980/163 = 61.23), the join's 927
lines. The change lands wholly inside chain-core.

## A seventh figure the Implementer missed

Its own warning — that `:142`'s ratio is *derived* from `:141`'s operands and that
other derived numbers on the same operands should be swept for — was correct, and
under-applied. Grepping the whole paper for the **old** values found one survivor:

`_DATE27_/sections/results.tex:144` — "`$10{:}1$` is the marginal cost."

That is the same ratio as the corrected `:142`, on the same operands
(chain-core `.v` over chain-core Rust), restated three lines later in prose. With
`:141-142` corrected and `:144` not, the paragraph contradicted itself: "2 059
lines over 229 of Rust — 9:1 … 10:1 is the marginal cost." Corrected on disk to
`$9{:}1$`. Nothing else survived the sweep: `12 834`, `1 927`, `196`, `359`, `63
Qed`, `13 tests` and `36:1` appear nowhere in `main.tex` or any section.

## The rebuild time — measured, not inferred

`:48` claims "Clean sequential rebuild ≈290 s on an Apple M1, `coqc` 8.18.0, ±5%
between runs." The Implementer could not run this inside its command ceiling and
declined to report inference as measurement, which was right.

Measured here, twice, from clean: sources copied out of the tree, `make -j1` per
tier in dependency order, then `crypto/build.sh` (full, not `--det-only`).

| run | update-core | chain-core | crypto | total |
|---|---|---|---|---|
| 1 | 245 s | 16 s | 30 s | **291 s** |
| 2 | 250 s | 16 s | 31 s | **297 s** |

Mean 294 s; spread 6 s = 2.0%, inside the stated ±5%. Against the printed 290 s:
+0.3% and +2.4%. Machine: `machdep.cpu.brand_string` = **Apple M1**, `coqc`
**8.18.0** — the configuration the sentence names. All tiers complete (11 + 10 +
14 `.vo`), so this is the full build including the four SSProve/mathcomp game
files, not the deterministic subset.

**`:48` needs no edit.** chain-core is 16 s of 291 s (5.5%); its ~7% growth in
hand-written lines cannot move the total outside the stated tolerance, and now
that is measured rather than argued. "A rebuild under five minutes" at `:137`
also survives — 297 s is 4 min 57 s, though with only 3 s of headroom it is worth
knowing that it is a claim about *this* machine and would not survive much more
growth in Tier D, which is 84% of the total.

---

# Closing audit of the paper's numbers

Every figure in the Totals row recomputed from the file measurements, all ten
agree: Tier D 9 016, Tier G 1 891, update-core 10 907, chain-core 2 059,
hand-written 12 966, Rust 392, and the four ratios 33:1 (33.08), 67:1 (66.91),
61:1, 9:1. The table is internally consistent.

Sweep for retired values re-run independently over the whole `_DATE27_` tree,
not only `results.tex`: `12 834`, `1 927`, `196`, `359`, `36:1`, `10:1`,
`63 Qed`, `13 tests` — **zero hits in any `.tex` or `.md`**. The single `1927`
occurrence is in `main.log`, stale LaTeX build output that is regenerated on the
next compile, not a source file. Every `N:1` in the tree enumerated: 33:1 (:47),
67:1 (:44, :141), 61:1 (:45), 9:1 (:143, :146), 23:1 (:140, seL4's). Nothing
unaccounted for.

## An unreported edit, and a correct one

`:138` read "a rebuild **under** five minutes" when I flagged that 297 s clears
it by 3 s. It now reads "a rebuild **of about** five minutes". That change is
right — it is what my two measurements support, and it removes the fragility —
but it was not in the Implementer's list of its edits. Recording it because the
discipline this loop runs on is that changes are reported and then verified by
the other side, and an unreported edit is one that got only half of that.

## 67:1 versus 33:1 — authorial, with one place it costs the paper

`67` appears four times. Once correctly scoped: `:44`, inside the Totals row,
"10 907 L and 371 Qed over 163 L of Rust, 67:1" — explicitly update-core's two
tiers. Three times unqualified:

- `introduction.tex:37` — "None of it is free: 67 lines of hand-written Rocq per
  line of verified Rust";
- `results.tex:138` — "The price is Table~\ref{tab:layers}: about 67 lines of
  hand-written Rocq per line of verified Rust";
- `results.tex:141` — "ours is 67:1 through a general-purpose backend".

The table's own global figure is **33:1**, and this change widened the gap
(36 → 33) because chain-core is the cheaper tier and got cheaper still.

This is the author's call, and the Implementer was right not to edit it
unilaterally. Two observations for whoever decides:

1. The paper takes the **worse** of its two ratios in all three prose
   instances, consistently. That consistency is evidence of deliberate
   conservatism rather than oversight, which is an argument for leaving it.
2. The exception is `:140-141`. It sets seL4's 23:1 against "ours is 67:1".
   23:1 is a whole-artifact proof-to-code ratio; 67:1 is one crate's. The
   like-for-like figure on this side is the artifact-level 33:1, which would put
   the comparison at 33:1 against 23:1 rather than 67:1 against 23:1 — the
   conservative choice costing the paper precisely where it is making its
   headline comparison. I cannot verify from this repository what the cited
   SOSP 2009 figure covers, so I state the concern and not a correction.

The safe fix for all three is scoping rather than renumbering: say
"update-core's 67:1" and "the artifact's 33:1" where each is meant, so a
reviewer who computes 12 966/392 from the table and then meets 67 in the
introduction is not ambushed.

---

# A third party is editing the paper, and it applied the gated edit

The section above is **already stale**, and the way it went stale is the finding.

## Provenance, settled by what each of us can prove about itself

`:138`'s "under" → "of about five minutes" is not the Implementer's; it is also
not mine. My only write to `_DATE27_/` in this session was one substitution in
`sections/results.tex`, `$10{:}1$ is the marginal cost.` → `$9{:}1$ …`. Two
independent facts settle it:

- **I never wrote `sections/introduction.tex` at all**, and its mtime is
  `08:00:22`. Whoever changed the introduction is not me, and the same hand
  almost certainly made the `results.tex` change at `08:01:52`.
- A same-length string substitution cannot insert a blank line or shift line
  numbering. Between my first read of that paragraph and my second, "The price
  is Table…" moved from line 136 to line 137 — a line was inserted. My edit
  could not have done that.

Timing: my closing-audit commit landed at `08:00:37`. `introduction.tex` was
modified at `08:00:22` — **fifteen seconds earlier**. So the audit I committed,
which described the introduction's `67` as unqualified, was already false when I
committed it. I did not re-read the file between writing and committing.

## What the third party changed, and why it matters

It applied, almost verbatim, the scoping fix I had recommended and that the
Implementer and I had both **explicitly declined to make**:

- `results.tex:137-141` — "about $67$ lines … per line of **update-core's** Rust
  … **the like-for-like figure here is this artifact's $33{:}1$** --- $67{:}1$ is
  the first crate alone";
- `introduction.tex:37-39` — "$67$ lines … per line of **the first crate's** Rust
  --- $33{:}1$ once the second crate amortises the shared quarantine".

The scoping is right and the arithmetic checks: `10907/163 = 66.91`,
`12966/392 = 33.08`, `2059/229 = 8.99`. Every ratio in the tree is now
accounted for: 67:1 (`:44`, `:140`), 61:1 (`:45`), 33:1 (`:47`, `:140`,
`introduction:38`), 9:1 (`:143`, `:146`), 23:1 (`:139`, seL4's).

**But it also asserts the comparability claim both of us refused to assert.**
"The like-for-like figure here is this artifact's 33:1" states that 33:1 and
seL4's 23:1 measure the same quantity. Neither agent could establish what the
cited figure covers — `bibi.bib:205-213` carries author, title, venue, pages and
year and no proof-line or code-line counts, and nothing else in the tree supplies
them. We each independently declined the edit *for that reason*. It is now in the
paper as a positive claim rather than an open question.

That is not an argument that it is wrong; it is probably right. It is an argument
that it is now **load-bearing and unverified**, and that whoever made it may not
know two agents had gated it deliberately. Opening Klein et al., SOSP 2009 and
establishing what the 23:1 covers has gone from advisable to **required before
submission**.

## The hazard itself

`_DATE27_/` is untracked, so git cannot attribute any of this. At least three
parties have had the tree open in one hour, and neither the Implementer nor I
would have detected the third had my second read not happened to land after its
edit. Any certification either of us gives this paper is a statement about a file
at an instant, not about the file.

So this one is pinned: `sections/results.tex`, mtime `2026-07-28 08:01:52`,
`md5 e0bedb1fc717033bfacb64f9d5bab4c0`. Every figure above was verified against
**that** content. Re-verify against the hash before relying on any of it, and put
the paper tree under version control.

---

# The pin broke, and the denominator measured

## The pin broke within minutes

`sections/results.tex` moved again at `08:04:45`:
`e0bedb1fc717033bfacb64f9d5bab4c0` → `f51910831b9778b95f5e8561f886a557`.
Both agents had just certified against the old hash and both certifications were
stale on arrival. This is now the second time in one hour that a statement about
this file was false before it was delivered. The conclusion is not "re-pin
harder" — it is that an untracked, concurrently-edited tree cannot be certified
at all, only sampled.

## What the third party changed, and it is the right fix

The gated sentence is **gone**. `:140` no longer asserts comparability:

> seL4 reports near $23{:}1$ with a framework built for the job over years;
> **this artifact is $33{:}1$ across all its verified Rust, or $67{:}1$ counting
> update-core alone**, through a general-purpose backend …

"The like-for-like figure here is this artifact's 33:1" has been replaced by a
statement of *scope*. That is precisely the resolution the Implementer proposed
— say what our ratio ranges over rather than claim comparability — and it
removes the blocking item. Arithmetic re-verified on the new content: 66.91,
33.08, 8.99; Totals row unchanged and still consistent.

One asymmetry survives: our denominator is now stated ("across all its verified
Rust"), seL4's still is not ("reports near 23:1"). The two figures remain
adjacent in one sentence, so the comparison is still made by juxtaposition — but
it is no longer asserted, and a reader can see one side's scope. Reading Klein
et al. is now advisable rather than blocking.

## The denominator, measured

The Implementer argued the ratios may not be comparable because the denominators
may not mean the same thing, and that this *strengthens* rather than softens the
concern. It is right, and the size of the effect is measurable on our side:

| | lines |
|---|---|
| verified Rust (the paper's denominator) | **392** |
| Rust in `src/kernel/src` | 1 361 |
| `src/hardware/platform/stm32n657` | 13 488 |
| `src/hardware/platform/stm32l552` | 10 778 |
| `src/hardware/platform/riscv32` | 1 564 |
| `crates/` | 2 030 |
| **total** (`*.rs`, excluding `*_tests.rs`, `*_proptests.rs`, `target/`) | **29 221** |

**392 / 29 221 = 1.34%.** The paper's verified Rust is 1.3% of the Rust in the
kernel, the three platform trees and the crates. A ratio of 33:1 over 1.3% of a
codebase is a different object from a ratio over a whole verified kernel, and the
paper states the former without stating that it is the former.

What I can and cannot say: I measured **our** side and the command above
reproduces it. I did **not** establish what seL4's 23:1 ranges over — that
remains outside this repository, and I will not assert it from recollection any
more than the Implementer would. The asymmetry is the point: the paper now
states the scope of its own ratio and not of the one it sits beside.

## `c7de92c` is not mine

The Implementer credited me with `c7de92c`, "make the documented host-test
command actually run". I did not make it. It edits `.github/workflows/build.yml`
and `xtask/src/main.rs`, adding `umbra-update-core` and `umbra-chain-core` to
the host-test member list — implementing the CI gap the Implementer itself
reported. I never touched either file.

Worth stating plainly because it generalises: **every commit in this repository
carries the same git author**, so git cannot attribute work between the agents in
this loop any more than it can attribute the untracked paper edits. Attribution
here rests entirely on each agent reporting what it did, which is exactly the
mechanism that failed twice on `_DATE27_/`. The code is certifiable because it is
*tracked and testable*, not because it is attributable.

---

# Closing reconciliation

## The denominator, reconciled exactly

The Implementer measured the wider scope independently and got **31 363**; I
reproduce that number exactly with `find src crates -name '*.rs'` under the same
exclusions. Its reconciliation to my 29 221 was 65 lines short, though — the
stated pieces (`src/hardware/architecture` 1 916, `src/hardware/common` 161) sum
to 31 298. The remainder is `src/kernel/build.rs`, 65 lines, which sits directly
under `src/kernel/` and so falls outside both my five named subtrees and the two
it added:

```
  my five subtrees            29 221
  src/hardware/architecture    1 916
  src/hardware/common            161
  src/kernel/build.rs             65
  TOTAL                       31 363   = measured, exact
```

`392/29 221 = 1.34%`, `392/31 363 = 1.25%`. The Implementer's point stands and is
strengthened by the reconciliation: the verified fraction is ~1.3% on **any**
scope, so the finding does not depend on which denominator anyone picks. That
insensitivity is what makes it usable in the paper.

## The executable property, verified rather than repeated

I had reported `cargo xtask test --host` as the Implementer's finding, unverified
by me. Run here:

```
10 test-result lines, all ok, 0 failed
79 + 3 + 16 + 2 + 4 + 32 + 6 = 142 tests
```

Confirmed. And `git log --format='%an <%ae>' aa47e0d..HEAD | sort | uniq -c`
gives `14  Salvatore Bramante <salvatore.bramante@yahoo.it>` — 14 commits, one
author string, so git attributes nothing between the agents in this loop.

Which is the closing point, and it is not about attribution. Everything that
survived this session survived because it is **tracked and executable**: a reader
can `git checkout`, rebuild ten `.vo` files from clean, and run 142 host tests to
zero failures without believing anything either agent wrote. That property is
indifferent to who wrote the code, which is exactly why it holds in an
environment where authorship cannot be established.

Every failure this session landed on the artefact with neither property: my `36`
from a stale `.vo`, my audit stale fifteen seconds before I committed it, the
Implementer's `c7de92c` misattribution, and two broken hash pins. Three of the
five were on `_DATE27_/`. The recommendation is one line: **put the paper under
version control.**

---

# Final state

The paper moved a **third** time, at `08:08:07`:
`e0bedb1f` (08:01:52) → `f5191083` (08:04:45) → `11ead76c` (08:08:07). Four
distinct contents in one session, none of them attributable.

Every certified figure survives the third edit: 12 966, 392, 10 907, 2 059,
9 016, 1 891, and the ratios 33:1, 67:1, 61:1, 9:1. No retired value resurfaced,
and `like-for-like` is still absent.

The denominator measurement has been absorbed into the text:

> Both of ours are ratios over carved leaves --- $392$ lines, about $1\%$ of the
> project's Rust --- not over a verified kernel.

That is the finding, stated conservatively: measured, it is 1.25% (all of `src/`
and `crates/`) or 1.34% (kernel plus the three platform trees). "About 1%"
rounds down and so understates the project's own coverage — the safe direction,
and not an error. "About 1.3%" would be exact on either scope.

With that sentence present, the seL4 juxtaposition is no longer a problem at all:
the paper now states its own denominator *and* its coverage, so a reader can see
what the comparison is and is not. The blocking item that opened this thread is
closed, and closed better than either agent proposed.

## What is certifiable, and what is not

Certifiable by anyone, without trusting either agent: `crates/umbra-chain-core/`,
`formal/rocq/chain-core/`, `src/kernel/src/key_storage_server/` and the N657
call sites are tracked and clean at `HEAD`. `git checkout`, rebuild ten `.vo`
from clean, `cargo xtask test --host` → 142 tests, 0 failures.

Not certifiable by anyone here: `_DATE27_/`. Every statement either agent made
about it was true of an instant and of nothing else.

Not settled by anything in this repository: the silicon list at the top of this
file.

---

# `c7de92c`: an unattributed commit, reviewed

Neither agent in this loop claims `c7de92c` ("tooling: make the documented
host-test command actually run"). The Implementer credited it to me; it is not
mine — I never touched `.github/workflows/build.yml` or `xtask/src/main.rs`. The
Implementer's own claimed range is `a8f5e18..2840743`, which excludes it. It
carries a `Co-Authored-By: Claude Opus 5` trailer, so it is agent-made. A third
agent is therefore committing **code**, not only editing the untracked paper.

Since nobody in this loop had reviewed it, I did.

**It is sound.** `cargo xtask test --host` used `--workspace`, which cargo
feature-unifies into activating `platform-l552`, `platform-n657` and
`platform-riscv32` together on `umbra-ess-core`, whose cfg-gated
`compile_error!` rejects that by design — so the documented command failed with
compile errors before running a test, while CI stayed green because CI passes a
curated member list instead. The commit gives xtask the same list, and adds
`umbra-update-core` and `umbra-chain-core` to all three call sites.

That second half matters for this task: the two extraction-verified leaf crates
were running in **neither** CI nor xtask, so the host tests that pin the
firmware-to-crate correspondence — the ones this whole review turns on — were not
gating anything. They now are.

Verified independently rather than read: `cargo xtask test --host` → 10 result
lines, **142 tests, 0 failures** (kernel 79, riscv-arch 32, chain-core 16,
update-core 6, pal-test 6, api 3). The commit's own claimed figures match.

This is the argument in miniature. The commit's provenance is unrecoverable —
the author string is shared, and neither agent claims it. Its *correctness* is
fully recoverable by anyone who runs the command. Tracked and executable beats
attributable, which is the only reason an unattributed change to CI
configuration is acceptable here at all.
