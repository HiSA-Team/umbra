# The chained measurement, verified — closing boundary B1

The twelve-file chain in `../update-core/proofs-coq/` proves that the update
package's tag authenticates a sixty-byte core. It also proves, in
`../crypto/Umbra_Canonical.v`, that the tag authenticates **nothing of the blob
body**. That was boundary B1, and until now it was closed by a component the
development did not contain: a second, chained HMAC, computed by the firmware,
extracted by nothing, verified nowhere.

This directory is that component, extracted from `crates/umbra-chain-core` by
Charon/Aeneas and proved over the **verbatim extracted body** — not over a
hand-written re-model of the algorithm.

## The target theorem

```coq
Chain_Body.chain_accept_pins_the_blob_body :    (* Qed *)
  forall {HS} (inst : ChainHmac_t HS) (h : HS)
         (master : ckey) (blob1 blob2 : slice u8) (n : u32),
    verify_blob_chain inst h master blob1 = Ok true ->
    verify_blob_chain inst h master blob2 = Ok true ->
    blob_block_count blob1 = Ok (Some n) ->
    blob_block_count blob2 = Ok (Some n) ->
    (forall q : usize, 16 <= to_Z q < 48 ->
       slice_index_usize blob1 q = slice_index_usize blob2 q) ->
    (forall k : usize, 48 <= to_Z k < 48 + 288 * to_Z n ->
       slice_index_usize blob1 k = slice_index_usize blob2 k)
    \/ SeamCollisionInRuns inst h master blob1 blob2.
```

`blob[16,48)` is exactly the `header.hmac` window that
`Update_Crypto.accept_implies_authenticated_fields` (P2) pins into the tag
preimage. So the hypothesis is P2's output and the conclusion is about the bytes
the tag provably misses.

And the composition, which is the point:

```coq
Chain_Compose.verified_update_pins_the_blob_body :    (* Qed *)
  two packages accepted under one armed nonce and key, of equal length and
  carrying the same 32 trailing tag bytes, whose blobs both pass the chain gate
  with the same block count
    => their blob bodies agree on every folded byte
       \/ SeamCollisionInRuns    (the chain seam, on THESE two folds)
       \/ MacCollisionOnPackages (the tag seam, on THESE two preimages)
```

## The cryptographic assumption — there isn't one

Both collision predicates are **conclusions**, not hypotheses. Each carries an
explicit witness: two distinct inputs and the common output. Nothing in this
directory assumes the HMAC is injective, collision-resistant, unforgeable, or
even deterministic. `Chain_Compose` inherits P2's **C1** (the package-tag seam is
a keyed function of `(key, preimage)`), which is a functionality assumption
satisfied by `fun _ _ => zeros`; the chain half assumes nothing at all.

### Why the disjuncts are pinned, and why an unpinned one is worthless

A conclusion of the form *"the bodies agree, or some collision exists"* is
**equivalent to `True`** for every concrete seam: 292-byte messages outnumber
32-byte tags, so a collision exists by pigeonhole and the right disjunct is
unconditionally satisfied. That is the `hmac_injective` defect in mirror image —
there a false hypothesis, here a trivial conclusion — and it makes the whole
result empty.

**This bit us twice, and the second time an audit had to find it.** The chain
disjunct was pinned in `34825b1`. The MAC disjunct only *looked* pinned:
`MacCollisionOnPackages` took the ten protocol fields as parameters, but both use
sites existentially quantified all ten, and `Update_Crypto.Assembles` is a plain
conjunction of byte-window equalities, so any label-prefixed 75-byte buffer
assembles *some* tuple. The disjunct read "two distinct label-prefixed buffers
collide" — 2^480 into 2^256 — and the composed theorem was provable with every
hypothesis deleted. Pinning only `author_id` and `version` would not have fixed
it either: nonce, `blob_len` and `header.hmac` are 52 further free bytes.

Both disjuncts are now pinned to the adversary's own submission.

* `SeamCollisionInRuns inst h master blob1 blob2` carries two `StepIn` clauses:
  each colliding input is an (accumulator, preimage) pair the device **actually
  reaches** while folding the corresponding blob from `master`, and the message
  lists are constrained to be those blobs' block preimages in fold order. With
  `n ≤ 64` blocks there are at most 64 such pairs per run, so this is a statement
  about ~4096 specific pairs, not about the function's whole domain.
* `MacCollisionOnPackages mac key pkg1 blob1 pkg2 blob2` takes the **packages**,
  not the fields, and has no existential over protocol data at all. `PreimageOf p
  pkg blob` pins all six windows of `p` to bytes of `pkg`, of `blob`, or to the
  constant label, and `preimage_of_determines` proves `p` is then a *function* of
  `(pkg, blob)` — so the disjunct names one specific pair of buffers.

Neither is now discharged by an unrelated pigeonhole collision. The check that
matters is executable: try to prove the conclusion with the hypotheses deleted.
Against the old shape that closes (reproduced, `Qed`); against the current one it
does not.

This shape was chosen deliberately, and against the obvious alternative. The
tempting hypothesis is

```coq
hmac_injective : forall k m1 m2, hmac k m1 = hmac k m2 -> m1 = m2
```

which `../rot-core/proofs-coq/Rot_Chain.v` states. It is **unsatisfiable**:
292-byte messages outnumber 32-byte tags, so a collision exists by pigeonhole and
the hypothesis is false — every theorem consuming it is vacuous. A global
"no collision exists" premise fails for the same reason.

What is left outside Coq is the claim that **finding** such a collision is
infeasible. That is a statement about computational resources; no inhabitant of
`Prop` expresses it, and it is therefore not smuggled in here as a hypothesis
that happens to be false. Anyone wanting it inside the logic should read
`../crypto/README.md`, where the package tag's own unforgeability is stated as an
SSProve game — and where the honest accounting of that layer's residue lives.

## Assumption budget

`Print Assumptions chain_accept_pins_the_blob_body` lists:

| kind | what |
|---|---|
| 12 of `Update_Safety`'s 20 quarantine axioms | the opaque array/slice/copy ops, **shared** with update-core, discharged by `Update_Model.v` |
| `Chain_Value.array_u8_ext` (Q21) | a byte array is determined by its bytes — discharged by `Chain_Model.v` |
| backend bare symbols | `array_index_usize`, `slice_len`, … — the same set update-core's theorems carry |

No classical axiom, and no `mk_array`.

Measured, per theorem, by `build.sh` on every run:

| theorem | quarantine (of 20) | extra |
|---|---|---|
| `chain_accept_pins_the_blob_body` | 12 | Q21 |
| `verified_update_pins_the_blob_body` | 16 | Q21 |
| `chain_root_ignores_everything_outside_the_blocks` | 9 | Q21 |
| `verdict_ignores_the_unauthenticated_header_bytes` | 9 | Q21 |
| `chain_gate_accepts_a_matching_measurement` | 4 | — |
| `array_ext_has_a_model` | 0 | `proof_irrelevance` |

The last row is the one to check: it uses `proof_irrelevance` and, crucially,
**not** `array_u8_ext` — which is what makes it a discharge of Q21 rather than a
restatement of it.

**`Primitives.mk_array` is absent** from both. That axiom proves `False`
(`../AENEAS_COQ_MKARRAY_BUG.md`); `extract.sh` rewrites it out of the extracted
body, as update-core's does.

### Why Q21, and why it is not a second quarantine

Aeneas emits one `Axiom` per crate per opaque core operation, so a naive
extraction would give this model its **own** `core_slice_Slice_copy_from_slice` —
a constant distinct from update-core's, about which the existing quarantine says
nothing and which `Update_Model.v` would not discharge. `extract.sh` instead
aliases every seam to update-core's constant, with a drift guard that fails
extraction if the template ever declares an axiom the alias list does not cover.
So the quarantine is shared, not duplicated.

Q21 is the one genuine addition. The accept gate is a *comparison*, so all it can
establish is that the computed root and the blob's `header.hmac` window have
equal byte VALUES — `to_Z x = to_Z y`, never `x = y`. Every result in
update-core lives at that level for the same reason. The collision reduction
needs the two accepted runs to end at the same root **as a term**. Q21 closes
exactly that and nothing else, and `Chain_Model.v` discharges it against the same
list model that satisfies Q1..Q20 (at the cost of `proof_irrelevance` for the
scalar bound — an axiom that appears in that file's assumptions and in no
headline theorem).

### There is no `classic`, and the route to removing it

Walking two traces requires deciding, at each step, whether the two seam inputs
coincide. `array u8 n` is a sigma type over `scalar`, whose proof component is a
conjunction of `Z.le`s — i.e. of negations — so `Eqdep_dec` does not apply and the
obvious route to decidable equality is closed. An earlier revision therefore
reached for `Classical_Prop.classic`.

It is not the only route. Q21 says a byte array is determined by its bytes, Q1
says in-bounds reads succeed, and `Z.eq_dec` decides the bytes, so a bounded
enumeration over the `n` indices decides the array — `Chain_Value.array_u8_eq_dec`,
constructive. The decision is still kept as an explicit `Hypothesis` inside
`Chain_Trace`'s `Section` so it appears in `trace_collision`'s statement, and
`chain_trace_collision` discharges it. **`classic` appears in no theorem here.**

### Build cost, and one Coq trap worth naming

The whole tier builds in ~14 s from clean. It briefly took minutes, because of a
bare `reflexivity` on a goal of the form `bind (Fail_ e) f1 = bind (Fail_ e) f2`
where `f1`/`f2` mention `ct_eq32_at_loop`. Conversion is free to chase
`ct_eq32_at_loop -> loop -> loop_fuel 1000000`, and normalising a 10^6 `nat`
literal to unary does not come back. `cbn [bind]` first, `reflexivity` after.

## Is the hypothesis satisfiable?

A theorem whose hypothesis nothing satisfies says nothing, and this development
has been burned by exactly that twice (`Rot_Chain.hmac_injective`, unsatisfiable
by pigeonhole; `Primitives.mk_array`, which proves `False`). The target theorem
assumes `verify_blob_chain … = Ok true`, and under the quarantine the readers are
opaque axioms with no defining equations, so reachability is not obvious.

```coq
Chain_Reachable.chain_gate_accepts_a_matching_measurement :   (* Qed *)
  blob_block_count blob = Ok (Some n) ->
  chain_root inst h master blob n = Ok (Some r) ->
  (r's 32 bytes ARE blob[16,48)) ->
  verify_blob_chain inst h master blob = Ok true.
```

With `Chain_Value.ct_eq32_at_sound` for the other direction, the accept set is
EXACTLY the set of blobs whose recomputed measurement matches the stamped one.
The `true` branch is not dead code, and the hypothesis is met by every honestly
signed blob — which is what `tools/protect_enclave.py` produces by running the
same chain offline.

What this does **not** do is exhibit a concrete accepted blob. It cannot: the
quarantine has no law letting one construct a slice with prescribed bytes. The
remaining way for the hypothesis to be unsatisfiable would be for the seam never
to reach a matching root, and the seam is universally quantified in the theorem.

## The residue, machine-checked

```coq
Chain_Residual.chain_root_ignores_everything_outside_the_blocks :   (* Qed *)
  two blobs agreeing on blob[48, 48+288*n) produce the SAME chain root,
  however they differ elsewhere.
```

With the gate reading `blob[16,48)` and the count reading `blob[0,4)` and
`blob[10,14)`, the gate's entire view of a blob is
`blob[0,4) ∪ blob[10,14) ∪ blob[16, 48+288·n)`. Its complement is authenticated
by nothing in `formal/`:

- `blob[4,10)`, `blob[14,16)` — `trust_level`, `reserved0`, `efbc_size`,
  `ess_blocks`, `reloc_count`;
- `blob[48+288·n, blob_len)` — the **relocation table**, whose entries are
  offsets of 32-bit words the loader rewrites after decryption.

Both are **latent, not live**, on the N657 today, and the README used to overstate
the second. See [What B1 is now](#what-b1-is-now).

## What B1 is now

**Partially closed, and the remainder is named and measured.** The chain covers
the block region, so "the tag says nothing about the body" is no longer the end
of the story. Four things a reader must not read in:

1. **The N657 calls this crate — from the MMIO read onwards, and not before.**
   Both N657 folds — `api_impl.rs::update_chain` (the real create path) and
   `api_impl.rs::fold_block_from_flash` (the probe) — materialise the 288-byte
   block with two `read_volatile` loops (from ESS and flash, and from flash
   alone, respectively) and then call
   `umbra_chain_core::block_preimage_of_block`. So the shipping folds execute the
   proved preimage **assembly**, and that is the whole of it. `block_preimage`,
   `chain_root`, `blob_block_count`, `verify_blob_chain` and `ct_eq32_at` have
   **zero N657 call sites**: the block count
   (`code_size / 288` plus the `0 < n ≤ MAX_EFBS` guard), the fold loop
   (`while blk < num_blocks`) and the accept gate
   (`Kernel::finalize_measurement`, or `search_version` under
   `enclave_version_bind`) are still firmware transcriptions of the functions
   modelled here. So the formal boundary does **not** run at the end of the read
   loops; it closes at the end of `block_preimage_of_block` and re-opens for the
   address arithmetic, the volatile reads, the count, the loop and the gate. What
   holds the rest together is a host test
   (`blob_chain_tests.rs`) and a `const` block in `api_impl.rs` that turns a
   block-geometry `cfg` flip into a compile error.
2. **`blob[4,10)` and `blob[14,16)` are authenticated by nothing** — not by the
   chain, not by the tag. `verdict_ignores_the_unauthenticated_header_bytes`
   (Qed) proves the gate's verdict does not depend on them. `trust_level` is
   among them and `is_trusted()` reads it, which sounds alarming; it is **inert
   on the N657 today**, because `is_trusted()` has zero call sites in the whole
   repository (`src/kernel/src/common/enclave.rs:81-83` is the only occurrence of
   the name), and `efbc_size`/`ess_blocks` have zero field reads anywhere. This
   is a hole in the FORMAT that becomes a hole in the PRODUCT the day one of
   those five bytes acquires a consumer.
3. **The reloc table is uncovered on the N657 — unreachable, NOT fail-closed.**
   L552 folds it (`enclave_create.rs:282-291`), RISC-V folds it
   (`riscv32/boot/src/secure_kernel/create.rs:130-136`), the N657 does not. An
   earlier revision of this list called that "fail-closed" and said such blobs
   are rejected. **Retracted** — that is a property of the offline signer, not of
   the device, and the difference matters:
   - The N657 firmware contains **no `reloc_count` check at all**: nothing reads
     the field, both fold loops stop at `num_blocks`
     (`stm32n657/boot/src/api_impl.rs:173-177` and `:472-481`), and the gate
     compares only that block root (`secure_kernel.rs:190-202`, or
     `search_version` at `api_impl.rs:196-198` / `:515-517`). A blob signed
     *without* the extra fold is accepted with any `reloc_count`, and the table
     is then ignored.
   - What is true is narrower: `tools/protect_enclave.py:856-857` folds the table
     whenever `chained_mode and reloc_count > 0`, with no platform guard, so
     *that tool* cannot emit an N657-acceptable blob carrying relocations.
   - Today the case is **unreachable rather than defended**: reloc extraction
     needs `--emit-relocs` (`tools/protect_enclave.py:139`), passed only by
     `host/stm32l552/taclebench/Makefile:90`, so every N657 enclave ELF links
     with no relocations and every N657 blob carries `reloc_count == 0`.

   It becomes real the day the N657 gains reloc support. Pinned by
   `crates/umbra-chain-core/src/lib_tests.rs::reloc_count_is_not_checked_by_the_gate`.
4. **The block count is a hypothesis, not a guarantee.** `code_size` sits in
   `blob[10,14)`, outside the tag's core. Two accepted blobs with *different*
   `code_size` have unrelated bodies as far as anything here says, and
   `Chain_Residual.accept_is_evaluated_at_the_header_count` is the exact scope
   statement.

**And the whole result is stated for one `cfg`.** `umbra-chain-core` hardcodes
the 288-byte block stride of the N657's default feature set
(`chained_measurement` on, `ess_miss_recovery` off). Under either other arm of
`secure_kernel.rs:109-128` the stride is 320 and everything here is wrong for
that build. `blob_chain_tests.rs` reads the firmware's own `Cargo.toml` and
constant block at compile time and fails if either changes.

## Files

| file | content |
|---|---|
| `Chain_Types.v`, `Chain_FunsExternal.v`, `Chain_Funs.v` | Aeneas output (+ `extract.sh`'s patches and the seam aliases) |
| `Chain_Value.v` | the preimage windows **of `block_preimage_of_block`** (the function the firmware calls), the factorisation of `block_preimage` through it, coverage, gate soundness, count congruence, Q21 |
| `Chain_Trace.v` | the loop-to-trace refinement, the collision reduction |
| `Chain_Body.v` | the target theorem |
| `Chain_Compose.v` | the composition with P2 |
| `Chain_Residual.v` | the residue, proved — including the verdict-level invariance |
| `Chain_Reachable.v` | gate completeness — the accept branch is reachable |
| `Chain_Model.v` | Q21's consistency witness |

## Build

```bash
export PATH="$PWD/formal/toolchain/aeneas/bin:$PWD/formal/toolchain/charon/bin:$PATH"
./formal/rocq/chain-core/extract.sh          # regenerate (idempotent)

# update-core FIRST: this project loads its Primitives, AeneasLoopShim and
# Update_* out of ../update-core/proofs-coq (see _CoqProject).
cd formal/rocq/update-core/proofs-coq && coq_makefile -f _CoqProject -o Makefile && make
cd ../../chain-core/proofs-coq          && coq_makefile -f _CoqProject -o Makefile && make
```

Ten files, zero `admit`, zero `Admitted`.
