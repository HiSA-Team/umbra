# umbra-chain-core — the blob-body half of the verifiable update

`umbra-update-core` authenticates an update package's **76-byte core** (pkg-tag
v2): nonce, `author_id`, `version`, `blob_len` and the full 48-byte UMBR header
`blob[0,48)` (which includes `header.hmac` at `blob[16,48)`). It does not
authenticate the blob's body, and that is a theorem, not an omission:

```coq
Umbra_Canonical.blob_body_is_not_covered_by_pkg_tag :   (* Qed *)
  two packages of equal length agreeing on pkg[4,32), pkg[48,80) and the
  trailing 32 bytes have the SAME tag, however they differ in the blob body.
```

Body integrity rests instead on a **second, chained HMAC** rooted at that
authenticated `header.hmac`:

```text
  M₀    = master_key
  Mₖ₊₁  = HMAC(Mₖ,  blk_le32(k) ‖ block[k].code ‖ block[k].meta)
  accept  ⟺  M_n == blob[16..48)
```

Until this crate existed, that chain lived only inside the N657 boot crate,
behind `read_volatile` on the memory-mapped XSPI2 window — extractable by
nothing, and verified nowhere. This crate is that chain as pure logic:
`#![no_std]`, `#![forbid(unsafe_code)]`, the HMAC behind a trait seam taking one
flat preimage array. `formal/rocq/chain-core/` proves things about it; see
[that directory's README](../../formal/rocq/chain-core/README.md) for what,
exactly, and under which assumptions.

## Fidelity — and the one configuration this is true of

The flash reads become indexing into a caller-owned `&[u8]`. Order, offsets,
bounds and gate are the firmware's. The constants are those of the **default**
N657 feature set (`chained_measurement` on, `ess_miss_recovery` off), where a
block is `[meta(32) | code(256)]`.

**This crate hardcodes that configuration.** Under either other `cfg` arm of
`secure_kernel.rs:109-128` the block header is 64 bytes, the meta offset is 32
and the stride is 320 — and then the crate, the transcription and every Coq
theorem about them are wrong for that build. A drift guard
(`blob_chain_tests.rs::the_firmware_still_uses_the_configuration_we_transcribed`)
reads the firmware's own `Cargo.toml` and constant block at compile time and
fails if the default feature list or the `chained_measurement` arm changes.

| constant | value | firmware source |
|---|---|---|
| `HDR_LEN` | 48 | `kernel::common::enclave::UMBRA_HEADER_SIZE` |
| `HDR_HMAC_OFF` | 16 | `UmbraEnclaveHeader::hmac` offset |
| `CODE_SIZE_OFF` | 10 | `UmbraEnclaveHeader::code_size` offset |
| `CODE_LEN` | 256 | `secure_kernel::CODE_BLOCK_SIZE` |
| `META_LEN` | 32 | `secure_kernel::BLOCK_META_SIZE` |
| `BLOCK_LEN` | 288 | `secure_kernel::TOTAL_BLOCK_SIZE` |
| `BLOCK_PREIMAGE_LEN` | 292 | `fold_block_from_flash`'s `verify_buf` |
| `MAX_BLOCKS` | 64 | `umbra_ess_core::MAX_EFBS` |

`src/kernel/src/key_storage_server/blob_chain_tests.rs` used to transcribe the
whole of `stm32n657/boot/src/api_impl.rs::fold_block_from_flash`. Now that the
firmware calls this crate, the assembly is not duplicated and cannot drift;
what the file still transcribes is the MMIO half (the address arithmetic and the
two read loops, with the pointer reads replaced by slice indexing), and its
`firmware_replica_preimage` calls `block_preimage_of_block` exactly as the
firmware does. `the_firmware_calls_the_proved_assembly` slices both
`update_chain` and `fold_block_from_flash` out of the firmware source at compile
time and checks, for each, that the call is there, that the inline assembly has
not grown back, and that exactly the two volatile read loops remain. `authenticated_version_at`'s accept condition is
still transcribed, and verdicts are still compared across every single-byte flip
of a blob.

## Wiring status — read before quoting the proofs

The kernel re-exports this crate at `kernel::key_storage_server::blob_chain`, and
**both N657 folds call `block_preimage_of_block`**:
`stm32n657/boot/src/api_impl.rs::update_chain` (the real create path, whose
measurement decides whether an enclave runs) and the same file's
`fold_block_from_flash` (the side-effect-free probe behind A/B slot selection and
post-update re-verification). The shipping folds execute the proved assembly.

### The shape of the wiring, and why it is a dependency inversion

The firmware cannot pass a blob slice: it reads block bytes out of the
memory-mapped XSPI2 window with `read_volatile` into a local buffer. Adding a
block-shaped entry point *alongside* `block_preimage` would have given the
firmware a **cousin** of the proved code — every theorem in
`formal/rocq/chain-core/` is about `block_preimage` — and moved the gap down one
level rather than closing it.

So the dependency runs the other way. `block_preimage_of_block(blk, &[u8; 288])`
is the assembly and the single source of truth; `block_preimage(blob, blk)` keeps
the two bounds guards, materialises `blob[base, base+288)` and delegates. The
extraction was redone over that body, and the Coq side follows the same shape:

| lemma | about |
|---|---|
| `Chain_Value.preimage_of_block_windows` | `block_preimage_of_block` — the three windows, no blob in the statement |
| `Chain_Value.preimage_of_block_pins_block` | `block_preimage_of_block` — all 288 block bytes are covered |
| `Chain_Value.preimage_factors_through_block` | `block_preimage` = guards ∘ materialise ∘ `block_preimage_of_block` |
| `Chain_Value.preimage_windows` | now a **corollary** of the two above, statement unchanged |

`Print Opaque Dependencies` on `Chain_Body.chain_accept_pins_the_blob_body` and
on `Chain_Compose.verified_update_pins_the_blob_body` lists both new lemmas, so
the headline theorems constrain the function the firmware calls.

### What this does NOT close

**The firmware runs one of this crate's six entry points.** It calls
`block_preimage_of_block`. `block_preimage`, `chain_root`, `blob_block_count`,
`verify_blob_chain` and `ct_eq32_at` have **zero N657 call sites**. So the
boundary does not run "at the end of the read loops": it closes at the end of
`block_preimage_of_block` and re-opens straight away.

Still firmware, still transcription, touched by no theorem:

| firmware | the modelled counterpart it transcribes |
|---|---|
| the address arithmetic (`block_base`, `code_src`, `meta_src`) and the volatile reads | nothing — this is the `&[u8; 288]` boundary itself |
| `header.code_size / TOTAL_BLOCK_SIZE`, then `n == 0 \|\| n > MAX_EFBS` | `blob_block_count`, magic check included |
| `while blk < num_blocks { … }` | `chain_root`, accumulator threading included |
| `Kernel::finalize_measurement`, or `search_version` under `enclave_version_bind` | `verify_blob_chain`'s gate / `ct_eq32_at` |

The accurate sentence is: *the shipping folds execute the proved preimage
assembly; the block count, the fold loop and the accept gate remain firmware
transcriptions of the modelled ones.* Not "residual (i) is closed", not "the
firmware executes the proved code", not "the fold is verified".

Three guards hold what is held:

- a `const` block in `api_impl.rs` asserts the platform's block geometry against
  this crate's (`TOTAL_BLOCK_SIZE == 288`, `BLOCK_META_OFFSET == 0`,
  `BLOCK_HEADER_SIZE == 32`), so building the other `cfg` arm is a **compile
  error** rather than a silent chained-measurement break;
- `blob_chain_tests.rs::the_firmware_calls_the_proved_assembly` reads the two
  firmware fold bodies at compile time and checks the call, the absence of a
  regrown inline assembly, the two volatile read loops, **and the destination
  offsets those loops write to** — the last of these because a mutation that
  swaps only the destinations (code into `block[0..256]`, meta into
  `block[256..288]`) inverts the halves, would reject every already-signed
  enclave, and passed every other test in this file;
- `blob_chain_tests.rs::the_replica_block_is_the_blobs_block` pins the
  **replica's** offset arithmetic against this crate's `base`. It does not, and
  cannot, execute the firmware's own arithmetic: the guard above is structural
  precisely because this one is one level of indirection away from the device.

## The residue

The chain covers `blob[48, 48 + 288·n)` and nothing else. Machine-checked in
`formal/rocq/chain-core/proofs-coq/Chain_Residual.v`, the gate's entire view of a
blob is `blob[0,4) ∪ blob[10,14) ∪ blob[16, 48+288·n)` plus its length. Outside
it: `blob[4,10)`, `blob[14,16)`, and everything at or beyond `48+288·n`. Both are
latent rather than live on the N657, for reasons that are about the CONSUMERS,
not about the proof.

### The header bytes (`blob[4,10)`, `blob[14,16)`) — CLOSED at the tag (pkg-tag v2)

Historically authenticated by nothing — not by the chain, not by the v1 tag.
`Chain_Residual.verdict_ignores_the_unauthenticated_header_bytes` (Qed) proves
the CHAIN gate's verdict does not depend on them at all — still true, and by
design: the chain covers the body, not the header.

**Since pkg-tag v2 the update package tag covers the full header `blob[0,48)`**
(label `umbra-update-v2`, preimage 75 → 91 bytes; see
`crates/umbra-update-core/src/lib.rs` and ADR 013). A post-signing flip of
`trust_level`, `efbc_size`, `ess_blocks` or `reloc_count` now dies at the tag
gate (`ERR_AUTH`) before any flash write — `header-flip` in
`tools/attest_update.py --attack` is the on-device regression. The measurement
chain itself is untouched.

Context that motivated the fix (still true): `is_trusted()` has **zero call
sites in the repository** — `EnclaveTrustLevel` occurs only in its own
declaration and in the single comparison inside `is_trusted`
(`src/kernel/src/common/enclave.rs`), and nothing anywhere calls the method;
`efbc_size` and `ess_blocks` have zero field reads on any platform. The hole
was in the **format**, latent until one of those bytes acquired a consumer;
v2 removes the trap instead of waiting for it to spring. Note the tag only
protects blobs that arrive through the signed update path — a blob written to
flash out-of-band is still constrained only by the chain.

### The relocation table (`blob[48+288·n, blob_len)`)

A real asymmetry, **latent**, not live. L552 folds the reloc bytes into the chain
(`stm32l552/boot/src/api_impl/enclave_create.rs:282-291`,
`generator.update_chain(&mut kernel.chain_state, reloc_bytes)`); RISC-V folds
them (`riscv32/boot/src/secure_kernel/create.rs:130-136`); the N657 does not.
Three facts bound it there today — note that the first two are properties of the
*consumers* and of the *signer*, and only the third would be a property of the
device, which is why the device-level phrasing below is the careful one:

- **No N657 consumer.** `apply_relocs_to_block` exists only at
  `stm32l552/boot/src/secure_kernel/init.rs:101`, with a separate RISC-V
  equivalent and no N657 one. No N657 code reads `header.reloc_count` or the
  table. Unmeasured bytes nothing consumes are inert.
- **The signer cannot produce an accepted reloc blob.**
  `tools/protect_enclave.py:856-857` folds the table into the chain whenever
  `chained_mode and reloc_count > 0` (no platform guard) and stamps the result
  into `header.hmac` (`:893-894`, `:917`), so an N657 blob built by that script
  with relocations presents a root the device's block-only fold cannot reproduce
  and is rejected.
- **Not producible in this tree at all.** Reloc extraction needs `--emit-relocs`
  (`tools/protect_enclave.py:139`), passed only by
  `host/stm32l552/taclebench/Makefile:90`. No N657 link passes it, so
  `arm-none-eabi-readelf -W -r` on an N657 enclave ELF reports *no relocations in
  this file* and every N657 blob carries `reloc_count == 0` (verified on
  `host/stm32n657/two_enclaves/app/ndes.elf`: `reloc_count = 0` in its
  `._enclave_header`).

**What is NOT true — corrected here.** An earlier revision of this section and of
`src/lib.rs` called this "fail-closed" and said the N657 *rejects* blobs with
`reloc_count > 0`. The device does no such check: it has no read of the field,
its fold loops (`stm32n657/boot/src/api_impl.rs:173-177`, `:472-481`) stop at
`num_blocks`, and the gate compares only that root
(`stm32n657/boot/src/secure_kernel.rs:190-202`, or `search_version` at
`api_impl.rs:196-198` / `:515-517` under `enclave_version_bind`). A blob signed
with the master key but *without* the extra reloc fold is accepted with any
`reloc_count`. `src/lib_tests.rs::reloc_count_is_not_checked_by_the_gate` pins
both halves: fold-then-sign is rejected, sign-without-fold is accepted.

If the N657 is ever to *enforce* `reloc_count == 0` rather than merely never be
handed a non-zero one, that needs an explicit check in the firmware
(`num_blocks` guard site in `authenticated_version_at` and
`umbra_enclave_create_imp`, both, or it drifts) — proposed, not made here, since
the fold-instead-of-reject fix below is the one that also keeps the feature
usable.

It becomes real the day the N657 gains reloc support, which it would need to run
the static-PIE applications the L552 runs. **Proposed fix, for that day:** fold
the reloc table on the N657 too, as one further `hmac_sha256` step after the
block loop, in both `umbra_enclave_create_imp` and `authenticated_version_at`
(they must stay in sync). L552's own comment (`enclave_create.rs:250-257`) says
the fold is exactly what catches on-flash tampering of those offsets. Not made
here, for the same reason as above.
