# The cryptographic layer of the verifiable update core

The twelve-file chain in `../update-core/proofs-coq/` proves **functional**
properties of the secure enclave-update parser extracted from Rust by
Charon/Aeneas: that it never panics or reads out of bounds (P3), that acceptance
implies both authentication gates ran (P1), that acceptance implies the compared
tag equals `mac key pre` for a 91-byte preimage whose every byte is pinned (P2),
that the preimage assembly is injective in the five protocol fields
(`assembly_injective`), and that activation implies a strictly newer version
(P4). All `Qed`, zero admits.

None of that rules out an attack. The chain's only cryptographic-looking
hypothesis, **C1** (`Hseam`), says merely that the HMAC seam is a *deterministic
function* of `(key, preimage)` — the constant function `fun _ _ => zeros`
satisfies it. There is no adversary, no unforgeability and no probability
anywhere in the development.

This directory adds those three. It states **EUF-CMA** as a game in
[SSProve](https://github.com/SSProve/ssprove) — a game-based cryptography
library that lives inside Coq — keeps the functional results as the lemmas the
cryptographic proof consumes, and proves a **reduction**: an adversary that gets
the device to accept a package whose authenticated core was never signed is an
adversary against the EUF-CMA security of the underlying MAC.

> **Revision note (2026-09-02).** The Aeneas half of the axiom budget described
> below no longer exists: the backend operations are defined, not postulated
> (`../update-core/proofs-coq/Primitives.v`), `Update_Safety`'s laws are lemmas,
> `Update_Model.v` is gone, and `ArrayVectors` is a theorem
> (`Umbra_ArrayVectors.ArrayVectors_holds`) rather than a premise, so
> `device_forgery_le_eufcma_for_the_concrete_engine` no longer carries it.
> `Print Assumptions device_forgery_le_eufcma_at_the_real_seam` now lists the
> **7** SSProve/mathcomp foundations and nothing else; every count of 43 or 50
> below is historical.

Read ["What is *not* proved"](#what-is-not-proved) before quoting any of it.

## Read this first: the bound does not cover the update blob

The authenticated message is seventy-six bytes: `pkg[4,32)` — nonce, `author_id`,
`version`, `blob_len` — and `pkg[32,80)`, which is `blob[0,48)`, the FULL
48-byte UMBR header (its 32-byte **`header.hmac`** field included; v1 covered
only that field). That is the whole of what `msg_of_pkg` reads and the whole of
what the package tag authenticates.

**The blob's own body is not in the preimage.** `blob[48,blob_len)` is outside
it, and `parse_and_verify` performs no check on it: it copies `blob[0,48)` into
its header scratch, tags the fixed core, compares the trailing 32 bytes, and
returns the entire blob unexamined as `verifiedUpdate_blob`. The consequence is
a theorem, not a caveat:

```coq
Umbra_Canonical.blob_body_is_not_covered_by_pkg_tag :   (* Qed *)
  forall p q : slice u8,
    to_Z (slice_len p) = to_Z (slice_len q) ->
    (forall i, 4  <= i < 32 -> rdS p i = rdS q i) ->
    (forall i, 32 <= i < 80 -> rdS p i = rdS q i) ->
    (forall i, to_Z (slice_len p) - 32 <= i < to_Z (slice_len p) ->
       rdS p i = rdS q i) ->
    msg_of_pkg p = msg_of_pkg q /\ tag_of_pkg p = tag_of_pkg q.
```

Two packages of equal length that agree on the authenticated core and on the
trailing tag are **indistinguishable to the package-tag check**, however they
differ in the blob body.

So **blob integrity is established by nothing in THIS directory.** It rests on a
second, **chained HMAC** that the firmware computes over the blob and compares
against the authenticated `header.hmac` window. What this development contributes
to it is exactly one thing: *the 48-byte header carrying the value it compares
against — the 32-byte `header.hmac` field included — is authenticated.*

That chained HMAC used to be verified nowhere. It now is, in
[`../chain-core/`](../chain-core/README.md): the fold is extracted from
`crates/umbra-chain-core` by the same pipeline, and
`Chain_Body.chain_accept_pins_the_blob_body` (Qed) proves that two blobs accepted
against the same `header.hmac` window either agree on every byte of the folded
region or exhibit an HMAC collision — a reduction, with no assumption on the
seam. `Chain_Compose.verified_update_pins_the_blob_body` (Qed) joins it to P2 at
exactly the window above.

Read the residue before quoting any of that. The chain covers
`blob[48, 48+288·n)` only. Its own verdict ignores `blob[4,10)` and
`blob[14,16)`, but pkg-tag v2 authenticates those header bytes; bytes after the
folded blocks — including the relocation table — remain outside both
authenticators. No N657 code consumes that table today, and the offline signer
cannot emit one that the N657 accepts. The N657 folds now call the extracted
crate's proved `block_preimage_of_block` assembly, while their address
arithmetic, volatile reads, block-count loop and final gate remain firmware
transcriptions guarded by structural and differential host tests.

Every reader of "verified secure enclave update" will read *whole-blob* integrity
into it. That reading is still wrong, and this paragraph is the reason the phrase
should not be used unqualified.

## Before the claim: `Umbra_Reduction.v` contains no Umbra content — `Umbra_RealGame.v` does

Read this section and the next one together. The first records the defect as it
stood; the second records what changed and what did not.

`Print Assumptions update_forgery_le_eufcma` shows **no Aeneas axiom and no
`Update_*` dependency at all**. Tier G is a general fact about a relabelled
EUF-CMA game: `UPD` is `EUF_CMA` with `gettag`/`checktag` renamed to
`sign`/`submit` and the verification query pre-composed with two arbitrary
readers, so `RED` is a bijection of oracle names and both game hops are perfect
for trivial reasons. **The two SSProve files would compile unchanged if
`parse_and_verify` did not exist.**

All of the Umbra-specific content lives in Tier D, and the two tiers meet only
through `device_accept_implies_submit_true` — a Coq implication whose lifting to
probabilities is [taken on paper](#the-remaining-obligation-precisely). So the
bound is a real theorem about a real reduction, and it is not a theorem *about
this parser*; what ties it to this parser is Tier D, and the tie is an event
inclusion, not a game hop.

## What `Umbra_RealGame.v` changes, and what it does not

`Umbra_RealGame.v` states the same bound over a game whose `submit` oracle **is**
the extracted `parse_and_verify`. The measurable difference:

```
Print Assumptions Umbra_Reduction.update_forgery_le_eufcma
  -> 7 axioms, 0 of them Aeneas   (propositional_extensionality, proof_irrel, reals, ...)
Print Assumptions Umbra_RealGame.device_forgery_le_eufcma
  -> 50 axioms, 43 of them Aeneas (20 bare uninterpreted declarations,
                                   3 usize/isize bound propositions,
                                   20 Update_Safety quarantine laws)
```

**These figures are re-measured, and the previous ones were wrong.** An earlier
revision of this README and of the commit message said 49/42, deriving the
Aeneas half from "22 backend symbols" where the revision before it had correctly
said 23. Both numbers were off by one, in the one document whose value
proposition is honest accounting. The current figures come from counting the
`Print Assumptions` output of `device_forgery_le_eufcma` itself; see the [axiom
budget](#axiom-budget), which now presents the 43 in the three classes they
actually fall into rather than as one lump.

(The Aeneas count rose from 23 when `(F)` became a theorem: proving the parser's
*converse* needs the "what the ops RETURN" value laws that P3, a pure totality
statement, did not. They are the same quarantine block, already exhibited
consistent by `Update_Model.v`, so no new trust is taken on.)

Those 43 reach the statement through exactly one path — `DEV` ▸ `dev_accepts` ▸
`Umbra_Wire.accepts` ▸ `Update_Funs.parse_and_verify` — so this file, unlike the
other two Tier-G files, does not survive the deletion of the extracted code.

**The type obstruction was not where the development thought it was.** It is true
that an Aeneas `slice u8` is not a `choice_type` and cannot be made one. It is
false that this prevents the parser from appearing in an oracle. SSProve requires
a `choice_type` of the oracle's *argument*, not of the function's semantic domain
(`opsig := ident * (choice_type * choice_type)`; `Inductive raw_code (A :
choiceType) := ret (x : A) | ...`). `chList chNat` is a `choice_type`, so the
adversary submits **wire bytes** — what a real attacker actually controls — and
`Umbra_Wire.wire` marshals them into a `slice u8` inside the oracle body, as an
ordinary total Coq function. `ret` neither requires nor uses reduction, so it is
irrelevant that `accepts` is a stuck term over `Primitives`' axioms. This also
retires item 1 of [the remaining obligation](#the-remaining-obligation-precisely):
the package space is now `list nat` with a marshalling proved value-preserving
(`Umbra_Wire.wire_bytes`, `Qed`), not an unconstructed injection into `nat`.

**The real obstruction is simulability, and it is unchanged.** A key-less `RED`
cannot run an HMAC, so to answer `submit` with the *device's* verdict it needs the
verdict to factor as

```
accepts key p  =  struct_ok p && (wtag p == MAC k (wmsg p))          (F)
```

with `struct_ok` key-free. `(F)` **used to be** the section hypothesis
`Umbra_RealGame.Hfactorise`, and was the only thing between this file and a
machine-checked end-to-end bound. It is now a `Lemma`, proved over the verbatim
extracted body:

| piece | file | what it proves |
|---|---|---|
| `ct_eq16_complete`, `ct_eq32_complete` | `../update-core/proofs-coq/Update_Value.v` | equal bytes ⇒ the constant-time comparators return `Ok true` (the converse of the pre-existing `*_sound`; genuinely new) |
| `accept_implies_struct` | `Update_Converse.v` | acceptance ⇒ branches 1–5 of the parser hold, each as an equation on package BYTES |
| `parse_walk` | `Update_Converse.v` | branches 1–5 ⇒ the body reduces to a *single* `ct_eq32`, over a preimage that assembles this package's fields and encodes to `msg_of_pkg` |
| `tag_gate_iff` | `Update_Converse.v` | that comparison holds **iff** the base-257 encodings of the two 32-byte windows are equal |
| `accept_factorises` | `Update_Converse.v` | (F) over `slice u8`, under C1 + C1e |
| `wstruct_ok`, `wstruct_ok_iff` | `Umbra_WireConverse.v` | the CONCRETE key-free `struct_ok : list nat -> bool`, proved equal to branches 1–5 |
| `wire_accept_factorises` | `Umbra_WireConverse.v` | (F) at the wire — i.e. `Hfactorise` |

All `Qed`, zero admits, no axiom outside the existing quarantine.
`Check @Umbra_RealGame.device_forgery_le_eufcma` no longer shows `struct_ok` or
`Hfactorise` in the type.

**What survives.** Two named seams, both inherited verbatim from the
deterministic tier and both already documented in `Umbra_DeviceLink.v`: **C1**
(`SeamC1` — the HMAC seam is a deterministic function of key material and
preimage; the constant function satisfies it) and **C1e** (`SeamC1e` — the seam
depends only on the byte values of an *assembled* preimage, and `dkey k` is the
device-side realisation of the game key `k`). Neither seam carries
unforgeability.

## The abstract `MAC` is now pinned to the seam, constructively

This was the largest remaining gap and it was not previously stated as one.
`device_forgery_le_eufcma` quantifies over an abstract `MAC` and ties it to the
real seam only through C1e — i.e. **only on the image of the assembled
encoding**. The only witness the directory exhibited was obtained by
`ClassicalEpsilon`, which leaves `MAC` arbitrary off that image. Under that
reading, *"HMAC-SHA256 is EUF-CMA-secure, therefore the right-hand side of the
bound is small"* **was not a valid inference**, because the right-hand side is
an advantage against the chosen `MAC`, not against HMAC.

What replaces it:

| | |
|---|---|
| `Umbra_Canonical.canon_rd` | decodes a message integer back to the 91 preimage **byte values**: base-257 digits for the 76-byte core, the constant `PKG_TAG_LABEL` for the 15-byte label the encoding never reads |
| `Umbra_Canonical.canon_rd_of_assembled` (`Qed`) | for an **assembled** preimage the decoding reproduces all 91 of its bytes — the constructive replacement for the choice step |
| `Umbra_Canonical.MG_of` | `MG_of mb kb m := mb (key bytes of kb) (canonical 91 bytes of m)` — a **definition**, not a chosen function; the seam itself at every argument |
| `Umbra_Canonical.MG_of_satisfies_C1e` (`Qed`) | it satisfies C1e |
| `Umbra_Canonical.canon91_injective` (`Qed`) | the message encoding is **injective** on `[0, 257^76)`, which contains every message the protocol can produce (`msg_of_pkg_lt`) — so `MAC` is the engine precomposed with an injective encoding, the shape under which an EUF-CMA assumption transfers |
| `Umbra_ByteSpace.spread`, `spread_injective` (`Qed`) | the game's message space is the **byte-valid subimage** `[0, 256^76)`, included into the base-257 numerals by `spread` (same seventy-six digits, different radix). `[0, 257^76)` was tried first and is the **wrong** set: 25.64 % of it decodes to lists containing the sentinel `256`, where `ByteSeam` says nothing — see *What pinning exposed* |
| `Umbra_WireConverse.SeamC1e_realisable_over_keymap` (`Qed`) | the composition the theorem actually needs: `exists MAC : K -> nat -> nat, forall k, SeamC1e macf (dkey k) (MAC k)`. The previous `SeamC1e_realisable` delivered `slice u8 -> nat -> nat` and stopped one step short of the hypothesis it justified |
| `Umbra_RealGame.device_forgery_le_eufcma_at_the_real_seam` (`Qed`) | the bound, instantiated at `MACg` of `MACb_canonical` — i.e. at `Umbra_ByteSpace.MG_spread`, and at the message bound `256^76` |

**`Print Assumptions` over every theorem in this directory (196 of them) now
reports no `Classical_Prop.classic` and no
`ClassicalEpsilon.constructive_indefinite_description`.**

**Read that as the NAME-level check it is.** It says the *deterministic* tier
(`Update_Encoding`, `Umbra_Canonical`, `Umbra_Wire`, `Update_Converse`,
`Umbra_WireConverse` — every theorem quoted as evidence about the extracted
parser and the encoding) is constructive up to the Aeneas quarantine. It does
**not** say the development is classical-logic-free. The game tier carries
`boolp.constructive_indefinite_description` **and**
`boolp.propositional_extensionality`, both from mathcomp-analysis inside the
pre-existing SSProve base; together they give full classical logic plus choice,
under different names. Anything in Tier G — every SSProve-side theorem,
including `device_forgery_le_eufcma` and
`device_forgery_le_eufcma_at_the_real_seam` — is proved in a classical
metatheory. The full inventory is under *Axiom budget* below.

### What pinning exposed, and how it was fixed

Pinning the MAC made a modelling defect computable, and therefore statable. It
is now also fixed; the defect is recorded here because the fix is only legible
against it.

**The defect.** The abstract game's message space was `nat`. The engine hashes
**91 bytes**. By pigeonhole no total `MAC : nat -> nat` built from that engine
can be injectively encoded, and `MG_of` was no exception:

```coq
Umbra_Canonical.MG_of_collides_above_range :   (* Qed, no hypothesis on the seam *)
  forall mb kb (m : nat), MG_of mb kb (m + Z.to_nat (257 ^ 76)) = MG_of mb kb m.
```

So an adversary queried `gettag m`, received `t`, and submitted
`checktag (m + 257^76, t)`. The real package answered `true`, the ideal package
`false`, and the advantage was **1**. The bound
`device_forgery_le_eufcma_at_the_real_seam` was *true* and **vacuous**: its
right-hand side was not small, and no assumption about HMAC-SHA256 could make
it small. That theorem is still in the file, unchanged and still true — it is
simply no longer playable, because the game no longer has `m + 257^76` in it.

**The first fix, and why it was not enough.** The message space of
`Umbra_EUFCMA.v` became `chFin`, i.e. the ordinals below a bound:

```coq
Variable (MsgN : nat).  Context {HMsgN : Positive MsgN}.
Definition Msg : choice_type := chFin (mkpos MsgN).
```

instantiated at `257^76`. That killed the periodicity collision — and
restricted to **the wrong set**. `257^76` counts 76-digit base-257 *numerals*,
and base-257 digit `256` is the out-of-range **sentinel** of
`Update_Encoding.rdA` (`| _ => 256`). On `1 - (256/257)^76 = 25.64 %` of that
space `canon91` produces a 91-element list containing `256`, which is provably
not `bytes91` of any array (`Umbra_Canonical.dead_zone_is_no_preimage`, `Qed`),
so `ByteSeam` constrains the seam there **nowhere**. Two theorems — kept in the
tree as the honest record of what that revision shipped — turn the hole into an
adversary:

```coq
Umbra_WireConverse.restricted_space_still_admits_a_broken_seam_at_MSGBn
Umbra_WireConverse.dead_zone_collides_with_any_live_message_at_MSGBn
```

both `Qed`, 10 quarantine axioms, no classical anything. From **any** `mb0` the
premise admits they build another `mb` the premise also admits, equal to `mb0`
at every genuine byte list — the same real engine everywhere the real engine is
defined — under which the pinned MAC collides at two reachable messages
(witnesses `256` and `513`, both `≡ 256 (mod 257)`). The attack: ask
`dsign 256` for `t`; submit a package encoding to a live `m0` carrying `t`;
`RED_dev` forwards `checktag (m0, t)`; real says **true**, ideal says **false**.
**Advantage 1**, again.

**The fix that holds: index the game at the byte-valid subimage `256^76`.**
`Umbra_ByteSpace.spread` includes the 76-digit base-256 numerals into the
base-257 ones — the same seventy-six digits, a different radix — and `shrink` is the
total left inverse that clamps each digit modulo 256, so it can be applied to
any submission. **The encoding itself is not re-based**: base-257 is
load-bearing for `msg_of_pkg` injectivity precisely *because* of the sentinel,
and `enc_from_inj`, `msg_of_pre_inj` and `canon91_injective` all rest on the
digit bound being `256` rather than `255`. Only the index set changes.

| | |
|---|---|
| `Umbra_ByteSpace.spread_canon91_allbytes` (`Qed`) | every message of the new space decodes to **ninety-one genuine bytes** — the fifteen label positions included, which needed `pKG_TAG_LABEL`'s reads discharged (it is `array_to_slice` of a 15-element array, so `slice_len_array_to_slice` plus `slice_index_usize_ok` settle it) |
| `Umbra_WireConverse.wstruct_ok_msg_is_byte_valid` (`Qed`) | an accepted package is ≥ 112 bytes, so every read the encoding performs is in bounds and returns a byte rather than the sentinel — the messages the device can be made to authenticate all lie in the subimage |
| `Umbra_WireConverse.widx_spreads_back` (`Qed`) | on an accepted package the game's index spreads back to exactly the message the device authenticates |
| `Umbra_WireConverse.msg_space256_pins_the_seam` (`Qed`, premise `ArrayVectors`) | **any two seams `ByteSeam` admits give the same pinned MAC at every message of the space** — the exact negation of the counterexample |
| `Umbra_WireConverse.patching_cannot_create_a_collision_at_MSGB256n` (`Qed`, premise `ArrayVectors`) | no choice of conforming seam creates a collision the engine did not already have |
| `Umbra_ArrayVectors.ArrayVectors_holds` (`Qed`, unconditional since 2026-09-02; was `ArrayVectors_holds_in_the_list_model : ModelIndex -> ArrayVectors`) | that premise is **satisfiable in the same list model** that witnesses `Update_Model.quarantine_has_a_model` — the very interpretation of `array_index_usize` that discharges the twenty quarantine laws also validates `ArrayVectors`, so adding it displaced nothing |
| `Umbra_ArrayVectors.pinning_forces_ArrayVectors_on_the_reachable_messages` (`Qed`) | and it is **necessary**: deny it at a single reachable message and the dead-zone counterexample rebuilds there |

**A correction to the record.** The `ArrayVectors` annotation on the
`patching_cannot_create_a_collision_at_MSGB256n` row is new: that row carried
none until now, while the `msg_space256_pins_the_seam` row directly above it
always did — and the commit message of `6330788`, the commit that introduced
the re-indexing, describes the theorem the same way, without the premise. The
Coq type has always carried it; only the prose omitted it. The history is left
as written and corrected here rather than rewritten.

`MACb` is the base MAC that C1e ties to the seam; the game's MAC is `MACg`,
i.e. `Umbra_ByteSpace.MG_spread` — the same engine, indexed by the subimage.
Both perfect-indistinguishability links (`DEV_tt_link`, `DEV_ff_link`) and the
bound go through unchanged in structure. The side-condition got **cheaper**:

```coq
(forall p : list nat, widx p < MsgN)
```

is discharged by `Umbra_WireConverse.widx_lt_MSGB256n` (`Qed`) with **no fact
about the package at all**, since `shrink` lands in `[0, 256^76)` by
construction. At `257^76` the analogous condition needed `msg_of_pkg_lt`.
**Nothing on the left-hand side is given up on the submission oracle:**
`dsubmit` still takes an arbitrary `list nat`, and the clamp inside `shrink`
can only fire on packages the key-free structural guards already reject.

**One thing the restriction does narrow, and it is not a nicety.** The
*signing* oracle `dsign` takes a message of the space rather than a `nat`, so
the modelled adversary cannot ask the signing service to tag a message outside
it. That is a narrower adversary class, and the narrowing is load-bearing: an
adversary that *can* get an out-of-range message signed **wins with advantage
1** against the pinned MAC. This is not a conjecture —
`Umbra_Canonical.MG_of_collides_above_range` (`Qed`, no hypothesis on the seam
at all) gives `MAC k m = MAC k (m + 257^76)` for every seam. The justification
for excluding it is now sharper than it was at `257^76`: the space is *exactly*
the set of 76-byte authenticated cores, which is exactly what a real signing
service signs. It remains a modelling choice, not a theorem. If it is wrong for
a deployment, the bound in this directory says nothing about it.

**Non-vacuity, and its exact shape.**

```coq
Umbra_RealGame.game_messages_have_distinct_preimages :   (* Qed *)
  forall m m' : Msg MSGB, m <> m' ->
    canon91_of_idx (nat_of_ord m) <> canon91_of_idx (nat_of_ord m').

Umbra_RealGame.game_messages_decode_to_bytes :           (* Qed *)
  forall m : Msg MSGB, allbytes (canon91_of_idx (nat_of_ord m)) = true.
```

Distinct messages of the game's message space decode to **distinct 91-byte
preimages**, and — this is what the re-indexing adds — those preimages are
**genuine byte vectors, at every message, unconditionally**. Equivalently
(`Umbra_WireConverse.msg_space256_collision_is_seam_collision_at_byte_vectors`,
`Qed`): every collision of the abstract MAC inside the message space is a
collision **of the seam** at two distinct 91-*byte* inputs. Reading that as a
collision **of the engine** — the event an EUF-CMA assumption on HMAC-SHA256
bounds — takes one more step, and it is the same one as everywhere else in this
directory: the seam is identified with `macf` only on the image of `bytes91`,
so the engine reading holds **under `ArrayVectors`** (with `ByteSeam macf mb`),
which is exactly what makes those two byte vectors the read-sequences of real
arrays. The theorem is deliberately named for the weaker, premise-free thing it
actually proves. The `nat` message space destroyed this
outright (the colliding messages had the *same* 91 bytes); the `257^76` space
destroyed it on 25.64 % of itself (the "preimages" were not byte vectors at
all, so no assumption about a byte-consuming engine reached them).

**What is *not* claimed.** `MG_spread` is **not** injective and no such theorem
is true: it ends in a 32-byte tag and starts from `256^76` messages, so it
collides by pigeonhole for every seam, exactly as a real HMAC does. Anyone
quoting "the MAC is now injective" is overstating this.

**Four shapes were chosen against the grain. Two of the four justifications
were wrong, and are corrected here rather than quietly dropped.** `257^76` as a
`nat` is a unary numeral with about 10^144 successors, and Coq will try to build
it given some — not any — excuse:

| choice | claimed reason | re-measured |
|---|---|---|
| bound is `mkpos MsgN` with `MsgN : nat`, not a bare `positive` variable | Equations' derived `NoConfusion` for `choice_type` only reduces on a **constructor**; with `chFin MsgB` for `MsgB` a variable, `simplify_eq_rel` leaves an `eq_rect` over `MsgB = MsgB` that never reduces and `DEV_tt_link` fails with `Tactic failure: No head found` | **confirmed** |
| the nat/`Z` bridge is proved over an abstract `B` (`Umbra_WireConverse.lt_toNat_iff`) and *instantiated* | the direct proof "elaborates in milliseconds and then hangs in the kernel at `Qed`" (>11 min, ~800 MB) | **refuted.** The same script at the concrete bound — `Nat2Z.inj_lt`, then `Z2Nat.id` — compiles in **0.35 s wall including `Qed`**. The abstract-`B` shape is kept because it is the better shape, not because the direct one diverges |
| `MSGB` is a `Notation`, not a `Definition` | ssreflect's `rewrite /c` normalises beta-iota after the delta step; `rewrite /MSGB` on `Z.to_nat (256^76)` does not return | **confirmed** at the v1 bound `257^60` — 2 m 38 s and 1.16 GB, still climbing when killed; `256^76` is larger still |
| the `Positive` instance is passed **explicitly** at every use site | the first hint for the `Positive` class is `reflexivity`, which would evaluate the bound | **refuted.** `Definition probe : Positive MSGBn := _.` resolves to `erefl`, kernel check included, in about a second. Explicit passing is kept because it pins which positivity proof appears in the closed type |

The `%N` / `N_scope` constraint — `ZArith` must not be imported into
`Umbra_RealGame.v` — is real and is worse than any of these, because it does not
fail: it silently changes what the statements mean.

**The price of pinning, stated plainly.** The realiser cannot be `tag_of_arr
(macf kb (canonical_preimage m))`, because `Primitives.array_index_usize` is a bare axiom
with no law relating any constructor to indexing at general `n` (`Update_Model.v`
§5 records that the backend's `mk_array` is *inconsistent* and is deliberately
unused), so **no constructible `array u8 91` has known reads**. The seam is
therefore factored the other way, through a new premise:

```coq
ByteSeam macf mb  :=  forall kb p, tag_of_arr (macf kb p)
                                 = mb (kbytes kb) (bytes91 p)
```

"the engine's output is a function of the key byte string and the 91 preimage
byte values". This is **strictly stronger** than the old premise `Hreads` (byte
agreement implies tag agreement) — `Umbra_Canonical.ByteSeam_reads` derives
`Hreads` from it, and the converse needs choice. What has happened is that the
classical description step moved *out of the proof* and *into a named premise*
that supplies the function. That is a real improvement, because the premise is a
true and checkable statement about any HMAC implementation whereas a chosen
function is not; it is not a free lunch, and should not be presented as one. Like
C1 and C1e, `ByteSeam` carries **no** unforgeability: the constant function
satisfies it.

**Two things `ByteSeam` does not say, and a reader should not read into it.**
First, `mb` returns a `Z` — the **base-257 encoding** of the tag, via
`tag_of_arr` — not the `array u8 32` the engine produces. So the premise
constrains the *encoded* tag, not the array term, and the same
constructible-array wall that forced the premise is why it cannot be stated at
the array. Nothing downstream needs the array (the game compares tag integers),
but the premise is weaker than "the engine is this function" reads. Second, it
constrains `mb` only where `bytes91` reaches: at 91-byte lists that are the
reads of an array, and those are exactly the arrays this development can talk
about. Both consequences are in the open-items list below.

## `dkey` injectivity is documented, but not carried by the bound

`Umbra_RealGame` now carries

```coq
Hypothesis Hdkey_inj :
  forall k k' : Key n, kbytes (dkey k) = kbytes (dkey k') -> k = k'.
```

stated at byte-value granularity, because term equality of `slice u8` is not
available anywhere in this development.

**It is not used by the bound**, and Coq's section generalisation confirms that:
`Check device_forgery_le_eufcma` does not quantify over it. What needs it is the
*reading* of the bound. `MG_of` sees the key only through `kbytes`, so a `dkey`
that collapses two game keys onto one key string makes them literally the same
abstract MAC — `Umbra_Canonical.MG_of_collapses_on_equal_key_bytes` (`Qed`) — and
the game's `uniform KeyN` then ranges over fewer than `2^n` distinct HMAC keys.
A constant `dkey` degenerates the right-hand side to an advantage against one
fixed key, which is not what any EUF-CMA assumption about HMAC-SHA256 asserts.

`Umbra_RealGame.dkey_faithful` (`Qed`) is the whole formal content: distinct game
keys are provisioned to distinct key strings. **The measure-theoretic step from
there — that the pushforward of `uniform KeyN` along an injection is uniform on
its image, hence that the RHS is an HMAC advantage under a uniform key — is not
formalised.** It is prose, and it is named here so a reviewer can see where it is
taken on faith.

The other two open items of this directory are **unchanged**: the lifting of the
Tier-D event inclusion to a probability statement for `Umbra_Reduction.v`, and
**C2**, the assumed correspondence between the vendor's signing service and the
game's query set (`Umbra_DeviceLink.v`, "the freshness seam"). Anyone quoting a
fully machine-checked end-to-end *security* result must still say that C2 is
assumed and that the signer is neither verified nor extracted.

## The claim, in full

**The one sentence the authors may write.** This is the shortest form that
survives adversarial review; it is quotable verbatim and nothing may be trimmed
from it.

> Against the Aeneas-extracted `parse_and_verify`, we prove in Coq/SSProve that
> any adversary making the device accept a package whose 76-byte authenticated
> core was never signed is, with no loss, an EUF-CMA adversary against the
> package MAC — where the abstract MAC is *computed* from the HMAC engine rather
> than chosen, the game is indexed at the byte-valid message space `256^76` on
> which every message provably decodes to ninety-one genuine bytes, and the
> identification of that computed MAC with the engine holds under one named
> premise (`ArrayVectors`: every 91-byte list is some `array u8 91`'s
> read-sequence) which is true of Rust, unprovable against the backend's
> uninterpreted `array_index_usize`, satisfiable in the same list model that
> discharges our twenty quarantine laws, and exactly equivalent to the pinning
> it buys; the bound says nothing about the update blob's body, which no
> verified component authenticates, and the game tier inherits SSProve's
> classical axioms including one admitted lemma.

The long form below itemises the same thing. Anything shorter than either
overstates it.

> For the Coq code extracted by Charon/Aeneas from the enclave-update parser, we
> prove (`Qed`, no admits, using no axiom beyond the quarantined Aeneas array
> axioms the extraction already carries) that any package the device accepts
> yields a message/tag pair computable from the wire alone without the key, that
> this pair is valid under an abstract MAC given a stated byte-factorisation
> hypothesis on the HMAC seam, and that if the package's five authenticated
> fields were never signed then its encoding lies outside the signing query set;
> separately, in SSProve, we prove `Advantage UPD A ≤ Advantage EUF_CMA (A ∘
> RED)` — but the step from the Coq event inclusion to that probabilistic bound
> is taken on paper, the SSProve development contains no Umbra-specific content,
> and the correspondence between the signing service and the game's query set is
> assumed, not proved. Separately again, in `Umbra_RealGame.v`, we prove the same
> bound for a game whose `submit` oracle *is* the extracted `parse_and_verify` —
> its `Print Assumptions` lists 50 axioms, 43 of them Aeneas — and the
> factorisation `(F)` that makes the reduction simulable is a theorem about that
> extracted body, not a hypothesis. The abstract MAC on the right-hand side is
> **defined** as the device's own seam applied to a canonical byte decoding of
> the message, injective on the protocol's message range, so that the bound can
> be read against an EUF-CMA assumption on HMAC-SHA256; that costs a premise
> (`ByteSeam`) saying the engine is a function of the key bytes and the preimage
> bytes, which — like C1 and C1e — carries no unforgeability. **The game's message
> space is the encoding's range and not `nat`: an earlier revision took it to be
> `nat`, and the pinned MAC then provably collided above `257^76`, which made
> the right-hand side of the pinned bound equal to 1. It is now `chFin` at
> `256^76` — the byte-valid subimage, after `257^76` was found to have a 25.64 %
> dead zone where `ByteSeam` constrained nothing — both perfect hops are
> re-proved there, and distinct messages of the space are proved to have
> distinct 91-byte preimages that are genuine byte vectors, so an in-space
> collision is a collision of the seam, and of the engine under
> `ArrayVectors`.** **The
> authenticated message is seventy-six bytes and does not include the update blob's
> body: blob integrity rests on a chained HMAC that is not extracted or verified
> HERE, and what this directory authenticates is the 48-byte UMBR header —
> including the 32-byte value that chained HMAC is compared against. That
> chain is now extracted and proved in
> [`../chain-core/`](../chain-core/README.md), over its own residue.**

---

## Install recipe (the one that actually worked)

Coq lives in the opam switch `default` (OCaml 5.1.1, coqc 8.18.0) — **not** in
the `aeneas` switch, which carries only `coq-lsp`.

```sh
opam repo add coq-released https://coq.inria.fr/opam/released --switch=default
opam install coq-ssprove.0.2.4 --switch=default -j 8
eval $(opam env --switch=default)
```

### Why 0.2.4 and not the newest tag

SSProve tags run through v0.3.1, but the Coq constraint moves:

| SSProve | `coq` constraint |
|---------|------------------|
| 0.2.1   | `>= 8.18 & < 8.20~` |
| 0.2.2   | `>= 8.18 & < 8.21~` |
| 0.2.3   | `>= 8.18 & < 8.21~` |
| **0.2.4** | **`>= 8.18 & < 9.1~`** |
| 0.3.0   | `>= 8.20 & < 9.2~` |
| 0.3.1   | `>= 8.20 & < 9.2~` |

`0.3.x` requires Coq **≥ 8.20**. The update-core chain is built with Coq 8.18
and must stay that way, so **0.2.4 is the newest tag compatible with this
toolchain** — and it is the last of the 0.2 line, so nothing is lost relative to
0.2.x. Upgrading to 0.3.x would mean moving the whole development to Coq 8.20+
and re-validating the Aeneas extraction, which is a separate exercise.

The solve pulls 24 packages; the long pole is `coq-mathcomp-analysis.1.3.1`
(tens of minutes on 8 cores). Everything resolved on the first attempt — there
was no dependency fight to report.

## Building

```sh
./build.sh              # everything (needs SSProve)
./build.sh --det-only   # deterministic tier only (bare Coq 8.18, no mathcomp)
```

`../update-core/proofs-coq` must already be built; this project never rebuilds
it. **The dependency arrow points one way only**: files here `Require` files
there, never the reverse, so the update-core chain keeps building with nothing
but a bare Coq 8.18 and never acquires a mathcomp dependency. That is the whole
reason this is a separate directory with its own `_CoqProject`.

## The files

### Tier D — deterministic. Bare Coq 8.18, no mathcomp.

| File | Contains |
|------|----------|
| `Update_Forgery.v` | The reduction core: from any accepted package, a message/tag pair that is **valid** and **fresh**. |
| `Update_Encoding.v` | The Aeneas ⇄ `Z` type bridge, `accept_encodes`, and the injectivity of the base-257 encoding (`enc_from_inj`, `msg_determines_fields`). |
| `Umbra_Canonical.v` | The canonical byte **decoding** of a message integer (`canon_rd`, `canon91`), its faithfulness on assembled preimages and its injectivity on the protocol's message range; the computed C1e realiser `MG_of`; **the dead-zone counterexamples** that show `[0, 257^76)` is the wrong message space; and the theorem that the package tag does **not** cover the blob body. |
| `Umbra_ByteSpace.v` | The **byte-valid subimage** `[0, 256^76)` and the maps to and from it (`spread`, `shrink`); the proof that every message of it decodes to ninety-one genuine bytes; the named premise `ArrayVectors` and the two theorems that, under it, pin the seam at every reachable message. |
| `Umbra_ArrayVectors.v` | The **audit of that premise**. `ArrayVectors` is *satisfiable* in the same list model that witnesses `Update_Model.quarantine_has_a_model` — constructively, by building the array — so it displaced none of the twenty quarantine laws; and it is *necessary*, since denying it at one reachable message rebuilds the dead-zone counterexample there. Necessary **and** sufficient: the fix has no slack in either direction. |
| `Umbra_DeviceLink.v` | The joint: real acceptance implies the game's win condition — validity and freshness in one statement; plus the three theorems justifying the shape of C1e. |
| `Umbra_Wire.v` | The wire package space (`list nat`, a `choice_type`), the total marshalling `wire : list nat -> slice u8` with `wire_bytes` (value preservation), the **real** acceptance predicate `accepts` as a `bool`, and the concrete readers `wmsg`/`wtag`. |

### Tier G — game-based. Needs SSProve.

| File | Contains |
|------|----------|
| `Umbra_EUFCMA.v` | The EUF-CMA game for a MAC, in SSProve. |
| `Umbra_Reduction.v` | The UPD forgery game, the reduction package `RED`, and the bound. Contains no Umbra content. |
| `Umbra_RealGame.v` | The same bound over a game whose `submit` oracle **is** `parse_and_verify` — `(F)` is a `Lemma` here, not a hypothesis — plus `device_forgery_le_eufcma_at_the_real_seam`, the abstract seam instantiation at `256^76`, and `device_forgery_le_eufcma_for_the_concrete_engine`, whose closed type carries `ArrayVectors` and also yields a concrete engine-evaluation witness for every message. The abstract bound's `Print Assumptions` lists 50 axioms, 43 of them Aeneas. |

---

## What is proved

### 1. The EUF-CMA game (`Umbra_EUFCMA.v`)

Two packages exporting `gettag` (the chosen-message tagging oracle) and
`checktag` (the verification oracle), over an abstract keyed function
`MAC : Key -> nat -> nat` with `Key = chFin (mkpos (2^n))`:

```coq
Definition EUF_pkg_tt : package EUF_locs_tt [interface] EUF_I :=
  [package
    #def #[gettag] (m : 'nat) : 'nat {
      k ← kgen ;;
      ret (MAC k m)
    } ;
    #def #[checktag] ('(m, t) : 'nat × 'nat) : 'bool {
      k ← kgen ;;
      ret (t == MAC k m)
    }
  ].

Definition EUF_pkg_ff : package EUF_locs_ff [interface] EUF_I :=
  [package
    #def #[gettag] (m : 'nat) : 'nat {
      S ← get S_loc ;;
      k ← kgen ;;
      let t := MAC k m in
      #put S_loc := setm S (m, t) tt ;;
      ret t
    } ;
    #def #[checktag] ('(m, t) : 'nat × 'nat) : 'bool {
      S ← get S_loc ;;
      ret ((m, t) \in domm S)
    }
  ].

Definition EUF_CMA := mkpair EUF_pkg_tt EUF_pkg_ff.
```

The real package verifies honestly; the ideal one accepts only pairs `gettag`
issued. The two therefore differ exactly on the event "a valid pair that was
never issued" — a forgery — so `Advantage EUF_CMA A` **is** the EUF-CMA
advantage. This is SSProve's own `examples/PRFMAC.v` game with the PRF replaced
by an arbitrary keyed function, so the reduction cannot exploit structure the
device's HMAC may not have.

Nothing here claims any MAC *is* EUF-CMA-secure. That is the assumption, and it
now appears on the right-hand side of a bound instead of being invisible.

### 2. The reduction (`Umbra_Reduction.v`)

The update-forgery game `UPD` exports `sign` (the vendor signing service) and
`submit` (the device). `RED` is a stateless, key-less package that forwards
`sign` to `gettag` and turns a submitted package into one `checktag` query on
the message/tag pair read off the wire. Both game hops are **perfect**:

```coq
Lemma UPD_tt_link : UPD true  ≈₀ RED ∘ EUF_CMA n MAC true.   (* Qed *)
Lemma UPD_ff_link : UPD false ≈₀ RED ∘ EUF_CMA n MAC false.  (* Qed *)
```

and the bound is

```coq
Theorem update_forgery_le_eufcma :
  forall LA (A : raw_package),
    ValidPackage LA UPD_I A_export A ->
    fdisjoint LA (EUF_locs_tt n :|: EUF_locs_ff n) ->
    Advantage UPD A <= Advantage (EUF_CMA n MAC) (A ∘ RED).
```

`Qed`, zero admits. In words: an adversary with chosen-message access to the
signing service, which gets a package accepted whose authenticated core was
never signed, breaks EUF-CMA of the device's MAC with at least the same
advantage.

### 3. The type bridge (`Update_Encoding.v`)

An Aeneas `array u8 91` is `{l : list u8 | length l = 91}` with `array_index_usize`
an opaque **Axiom**; `u8` is a sigma type over a `Prop`, so two bytes with the
same value are not provably equal terms without proof irrelevance (a point the
existing `Update_Auth.v` already makes). Such a type cannot be an SSProve
message space: `choice_type` needs decidable equality, and the development
cannot observe array identity — only byte values.

So the bridge encodes arrays and slices **through their reads** into a plain `Z`,
in **base 257** (the out-of-range sentinel is 256, so a failed read can never be
confused with a byte value). Byte agreement becomes Leibniz equality on `Z`,
which is what a game's "was this queried?" test needs.

The message space is the protocol's **76-byte authenticated core** — the HMAC
preimage minus its 15-byte constant label:

```
pre[15,31)  nonce        = pkg[ 4,20)
pre[31,35)  author_id    = pkg[20,24)
pre[35,39)  version      = pkg[24,28)
pre[39,43)  blob_len     = pkg[28,32)
pre[43,91)  header       = blob[0,48) = pkg[32,80)   (the full 48-byte UMBR header)
```

The headline:

```coq
Theorem accept_encodes :
  forall (pkg : slice u8) (en : array u8 16%usize) r,
    parse_and_verify inst pkg en h key = Ok (Core_result_Result_Ok r) ->
    exists (f : Fields) (pre : array u8 91%usize) (t : array u8 32%usize),
      AssemblesF pre f
      /\ t = mac key pre
      /\ f.(fld_author)  = r.(verifiedUpdate_author_id)
      /\ f.(fld_version) = r.(verifiedUpdate_version)
      /\ msg_of_pre pre  = msg_of_pkg pkg
      /\ tag_of_arr t    = tag_of_pkg pkg.
```

That is what makes the reduction *implementable*: a party holding no key can
compute the exact message and tag it must forward to its EUF-CMA challenger,
from the submitted package alone.

Stating the game at the byte level rather than at the five semantic fields also
removes the suspicion that the encoding was chosen to make the proof work. What
licenses reading the result back as a statement about nonce / author_id /
version / blob_len / header bytes is `msg_determines_fields` — see the next
section. It is **not** `Update_Forgery.assemble_injective`, and an earlier
revision of this README said it was. `assemble_injective` is stated over
`ByteEq`: it *assumes* byte agreement and concludes field agreement. The game
stores integers, so the premise actually available at the game level is an
equation in `Z`, and getting from that to byte agreement is a separate
obligation.

### 4. Encoding injectivity (`Update_Encoding.v`)

That obligation. The base-257 encoding is injective, and this is now proved
rather than assumed:

```coq
Lemma enc_from_inj : forall (k : nat) (f g : Z -> Z) (a b : Z),
  (forall i, 0 <= i < Z.of_nat k -> 0 <= f (a + i) <= 256) ->
  (forall i, 0 <= i < Z.of_nat k -> 0 <= g (b + i) <= 256) ->
  enc_from f a k = enc_from g b k ->
  forall i, 0 <= i < Z.of_nat k -> f (a + i) = g (b + i).
```

`Print Assumptions enc_from_inj` reports **`Closed under the global context`** —
zero axioms; it is arithmetic. The digit bound is discharged for real reads by
`rdA_digit` (a successful read yields a `u8`, bounded by its own proof
component; a failing read yields the sentinel 256, which is a legal base-257
digit). The protocol-level consequences:

```coq
Theorem msg_of_pre_inj : forall p q : array u8 91%usize,
  msg_of_pre p = msg_of_pre q ->
  forall i, 15 <= i < 91 -> rdA p i = rdA q i.

Theorem msg_determines_fields :
  forall (p q : array u8 91%usize) (f g : Fields),
    AssemblesF p f -> AssemblesF q g ->
    msg_of_pre p = msg_of_pre q ->
    FieldsEqR f g.
```

and, lifted to acceptance, `Umbra_DeviceLink.accepted_msg_determines_fields`.
`Qed`, zero admits; assumptions are a **subset** of classes 1-3 of the [axiom
budget](#axiom-budget).

**The conclusion is at `to_Z` granularity (`ReadEq`/`FieldsEqR`), not `ByteEq`,
and that is the right choice — but not for the reason an earlier revision of
this README gave.** That revision said reaching `ByteEq`/`FieldsEq` "needs
functional extensionality, which this tier does not assume". Both halves of that
are wrong. `ByteEq` is *term* equality of `array_index_usize` results; an
equation between integers gives `to_Z b1 = to_Z b2`, and `b1 = b2` follows from
**proof irrelevance** for `0 <= x <= 255` — not functional extensionality — at a
cost of exactly one extra axiom. And this directory is in no position to
call that unaffordable: the [axiom budget](#axiom-budget) below already records
Tier G carrying `SPropBase.ax_proof_irrel : ClassicalFacts.proof_irrelevance`.
The axiom the prose said it could not afford was already on the bill.

**The real reason `FieldsEqR` is the right relation is that the finer relation
would make the theorem that uses it false.** In
`Umbra_DeviceLink.accept_of_unsigned_fields_is_off_query_set` the relation sits
in **premise** position:

```coq
(forall g, In g Q -> ~ FieldsEqR f g) -> ~ Sloc (Z.to_nat (msg_of_pkg pkg))
```

Substituting the finer `FieldsEq` there *weakens* the premise — `FieldsEq` is
harder to satisfy, so `~ FieldsEq f g` is easier — and the theorem becomes
**false**: two field tuples that are term-distinct but byte-identical would
satisfy "never signed" while their common encoding sits in the query set, and
the conclusion `~ Sloc …` would not hold. Coarse is not a concession here; it is
what makes the statement true. Byte *values* are in any case the
security-relevant notion — an attacker forges bytes, not Coq terms.
`ByteEq_ReadEq` and `FieldsEq_FieldsEqR` record that the finer relations imply
the coarser ones, which is the direction that is safe to have.

**A caveat on the sentinel, since the encoding's own comment overstates it.**
`Update_Encoding.v` says the out-of-range sentinel `256` means "a failing read
can never be confused with a byte value". Only half true. `rdA` returns `256`
for **both** `Fail_ Failure` and `Fail_ OutOfFuel`, so a failing read is indeed
never confused with a byte — but it *is* confused with the *other* failure mode.
`ReadEq` therefore does not imply `ByteEq` even under proof irrelevance. What
rescues the development is that no read on the acceptance path fails at all:
`Update_Safety.array_index_usize_ok` (already in class 3) discharges every
in-range read, so the sentinel is never produced where any theorem here depends
on it.

### 5. The joint (`Umbra_DeviceLink.v`)

```coq
Theorem device_accept_implies_submit_true :
  forall (pkg : slice u8) (en : array u8 16%usize) r,
    parse_and_verify inst pkg en hs key = Ok (Core_result_Result_Ok r) ->
    Z.to_nat (tag_of_pkg pkg) = MACg k0 (Z.to_nat (msg_of_pkg pkg)).
```

Every package the real device accepts is a UPD-game win.

The same file carries the three theorems that justify the shape of C1e instead
of asserting it. None is used by anything else; they exist to be checked:

```coq
(* the guard is NECESSARY — this needs no assumption about macf at all *)
Theorem unguarded_C1e_forces_label_obliviousness :
  forall MG : nat -> nat,
    (forall pre, MG (Z.to_nat (msg_of_pre pre))
                 = Z.to_nat (tag_of_arr (macf key pre))) ->
    forall p q, (forall i, 15 <= i < 91 -> rdA p i = rdA q i) ->
      Z.to_nat (tag_of_arr (macf key p)) = Z.to_nat (tag_of_arr (macf key q)).

(* with the guard, the constrained relation is a FUNCTION *)
Theorem restricted_C1e_is_functional :
  (forall p q, (forall i, 0 <= i < 91 -> rdA p i = rdA q i) ->
     tag_of_arr (macf key p) = tag_of_arr (macf key q)) ->
  forall p q f g, AssemblesF p f -> AssemblesF q g ->
    msg_of_pre p = msg_of_pre q ->
    tag_of_arr (macf key p) = tag_of_arr (macf key q).

(* … and therefore a MACg satisfying C1e EXISTS — the guard is SUFFICIENT.
   The witness is COMPUTED (Umbra_Canonical.MG_of), not chosen: no classical
   axiom. The premise is ByteSeam, which NAMES the byte-level engine. *)
Theorem restricted_C1e_is_realisable :
  forall mb : byteseam_t,
    ByteSeam macf mb ->
    exists MG : nat -> nat,
      forall pre f, AssemblesF pre f ->
        MG (Z.to_nat (msg_of_pre pre)) = Z.to_nat (tag_of_arr (macf key pre)).
```

The third exists because the second does not say what an earlier revision of
this README claimed it said. `restricted_C1e_is_functional` concludes
`tag_of_arr (macf key p) = tag_of_arr (macf key q)`; it never produces a `MACg`,
so the step "the relation is a function, therefore a `MACg` satisfying C1e
exists" was **prose**. One revision closed it with a classical description step,
at a cost of two axioms. It is now closed CONSTRUCTIVELY, by
`Umbra_Canonical.MG_of` — the seam applied to the canonical byte decoding of the
message — under the premise `ByteSeam`; the premise is now stated where the
choice used to be. See [the pinning
section](#the-abstract-mac-is-now-pinned-to-the-seam-constructively).

The joint also carries the theorem that states the game's win condition as one
proposition rather than two, which is what a reader expects to find and, until
this revision, could not:

```coq
Theorem accept_of_unsigned_fields_is_valid_and_fresh :
  forall pkg en r,
    parse_and_verify inst pkg en hs key = Ok (Core_result_Result_Ok r) ->
    exists f : Fields,
      f.(fld_author) = r.(verifiedUpdate_author_id)
      /\ f.(fld_version) = r.(verifiedUpdate_version)
      /\ ((forall g, In g Q -> ~ FieldsEqR f g) ->
          Z.to_nat (tag_of_pkg pkg) = MACg k0 (Z.to_nat (msg_of_pkg pkg))
          /\ ~ Sloc (Z.to_nat (msg_of_pkg pkg))).
```

Validity and freshness are the two halves an EUF-CMA challenger checks, and they
were proved in statements that shared no variable: the closed type of the
freshness theorem mentions no `MACg`, no `k0` and no `Hfactor`. This one
mentions all of them, plus `Q`, `Sloc` and `Hsign_sound` — it is the first
statement in the development in which both seams appear at once, about the same
wire integer `Z.to_nat (msg_of_pkg pkg)`. (Validity holds of every accepted
package, premise or no premise; it is stated under the premise because the
conjunction under that premise *is* the win predicate.)

---

## What is assumed

| | Where | What it says | Weight |
|---|---|---|---|
| **C1** | inherited, `Update_Crypto.Hseam` | the seam is a deterministic function of `(key, preimage)` | none — the constant function satisfies it |
| **C1e** | new, `Umbra_DeviceLink.Hfactor` | on **assembled** preimages the seam **factors through the byte encoding**: `AssemblesF pre f -> MACg k0 (msg_of_pre pre) = tag_of_arr (macf key pre)` | none cryptographically; see below |
| **ByteSeam** | new, `Umbra_Canonical.ByteSeam` | the engine's output is a **function** of the key bytes and the 91 preimage bytes: `tag_of_arr (macf kb p) = mb (kbytes kb) (bytes91 p)` | none — the constant function satisfies it. It is the constructive form of C1e's justification; it is what lets the C1e realiser be *computed* instead of chosen classically |
| **`dkey` injective** | documented as `Umbra_RealGame.Hdkey_inj` | distinct game keys would be provisioned to distinct key **byte strings** | not used by the bound; a collapsing map still makes the RHS range over a degenerate key distribution |
| **C2a** | new, `Umbra_DeviceLink.FreshnessSeam` | everything the vendor signs lands in `S_loc` (`S_loc` is no smaller than `Q`'s encodings) — used by `accept_of_signed_fields_is_in_query_set`, which is what stops C2b being satisfiable by an empty `S_loc` | a real gap — the signer is neither verified nor extracted; see [below](#the-freshness-seam-c2-is-named-not-closed) |
| **C2b** | new, `Umbra_DeviceLink.FreshnessSeam` | and nothing else does (`S_loc` is no larger) — this is the one the freshness theorem actually uses; its closed type does **not** mention C2a | same gap, same section |
| **EUF-CMA** | not assumed — appears on the RHS of the bound | the device's HMAC is existentially unforgeable | the real assumption |

**C1e is the only new hypothesis inside the acceptance→win chain** (C2 stands
beside it, on the freshness side, and is discussed separately). It is not a cryptographic
claim: it says the HMAC engine's output depends on nothing but the byte values
of its input, which is vacuously true of every real implementation. It is needed
only because Aeneas gives no array extensionality, so `macf` cannot be shown
*from the inside* to respect byte equality.

**The `AssemblesF` guard is load-bearing, and an earlier revision of this
directory got the argument for it exactly backwards.** That revision stated C1e
over *all* 91-byte preimages and defended the choice as "so it cannot be
satisfied vacuously". That defence is wrong twice over. `msg_of_pre` reads
offsets `[15,91)` only — the 15-byte domain-separation label is never read — so
the left-hand side is a function of the 76-byte core alone. Quantifying over all
preimages therefore *forces*

```coq
forall p q, (forall i, 15 <= i < 91 -> rdA p i = rdA q i) ->
  tag_of_arr (macf key p) = tag_of_arr (macf key q)
```

i.e. label-obliviousness, which HMAC-SHA256 does not have. Universal
quantification made the hypothesis **stronger and false**, not safer, and no
choice of `MACg`/`k0` could satisfy it at a real seam — strictly worse than a
gap, since a false hypothesis proves anything.

Restricting to assembled preimages is sound because `Assembles` clause 1
(`Update_Crypto.v`) pins `pre[0,15)` to the *constant* `pKG_TAG_LABEL`: every
assembled preimage carries the same label, the label varies over nothing, and
the 76-byte core determines all 91 bytes. Nothing is lost, because every
preimage the device ever hashes is assembled (`compute_pkg_tag_assembles`,
`Qed`). And the restricted form is *realisable*: the pairs it constrains form a
function of `msg_of_pre pre`, so a `MACg` satisfying it exists.

All three steps are machine-checked in `Umbra_DeviceLink.v`.
`unguarded_C1e_forces_label_obliviousness` gives necessity.
`restricted_C1e_is_functional` gives functionality — and an earlier revision of
this README called that "sufficiency", which it is not: its conclusion is an
equation between two tags, and it never produces a `MACg`. The inference
*function, therefore a realising `MACg` exists* is
`restricted_C1e_is_realisable`, which one revision took via a classical
description lemma and which now goes via `Umbra_Canonical.MG_of` — a computed
witness, no classical axiom; see [the pinning
section](#the-abstract-mac-is-now-pinned-to-the-seam-constructively) and the
[axiom budget](#axiom-budget).

`k0 : K` is a `Variable` of the Tier-D section, never related to any sampled key
— there is no Coq object *in `Umbra_DeviceLink.v`* identifying it with the
game's `k`, and an earlier revision of this README claimed there was. At the
Tier-G level the correspondence *is* named, as `dkey : Key n -> key_bytes`
(`Umbra_RealGame.v`), but the bound leaves that map arbitrary. Read C1e as:
*for the device's provisioned key material there is a game key whose abstract MAC
agrees with the seam on assembled preimages* — and, since the pinning revision,
that abstract MAC is the seam itself. That the provisioned key is uniformly
sampled is the standard key-generation assumption; it is **not** formalised
here, and the Tier-D files never mention a distribution.

### Axiom budget

The headline number is **50**, for `Umbra_RealGame.device_forgery_le_eufcma` and
for `device_forgery_le_eufcma_at_the_real_seam`. Quoting it as one lump is
misleading in both directions, so here it is in the three classes it actually
falls into. All figures below were obtained by running `Print Assumptions` on
the theorem and counting the output; do the same before quoting them.

| Class | Count | What it is | Can it make anything unsound? |
|---|---|---|---|
| **1. Bare uninterpreted declarations** | **20** | `Primitives.array_index_usize`, `slice_index_usize`, `slice_len`, `array_to_slice`, `array_from_slice`, `array_repeat`, `core_slice_index_*` (5), `core_array_Array_index_mut`, `scalar_or`, `scalar_xor`, `usize_max`, `isize_min`, `isize_max`, and `Update_FunsExternal`'s 3 (`core_num_U32_{to,from}_le_bytes`, `core_slice_Slice_copy_from_slice`) | **No.** These carry *no proposition*. They are `Axiom f : A -> B` declarations — opaque constants, exactly like a `Variable`. A declaration with no axiom content cannot make a theory inconsistent. |
| **2. Bound propositions** | **3** | `usize_max_bound : u32_max <= usize_max`, `isize_max_bound`, `isize_min_bound` | Yes in principle — but these are the platform-width facts every Rust target satisfies, and they are *lower* bounds only. |
| **3. `Update_Safety` quarantine laws** | **20** | the "what the ops return" laws: `array_index_usize_ok/_ext`, `slice_index_usize_ok/_ext`, `slice_index_range_ok/_len/_val`, `array_index_mut_range_ok/_val_in/_val_out`, `copy_from_slice_ok/_val`, `slice_len_array_to_slice`, `slice_index_array_to_slice`, `array_from_slice_val`, `mk_array4_val`, `u32_{to,from}_le_bytes_val`, `u8_xor_to_Z`, `u8_or_to_Z` | Yes in principle — and **all twenty are discharged** against the concrete list model in `../update-core/proofs-coq/Update_Model.v` (`quarantine_is_the_axioms`), so a model satisfying them exists and they add no inconsistency. |
| | **43** | **= the Aeneas half** | |
| **4. SSProve base** | **7** | see below | inherited from mathcomp-analysis/SSProve, not from this work |
| | **50** | **total** | |

The difference between "50 axioms" and this table is the difference between a
number that reads as alarming and one that reads as disciplined. Class 1 is
larger than class 3 and is the class that cannot possibly matter; class 3 is the
class that could, and every member of it is discharged.

Tier D on its own needs less. `Print Assumptions` on **every Tier-D theorem on
the acceptance→win path** — `accept_yields_valid_forgery`, `accept_encodes`,
`device_accept_implies_submit_true`, `accepted_msg_determines_fields`,
`accept_of_unsigned_fields_is_off_query_set`,
`accept_of_signed_fields_is_in_query_set`,
`accept_of_unsigned_fields_is_valid_and_fresh` — lists a **subset of classes 1–3
and nothing else**. Some of the new theorems need far fewer: `msg_of_pre_inj`
uses 7, and `enc_from_inj` and `Umbra_Canonical.enc_from_digits` report `Closed
under the global context`.

**There is no longer an exception.** An earlier revision recorded one:
`restricted_C1e_is_realisable` reported `Classical_Prop.classic` and
`ClassicalEpsilon.constructive_indefinite_description`, inherited from a
classical description lemma. Both are gone — the realiser is now computed
(`Umbra_Canonical.MG_of`), not chosen. Running `Print Assumptions` over **all
196 theorems in this directory** reports neither constant anywhere.

Tier G is different, and the difference is worth knowing — its axioms are a
**disjoint set**, not a subset, so "classes 1–3, no new axiom" is a statement
about Tier D **only** and does not cover the whole directory. `Print Assumptions
update_forgery_le_eufcma` reports SSProve's own base (class 4):

```
boolp.propositional_extensionality
boolp.functional_extensionality_dep
FunctionalExtensionality.functional_extensionality_dep
boolp.constructive_indefinite_description
SPropBase.ax_proof_irrel : ClassicalFacts.proof_irrelevance
realsum.__admitted__interchange_psum
Axioms.R : reals.Real.type
```

The first five are the standard classical axioms any development over
mathcomp-analysis inherits. The last two deserve a line each. `Axioms.R` is
SSProve's abstract real-closed field — a parameter, not a gap. But
`realsum.__admitted__interchange_psum` is, as its name says, an **admitted**
lemma (interchange of double sums) shipped as an axiom by `mathcomp-analysis`'s
`realsum`, and SSProve's advantage machinery rests on it. So "the SSProve half
is `Qed` with zero admits" is true of *our* files and false of the stack
underneath them. This is the same class of finding as this project's Phase-1
result that the Aeneas Coq backend ships arrays as bare axioms: **typechecks ≠
proved, all the way down**. It should be stated in any paper that quotes the
bound.

---

## What is *not* proved

**The end-to-end bound is not machine-checked as a single chain.** It is two
pieces joined by a step taken in prose:

```
Pr[real device accepts an unsigned package]
   ≤  Pr[UPD-game win]                          <-- NOT lifted into SSProve
   ≤  Advantage EUF_CMA (A ∘ RED)               <-- Qed, update_forgery_le_eufcma
```

The `submit` oracle of the UPD game returns the **tag-verification verdict**
`tag_of_pkg p == MAC k (msg_of_pkg p)`, not "`parse_and_verify` accepted".
`device_accept_implies_submit_true` (`Qed`) proves real acceptance *implies*
that verdict, so the UPD game is a strict **relaxation** of the real device and
the first inequality is an inclusion of events. But it is an inclusion proved as
a Coq implication, not as an SSProve game hop.

### The remaining obligation, precisely

To close the first inequality inside SSProve, the real device's acceptance
predicate would have to be a `raw_code` over a `choice_type` package space —
i.e. `parse_and_verify` would have to be runnable inside a package. Two things
block that, and only one is hard:

> **Status.** BOTH items below are now CLOSED — item 1 by `Umbra_Wire.v` /
> `Umbra_RealGame.v`, item 2 by `Update_Converse.v` / `Umbra_WireConverse.v`
> (`accept_implies_struct` + `parse_walk` + `tag_gate_iff` + the two new
> `ct_eq*_complete` lemmas), so that `Umbra_RealGame.Hfactorise` is a `Lemma`
> and `device_forgery_le_eufcma` no longer carries it. The text below is kept
> as written because it diagnosed item 2 correctly, and because the *closure*
> should be read against the diagnosis rather than replacing it. What is still
> open in this directory is C1, C1e, C2, and the un-lifted probability step of
> `Umbra_Reduction.v` — see the sections below.

1. *(Not hard, but not "handled" either. **Now closed.**)* A wire package is a `slice u8`, not a
   `choice_type`, so the games name packages by a `nat` and read them through
   `msgN`/`tagN`. An earlier revision of this README defended that with "the
   games are universally quantified over `msgN`/`tagN`, so every slice is
   reachable — take `msgN := fun _ => msg_of_pkg s`". **That defence is
   unsound.** A constant reader models an adversary that submits one fixed
   package, chosen non-adaptively before the game starts; and "for each `s`
   there is an instantiation reaching `s`" is not "one instantiation reaches
   every `s`". What is actually needed is a single injection from wire packages
   into `nat` — one exists (`msg_of_pkg`/`tag_of_pkg` are `Z`-valued and
   non-negative, `msg_of_pkg_nonneg`, so a pairing bijection `nat × nat → nat`
   gives it) — and the games instantiated at *that*. That construction is not
   in the development. Note this does not touch the Tier-G theorem: it is a
   defence of the *modelling*, and the theorem is true for every `msgN`/`tagN`.

2. *(The real obligation.)* The reduction `RED` holds no key, so to reproduce
   `submit`'s **output** it must compute acceptance from `checktag` alone. That
   needs the **converse characterisation** of the parser:

   > `parse_and_verify` accepts `pkg` **iff** the key-independent structural
   > guards pass **and** `tag_of_pkg pkg = MAC key (msg_of_pkg pkg)`.

   The `⇒` direction is `accept_encodes` (`Qed`). The `⇐` direction — a
   completeness statement for the parser, requiring the structural predicate to
   be defined and the extracted body walked in the other direction, at roughly
   the cost of P2 — **is now proved**, at exactly that cost:
   `Update_Converse.parse_walk` walks the body forward under the five key-free
   guards and shows it reduces to one `ct_eq32`, and
   `Umbra_WireConverse.wstruct_ok` is the structural predicate, proved equal to
   branches 1–5 of the parser by `wstruct_ok_iff`. `Umbra_RealGame`'s `submit`
   oracle *is* the real acceptance predicate, and its bound carries no
   factorisation hypothesis.

Anyone quoting "a machine-checked end-to-end EUF-CMA bound for the update
protocol" is still overstating this directory, but for different reasons than
before. What is machine-checked in `Umbra_RealGame.v` is: the game, the
reduction, the perfect simulation, the bound between the two games, the type
bridge, and — new — the factorisation that makes the real parser simulable.
What is *not*: C1/C1e (two byte-level seam hypotheses, neither cryptographic),
C2 (the signing-service correspondence, about a component that is not even
extracted), and, for `Umbra_Reduction.v` specifically, the lifting of its event
inclusion to probabilities.

### `Umbra_Reduction.v` contains no Umbra content

Stated [in the opening section](#before-the-claim-umbra_reductionv-contains-no-umbra-content--umbra_realgamev-does),
where a reviewer meets it before the claim rather than on the fourth page of
five. Repeated here only so that this list of gaps is complete: `Umbra_EUFCMA.v`
and `Umbra_Reduction.v` are a general fact about a relabelled EUF-CMA game, their
`Print Assumptions` mentions no Aeneas axiom, and they would compile unchanged if
`parse_and_verify` did not exist.

`Umbra_RealGame.v` is the file that does not have this property — see
[what it changes](#what-umbra_realgamev-changes-and-what-it-does-not) — and it no
longer pays for that with hypothesis `(F)`, which is now a `Lemma`. It does pay
with C1 and C1e. Both files are kept: the first is the bound with no extra
hypothesis and no Umbra content, the second is the bound over the extracted
parser under two byte-level seam hypotheses. Neither on its own is an end-to-end
*security* result, because C2 is still assumed.

### The freshness seam (C2) is named, not closed

Validity and freshness are the two things an EUF-CMA challenger checks. Validity
is `device_accept_implies_submit_true`. **Freshness was, until this revision,
connected to nothing**: `Update_Forgery.accept_off_query_set_is_fresh_forgery`
quantifies over an abstract `Q : list Fields`, and nothing related `Q` to the
game's `S_loc`.

It is now stated, as `Umbra_DeviceLink.FreshnessSeam`:

```coq
Hypothesis Hsign_complete :
  forall g q, In g Q -> AssemblesF q g -> Sloc (Z.to_nat (msg_of_pre q)).
Hypothesis Hsign_sound :
  forall m, Sloc m ->
    exists g q, In g Q /\ AssemblesF q g /\ m = Z.to_nat (msg_of_pre q).
```

— the vendor's signing service tags exactly what it says it tags, so the
integers accumulating in `S_loc` are precisely the encodings of the packages the
vendor signed. C2a says `S_loc` is no *smaller* than that set, C2b that it is no
*larger*.

**They are not both used by the same theorem, and the split matters.**
`accept_of_unsigned_fields_is_off_query_set` (`Qed`) — a package the device
accepts whose five fields were never signed encodes to an integer *not* in the
query set — is derived from **C2b alone**. Coq generalises a closed section
theorem over exactly the hypotheses its proof used, and `Check` on the closed
type shows `Hsign_sound` and no `Hsign_complete`; an earlier revision of this
table presented the pair as jointly "the seam", which read as if both were doing
work in that theorem. Only one is. The strength of that one comes from
`msg_determines_fields` — without encoding injectivity the step is not provable.

C2a is not decoration either, and it is now load-bearing somewhere rather than
nowhere. C2b is satisfied *vacuously* by `Sloc := fun _ => False`, under which
the freshness theorem is true and says nothing, because every accepted package
is then trivially "fresh". C2a rules that out, and
`accept_of_signed_fields_is_in_query_set` (`Qed`) is where it does so: if the
accepted package's fields *were* signed, its encoding *is* in the query set.
That theorem's closed type carries `Hsign_complete` and not `Hsign_sound` — the
mirror image. Between them the two hypotheses pin `S_loc` from both sides; one
gives freshness, the other gives freshness its meaning.

**C2 is an assumption about a component that is neither verified nor extracted.**
The update-core crate contains the *device's parser*, not the *vendor's signer*;
there is no Coq object to walk. Naming C2 turns an undisclosed gap into a
disclosed one. It does not close it.

### Other things a reviewer should not be told

* **No concrete advantage.** The bound is `≤ Advantage EUF_CMA (A ∘ RED)`, with
  no `q_s`, `q_v` or `2^-128` term. `RED` makes one `gettag` per `sign` and one
  `checktag` per `submit`, so the query counts are preserved exactly and the
  reduction is tight — but that is an observation about the code, not a proved
  statement.
* **Replay/anti-rollback are not in the game.** The nonce and version fields are
  *inside* the authenticated core, so the bound covers "this exact tuple was
  never signed", not "this tuple was signed but for an earlier session". Replay
  freshness is `Update_Auth.accept_implies_nonce_equal` and anti-rollback is P4;
  both are functional statements and neither is a game.
* **Nothing after `parse_and_verify`.** Slot programming, flash, the anti-
  rollback counter and the reboot path are all outside every statement here, as
  they are outside the update-core chain.
* **The blob body is not authenticated by anything proved in THIS directory.**
  Stated in full
  [at the top](#read-this-first-the-bound-does-not-cover-the-update-blob), and
  repeated here so this list is complete. The chained HMAC that does authenticate
  it is extracted and proved in [`../chain-core/`](../chain-core/README.md) —
  but over `blob[48, 48+288·n)` only, so `blob[4,10)`, `blob[14,16)` and the
  relocation table appended after the blocks are authenticated by nothing, on
  either side. Both are inert on the N657 as the code stands; see that README's
  "What B1 is now" for why, and for the two proposed fixes.
* **"Total" means "terminates within 10⁶ steps".** The Coq backend omits
  Aeneas's loop combinator, so `AeneasLoopShim.v:17` supplies
  `loop := loop_fuel 1000000`. Every totality statement about the extracted code
  — including `Update_Safety.parse_and_verify_total`, on which
  `Umbra_Wire.accepts` rests — is therefore fuel-bounded. The parser's loops are
  16- and 32-iteration byte comparisons, so the bound is never approached; it is
  nonetheless part of the model and was not previously disclosed.
* **Packages are truncated at the device limit.** `Umbra_Wire.MAX_PKG = 65536`,
  matching the N657 Secure scratch and its `pkg_len <= 0x10000` front gate.
  `wire` truncates beyond that limit, where the real implementation rejects.
  The literal exists because `usize_max` is only known to be ≥ `u32_max`
  (`Primitives.usize_max_bound`), so a concrete bound is the direct way to
  discharge the `slice` well-formedness obligation without assuming more.
* **`dkey` is otherwise unconstrained, and `Hdkey_inj` is documentation.**
  Injectivity is assumed (`Hdkey_inj`) but is **not used**: Coq's section
  discharge does not quantify over it in the closed type of either
  `device_forgery_le_eufcma` or `device_forgery_le_eufcma_at_the_real_seam`, and
  `Check` shows this. It is stated so the reader can see which failure mode
  would otherwise be invisible — a collapsing `dkey` makes the game's
  `uniform KeyN` range over fewer than `2^n` HMAC keys
  (`MG_of_collapses_on_equal_key_bytes`, `Qed`) — and the step from injectivity
  to "the RHS is an HMAC advantage under a uniform key" is prose. It is not
  load-bearing and should not be quoted as if it were.
* **`ByteSeam` pins the engine only on the image of `bytes91`, and closing
  that needs one named premise about the extraction.** `ByteSeam macf mb`
  equates `tag_of_arr (macf kb p)` with `mb (kbytes kb) (bytes91 p)`, so it
  constrains `mb` only at arguments of the form `bytes91 p`. Those are lists of
  genuine bytes (`Umbra_Canonical.bytes91_allbytes`, `Qed`, from
  `array_index_usize_ok` and `u8_to_Z_range`).

  **This was a live counterexample one revision ago, and is not one now.** With
  the game indexed by `[0, 257^76)` — the 76-digit base-257 *numerals* — and
  base-257 digit `256` being `Update_Encoding.rdA`'s out-of-range **sentinel**,
  25.64 % of the space decoded under `canon91` to a 91-element list containing
  `256`, provably not `bytes91` of any array (`dead_zone_is_no_preimage`,
  `Qed`), where `ByteSeam` said nothing at all. `Umbra_WireConverse.restricted_
  space_still_admits_a_broken_seam_at_MSGBn` and `dead_zone_collides_with_any_
  live_message_at_MSGBn` (both `Qed`, 10 quarantine axioms) build from **any**
  conforming `mb0` another conforming `mb` that equals it at every genuine byte
  list and collides the pinned MAC at reachable messages — advantage 1. Both
  theorems are **kept in the tree**. The game is now indexed at `256^76`, where
  every message decodes to ninety-one genuine bytes
  (`Umbra_ByteSpace.spread_canon91_allbytes`, `Qed`), so the construction has
  nothing to patch.

  **What is left.** Byte-validity is necessary for `canon91 (spread j)` to be
  `bytes91` of an array; it is not *proved* sufficient, because
  `Primitives.array_index_usize` is a bare axiom with no law relating any
  constructor to indexing, so **no constructible `array u8 91` has known
  reads**. The gap is exactly one statement, named rather than hidden:

  ```coq
  Umbra_ByteSpace.ArrayVectors :=
    forall b : list Z, length b = 91 -> allbytes b = true ->
      exists p : array u8 91, bytes91 p = b.
  ```

  It is true of Rust arrays, unprovable against the extraction as shipped, and
  a **premise** rather than an `Axiom` — so it appears in the closed type of
  the theorems that use it and in **none** of the bound.

  **That last clause is true and is the wrong emphasis; the paper must not
  repeat it as reassurance.** The bound is `forall mb, ByteSeam macf mb ->
  Adv(DEV) <= Adv(EUF_CMA)`, and it is indeed true without `ArrayVectors` — but
  for a *broken* conforming `mb` the right-hand side is `1`, which is the old
  vacuity restated, not its absence. What `ArrayVectors` buys is that the
  right-hand side does not depend on **which** conforming seam is chosen: it is
  what makes the abstract MAC *be* the device's HMAC rather than merely agree
  with it somewhere. The security reading of the bound needs the premise even
  though the bound's statement does not. Two things are now machine-checked
  about that need, and they are why the premise is defensible rather than
  merely honest:

  * `Umbra_ArrayVectors.ArrayVectors_holds` (`Qed`; before 2026-09-02 it was conditional) — under
    `ModelIndex` (`array_index_usize` interpreted by
    `Update_Model.model_array_index`), `ArrayVectors` **holds**. That function
    is not a model built for the occasion: it is literally the
    `op_array_index` field of `Update_Model.model_ops`, the witness of
    `Update_Model.quarantine_has_a_model`. So the *same* interpretation of the
    *same* symbol satisfies all twenty quarantine laws and `ArrayVectors`
    together — the premise cannot have made the axiom set inconsistent, and it
    cannot have silently displaced one of the twenty. The proof is
    constructive: it builds the array and computes its read-sequence.
    `Print Assumptions`: `usize_max{,_bound}`, `isize_*`, `array_index_usize`
    — no quarantine axiom, no classical axiom, no admit.
  * `Umbra_ArrayVectors.the_counterexample_rebuilds_without_ArrayVectors` and
    `pinning_forces_ArrayVectors_on_the_reachable_messages` (both `Qed`) —
    deny `ArrayVectors` at a **single** reachable message and the dead-zone
    counterexample rebuilds at exactly that message (`point_patch` bumps the
    seam there; both seams still satisfy `ByteSeam`). Contrapositively, the
    pinning theorem *implies* the `ArrayVectors` instances it quantifies over.

  So the fix is **exactly** `ArrayVectors` on the reachable messages:
  sufficient, necessary, and nothing weaker will do. Granting it,
  `Umbra_WireConverse.msg_space256_pins_the_seam` (`Qed`) says any two seams
  `ByteSeam` admits give the *same* pinned MAC at every message of the space,
  and `patching_cannot_create_a_collision_at_MSGB256n` (`Qed`) that no choice
  of conforming seam creates a collision the engine did not already have —
  which is the exact negation of the counterexample above. Declining it leaves
  a bound over a class of seams on which **no counterexample is constructible**;
  that is weaker than "the engine, pinned", and stronger than what any previous
  revision could say.
* **`MG_of`'s output is not proved to lie in the 32-byte tag range.**
  `MG_of mb kb m := Z.to_nat (mb (kbytes kb) (canon91 (Z.of_nat m)))`, and
  `Z.to_nat` clamps negatives to `0`. Same blocker as the item above. It cannot
  make the bound false — a MAC outside the tag range only makes the device
  accept less — but it is the same defect class.
* ~~**The crate is still not wired into the kernel.**~~ **Stale — corrected.**
  It is wired, and was already wired when this line was written.
  `src/kernel/Cargo.toml` depends on `umbra-update-core`, and
  `src/kernel/src/key_storage_server/enclave_update.rs` calls
  `umbra_update_core::compute_pkg_tag` and
  `umbra_update_core::parse_and_verify` from the production path — the module
  is a thin closure-to-trait shim, so the firmware executes the extracted-and-
  proved code rather than a copy of it. The bound in this directory therefore
  applies to the function the device actually runs. What *is* still open is
  listed above, none of it about wiring.

---

## Provenance

* SSProve 0.2.4, Coq 8.18.0, mathcomp 2.2.0, mathcomp-analysis 1.3.1,
  extructures 0.5.0, deriving 0.2.3, equations 1.3+8.18, mathcomp-word 3.2,
  opam switch `default`.
* Game structure and tactic recipes follow SSProve's `theories/Crypt/examples/
  PRFMAC.v`, which formalises the same EUF-CMA game for a PRF-based MAC.
