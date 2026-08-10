# Aeneas Coq backend: `Primitives.mk_array` is inconsistent (proves `False`)

**Status:** already reported upstream, independently of us:
[AeneasVerif/aeneas#1116](https://github.com/AeneasVerif/aeneas/issues/1116)
(2026-06-10, still open, maintainer-confirmed; #1117 closed as duplicate).
Our discovery (2026-07-20) came five weeks later, so this file is no longer a
candidate issue — it remains the internal write-up, and its "Suggested fixes"
plus the 51-axiom inhabitedness audit are the parts not yet said upstream.

**Component:** `backends/coq/Primitives.v` (the Coq backend's runtime library,
copied verbatim into every Coq extraction).

**Affected versions (the ones we can attest to):**

| component | pin | ref |
|---|---|---|
| aeneas  | `8dd8bfb3047ce9797fa08d8046d8410a3b6a21c4` | tag `nightly-2026.06.16` |
| charon  | `6f058254eb741c12e9b388df07adaf7cc8aac8ed` | `nightly-2026.06.13-7-g6f058254` |
| coqc    | 8.18.0 | — |

The declaration is old and unchanged in the file's history, so every earlier
Coq-backend release is very likely affected too. Only the Coq backend is
involved; we have not looked at the Lean or F\* backends.

---

## The bug

`backends/coq/Primitives.v` defines arrays as length-indexed lists

```coq
Definition array T (n : usize) := { l: list T | Z.of_nat (length l) = to_Z n}.
```

and then postulates a constructor from an **arbitrary** list:

```coq
(* TODO: finish the definitions *)
Axiom mk_array : forall {T : Type} (n : usize) (l : list T), array T n.
```

The axiom's conclusion type is inhabited only when a list of type `T` and
length `n` exists. Take `T := Empty_set` and `n := 4`: the only inhabitant of
`list Empty_set` is `nil`, whose length is `0 ≠ 4`, so `array Empty_set 4` is
**empty**. An axiom whose type is empty yields `False`.

This is not a subtle point about the `%usize` literal machinery — the axiom
takes the list as an argument and ignores its length entirely, so it can be fed
`nil` at any index `n > 0`.

## Minimal reproduction

Against an unmodified `backends/coq/Primitives.v`, with
`coqc -R . Lib Primitives.v` already run:

```coq
Require Import Primitives.
Import Primitives.
Require Import Coq.ZArith.ZArith.
Require Import Coq.Lists.List.
Import ListNotations.
Require Import Lia.
Local Open Scope Z_scope.
Local Open Scope Primitives_scope.

Lemma list_empty_nil : forall (l : list Empty_set), l = nil.
Proof. intros [|x l]; [ reflexivity | destruct x ]. Qed.

Theorem mk_array_is_inconsistent : False.
Proof.
  pose (a := mk_array (T:=Empty_set) 4%usize nil).
  destruct a as [l Hl].
  rewrite (list_empty_nil l) in Hl. cbn in Hl.
  change (to_Z (4%usize)) with 4 in Hl.
  lia.
Qed.

Print Assumptions mk_array_is_inconsistent.
```

`Qed` succeeds. `Print Assumptions` reports:

```
Axioms:
usize_max_bound : u32_max <= usize_max
usize_max : Z
mk_array : forall (T : Type) (n : usize), list T -> array T n
isize_min_bound : isize_min <= i32_min
isize_min : Z
isize_max_bound : i32_max <= isize_max
isize_max : Z
```

The six remaining assumptions — the three architecture parameters `usize_max`,
`isize_min`, `isize_max` and the three bounds `usize_max_bound`,
`isize_min_bound`, `isize_max_bound` — are **jointly** satisfiable: take
`usize_max := u32_max`, `isize_min := i32_min`, `isize_max := i32_max`, which
discharges all three bounds simultaneously. So `mk_array` is the sole source of
the contradiction.

## Why it matters in practice

`mk_array` is what the backend emits for **every array literal in extracted
Rust**, including `[u8; 4]` byte literals and `const`/`static` byte-string
constants. It is therefore in the `Print Assumptions` set of essentially every
theorem anyone proves about extracted code that touches an array literal —
which silently makes those theorems vacuous. A development can be `Qed`-clean,
`admit`-free, and carefully quarantine its own axioms, and still prove nothing.

Concretely, in our own tree the extracted body of a package parser contained

```coq
Definition pKG_TAG_LABEL : slice u8 :=
  array_to_slice (mk_array 15%usize [117%u8; 109%u8; (* … *) 49%u8]).
…
core_num_U32_from_le_bytes (mk_array 4%usize [ i3; i4; i5; i6 ])
```

and every headline theorem inherited `mk_array`.

## Suggested fixes

Any of these removes the unsoundness; (1) is the smallest change.

1. **Make the axiom conditional on the length.** Nothing in the generated code
   ever builds a literal whose length disagrees with its index:

   ```coq
   Axiom mk_array : forall {T : Type} (n : usize) (l : list T),
     Z.of_nat (length l) = to_Z n -> array T n.
   ```

   This changes the emitted call sites (they must pass a proof), but the proof
   is `eq_refl` for every literal the backend generates, so the extractor can
   emit `mk_array n [ … ] eq_refl` mechanically.

2. **Define it instead of postulating it**, defaulting on a length mismatch —
   only possible when `T` is inhabited, so it needs the element type's default
   or a `Fail` channel:

   ```coq
   Definition mk_array {T} (n : usize) (l : list T) : result (array T n) := …
   ```

   i.e. move array-literal construction into the `result` monad, which is where
   every other partial operation in `Primitives.v` already lives.

3. **Emit a length-indexed constructor per literal.** This is the workaround we
   applied downstream, in a post-extraction patch step: rewrite every
   `mk_array N%usize [b₀; …; b_{N-1}]` into an application of a total
   definition that carries its own length proof,

   ```coq
   Definition mk_array4 (b0 b1 b2 b3 : u8) : array u8 4%usize :=
     exist _ [b0; b1; b2; b3] eq_refl.
   ```

   `eq_refl` typechecks directly under `coqc` 8.18, because
   `scalar_le_max` tries the *conservative* bound first (`x <=? u32_max`), so
   `to_Z (4%usize)` reduces to `4` without unfolding the opaque `usize_max`.
   After the rewrite, `Print Assumptions` on our theorems no longer mentions
   `mk_array`.

## Related, but *not* bugs

For completeness, since they have the same result type: `array_repeat`,
`array_from_slice` and `array_update` are all sound as declared, because each
one already **takes** an inhabitant of `T` or of `array T n` as an argument, so
their conclusion types are inhabited whenever their arguments are.
`mk_array` is the only one that manufactures an `array T n` out of nothing.
