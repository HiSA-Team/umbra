(** Filled from the Aeneas template by ../extract.sh. NOT auto-generated
    verbatim: every opaque seam is an ALIAS of the constant of the same name in
    the shared library `Aeneas_Laws` (all DEFINITIONS there; update-core's
    FunsExternal binds the very same constants by Notation), so that the
    library's laws about them apply to this model too, and no second, parallel
    block of seams is opened.

    `mk_array4` is the library's TOTAL definition, never the Coq backend's
    `Primitives.mk_array`, which is an inconsistent axiom (it proves `False`;
    ../../AENEAS_COQ_MKARRAY_BUG.md). *)
Require Import Primitives.
Import Primitives.
Require Import Coq.ZArith.ZArith.
Require Import List.
Import ListNotations.
Local Open Scope Primitives_scope.
Require Import Chain_Types.
Include Chain_Types.
Require Import Aeneas_Laws.
Module Chain_FunsExternal.

(** [core::slice::{[T]}::copy_from_slice] — the library's seam, aliased. *)
Definition core_slice_Slice_copy_from_slice
  {T : Type} (markerCopyInst : core_marker_Copy T)
  : slice T -> slice T -> result (slice T)
  := Aeneas_Laws.core_slice_Slice_copy_from_slice markerCopyInst.

(** The byte<->u32 codecs the Coq backend has no theory for. Aliased for the
    same reason; the library's Q18/Q19 are laws about exactly these. *)
Definition core_num_U32_from_le_bytes : array u8 4%usize -> u32
  := Aeneas_Laws.core_num_U32_from_le_bytes.
Definition core_num_U32_to_le_bytes : u32 -> array u8 4%usize
  := Aeneas_Laws.core_num_U32_to_le_bytes.

(** The four-element array literal the extracted decoder builds. Total. *)
Definition mk_array4 : u8 -> u8 -> u8 -> u8 -> array u8 4%usize
  := Aeneas_Laws.mk_array4.
End Chain_FunsExternal.
