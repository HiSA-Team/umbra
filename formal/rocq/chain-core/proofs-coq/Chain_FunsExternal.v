(** Filled from the Aeneas template by ../extract.sh. NOT auto-generated
    verbatim: every opaque seam is an ALIAS of the constant of the same name in
    `Update_FunsExternal` (all DEFINITIONS there), so that `Update_Safety`'s
    laws about them apply to this model too, and no second, parallel block of
    seams is opened.

    `mk_array4` is update-core's TOTAL definition, never the Coq backend's
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
Require Import Update_FunsExternal.
Module Chain_FunsExternal.

(** [core::slice::{[T]}::copy_from_slice] — update-core's seam, aliased. *)
Definition core_slice_Slice_copy_from_slice
  {T : Type} (markerCopyInst : core_marker_Copy T)
  : slice T -> slice T -> result (slice T)
  := Update_FunsExternal.core_slice_Slice_copy_from_slice markerCopyInst.

(** The byte<->u32 codecs the Coq backend has no theory for. Aliased for the
    same reason; `Update_Safety`'s Q18/Q19 are laws about exactly these. *)
Definition core_num_U32_from_le_bytes : array u8 4%usize -> u32
  := Update_FunsExternal.core_num_U32_from_le_bytes.
Definition core_num_U32_to_le_bytes : u32 -> array u8 4%usize
  := Update_FunsExternal.core_num_U32_to_le_bytes.

(** The four-element array literal the extracted decoder builds. Total. *)
Definition mk_array4 : u8 -> u8 -> u8 -> u8 -> array u8 4%usize
  := Update_FunsExternal.mk_array4.
End Chain_FunsExternal.
