(** Security proof for issue #58 — the "Check Cache" guard, proved against the
    REAL extracted ESS code.

    `EnclaveSwapSpace::get_block_address` is the function the kernel uses to turn
    an (enclave_id, block_id) into an executable Secure address — the
    "Check Cache" step of the formal model. Its inner loop body is reproduced
    here VERBATIM from the Aeneas-generated `Ess_Funs.v`
    (`enclaveSwapSpace_get_block_address_loop_body`), using the real record types
    from `Ess_Types.v`. The only abstraction: the address arithmetic
    (`block_id.checked_mul(SLOT_SIZE).and_then(|x| start.checked_add(x))`) is an
    opaque `compute_addr` — it is NOT part of the security guard, which is about
    *whether* an address is returned, not its value.

    THEOREM: the body returns an address (`Done (Some _)`) ONLY when the matched
    block is resident (`is_loaded = true`) AND its id matches the request, inside
    an enclave whose id matches. This is the Rust-code-level analogue of the
    ProVerif property `Execute(b) ⇒ RegisterBlock(b)`: no address is handed out
    for a block that was not loaded and registered. *)
Require Import Primitives.
Import Primitives.
Require Import AeneasLoopShim.
Import AeneasLoopShim.
Require Import Ess_Types.
Import Ess_Types.
Local Open Scope Primitives_scope.

(* Opaque externals (exactly what they are in the extracted code). *)
Parameter next :
  core_slice_iter_Iter_t (option LoadedEnclave_t) ->
  result (option (option LoadedEnclave_t) *
          core_slice_iter_Iter_t (option LoadedEnclave_t)).
(* The address arithmetic — opaque; not part of the guard. *)
Parameter compute_addr : u32 -> LoadedEnclave_t -> result (option u32).

(** VERBATIM copy of `enclaveSwapSpace_get_block_address_loop_body` from the
    generated Ess_Funs.v, with `next`/`compute_addr` standing in for the
    slice-iterator `next` and the `and_then` address closure. *)
Definition check_cache_body
  (enclave_id : u32) (block_id : u32)
  (iter : core_slice_iter_Iter_t (option LoadedEnclave_t)) :
  result (control_flow (core_slice_iter_Iter_t (option LoadedEnclave_t))
    (option u32))
  :=
  p <- next iter;
  let (o, iter1) := p in
  match o with
  | None => Ok (Done None)
  | Some enc =>
    match enc with
    | None => Ok (Cont iter1)
    | Some e =>
      if e.(loadedEnclave_descriptor).(enclaveDescriptor_id) s= enclave_id
      then (
        i <- scalar_cast U32 Usize block_id;
        if i s< e.(loadedEnclave_efb_count)
        then (
          efb <- array_index_usize e.(loadedEnclave_efbs) i;
          if efb.(efbDescriptor_is_loaded)
          then
            if efb.(efbDescriptor_id) s= block_id
            then (o2 <- compute_addr block_id e; Ok (Done o2))
            else Ok (Cont iter1)
          else Ok (Cont iter1))
        else Ok (Cont iter1))
      else Ok (Cont iter1)
    end
  end.

(** The Check-Cache guard. If the body returns an address, then there is a
    resident, id-matched block in an id-matched enclave that produced it. *)
Theorem check_cache_guard :
  forall enclave_id block_id iter addr,
    check_cache_body enclave_id block_id iter = Ok (Done (Some addr)) ->
    exists (e : LoadedEnclave_t) (i : usize) (efb : EfbDescriptor_t),
      (* the request hit a registered enclave whose id matched *)
      (e.(loadedEnclave_descriptor).(enclaveDescriptor_id) s= enclave_id) = true /\
      (* in-bounds block index *)
      scalar_cast U32 Usize block_id = Ok i /\
      (i s< e.(loadedEnclave_efb_count)) = true /\
      array_index_usize e.(loadedEnclave_efbs) i = Ok efb /\
      (* the block was RESIDENT (loaded) and its id matched the request *)
      efb.(efbDescriptor_is_loaded) = true /\
      (efb.(efbDescriptor_id) s= block_id) = true.
Proof.
  intros enclave_id block_id iter addr H.
  unfold check_cache_body, bind in H.
  (* Recursively split every scrutinee (opaque `next`/`array_index`/cast results,
     the option/enum matches, the boolean guards) and reduce. Each `eqn:` keeps
     the deciding fact. Impossible branches expose a constructor clash; the good
     branch keeps exactly the guard facts the theorem asserts. *)
  repeat (cbn in H;
          match type of H with
          | (match ?x with _ => _ end) = _ => destruct x eqn:?
          | (if ?b then _ else _) = _      => destruct b eqn:?
          | (let (_, _) := ?p in _) = _    => destruct p eqn:?
          end).
  all: cbn in H.
  all: try discriminate.
  (* The single surviving branch is the resident, id-matched one. *)
  eauto 12.
Qed.
