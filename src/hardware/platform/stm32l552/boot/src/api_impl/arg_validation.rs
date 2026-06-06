//! Shared NS-pointer + length validation helpers for NSC veneers.
//! F1 fix lives here: the 256-byte length bound on
//! NS-supplied pointers passed through `umbra_debug_print_imp`. The bound
//! is a hard security invariant — see the threat-model ADR §5.

/// Max bytes that the NS host can ask us to print in one call.
/// Per the threat-model ADR §5, this bounds NS-pointer reads
/// from NSC veneers so a malicious `str_ptr` cannot make us read off the
/// end of valid memory. The SAU/MPCBB raises SecureFault if the pointer
/// lies in Secure-only memory; `panic_policy::handle_fault` then resets
/// (or halts with `--features debug-halt`).
pub const MAX_PRINT_LEN: usize = 256;
