//! `umbra_debug_print_imp` NSC veneer.
//! Bounded NS-string printer. The 256-byte `MAX_PRINT_LEN` bound is the
//! F1 security fix — it prevents a malicious NS
//! pointer from making us read arbitrary Secure memory off the end of a
//! valid string. Do NOT revert to an unbounded `print_cstr`.

use super::arg_validation::MAX_PRINT_LEN;

#[no_mangle]
#[link_section = ".umbra_api_implementation"]
pub extern "C" fn umbra_debug_print_imp(str_ptr: *const u8) {
    if str_ptr.is_null() {
        return;
    }
    // SAFETY: `from_raw_parts` with `MAX_PRINT_LEN` bounds the read at 256
    // bytes. The caller is the NS host; we DO NOT trust the pointer to point
    // to readable memory. If it points into Secure-only memory or unmapped
    // space, the SAU/MPCBB/bus raises SecureFault/BusFault and the panic
    // policy handles it. The bound prevents UB read past 256 bytes when the
    // pointer is valid but the string happens to be unterminated.
    // CAUTION: recursive-fault path (slice spans beyond a Secure-readable
    // region while panic_policy itself is logging) is theoretically possible
    // but untested. Negative test deferred to — see plan Step 8.4b.
    let bytes = unsafe { core::slice::from_raw_parts(str_ptr, MAX_PRINT_LEN) };
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(MAX_PRINT_LEN);
    crate::raw_print::print_bytes(&bytes[..len]);
}
