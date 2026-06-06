//! `umbra_enclave_status_imp` NSC veneer.
//! Query enclave state. Returns the full 32-bit `ctx.result` (R0 at
//! termination) when the enclave has terminated, the status code otherwise.

use crate::secure_kernel::Kernel;
use kernel::common::enclave::EnclaveState;
use kernel::common::ess::MAX_ENCLAVES_CTX;

#[no_mangle]
#[link_section = ".umbra_api_implementation"]
/// Query enclave state. Returns the full 32-bit `ctx.result` (R0 at
/// termination) when the enclave has terminated, the status code otherwise.
pub extern "C" fn umbra_enclave_status_imp(enclave_id: u32) -> u32 {
    let kernel = unsafe {
        match Kernel::get() {
            Some(k) => k,
            None => return 0xFF,
        }
    };

    for (i, slot) in kernel.ess.loaded_enclaves.iter().enumerate() {
        if let Some(le) = slot {
            if le.descriptor.id == enclave_id && i < MAX_ENCLAVES_CTX {
                let ctx = &kernel.enclave_contexts[i];
                if ctx.status == EnclaveState::Terminated {
                    return ctx.result;
                }
                return ctx.status as u32;
            }
        }
    }
    0xFF
}
