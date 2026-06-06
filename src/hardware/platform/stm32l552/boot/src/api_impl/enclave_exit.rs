//! `umbra_enclave_exit_imp` NSC veneer.
//! Transitions a Suspended enclave to Terminated, or simply reports the
//! existing terminal status. Never preempts a Running enclave — the
//! cooperative-exit path is via SVC inside the enclave itself.

use crate::secure_kernel::Kernel;
use kernel::common::enclave::EnclaveState;
use kernel::common::ess::MAX_ENCLAVES_CTX;
use umbra_error::UmbraError;

use super::nsc_status;

#[no_mangle]
#[link_section = ".umbra_api_implementation"]
pub extern "C" fn umbra_enclave_exit_imp(enclave_id: u32) -> u32 {
    let kernel = unsafe {
        match Kernel::get() {
            Some(k) => k,
            None => return 0xFFFF_FFFE,
        }
    };

    let enclave_idx = {
        let mut found: Option<usize> = None;
        for (i, slot) in kernel.ess.loaded_enclaves.iter().enumerate() {
            if let Some(le) = slot {
                if le.descriptor.id == enclave_id {
                    found = Some(i);
                    break;
                }
            }
        }
        match found {
            Some(i) => i,
            None => return nsc_status(UmbraError::EnclaveNotFound { id: enclave_id }),
        }
    };

    if enclave_idx >= MAX_ENCLAVES_CTX {
        return 0xFFFF_FFF1;
    }

    let ctx = &mut kernel.enclave_contexts[enclave_idx];

    match ctx.status {
        EnclaveState::Suspended => {
            ctx.status = EnclaveState::Terminated;
            ((enclave_id & 0xFFFF) << 16) | ((EnclaveState::Terminated as u32 & 0xFF) << 8)
        }
        EnclaveState::Terminated | EnclaveState::Faulted => {
            ((enclave_id & 0xFFFF) << 16) | ((ctx.status as u32 & 0xFF) << 8)
        }
        _ => nsc_status(UmbraError::EnclaveStateInvalid),
    }
}
