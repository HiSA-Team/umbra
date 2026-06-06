//! `umbra_enclave_enter_imp` NSC veneer.
//! Validates the enclave id, reconfigures MPU regions 4+5 for the target
//! enclave, then drops into Secure-side Thread/PSP via `svc #0`. Returns
//! the enclave's final result code (or a fault-encoded status).

use crate::secure_kernel::Kernel;
use kernel::common::enclave::{EnclaveContext, EnclaveState};
use kernel::common::ess::MAX_ENCLAVES_CTX;
use umbra_error::UmbraError;

use super::nsc_status;

#[no_mangle]
#[link_section = ".umbra_api_implementation"]
pub extern "C" fn umbra_enclave_enter_imp(enclave_id: u32) -> u32 {
    // switch bracket: scope-guard pattern so we record
    // on EVERY return path (incl. early-exit errors and the long
    // post-enclave-execution path) without sprinkling boilerplate. The
    // `Drop` impl fires at function exit regardless of how we get
    // there. The accumulator distinguishes "fast error" calls from
    // legitimate switches by min vs max spread.
    #[cfg(feature = "bench-eval")]
    let _bench_switch_guard = crate::bench_eval::SwitchGuard::start();

    let kernel = unsafe {
        match Kernel::get() {
            Some(k) => k,
            None => return 0xFFFFFFFE,
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
        EnclaveState::Ready | EnclaveState::Suspended => {}
        EnclaveState::Terminated => {
            return ((enclave_id & 0xFFFF) << 16)
                | ((EnclaveState::Terminated as u32 & 0xFF) << 8)
                | (ctx.result & 0xFF);
        }
        EnclaveState::Faulted => {
            return ((enclave_id & 0xFFFF) << 16) | ((EnclaveState::Faulted as u32 & 0xFF) << 8);
        }
        _ => return nsc_status(UmbraError::EnclaveStateInvalid),
    }

    // Extract the raw pointer from ctx before releasing the mutable borrow so
    // that we can later call kernel.enable_systick() (which takes &self) without
    // a simultaneous &mut alive.
    let ctx_raw: *mut EnclaveContext = &mut kernel.enclave_contexts[enclave_idx];

    // Safety: we own the kernel singleton exclusively here.
    let ctx = unsafe { &mut *ctx_raw };

    match ctx.status {
        EnclaveState::Ready | EnclaveState::Suspended => {}
        EnclaveState::Terminated => {
            return ((enclave_id & 0xFFFF) << 16)
                | ((EnclaveState::Terminated as u32 & 0xFF) << 8)
                | (ctx.result & 0xFF);
        }
        EnclaveState::Faulted => {
            return ((enclave_id & 0xFFFF) << 16) | ((EnclaveState::Faulted as u32 & 0xFF) << 8);
        }
        _ => return nsc_status(UmbraError::EnclaveStateInvalid),
    }

    ctx.status = EnclaveState::Running;
    // Drop the ctx reference so we can borrow kernel freely below.
    let _ = ctx;

    kernel.current_enclave_id = Some(enclave_id);

    // G3: pre-load all reachable blocks BEFORE MPU Region 5 is configured.
    // Region 5 marks the EFBC as RO+Execute (AP=0b11) which blocks ALL
    // writes, even privileged. The prefetch must write to the EFBC, so
    // it runs before the MPU locks it down.
    // also gated by `umbra-speculation` so spec-OFF
    // sweep cells bypass the prefetch entirely — every code fetch past
    // the entry block then triggers a synchronous miss + validation.
    #[cfg(all(feature = "ess_miss_recovery", feature = "umbra-speculation"))]
    unsafe {
        crate::prefetch::prefetch_reachables(enclave_id);
    }

    // Reconfigure MPU for this enclave (after prefetch)
    unsafe {
        let mpu_rbar = arm::mmio::MPU_RBAR;
        let mpu_rlar = arm::mmio::MPU_RLAR;
        let mpu_rnr = arm::mmio::MPU_RNR;

        let psp_base = kernel::common::ess::enclave_psp_top(enclave_idx)
            - kernel::common::ess::ENCLAVE_PSP_STACK_SIZE;
        let psp_limit = kernel::common::ess::enclave_psp_top(enclave_idx) - 1;

        // Region 4: Enclave stack (RW, unprivileged, XN)
        core::ptr::write_volatile(mpu_rnr, 4);
        core::ptr::write_volatile(mpu_rbar, (psp_base & 0xFFFF_FFE0) | (0b01 << 1) | 0x01);
        core::ptr::write_volatile(mpu_rlar, (psp_limit & 0xFFFF_FFE0) | 0x01);

        // Region 5: Enclave code+data (RW any, executable).
        // AP=0b01 (RW, all privilege levels). XN=0 (executable). Under
        // `-fpic -mpic-data-is-text-relative`, the enclave's.data/.bss
        // are emitted into the same._enclave_code section as code (see
        // host/stm32l552/taclebench/linker/enclave_blob.ld) and loaded into ESS,
        // so the region must permit writes for any enclave that touches
        // a global. RO+X (AP=0b11) was the original intent but trips
        // MemManage.DACCVIOL on the first global store, which the
        // current handler can't actually resolve — the recover path
        // re-runs the same store and re-faults, draining only when
        // SysTick eventually preempts the cycle.
        // Integrity is enforced at load time by the chained-measurement
        // HMAC over the on-flash blob; runtime modifications affect only
        // the volatile ESS RAM copy, never the signed image on flash.
        if let Some(le) = &kernel.ess.loaded_enclaves[enclave_idx] {
            let code_base = le.start_address | 0x1000_0000;
            let code_limit = code_base + le.descriptor.code_size - 1;
            core::ptr::write_volatile(mpu_rnr, 5);
            core::ptr::write_volatile(mpu_rbar, (code_base & 0xFFFF_FFE0) | (0b01 << 1));
            core::ptr::write_volatile(mpu_rlar, (code_limit & 0xFFFF_FFE0) | 0x01);
        }
    }

    let status: u32;
    unsafe {
        let ctx_ptr = ctx_raw as u32;
        core::arch::asm!(
            "svc #0",
            inout("r0") ctx_ptr => status,
            out("r1") _,
            out("r2") _,
            out("r3") _,
        );
    }

    unsafe {
        crate::secure_kernel::CURRENT_ENCLAVE_CTX_PTR = core::ptr::null_mut();
    }
    kernel.current_enclave_id = None;

    status
}
