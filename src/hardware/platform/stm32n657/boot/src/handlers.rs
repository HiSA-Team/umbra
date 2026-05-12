//! Exception handlers for STM32N657 Secure Boot.
//!
//! All handlers referenced by the shared startup.s must be defined here so
//! the linker resolves the symbols. Fault paths emit a register dump over
//! the secure UART; ESS-miss recovery uses the UsageFault dispatcher below.

use core::ptr;
use core::sync::atomic::AtomicU32;
use arm::mmio::{
    ICIALLU, MPU_RBAR, MPU_RNR,
    SCB_BFAR, SCB_CFSR, SCB_HFSR, SCB_MMFAR, SCB_SFAR, SCB_SFSR, SCB_VTOR,
};
use crate::raw_print::{print_str, print_hex};

/// Non-zero while the FSBL oracle is running. The asm `_umb_SysTick_Handler`
/// reads this flag and takes an early-return path (kick IWDG only, skip
/// enclave preempt logic) when it is set, so the oracle's stacked R0 isn't
/// clobbered by the enclave-preempt write at `sp+32`.
///
/// AtomicU32 (not AtomicBool) because the asm reads it as a plain 32-bit
/// word via `ldr`; a layout-stable u32 is the safest contract.
#[no_mangle]
pub static IN_ORACLE: AtomicU32 = AtomicU32::new(0);

/// Save fault registers to AXISRAM1 @ 0x340F0000 so they survive watchdog reset.
/// Read after reset via: monitor mdw 0x340F0000 12
unsafe fn save_fault_to_sram(sp: u32, fault_id: u32) {
    let save = 0x340F_0000 as *mut u32;
    save.add(0).write_volatile(0xDEAD_BEEF);  // magic
    save.add(1).write_volatile(fault_id);      // which handler
    save.add(2).write_volatile(ptr::read_volatile(SCB_CFSR));
    save.add(3).write_volatile(ptr::read_volatile(SCB_HFSR));
    save.add(4).write_volatile(ptr::read_volatile(SCB_SFSR));
    save.add(5).write_volatile(ptr::read_volatile(SCB_MMFAR));
    save.add(6).write_volatile(ptr::read_volatile(SCB_BFAR));
    save.add(7).write_volatile(sp);  // SP
    let frame = sp as *const u32;
    save.add(8).write_volatile(frame.add(5).read_volatile());  // stacked LR
    save.add(9).write_volatile(frame.add(6).read_volatile());  // stacked PC
    save.add(10).write_volatile(frame.add(7).read_volatile()); // stacked xPSR
    save.add(11).write_volatile(ptr::read_volatile(SCB_VTOR));
}

fn dump_stack_frame(sp: u32, exception_name: &str) {
    print_str("\r\n[");
    print_str(exception_name);
    print_str("] Handler Reached!\r\n");

    print_str("Stack Pointer: 0x");
    print_hex(sp);
    print_str("\r\n");

    let frame_ptr = sp as *const u32;
    // Avoid Range iterator — use while loop to prevent core::iter::range panics
    let regs: [&str; 8] = ["R0  ", "R1  ", "R2  ", "R3  ", "R12 ", "LR  ", "PC  ", "xPSR"];
    let mut i: usize = 0;
    while i < 8 {
        print_str(regs[i]);
        print_str(": 0x");
        unsafe {
            let val = frame_ptr.add(i).read_volatile();
            print_hex(val);
        }
        print_str("\r\n");
        i += 1;
    }
}

#[no_mangle]
pub extern "C" fn umbra_hard_fault_handler(sp: u32, exc_return: u32) {
    unsafe { save_fault_to_sram(sp, 1); } // 1 = HardFault
    print_str("\r\nHF ");
    unsafe {
        let frame = sp as *const u32;
        print_hex(exc_return);                                 print_str(" ");
        // Stacked frame (S or NS depending on EXC_RETURN.S bit).
        print_hex(frame.add(6).read_volatile());               print_str(" "); // PC
        print_hex(frame.add(7).read_volatile());               print_str(" "); // xPSR
        print_hex(frame.add(0).read_volatile());               print_str(" "); // R0
        // Secure-side fault status: SFSR, SFAR, CFSR, HFSR.
        print_hex(ptr::read_volatile(SCB_SFSR)); print_str(" ");
        print_hex(ptr::read_volatile(SCB_SFAR)); print_str(" ");
        print_hex(ptr::read_volatile(SCB_CFSR)); print_str(" ");
        print_hex(ptr::read_volatile(SCB_HFSR));
        print_str("\r\n");
        // Memory + Bus fault address registers (only valid when their
        // *VALID bit is set in CFSR — see MMFSR.MMARVALID, BFSR.BFARVALID).
        print_str("MMFAR: 0x");
        print_hex(ptr::read_volatile(SCB_MMFAR));
        print_str(" BFAR: 0x");
        print_hex(ptr::read_volatile(SCB_BFAR));
        print_str("\r\n");
        // NS-side fault status (NS aliases of SCB at 0xE002Exxx). When the
        // fault originated in NS state and was promoted to Secure HardFault
        // (FORCED), the cause is recorded in the NS FSRs, not Secure ones.
        print_str("NS ");
        print_hex(ptr::read_volatile(0xE002ED28 as *const u32)); print_str(" "); // NS_CFSR
        print_hex(ptr::read_volatile(0xE002ED2C as *const u32)); print_str(" "); // NS_HFSR
        print_hex(ptr::read_volatile(0xE002ED34 as *const u32)); print_str(" "); // NS_MMFAR
        print_hex(ptr::read_volatile(0xE002ED38 as *const u32));                 // NS_BFAR
    }
    print_str("\r\n");
    loop { core::hint::spin_loop(); }
}

#[no_mangle]
pub extern "C" fn umbra_nmi_handler(sp: u32) {
    dump_stack_frame(sp, "NMI");
    loop { core::hint::spin_loop(); }
}

/// MemManage fault handler — enclave-termination path.
///
/// Recognises the end-of-task sentinel: an enclave launched with
/// LR = 0xFFFFFFFF that runs its final `bx lr` jumps to 0xFFFFFFFE, which
/// raises IACCVIOL on the unprivileged instruction fetch (no MPU region
/// covers 0xFFFFFFFE for unprivileged accesses). Returning a non-zero
/// encoded status causes the assembly trampoline to short-circuit back to
/// `umbra_enclave_enter_imp` with the result in r0.
///
/// Anything else here is unrecoverable from a MemManage perspective: dump
/// the frame and halt for diagnosis. (ESS-miss demand-paging is handled by
/// the UsageFault dispatcher, not here.)
#[no_mangle]
pub unsafe extern "C" fn umbra_mem_manage_handler(psp: u32) -> u32 {
    use kernel::common::enclave::EnclaveState;

    let cfsr_ptr = SCB_CFSR;
    let cfsr_val = ptr::read_volatile(cfsr_ptr);
    let mmfsr = (cfsr_val & 0xFF) as u8;
    let is_iaccviol = (mmfsr & 0x01) != 0;

    if is_iaccviol {
        let frame = psp as *const u32;
        let stacked_pc = ptr::read_volatile(frame.add(6));
        if stacked_pc == 0xFFFF_FFFE {
            // End-of-task sentinel: clear MMFSR sub-bits and terminate.
            ptr::write_volatile(cfsr_ptr, mmfsr as u32);
            return usage_fault_terminate(psp, EnclaveState::Terminated);
        }
    }

    save_fault_to_sram(psp, 2);
    dump_stack_frame(psp, "MemManage");
    print_str("CFSR: 0x"); print_hex(cfsr_val); print_str("\r\n");
    loop { core::hint::spin_loop(); }
}

/// SecureFault handler — diagnostic dump (both Secure and NS sides).
///
/// The assembly trampoline passes `sp` from the wrong domain when the fault
/// originates in NS state (it does `mrs psp` which reads Secure PSP, not
/// NS PSP). Read the correct frame here based on EXC_RETURN.S/ES bits.
#[no_mangle]
pub unsafe extern "C" fn umbra_secure_fault_handler(_sp: u32, exc_return: u32) {
    save_fault_to_sram(_sp, 3); // 3 = SecureFault
    let sfsr = ptr::read_volatile(SCB_SFSR);
    let sfar = ptr::read_volatile(SCB_SFAR);

    // EXC_RETURN was passed as r1 by `_umb_SecureFault_Handler` in
    // startup_n657.s (mirrors the Hard Fault calling convention). No need
    // to read LR from inline asm here.

    // Frame location depends on the security domain that was running when the
    // fault was taken: bit 6 (S=0) = returning to NS, bit 2 (SPSEL) = PSP/MSP.
    let from_ns = (exc_return & (1 << 6)) == 0;
    let use_psp = (exc_return & (1 << 2)) != 0;

    let frame_sp: u32 = if from_ns {
        // psp_ns / msp_ns are v8-M Security Extension registers (only
        // accessible from Secure mode). cortex-m 0.7 does NOT expose these
        // in `cortex_m::register::*`, so inline asm stays here.
        let sp: u32;
        if use_psp {
            core::arch::asm!("mrs {0}, psp_ns", out(reg) sp);
        } else {
            core::arch::asm!("mrs {0}, msp_ns", out(reg) sp);
        }
        sp
    } else if use_psp {
        cortex_m::register::psp::read()
    } else {
        // Came from Secure with MSP — frame on Secure MSP at handler entry.
        // The compiler's stack pointer differs by whatever Rust pushed; use
        // the assembly-passed _sp argument as a best-effort.
        _sp
    };

    print_str("\r\n[SecureFault] EXC_RETURN=0x"); print_hex(exc_return);
    if from_ns { print_str(" (from NS)"); } else { print_str(" (from S)"); }
    if use_psp { print_str(" PSP\r\n"); } else { print_str(" MSP\r\n"); }
    print_str("Frame@0x"); print_hex(frame_sp); print_str(":\r\n");
    let frame = frame_sp as *const u32;
    let labels = ["R0  ", "R1  ", "R2  ", "R3  ", "R12 ", "LR  ", "PC  ", "xPSR"];
    let mut i: usize = 0;
    while i < 8 {
        print_str(labels[i]);
        print_str(": 0x");
        print_hex(frame.add(i).read_volatile());
        print_str("\r\n");
        i += 1;
    }
    print_str("SFSR: 0x"); print_hex(sfsr); print_str("\r\n");
    print_str("SFAR: 0x"); print_hex(sfar); print_str("\r\n");
    // NS-side fault status (whatever caused the escalation lives here).
    print_str("NS_CFSR: 0x"); print_hex(ptr::read_volatile(0xE002ED28 as *const u32)); print_str("\r\n");
    print_str("NS_HFSR: 0x"); print_hex(ptr::read_volatile(0xE002ED2C as *const u32)); print_str("\r\n");
    loop { core::hint::spin_loop(); }
}

#[no_mangle]
pub unsafe extern "C" fn umbra_bus_fault_handler(sp: u32) {
    save_fault_to_sram(sp, 4); // 4 = BusFault
    let cfsr = ptr::read_volatile(SCB_CFSR);
    dump_stack_frame(sp, "BusFault");
    print_str("CFSR: 0x"); print_hex(cfsr); print_str("\r\n");
    loop { core::hint::spin_loop(); }
}

/// UsageFault dispatcher — ESS-miss demand-paging entry point.
///
/// Three sub-types matter:
///   UNDEFINSTR (UFSR bit 0) — UDF-filled block reached the decoder. The
///                              dispatcher synthetically "loads" the block
///                              with recovery code and signals RECOVER so
///                              the assembly trampoline resumes the enclave
///                              at the same PC (now valid).
///   INVSTATE   (UFSR bit 1) — `bx lr` against sentinel LR=0xFFFFFFFF.
///                              End-of-task; route to Terminated.
///   *other*                 — genuine fault; route to Faulted.
///
/// Return value:
///   0          — RECOVER (trampoline restores EXC_RETURN, resumes enclave)
///   non-zero   — TERMINATE (trampoline writes the encoded status to the
///                MSP frame's r0 slot and returns to umbra_enclave_enter_imp)
#[no_mangle]
pub unsafe extern "C" fn umbra_usage_fault_dispatch(psp: u32) -> u32 {
    use kernel::common::enclave::EnclaveState;

    let cfsr_ptr = SCB_CFSR;
    let cfsr_val = ptr::read_volatile(cfsr_ptr);
    let ufsr = (cfsr_val >> 16) as u16;
    let is_undefinstr = (ufsr & 0x01) != 0;
    let is_invstate   = (ufsr & 0x02) != 0;

    if is_undefinstr {
        let frame = psp as *const u32;
        let stacked_pc = ptr::read_volatile(frame.add(6));
        if let Some(kernel) = crate::secure_kernel::Kernel::get() {
            if let Some((enclave_id, block_idx)) = kernel.lookup_faulting_block(stacked_pc) {
                // Pull the enclave's flash_base + ess_base out of the
                // LoadedEnclave entry, mark the block as loaded, then call
                // load_block_n657 below. Recovery is unconditional for any
                // UNDEFINSTR with a valid block lookup; chained-measurement
                // validation is not yet wired into this path.
                let mut load_args: Option<(u32, u32)> = None; // (ess_base, flash_base)
                for slot in kernel.ess.loaded_enclaves.iter_mut() {
                    if let Some(le) = slot {
                        if le.descriptor.id == enclave_id {
                            load_args = Some((le.start_address, le.descriptor.flash_base));
                            le.efbs[block_idx as usize].is_loaded = true;
                            break;
                        }
                    }
                }
                if let Some((ess_base, flash_base)) = load_args {
                    // MPU region 5 was configured RO (AP=11). Flip to AP=00
                    // (priv RW + unpriv no access) while we copy the block
                    // from flash, then restore AP=11 before resuming the
                    // unprivileged enclave so its code stays RO.
                    let mpu_rnr  = MPU_RNR;
                    let mpu_rbar = MPU_RBAR;
                    ptr::write_volatile(mpu_rnr, 5);
                    let saved_rbar = ptr::read_volatile(mpu_rbar);
                    ptr::write_volatile(mpu_rbar, saved_rbar & !0x06); // AP=00
                    cortex_m::asm::dsb();
                    cortex_m::asm::isb();

                    // CPU-copy from XSPI2 at the block's flash address into
                    // the enclave's ESS slot.
                    let load_result = kernel.load_block_n657(block_idx, ess_base, flash_base);

                    // Restore AP=11 (RO) and invalidate I-cache so the
                    // newly-loaded instructions are fetched from memory.
                    cortex_m::asm::dsb();
                    ptr::write_volatile(mpu_rbar, saved_rbar);
                    ptr::write_volatile(ICIALLU, 0);
                    cortex_m::asm::dsb();
                    cortex_m::asm::isb();

                    if load_result.is_err() {
                        return usage_fault_terminate(psp, EnclaveState::Faulted);
                    }

                    print_str("[ESS-MISS] block ");
                    print_hex(block_idx);
                    print_str(" loaded from flash\r\n");

                    // Clear UFSR.UNDEFINSTR (write-1-to-clear at CFSR bit 16)
                    ptr::write_volatile(cfsr_ptr, 1 << 16);
                    return 0; // RECOVER
                }
            }
        }
        return usage_fault_terminate(psp, EnclaveState::Faulted);
    }

    if is_invstate {
        return usage_fault_terminate(psp, EnclaveState::Terminated);
    }

    usage_fault_terminate(psp, EnclaveState::Faulted)
}

/// Common terminate path — clears the entire UFSR, stamps the enclave context
/// with the final state and result, disables SysTick, and encodes the
/// (enclave_id, state, result) triple expected by `umbra_enclave_enter_imp`.
unsafe fn usage_fault_terminate(
    psp: u32,
    state: kernel::common::enclave::EnclaveState,
) -> u32 {
    use kernel::common::enclave::EnclaveContext;

    // UFSR occupies CFSR bits [31:16]; clear every sub-type that may be set.
    let cfsr_ptr = SCB_CFSR;
    ptr::write_volatile(cfsr_ptr, 0xFFFF_0000);

    let ctx_ptr = crate::secure_kernel::CURRENT_ENCLAVE_CTX_PTR as *mut EnclaveContext;
    if ctx_ptr.is_null() {
        return 0xFF;
    }
    let ctx = &mut *ctx_ptr;
    ctx.status = state;

    // Capture R0 from the stacked exception frame — the enclave's return
    // value when it executed `bx lr` against the sentinel.
    let frame = psp as *const u32;
    let result = ptr::read_volatile(frame.add(0));
    ctx.result = result;

    let kernel = match crate::secure_kernel::Kernel::get() {
        Some(k) => k,
        None => return 0xFF,
    };
    kernel.disable_systick();
    let enclave_id = kernel.current_enclave_id.unwrap_or(0);

    ((enclave_id & 0xFFFF) << 16)
        | ((state as u32 & 0xFF) << 8)
        | (result & 0xFF)
}

#[no_mangle]
pub extern "C" fn umbra_usage_fault_handler(sp: u32) {
    dump_stack_frame(sp, "UsageFault");
    loop { core::hint::spin_loop(); }
}

#[no_mangle]
pub extern "C" fn umbra_debug_mon_handler(_sp: u32) {
    print_str("\r\n[DebugMon] Handler Called\r\n");
    loop { core::hint::spin_loop(); }
}

#[no_mangle]
pub extern "C" fn umbra_pendsv_handler(_sp: u32) {
}

/// SysTick preemption tail.
///
/// Called from `_umb_SysTick_Handler` after `save_enclave_context` has
/// stashed r4-r11/PSP/EXC_RETURN/CONTROL into the EnclaveContext. We mark
/// the enclave Suspended, disable SysTick (so non-running code isn't
/// preempted), and return the encoded status the caller's `inout("r0")`
/// in `umbra_enclave_enter_imp` reads back.
#[no_mangle]
pub extern "C" fn umbra_systick_handler(ctx_ptr: *mut u8) -> u32 {
    use kernel::common::enclave::{EnclaveContext, EnclaveState};

    if ctx_ptr.is_null() {
        return 0;
    }

    let ctx = unsafe { &mut *(ctx_ptr as *mut EnclaveContext) };
    ctx.status = EnclaveState::Suspended;

    let kernel = unsafe {
        match crate::secure_kernel::Kernel::get() {
            Some(k) => k,
            None => return 0,
        }
    };
    unsafe { kernel.disable_systick(); }

    let enclave_id = kernel.current_enclave_id.unwrap_or(0);
    ((enclave_id & 0xFFFF) << 16) | ((EnclaveState::Suspended as u32 & 0xFF) << 8)
}

#[no_mangle]
pub extern "C" fn umbra_yield_handler(_ctx_ptr: *mut u8) -> u32 {
    0
}
