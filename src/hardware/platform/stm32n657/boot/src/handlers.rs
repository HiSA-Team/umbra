//! Exception handlers for STM32N657 Secure Boot.
//! All handlers referenced by the shared startup.s must be defined here so
//! the linker resolves the symbols. Fault paths emit a register dump over
//! the secure UART; ESS-miss recovery uses the UsageFault dispatcher below.
//! # Stack-frame access pattern (mirrors L552)
//! Hardware-stacked frame (R0-R3, R12, LR, PC, xPSR) is the only state
//! visible to a Rust handler. R4-R11 are unavailable unless the asm
//! trampoline explicitly pushed them and handed the pointer in; the
//! diagnostic path uses `save_fault_to_sram(sp, kind)` for the post-mortem
//! dump that survives a SecureFault-while-printing.
//! # ESS-miss recovery contract
//! The N657 protection controllers are RIF / RISAF (instead of MPCBB on
//! L552), but the recovery sequence shape is the same:
//! 1. Drop the target region's RISAF watermark / RIFSC bit so the DMA
//! via the NS alias is not silently dropped.
//! 2. DMA from XSPI2 (encrypted flash) into the slot.
//! 3. AES decrypt + chained-measurement validation.
//! 4. Re-raise the RISAF / RIFSC bit + `ICIALLU; DSB; ISB`.
//! 5. Exception return reruns the faulting instruction.
//! D-cache maintenance is heavier than on L552: the M55 has DCache and
//! requires `DCCMVAC` (clean-by-VA) + `DCIMVAC` (invalidate-by-VA) on the
//! buffer windows that DMA writes — see `cryp.rs` and the HPDMA notes for
//! the per-line offsets and the alignment requirement.

use crate::raw_print::{print_hex, print_str};
use arm::mmio::{
    ICIALLU, MPU_RBAR, MPU_RNR, SCB_BFAR, SCB_CFSR, SCB_HFSR, SCB_MMFAR, SCB_SFAR, SCB_SFSR,
    SCB_VTOR,
};
use core::ptr;
use core::sync::atomic::AtomicU32;

/// Non-zero while the FSBL oracle is running. The asm `_umb_SysTick_Handler`
/// reads this flag and takes an early-return path (kick IWDG only, skip
/// enclave preempt logic) when it is set, so the oracle's stacked R0 isn't
/// clobbered by the enclave-preempt write at `sp+32`.
/// AtomicU32 (not AtomicBool) because the asm reads it as a plain 32-bit
/// word via `ldr`; a layout-stable u32 is the safest contract.
#[no_mangle]
pub static IN_ORACLE: AtomicU32 = AtomicU32::new(0);

/// Save fault registers to AXISRAM1 @ 0x340F0000 so they survive watchdog reset.
/// Read after reset via: monitor mdw 0x340F0000 12
unsafe fn save_fault_to_sram(sp: u32, fault_id: u32) {
    let save = 0x340F_0000 as *mut u32;
    save.add(0).write_volatile(0xDEAD_BEEF); // magic
    save.add(1).write_volatile(fault_id); // which handler
    save.add(2).write_volatile(ptr::read_volatile(SCB_CFSR));
    save.add(3).write_volatile(ptr::read_volatile(SCB_HFSR));
    save.add(4).write_volatile(ptr::read_volatile(SCB_SFSR));
    save.add(5).write_volatile(ptr::read_volatile(SCB_MMFAR));
    save.add(6).write_volatile(ptr::read_volatile(SCB_BFAR));
    save.add(7).write_volatile(sp); // SP
    let frame = sp as *const u32;
    save.add(8).write_volatile(frame.add(5).read_volatile()); // stacked LR
    save.add(9).write_volatile(frame.add(6).read_volatile()); // stacked PC
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
    let regs: [&str; 8] = [
        "R0  ", "R1  ", "R2  ", "R3  ", "R12 ", "LR  ", "PC  ", "xPSR",
    ];
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
    unsafe {
        save_fault_to_sram(sp, 1);
    } // 1 = HardFault
    print_str("\r\nHF ");
    unsafe {
        let frame = sp as *const u32;
        print_hex(exc_return);
        print_str(" ");
        // Stacked frame (S or NS depending on EXC_RETURN.S bit).
        print_hex(frame.add(6).read_volatile());
        print_str(" "); // PC
        print_hex(frame.add(7).read_volatile());
        print_str(" "); // xPSR
        print_hex(frame.add(0).read_volatile());
        print_str(" "); // R0
                        // Secure-side fault status: SFSR, SFAR, CFSR, HFSR.
        print_hex(ptr::read_volatile(SCB_SFSR));
        print_str(" ");
        print_hex(ptr::read_volatile(SCB_SFAR));
        print_str(" ");
        print_hex(ptr::read_volatile(SCB_CFSR));
        print_str(" ");
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
        print_hex(ptr::read_volatile(0xE002ED28 as *const u32));
        print_str(" "); // NS_CFSR
        print_hex(ptr::read_volatile(0xE002ED2C as *const u32));
        print_str(" "); // NS_HFSR
        print_hex(ptr::read_volatile(0xE002ED34 as *const u32));
        print_str(" "); // NS_MMFAR
        print_hex(ptr::read_volatile(0xE002ED38 as *const u32)); // NS_BFAR
    }
    print_str("\r\n");
    kernel::common::panic_policy::handle_fault();
}

#[no_mangle]
pub extern "C" fn umbra_nmi_handler(sp: u32) {
    dump_stack_frame(sp, "NMI");
    kernel::common::panic_policy::handle_fault();
}

/// MemManage fault handler — enclave-termination path.
/// Recognises the end-of-task sentinel: an enclave launched with
/// LR = 0xFFFFFFFF that runs its final `bx lr` jumps to 0xFFFFFFFE, which
/// raises IACCVIOL on the unprivileged instruction fetch (no MPU region
/// covers 0xFFFFFFFE for unprivileged accesses). Returning a non-zero
/// encoded status causes the assembly trampoline to short-circuit back to
/// `umbra_enclave_enter_imp` with the result in r0.
/// Anything else here is unrecoverable from a MemManage perspective: dump
/// the frame and halt for diagnosis. (ESS-miss demand-paging is handled by
/// the UsageFault dispatcher, not here.)
#[no_mangle]
pub unsafe extern "C" fn umbra_mem_manage_handler(psp: u32) -> u32 {
    use kernel::common::enclave::EnclaveState;

    let cfsr_ptr = SCB_CFSR;
    let cfsr_val = ptr::read_volatile(cfsr_ptr);
    let mmfsr = (cfsr_val & 0xFF) as u8;

    // MPU eviction restore (Phase 2b probe): a MemManage on a hidden (evicted) block —
    // data load OR instruction fetch — is recoverable. Restore region 5 and resume.
    // LANDMINE: a DATA fault (DACCVIOL) sets MMFAR (MMARVALID); an instruction fetch fault
    // (IACCVIOL) does NOT — its address is the STACKED PC in the exception frame.
    #[cfg(feature = "mpu_evict_probe")]
    {
        let fault_addr = if (mmfsr & 0x02) != 0 && (mmfsr & 0x80) != 0 {
            ptr::read_volatile(SCB_MMFAR) // DACCVIOL → MMFAR
        } else if (mmfsr & 0x01) != 0 {
            ptr::read_volatile((psp as *const u32).add(6)) // IACCVIOL → stacked PC
        } else {
            0
        };
        if fault_addr != 0 && crate::prefetch::mpu_evict::restore(fault_addr) {
            print_str("[MPU-EVICT] restore @0x");
            print_hex(fault_addr);
            print_str("\r\n");
            ptr::write_volatile(cfsr_ptr, mmfsr as u32); // W1C the MMFSR sub-bits
            return 0; // RECOVER — the faulting instruction re-executes
        }
    }

    // Async ESS-miss (demonstrator): the enclave outran the async prefetch and reached the
    // hidden tail — restore it synchronously from the backing and reveal. Same DACCVIOL→MMFAR /
    // IACCVIOL→stacked-PC address rule as the MPU-evict probe above.
    #[cfg(feature = "async_ess_miss")]
    {
        let fault_addr = if (mmfsr & 0x02) != 0 && (mmfsr & 0x80) != 0 {
            ptr::read_volatile(SCB_MMFAR) // DACCVIOL → MMFAR
        } else if (mmfsr & 0x01) != 0 {
            ptr::read_volatile((psp as *const u32).add(6)) // IACCVIOL → stacked PC
        } else {
            0
        };
        if fault_addr != 0 && crate::prefetch::async_ess::on_fault(fault_addr) {
            print_str("[ASYNC-ESS] sync restore @0x");
            print_hex(fault_addr);
            print_str("\r\n");
            ptr::write_volatile(cfsr_ptr, mmfsr as u32); // W1C the MMFSR sub-bits
            return 0; // RECOVER — the faulting instruction re-executes
        }
    }

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
    print_str("CFSR: 0x");
    print_hex(cfsr_val);
    print_str("\r\n");
    kernel::common::panic_policy::handle_fault();
}

/// SecureFault handler — diagnostic dump (both Secure and NS sides).
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

    print_str("\r\n[SecureFault] EXC_RETURN=0x");
    print_hex(exc_return);
    if from_ns {
        print_str(" (from NS)");
    } else {
        print_str(" (from S)");
    }
    if use_psp {
        print_str(" PSP\r\n");
    } else {
        print_str(" MSP\r\n");
    }
    print_str("Frame@0x");
    print_hex(frame_sp);
    print_str(":\r\n");
    let frame = frame_sp as *const u32;
    let labels = [
        "R0  ", "R1  ", "R2  ", "R3  ", "R12 ", "LR  ", "PC  ", "xPSR",
    ];
    let mut i: usize = 0;
    while i < 8 {
        print_str(labels[i]);
        print_str(": 0x");
        print_hex(frame.add(i).read_volatile());
        print_str("\r\n");
        i += 1;
    }
    print_str("SFSR: 0x");
    print_hex(sfsr);
    print_str("\r\n");
    print_str("SFAR: 0x");
    print_hex(sfar);
    print_str("\r\n");
    // NS-side fault status (whatever caused the escalation lives here).
    print_str("NS_CFSR: 0x");
    print_hex(ptr::read_volatile(0xE002ED28 as *const u32));
    print_str("\r\n");
    print_str("NS_HFSR: 0x");
    print_hex(ptr::read_volatile(0xE002ED2C as *const u32));
    print_str("\r\n");
    kernel::common::panic_policy::handle_fault();
}

#[no_mangle]
pub unsafe extern "C" fn umbra_bus_fault_handler(sp: u32) {
    save_fault_to_sram(sp, 4); // 4 = BusFault
    let cfsr = ptr::read_volatile(SCB_CFSR);
    dump_stack_frame(sp, "BusFault");
    print_str("CFSR: 0x");
    print_hex(cfsr);
    print_str("\r\n");
    kernel::common::panic_policy::handle_fault();
}

/// UsageFault dispatcher — ESS-miss demand-paging entry point.
/// Three sub-types matter:
/// UNDEFINSTR (UFSR bit 0) — UDF-filled block reached the decoder. The
/// dispatcher synthetically "loads" the block
/// with recovery code and signals RECOVER so
/// the assembly trampoline resumes the enclave
/// at the same PC (now valid).
/// INVSTATE (UFSR bit 1) — `bx lr` against sentinel LR=0xFFFFFFFF.
/// End-of-task; route to Terminated.
/// *other* — genuine fault; route to Faulted.
/// Return value:
/// 0 — RECOVER (trampoline restores EXC_RETURN, resumes enclave)
/// non-zero — TERMINATE (trampoline writes the encoded status to the
/// MSP frame's r0 slot and returns to umbra_enclave_enter_imp)
#[no_mangle]
pub unsafe extern "C" fn umbra_usage_fault_dispatch(psp: u32) -> u32 {
    use kernel::common::enclave::EnclaveState;

    let cfsr_ptr = SCB_CFSR;
    let cfsr_val = ptr::read_volatile(cfsr_ptr);
    let ufsr = (cfsr_val >> 16) as u16;
    let is_undefinstr = (ufsr & 0x01) != 0;
    let is_invstate = (ufsr & 0x02) != 0;

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
                            // CJ3 + integrity guard: `block_idx` comes
                            // from `lookup_faulting_block`, which computes
                            // `(pc - base) / CODE_BLOCK_SIZE`. With the
                            // checked-mul wrap fixed in `lookup_faulting_block`
                            // the result is bounded by `le.efb_count`, but a
                            // regression in either place would index past
                            // `MAX_EFBS` and panic. Guard against both upper
                            // bounds before the mutable indexing. Mirrors the
                            // L552 `secure_kernel/exit.rs` `MAX_EFBS` pattern.
                            let bi = block_idx as usize;
                            if bi < kernel::common::ess::MAX_EFBS && bi < le.efb_count {
                                le.efbs[bi].is_loaded = true;
                            }
                            break;
                        }
                    }
                }
                if let Some((ess_base, flash_base)) = load_args {
                    // MPU region 5 was configured RO (AP=11). Flip to AP=00
                    // (priv RW + unpriv no access) while we copy the block
                    // from flash, then restore AP=11 before resuming the
                    // unprivileged enclave so its code stays RO.
                    let mpu_rnr = MPU_RNR;
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
unsafe fn usage_fault_terminate(psp: u32, state: kernel::common::enclave::EnclaveState) -> u32 {
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

    // NB: the terminated enclave's EFBC window + slot are NOT freed here — the NS
    // host still reads its result via `umbra_enclave_status` (which looks the id up
    // in `loaded_enclaves`) AFTER terminate, so the slot must stay live until then.
    // The freeing is done lazily at the next `enclave_create` (reap terminated
    // enclaves before allocating). See `umbra_enclave_create_imp`.

    // Done enclave: invalidate its checkpoint so a later reset starts a fresh run.
    drivers::state_anchor::StateAnchor::new().invalidate();

    ((enclave_id & 0xFFFF) << 16) | ((state as u32 & 0xFF) << 8) | (result & 0xFF)
}

#[no_mangle]
pub extern "C" fn umbra_usage_fault_handler(sp: u32) {
    dump_stack_frame(sp, "UsageFault");
    kernel::common::panic_policy::handle_fault();
}

#[no_mangle]
pub extern "C" fn umbra_debug_mon_handler(_sp: u32) {
    print_str("\r\n[DebugMon] Handler Called\r\n");
    kernel::common::panic_policy::handle_fault();
}

/// PendSV: the deferred install tail of the async prefetch pipeline. Runs at the lowest
/// priority — outside the enclave/SysTick execution window — so the cache-maintenance
/// window never overlaps unprivileged enclave code (mirrors the L552 G3 design).
#[no_mangle]
pub extern "C" fn umbra_pendsv_handler(_sp: u32) {
    crate::prefetch::on_pendsv();
}

/// HPDMA1 channel-2 TC IRQ (IRQn = 70): a background prefetch DMA completed. Clears the
/// channel flags and sets PendSV pending to defer the install.
#[no_mangle]
pub extern "C" fn HPDMA1_Channel2_Handler() {
    crate::prefetch::on_dma_complete();
}

/// HASH peripheral IRQ (HASH_IRQn = 39): SHA-256 digest-complete (DCIS). Posts the
/// completion flag so `Hash::sha256`'s interrupt-driven wait proceeds. Priority is
/// raised above SVC (see `crypto_wait::hash_irq_setup`) so this preempts the SVC#2
/// checkpoint handler where the hot-path digests run.
#[no_mangle]
pub extern "C" fn HASH_IRQHandler() {
    drivers::crypto_wait::on_hash_irq();
}

/// SysTick preemption tail.
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

    // Phase 4.2 overlay scheduler: round-robin to the next RUNNABLE enclave, switch the EFBC
    // window (evict current -> its backing, restore next <- its backing) AND the CPU context,
    // then tell the asm to RESUME that enclave — preemption itself drives the A<->B alternation,
    // the host no longer has to. We tag the returned EnclaveContext pointer with bit 0 (pointers
    // are 4-aligned) so the asm can tell "resume this ctx" from "return this status to the host".
    // If no OTHER enclave is runnable, fall through to the return-to-host path (default build).
    #[cfg(feature = "interenclave_overlay")]
    {
        let cur_id = kernel.current_enclave_id.unwrap_or(0);
        let slots = kernel.ess.loaded_enclaves.len();
        let mut cur_slot = None;
        for i in 0..slots {
            if let Some(le) = &kernel.ess.loaded_enclaves[i] {
                if le.descriptor.id == cur_id {
                    cur_slot = Some(i);
                    break;
                }
            }
        }
        if let Some(cs) = cur_slot {
            for off in 1..slots {
                let ns = (cs + off) % slots;
                let runnable = kernel.ess.loaded_enclaves[ns].is_some()
                    && matches!(
                        kernel.enclave_contexts[ns].status,
                        EnclaveState::Ready | EnclaveState::Suspended
                    );
                if !runnable {
                    continue;
                }
                let next_id = kernel.ess.loaded_enclaves[ns]
                    .as_ref()
                    .map(|le| le.descriptor.id)
                    .unwrap_or(0);
                // Rate-limited state-continuity checkpoint of the OUTGOING enclave. A checkpoint is
                // an XSPI2 flash write (slow + wear), so it CANNOT run on every ~1 ms switch — bound
                // it to at most one per CKPT_EVERY switches. Kernel-driven: no enclave svc #2 needed.
                // Safe from this handler because HASH (IRQ prio 0x00) preempts SysTick (0x40) so the
                // digest completes; the flash write polls. Runs while `cs` is still resident (its PSP
                // stack + `ctx`, saved with status=Suspended above, are the snapshot source).
                {
                    use core::sync::atomic::{AtomicU32, Ordering};
                    const CKPT_EVERY: u32 = 16; // ponytail: fixed cadence; tune if the flash wall bites
                    static CKPT_TICK: AtomicU32 = AtomicU32::new(0);
                    if CKPT_TICK.fetch_add(1, Ordering::Relaxed) % CKPT_EVERY == 0 {
                        let state_root = kernel.state_root;
                        let ok = crate::secure_kernel::state_checkpoint::checkpoint_enclave(
                            cur_id, cs, &*ctx, &state_root,
                        );
                        crate::raw_print::print_str(if ok {
                            "[SC] overlay checkpoint (evict)\r\n"
                        } else {
                            "[SC] overlay checkpoint FAIL\r\n"
                        });
                    }
                }
                // window switch: evict current -> backing[cs], restore next <- backing[ns].
                unsafe {
                    crate::prefetch::overlay::make_resident(
                        ns,
                        kernel::common::ess::ESS_BASE,
                        false,
                    );
                    // reprogram the incoming enclave's per-enclave MPU regions (stack + code),
                    // else the exception-return unstacking from its PSP faults MemManage.
                    crate::api_impl::overlay_reconfigure_mpu(kernel, ns);
                }
                kernel.enclave_contexts[ns].status = EnclaveState::Running;
                kernel.current_enclave_id = Some(next_id);
                let nptr = &mut kernel.enclave_contexts[ns] as *mut EnclaveContext as u32;
                unsafe {
                    crate::secure_kernel::CURRENT_ENCLAVE_CTX_PTR = nptr as *mut u8;
                }
                return nptr | 1; // bit0 tag = "resume this context" (asm strips it)
            }
        }
        // no other runnable enclave -> return to host (fall through).
    }

    unsafe {
        kernel.disable_systick();
    }

    let enclave_id = kernel.current_enclave_id.unwrap_or(0);
    ((enclave_id & 0xFFFF) << 16) | ((EnclaveState::Suspended as u32 & 0xFF) << 8)
}

/// SVC#2 per-block checkpoint. `save_enclave_context` has just written the live enclave
/// context (PC right after `svc #2`) to `CURRENT_ENCLAVE_CTX_PTR`; checkpoint it and
/// return — the asm resumes the enclave (transparent save-and-continue).
#[no_mangle]
pub extern "C" fn umbra_checkpoint_handler() {
    use kernel::common::enclave::{EnclaveContext, EnclaveState};

    let ctx_ptr =
        unsafe { crate::secure_kernel::CURRENT_ENCLAVE_CTX_PTR } as *const EnclaveContext;
    if ctx_ptr.is_null() {
        return;
    }
    let kernel = unsafe {
        match crate::secure_kernel::Kernel::get() {
            Some(k) => k,
            None => return,
        }
    };
    let ctx_base = kernel.enclave_contexts.as_ptr() as usize;
    let idx = (ctx_ptr as usize).wrapping_sub(ctx_base) / core::mem::size_of::<EnclaveContext>();
    if idx >= kernel.enclave_contexts.len() {
        return;
    }
    let enclave_id = kernel.current_enclave_id.unwrap_or(0);

    // Snapshot with status=Suspended (so restore/enter resume it); the live context
    // stays Running so the enclave continues after the svc. ptr::read = bitwise copy.
    let mut snap = unsafe { core::ptr::read(ctx_ptr) };
    snap.status = EnclaveState::Suspended;
    let state_root = kernel.state_root;
    let ok = crate::secure_kernel::state_checkpoint::checkpoint_enclave(
        enclave_id,
        idx,
        &snap,
        &state_root,
    );
    crate::raw_print::print_str(if ok {
        "[SC] block checkpoint\r\n"
    } else {
        "[SC] block checkpoint FAIL\r\n"
    });

    // DEV-ONLY: pause at the FIRST cold checkpoint (gen==1) so the resume across a
    // reset is observable by hand. gen>=2 on a resumed run, so it fires once.
    #[cfg(feature = "checkpoint_reset_demo")]
    {
        use kernel::key_storage_server::state_checkpoint::AnchorStore;
        let gen = drivers::state_anchor::StateAnchor::new()
            .load()
            .map(|a| a.generation)
            .unwrap_or(0);
        if gen == 1 {
            crate::raw_print::print_str(
                "[SC] cold checkpoint (gen=1) — press RST to resume across the reset\r\n",
            );
            loop {
                cortex_m::asm::wfi();
            }
        }
    }
}
