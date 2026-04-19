
use core::ptr;

// Shared UART base address — single source of truth for raw-pointer UART
// access in exception handlers and API implementations.
#[cfg(feature = "stm32l562")]
pub const RAW_UART_BASE: u32 = 0x40013800; // USART1
#[cfg(not(feature = "stm32l562"))]
pub const RAW_UART_BASE: u32 = 0x50008000; // LPUART1

const RAW_UART_ISR_OFFSET: u32 = 0x1C;
const RAW_UART_TDR_OFFSET: u32 = 0x28;

// Helper function to print hex values to UART
// We use raw pointer access to LPUART1/USART1 to avoid borrowing issues in exception handlers
#[inline(never)]
pub fn print_hex(val: u32) {
    let hex = b"0123456789ABCDEF";
    unsafe {
        let uart_base = RAW_UART_BASE as *mut u32;
        let tdr_ptr = uart_base.add(RAW_UART_TDR_OFFSET as usize / 4);
        let isr_ptr = uart_base.add(RAW_UART_ISR_OFFSET as usize / 4);

        for i in (0..8).rev() {
            let nibble = (val >> (i * 4)) & 0xF;
            let c = hex[nibble as usize];
            while (isr_ptr.read_volatile() & (1 << 7)) == 0 {}
            tdr_ptr.write_volatile(c as u32);
        }
    }
}

#[inline(never)]
pub fn print_str(s: &str) {
    unsafe {
        let uart_base = RAW_UART_BASE as *mut u32;
        let tdr_ptr = uart_base.add(RAW_UART_TDR_OFFSET as usize / 4);
        let isr_ptr = uart_base.add(RAW_UART_ISR_OFFSET as usize / 4);

        for byte in s.bytes() {
            while (isr_ptr.read_volatile() & (1 << 7)) == 0 {}
            tdr_ptr.write_volatile(byte as u32);
        }
    }
}

/// Print a byte slice as lowercase hex via the raw UART.
#[inline(never)]
pub fn print_hex_bytes(data: &[u8]) {
    let hex = b"0123456789abcdef";
    unsafe {
        let uart_base = RAW_UART_BASE as *mut u32;
        let tdr_ptr = uart_base.add(RAW_UART_TDR_OFFSET as usize / 4);
        let isr_ptr = uart_base.add(RAW_UART_ISR_OFFSET as usize / 4);
        for &byte in data {
            let hi = hex[((byte >> 4) & 0xF) as usize];
            let lo = hex[(byte & 0xF) as usize];
            while (isr_ptr.read_volatile() & (1 << 7)) == 0 {}
            tdr_ptr.write_volatile(hi as u32);
            while (isr_ptr.read_volatile() & (1 << 7)) == 0 {}
            tdr_ptr.write_volatile(lo as u32);
        }
    }
}

// Common function to dump stack frame
fn dump_stack_frame(sp: u32, exception_name: &str) {
    print_str("\n[");
    print_str(exception_name);
    print_str("] Handler Reached!\n");

    print_str("Test Stack Pointer (R0): 0x");
    print_hex(sp);
    print_str("\n");

    // Dump Stack Frame
    // Stack Frame: R0, R1, R2, R3, R12, LR, PC, xPSR
    let frame_ptr = sp as *const u32;
    let regs = ["R0  ", "R1  ", "R2  ", "R3  ", "R12 ", "LR  ", "PC  ", "xPSR"];
    
    for i in 0..8 {
        print_str(regs[i]);
        print_str(": 0x");
        unsafe {
            let val = frame_ptr.add(i).read_volatile();
            print_hex(val);
        }
        print_str("\n");
    }
}

#[no_mangle]
pub extern "C" fn umbra_hard_fault_handler(sp: u32, exc_return: u32) {
    // Order: LR(exc_return) PC xPSR R0 SFSR SFAR CFSR HFSR
    print_str("\nHF ");
    unsafe {
        let frame = sp as *const u32;
        print_hex(exc_return);                                 print_str(" ");
        print_hex(frame.add(6).read_volatile());               print_str(" ");
        print_hex(frame.add(7).read_volatile());               print_str(" ");
        print_hex(frame.add(0).read_volatile());               print_str(" ");
        print_hex(ptr::read_volatile(0xE000EDE4 as *const u32)); print_str(" ");
        print_hex(ptr::read_volatile(0xE000EDE8 as *const u32)); print_str(" ");
        print_hex(ptr::read_volatile(0xE000ED28 as *const u32)); print_str(" ");
        print_hex(ptr::read_volatile(0xE000ED2C as *const u32));
    }
    print_str("\n");
    loop {}
}

#[no_mangle]
pub extern "C" fn umbra_nmi_handler(sp: u32) {
    dump_stack_frame(sp, "NMI");
    loop {}
}

/// MemManage fault handler. Three cases:
///
///   IACCVIOL @ PC=0xFFFFFFFE — normal end-of-task sentinel. Enclaves are
///                              launched with LR=0xFFFFFFFF; the final
///                              `bx lr` in thread mode jumps to 0xFFFFFFFE
///                              (Thumb bit stripped), an instruction fetch
///                              into unmapped space. Route to the terminate
///                              path so `umbra_enclave_enter_imp` sees
///                              `EnclaveState::Terminated`.
///   IACCVIOL  (bit 0)        — instruction fetch violation; faulting address
///                              is the stacked PC (MMFAR is NOT updated).
///   DACCVIOL  (bit 1)        — data access violation (e.g. literal-pool load
///                              across a block boundary); MMFAR holds the
///                              faulting address when MMARVALID (bit 7) is set.
///
/// Both violation sub-types are dispatched to `Kernel::handle_ess_miss` so
/// enclave code with cross-block literal pools works transparently.
///
/// Return value (consumed by the asm trampoline in `startup.rs`):
///   * `0`      — RECOVER: trampoline restores the original EXC_RETURN and
///                resumes the enclave (re-runs the faulting instruction).
///   * non-zero — TERMINATE: trampoline stores the value into the SVC-entry
///                stacked r0 slot on MSP so `umbra_enclave_enter_imp` sees
///                it as the encoded status.
#[no_mangle]
pub unsafe extern "C" fn umbra_mem_manage_handler(psp: u32) -> u32 {
    use kernel::common::enclave::EnclaveState;

    let cfsr = 0xE000ED28 as *mut u32;
    let cfsr_val = ptr::read_volatile(cfsr);
    let mmfsr = (cfsr_val & 0xFF) as u8;

    let is_iaccviol  = (mmfsr & 0x01) != 0;
    let is_daccviol  = (mmfsr & 0x02) != 0;
    let mmar_valid   = (mmfsr & 0x80) != 0;

    if !is_iaccviol && !(is_daccviol && mmar_valid) {
        panic_dump(psp, cfsr_val, "MemManage: unrecoverable");
    }

    // Read stacked PC up front — needed both for the end-of-task sentinel
    // check and for IACCVIOL fault-address lookup.
    let frame = psp as *const u32;
    let raw_pc = if is_iaccviol { ptr::read_volatile(frame.add(6)) } else { 0 };

    // End-of-task sentinel: LR=0xFFFFFFFF → `bx lr` jumps to 0xFFFFFFFE.
    if raw_pc == 0xFFFF_FFFE {
        ptr::write_volatile(cfsr, mmfsr as u32);
        return usage_fault_terminate(psp, EnclaveState::Terminated);
    }

    // IACCVIOL: faulting address = stacked PC.
    // DACCVIOL: faulting address = MMFAR register.
    // Normalize Secure alias bit (0x30xxxxxx → 0x20xxxxxx) so the
    // `lookup_faulting_block` match against the NS-aliased start_address
    // succeeds regardless of which alias the enclave was executing from.
    let fault_addr = if is_iaccviol {
        raw_pc & !0x1000_0000u32
    } else {
        let mmfar = 0xE000ED34 as *const u32;
        ptr::read_volatile(mmfar) & !0x1000_0000u32
    };

    #[cfg(feature = "ess_miss_recovery")]
    {
        let kernel = match crate::secure_kernel::Kernel::get() {
            Some(k) => k,
            None    => panic_dump(psp, cfsr_val, "MemManage: no kernel"),
        };
        let (enclave_id, block_idx) = match kernel.lookup_faulting_block(fault_addr) {
            Some(pair) => pair,
            None       => panic_dump(psp, cfsr_val, "MemManage: addr outside any enclave"),
        };
        let mut dma = match drivers::dma::Dma::new() {
            Some(d) => d,
            None    => panic_dump(psp, cfsr_val, "MemManage: DMA unavailable"),
        };
        if kernel.handle_ess_miss(enclave_id, block_idx, &mut dma, true).is_err() {
            panic_dump(psp, cfsr_val, "MemManage: handle_ess_miss failed");
        }
        ptr::write_volatile(cfsr, mmfsr as u32);
        0
    }

    #[cfg(not(feature = "ess_miss_recovery"))]
    {
        let _ = fault_addr;
        panic_dump(psp, cfsr_val, "MemManage: ess_miss_recovery disabled");
    }
}

/// SecureFault handler. On Armv8-M, a secure-state instruction fetch into an
/// address the SAU/MPCBB classifies as Non-Secure (and not in an NSC region)
/// raises SecureFault with SFSR.INVEP (bit 0) set. Uses MPCBB
/// per-256B slot flipping to turn unloaded ESS slots into NS, so an attempt
/// to execute one fires INVEP. We classify, walk the stack frame for the
/// stacked PC, and dispatch to the same `Kernel::handle_ess_miss` the
/// MemManage path uses.
///
/// Tail-called from the assembly trampoline in `startup.rs`; must not return
/// on unrecoverable paths. Success path returns via `bx lr`, which becomes
/// exception-return and re-issues the faulting instruction.
#[no_mangle]
pub unsafe extern "C" fn umbra_secure_fault_handler(sp: u32) {
    let sfsr = 0xE000EDE4 as *mut u32;
    let sfsr_val = ptr::read_volatile(sfsr);

    // SFSR.INVEP (bit 0) — "invalid entry point": secure branch to an NS
    // address that is not SG. This is our ESS-miss signature.
    let is_invep = (sfsr_val & 0x01) != 0;
    if !is_invep {
        return panic_dump(sp, sfsr_val, "SecureFault: non-INVEP");
    }

    let frame = sp as *const u32;
    // Normalize Secure alias bit to match against NS-aliased start_address.
    let stacked_pc = ptr::read_volatile(frame.add(6)) & !0x1000_0000u32;

    #[cfg(feature = "ess_miss_recovery")]
    {
        let kernel = match crate::secure_kernel::Kernel::get() {
            Some(k) => k,
            None    => return panic_dump(sp, sfsr_val, "SecureFault: no kernel"),
        };
        let (enclave_id, block_idx) = match kernel.lookup_faulting_block(stacked_pc) {
            Some(pair) => pair,
            None       => return panic_dump(sp, sfsr_val, "SecureFault: PC outside any enclave"),
        };
        let mut dma = match drivers::dma::Dma::new() {
            Some(d) => d,
            None    => return panic_dump(sp, sfsr_val, "SecureFault: DMA unavailable"),
        };
        if kernel.handle_ess_miss(enclave_id, block_idx, &mut dma, true).is_err() {
            return panic_dump(sp, sfsr_val, "SecureFault: handle_ess_miss failed");
        }
        // Clear the SFSR write-1-to-clear bits for the next fault.
        ptr::write_volatile(sfsr, sfsr_val);
        return;
    }

    #[cfg(not(feature = "ess_miss_recovery"))]
    {
        let _ = stacked_pc;
        panic_dump(sp, sfsr_val, "SecureFault: ess_miss_recovery disabled");
    }
}

/// Unrecoverable fault sink. Dumps the stack frame + CFSR + reason and spins
/// forever. Must NEVER return: the MemManage trampoline tail-calls the Rust
/// handler, so returning would perform an exception-return on garbage state.
fn panic_dump(sp: u32, cfsr: u32, reason: &str) -> ! {
    dump_stack_frame(sp, "MemManage");
    print_str("CFSR: 0x");
    print_hex(cfsr);
    print_str("\n");
    // MMFAR/BFAR are only meaningful when their *_VALID bit is set in CFSR,
    // but printing them unconditionally costs nothing and makes diagnosis
    // straightforward — the valid bit tells you whether to trust the value.
    unsafe {
        let mmfar = ptr::read_volatile(0xE000ED34 as *const u32);
        let bfar  = ptr::read_volatile(0xE000ED38 as *const u32);
        print_str("MMFAR: 0x"); print_hex(mmfar); print_str("\n");
        print_str("BFAR:  0x"); print_hex(bfar);  print_str("\n");
    }
    print_str("Reason: ");
    print_str(reason);
    print_str("\n");
    loop { core::hint::spin_loop(); }
}

/// BusFault handler. On STM32L5, MPCBB slot-level rejection of a secure
/// access raises BusFault with two recoverable sub-types:
///
///   IBUSERR   (bit 8)  — instruction fetch into an NS-marked slot.
///   PRECISERR (bit 9)  — data access (e.g. literal-pool load) into an
///                         NS-marked slot; BFAR holds the faulting address.
///
/// Both are routed through `Kernel::handle_ess_miss` so enclave code can
/// freely use PC-relative literal pools / `adr` across block boundaries
/// without the developer having to worry about block layout.
///
/// Tail-called from the assembly trampoline; must not return on
/// unrecoverable paths.
#[no_mangle]
pub unsafe extern "C" fn umbra_bus_fault_handler(sp: u32) {
    let cfsr = 0xE000ED28 as *mut u32;
    let cfsr_val = ptr::read_volatile(cfsr);
    let bfsr = ((cfsr_val >> 8) & 0xFF) as u8;

    let is_ibuserr  = (bfsr & 0x01) != 0;  // bit 8 of CFSR
    let is_preciserr = (bfsr & 0x02) != 0;  // bit 9 of CFSR
    let bfar_valid   = (bfsr & 0x80) != 0;  // bit 15 of CFSR

    if !is_ibuserr && !(is_preciserr && bfar_valid) {
        return panic_dump(sp, cfsr_val, "BusFault: unrecoverable");
    }

    // For IBUSERR the faulting address is the stacked PC (instruction fetch).
    // For PRECISERR the faulting address is in BFAR (data access).
    // Normalize the alias bit: the enclave executes from the Secure alias
    // (0x30xxxxxx) but `lookup_faulting_block` matches against start_address
    // which is the NS alias (0x20xxxxxx). Drop bit 28 so lookups succeed.
    let fault_addr = if is_ibuserr {
        let frame = sp as *const u32;
        ptr::read_volatile(frame.add(6)) & !0x1000_0000u32
    } else {
        let bfar = 0xE000ED38 as *const u32;
        ptr::read_volatile(bfar) & !0x1000_0000u32
    };

    #[cfg(feature = "ess_miss_recovery")]
    {
        let kernel = match crate::secure_kernel::Kernel::get() {
            Some(k) => k,
            None    => return panic_dump(sp, cfsr_val, "BusFault: no kernel"),
        };
        let (enclave_id, block_idx) = match kernel.lookup_faulting_block(fault_addr) {
            Some(pair) => pair,
            None       => return panic_dump(sp, cfsr_val, "BusFault: addr outside any enclave"),
        };
        let mut dma = match drivers::dma::Dma::new() {
            Some(d) => d,
            None    => return panic_dump(sp, cfsr_val, "BusFault: DMA unavailable"),
        };
        if kernel.handle_ess_miss(enclave_id, block_idx, &mut dma, true).is_err() {
            return panic_dump(sp, cfsr_val, "BusFault: handle_ess_miss failed");
        }
        ptr::write_volatile(cfsr, (bfsr as u32) << 8);
        return;
    }

    #[cfg(not(feature = "ess_miss_recovery"))]
    {
        let _ = fault_addr;
        panic_dump(sp, cfsr_val, "BusFault: ess_miss_recovery disabled");
    }
}

/// UsageFault dispatcher for enclave context. Called from the assembly
/// trampoline in `startup.rs` with `psp` = the enclave's stacked frame base.
///
/// Three sub-types matter in this build:
///
///   UNDEFINSTR (UFSR bit 0)  — evicted ESS block fetch: the UDF pattern
///                              0xDEDE_DEDE reached the decoder. Dispatch to
///                              `Kernel::handle_ess_miss` to reload the block
///                              and resume the faulting instruction.
///   INVSTATE   (UFSR bit 1)  — `bx lr` against the sentinel LR=0xFFFFFFFF
///                              set up by `umbra_enclave_enter_imp`. This is
///                              how the enclave signals normal end-of-task.
///   *other*                  — genuine enclave misbehavior.
///
/// Return value:
///   * `0`               — trampoline takes the RECOVER path, restoring the
///                         original EXC_RETURN and resuming the enclave.
///   * non-zero          — trampoline takes the TERMINATE path, storing the
///                         value as the SVC return code for
///                         `umbra_enclave_enter_imp`.
#[no_mangle]
pub unsafe extern "C" fn umbra_usage_fault_dispatch(psp: u32) -> u32 {
    use kernel::common::enclave::{EnclaveContext, EnclaveState};

    let cfsr_ptr = 0xE000_ED28 as *mut u32;
    let cfsr_val = ptr::read_volatile(cfsr_ptr);
    let ufsr = (cfsr_val >> 16) as u16;
    let is_undefinstr = (ufsr & 0x01) != 0;
    let is_invstate   = (ufsr & 0x02) != 0;

    #[cfg(feature = "ess_miss_recovery")]
    if is_undefinstr {
        let frame = psp as *const u32;
        let stacked_pc = ptr::read_volatile(frame.add(6));
        // Normalize the alias bit so lookups against an NS-aliased
        // `start_address` (the value returned by `EnclaveSwapSpace::allocate`)
        // succeed even if the enclave was executing from the Secure alias.
        let normalized_pc = stacked_pc & !0x1000_0000u32;

        if let Some(kernel) = crate::secure_kernel::Kernel::get() {
            if let Some((enclave_id, block_idx)) =
                kernel.lookup_faulting_block(normalized_pc)
            {
                if let Some(mut dma) = drivers::dma::Dma::new() {
                    match kernel.handle_ess_miss(enclave_id, block_idx, &mut dma, true) {
                        Ok(()) => {
                            // Clear UFSR.UNDEFINSTR (write-1-to-clear at bit
                            // 16 of CFSR) and signal RECOVER.
                            ptr::write_volatile(cfsr_ptr, 1 << 16);
                            return 0;
                        }
                        Err(_) => {
                            crate::api_impl::umbra_debug_print_imp(
                                b"[UMBRASecureBoot] handle_ess_miss failed\n\0".as_ptr(),
                            );
                            return usage_fault_terminate(psp, EnclaveState::Faulted);
                        }
                    }
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

/// Common UsageFault terminate path. Clears the entire UFSR, marks the
/// enclave context with the given state, disables SysTick, and encodes the
/// `(enclave_id, state, result)` triple expected by `umbra_enclave_enter_imp`.
unsafe fn usage_fault_terminate(
    psp: u32,
    state: kernel::common::enclave::EnclaveState,
) -> u32 {
    use kernel::common::enclave::{EnclaveContext, EnclaveState};

    // UFSR occupies CFSR bits [31:16]; clear every sub-type we might observe.
    let cfsr_ptr = 0xE000_ED28 as *mut u32;
    ptr::write_volatile(cfsr_ptr, 0xFFFF_0000);

    let ctx_ptr = crate::secure_kernel::CURRENT_ENCLAVE_CTX_PTR as *mut EnclaveContext;
    if ctx_ptr.is_null() {
        return 0xFF;
    }
    let ctx = &mut *ctx_ptr;
    ctx.status = state;

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
    loop {}
}

#[no_mangle]
pub extern "C" fn umbra_svc_handler(sp: u32) {
    // SVC handler for synchronous calls. Currently prints debug output only.
    // Assembly wrapper must return via bx lr for proper exception return.
    print_str("\n[SVC] Handler Called\n");
}

#[no_mangle]
pub extern "C" fn umbra_debug_mon_handler(sp: u32) {
    print_str("\n[DebugMon] Handler Called\n");
    loop {}
}

#[no_mangle]
pub extern "C" fn umbra_pendsv_handler(_sp: u32) {
}

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

    #[cfg(feature = "ess_miss_recovery")]
    {
        if let Some(enclave) = kernel.ess.loaded_enclaves.iter_mut()
            .flatten()
            .find(|e| e.descriptor.id == enclave_id)
        {
            // Only decay counters on currently-loaded blocks. evict_block
            // already zeroes the counter on eviction, so unloaded entries
            // read 0 and decaying them is a no-op today — but gating on
            // is_loaded keeps the semantics explicit if a future change
            // ever preserves counters across reloads.
            for i in 0..enclave.efb_count {
                if enclave.efbs[i].is_loaded {
                    enclave.efbs[i].counter >>= 1;
                }
            }
        }
    }

    ((enclave_id & 0xFFFF) << 16)
        | ((EnclaveState::Suspended as u32 & 0xFF) << 8)
}

#[no_mangle]
pub extern "C" fn umbra_yield_handler(ctx_ptr: *mut u8) -> u32 {
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

    ((enclave_id & 0xFFFF) << 16)
        | ((EnclaveState::Suspended as u32 & 0xFF) << 8)
}
