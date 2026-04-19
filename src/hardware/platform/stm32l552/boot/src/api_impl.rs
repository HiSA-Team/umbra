use kernel::common::enclave::UmbraEnclaveHeader;

use crate::secure_kernel::{Kernel, CODE_BLOCK_SIZE, TOTAL_BLOCK_SIZE};
use drivers::dma::Dma;
use kernel::common::enclave::EnclaveDescriptor;
use kernel::common::ess::{CACHE_LIMIT_PER_ENCLAVE, MAX_EFBS};
use kernel::common::enclave::{EnclaveContext, EnclaveState};
use kernel::common::ess::{enclave_psp_top, MAX_ENCLAVES_CTX};

static mut NEXT_ENCLAVE_ID: u32 = 1;

// --- EFB Structure Helper ---
// [HMAC (32)] [Count (1)] [Reachable (N)] [PAD] [EncData (256)]
// We assume Block 0 is at `code_flash_addr`.

// BFS-based Recursive Loader


#[no_mangle]
#[link_section = ".umbra_api_implementation"]
pub extern "C" fn umbra_tee_create_imp(base_addr: u32) -> u32{
    let enclave_flash_addr: u32 = base_addr;

    let kernel = unsafe {
        match Kernel::get() {
            Some(k) => k,
            None => return 0xFFFFFFFE,
        }
    };

    if base_addr < 0x0804_0000 || base_addr >= 0x0808_0000 {
        return 0xFFFF_FFF6;
    }
    if base_addr & 0xFFF != 0 {
        return 0xFFFF_FFF5;
    }
    for slot in kernel.ess.loaded_enclaves.iter() {
        if let Some(le) = slot {
            if le.descriptor.flash_base == base_addr {
                return 0xFFFF_FFF4;
            }
        }
    }
    if unsafe { NEXT_ENCLAVE_ID } > MAX_ENCLAVES_CTX as u32 {
        return 0xFFFF_FFF3;
    }

    let header = unsafe {
        match UmbraEnclaveHeader::from_address(enclave_flash_addr) {
            Some(h) => h,
            None => return 0xFFFFFFFF,
        }
    };

    let total_blob_size = header.code_size;
    
    // Calculate total blocks
    // blob size = NumBlocks * 320
    let num_blocks = total_blob_size / TOTAL_BLOCK_SIZE;
    if num_blocks == 0 { return 0xFFFFFFF7; }

    // Allocate TOTAL RAM needed (NumBlocks * 64)
    let total_ram_needed = num_blocks * CODE_BLOCK_SIZE;
    let ess_addr = match kernel.ess.allocate(total_ram_needed) {
        Some(addr) => addr,
        None => return 0xFFFFFFFD, 
    };

    let scratch_addr: u32 = 0x30010000;
    
    // Initialize EFB tracking
    use kernel::common::ess::EfbDescriptor;
    let mut efbs = [EfbDescriptor::default(); MAX_EFBS ];
    let mut efb_count = 0;

    if let Some(mut dma) = Dma::new() {

        dma.reserve_ch(0, 0);
        dma.reserve_ch(0, 1);
        dma.reserve_ch(0, 3);
        dma.reserve_ch(0, 4);
        dma.reserve_ch(0, 5);
        dma.reserve_ch(0, 6);
        dma.reserve_ch(0, 7);

        // Seed the chained HMAC state from the master key. This is a no-op
        // under the non-chained layout (the field is still written but never
        // consulted; the 32B cost sits in SRAM regardless).
        #[cfg(feature = "chained_measurement")]
        kernel.begin_measurement();

        // BFS State
        // Simple bitmap for visited blocks (Max 32 blocks for now)
        let mut loaded_mask: u32 = 0;
        // Queue (fixed size ring buffer or simple array)
        let mut queue = [0u8; MAX_EFBS];
        let mut head = 0;
        let mut tail = 0;
        
        // Push Block 0
        queue[tail] = 0;
        tail += 1;
        loaded_mask |= 1; // Mark 0 as visited/pending
        
        while head < tail {
            let curr_idx = queue[head] as u32;
            head += 1;
            
            // Load and Verify Block
            unsafe {
                match kernel.load_and_verify_block(curr_idx, ess_addr, scratch_addr, enclave_flash_addr, &mut dma) {
                    Ok((meta_ptr, count)) => {
                        // Update EFB List
                        if (curr_idx as usize) < MAX_EFBS {
                            efbs[curr_idx as usize] = EfbDescriptor {
                                id: curr_idx,
                                is_loaded: true,
                                counter: 0,
                                reachable: [0; kernel::common::ess::MAX_REACHABLE],
                                reachable_count: 0,
                            };
                            if (curr_idx as usize) >= efb_count {
                                efb_count = (curr_idx as usize) + 1;
                            }

                            // Cache reachability in EST
                            {
                                use kernel::common::ess::MAX_REACHABLE;
                                assert!((count as usize) <= MAX_REACHABLE,
                                    "Block reachable count exceeds MAX_REACHABLE. Increase the constant in ess.rs");
                                efbs[curr_idx as usize].reachable_count = count;
                                for ri in 0..count as usize {
                                    efbs[curr_idx as usize].reachable[ri] = *meta_ptr.add(1 + ri);
                                }
                            }
                        }

                        // Parse Reachable
                        // Meta format: [Count][Idx...]
                        if count > 0 {
                            for i in 0..count {
                                let next_blk = *meta_ptr.add(1 + i as usize);
                                if usize::from(next_blk) < MAX_EFBS {
                                    if (loaded_mask & (1 << next_blk)) == 0 {
                                        // Found new reachable block
                                        if tail < MAX_EFBS {
                                            queue[tail] = next_blk;
                                            tail += 1;
                                            loaded_mask |= 1 << next_blk;
                                        }
                                    }
                                }
                            }
                        }
                    },
                    Err(e) => return e, 
                }
            }
        }
        
    } else {
        return 0xFFFFFFFB;
    }

    // Finalize the chained measurement: compare against the reference HMAC in
    // the enclave header. On mismatch we emit a marker for the smoke test and
    // refuse to register the enclave.
    #[cfg(feature = "chained_measurement")]
    {
        let expected: [u8; 32] = header.hmac;
        if kernel.finalize_measurement(&expected).is_err() {
            umbra_debug_print_imp(b"[UMBRASecureBoot] chained-measurement FAIL\n\0".as_ptr());
            return 0xFFFFFFF6;
        }
        umbra_debug_print_imp(b"[UMBRASecureBoot] chained-measurement OK\n\0".as_ptr());
    }

    // Register enclave BEFORE eviction so evict_block can find it by ID.
    // ram_base stays at the NS alias (0x2002xxxx) because data writes —
    // DMA install, evict_block UDF-fill, handle_ess_miss copy — all go
    // through the NS alias so MPCBB slot-level bypass logic keeps working.
    // entry_point uses the Secure alias (0x3002xxxx): on STM32L5, IDAU
    // classifies the 0x20000000 alias as NS regardless of SAU, so a
    // Secure-state exception return to 0x2002xxxx raises SecureFault.INVTRAN.
    // Instruction fetches must use the Secure alias.
    let assigned_id = unsafe { NEXT_ENCLAVE_ID };
    let secure_entry = ess_addr | 0x1000_0000;
    let descriptor = EnclaveDescriptor {
         id: assigned_id,
         flash_base: enclave_flash_addr,
         ram_base: ess_addr,
         code_size: total_ram_needed,
         entry_point: secure_entry,
         is_loaded: true,
    };

    if !kernel.ess.register_enclave(descriptor, ess_addr, efbs, efb_count) {
        return 0xFFFFFFF8;
    }

    // UDF-fill every non-entry block at creation so their first
    // execution raises UsageFault.UNDEFINSTR and routes through
    // `umbra_usage_fault_dispatch -> handle_ess_miss`. The runtime reload
    // path is the only place where per-block HMAC is validated (the initial
    // BFS `load_and_verify_block` only folds the block into the chained
    // measurement), so forcing it on every non-entry block ensures every
    // block gets an on-demand integrity check. CACHE_LIMIT_PER_ENCLAVE is
    // still honored by `handle_ess_miss` when installing a reloaded block.
    #[cfg(feature = "ess_miss_recovery")]
    unsafe {
        let _ = CACHE_LIMIT_PER_ENCLAVE;
        for idx in 1..(num_blocks as usize) {
            if idx < MAX_EFBS {
                kernel.evict_block(assigned_id, idx as u32);
            }
        }
    }

    unsafe { NEXT_ENCLAVE_ID += 1; }

    // Initialize enclave context for preemptive scheduling.
    let enclave_idx = {
        let mut idx = 0usize;
        for (i, slot) in kernel.ess.loaded_enclaves.iter().enumerate() {
            if let Some(le) = slot {
                if le.descriptor.id == assigned_id {
                    idx = i;
                    break;
                }
            }
        }
        idx
    };
    if enclave_idx < MAX_ENCLAVES_CTX {
        let psp_top = enclave_psp_top(enclave_idx);
        let frame_base = psp_top - 32; // 8 words × 4 bytes
        unsafe {
            let frame = frame_base as *mut u32;
            core::ptr::write_volatile(frame.add(0), 0);            // r0
            core::ptr::write_volatile(frame.add(1), 0);            // r1
            core::ptr::write_volatile(frame.add(2), 0);            // r2
            core::ptr::write_volatile(frame.add(3), 0);            // r3
            core::ptr::write_volatile(frame.add(4), 0);            // r12
            core::ptr::write_volatile(frame.add(5), 0xFFFF_FFFF);  // LR (end-of-task)
            core::ptr::write_volatile(frame.add(6), secure_entry); // PC = Secure-alias entry
            core::ptr::write_volatile(frame.add(7), 0x0100_0000);  // xPSR (Thumb)
        }

        kernel.enclave_contexts[enclave_idx] = EnclaveContext {
            r4: 0, r5: 0, r6: 0, r7: 0,
            r8: 0, r9: 0, r10: 0, r11: 0,
            psp: frame_base,
            // EXC_RETURN 0xFFFFFFFD = Thread mode, PSP, Secure, standard frame
            // (FType=1, no FP context). Using 0xFFFFFFED (FType=0) would tell
            // the CPU to unstack an extended/FP frame on exception return,
            // which raises UsageFault.NOCP since CPACR never grants FPU
            // access. See FreeRTOS/CMSIS-RTOS Cortex-M33 port for reference.
            lr: 0xFFFF_FFFD,
            control: 0x03,
            status: EnclaveState::Ready,
            result: 0,
        };
    }

    assigned_id
}

#[no_mangle]
#[link_section = ".umbra_api_implementation"]
pub extern "C" fn umbra_enclave_enter_imp(enclave_id: u32) -> u32 {
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
            None => return 0xFFFF_FFF0,
        }
    };

    if enclave_idx >= MAX_ENCLAVES_CTX {
        return 0xFFFF_FFF1;
    }

    let ctx = &mut kernel.enclave_contexts[enclave_idx];

    match ctx.status {
        EnclaveState::Ready | EnclaveState::Suspended => {},
        EnclaveState::Terminated => {
            return ((enclave_id & 0xFFFF) << 16)
                 | ((EnclaveState::Terminated as u32 & 0xFF) << 8)
                 | (ctx.result & 0xFF);
        },
        EnclaveState::Faulted => {
            return ((enclave_id & 0xFFFF) << 16)
                 | ((EnclaveState::Faulted as u32 & 0xFF) << 8);
        },
        _ => return 0xFFFF_FFF2,
    }

    // Extract the raw pointer from ctx before releasing the mutable borrow so
    // that we can later call kernel.enable_systick() (which takes &self) without
    // a simultaneous &mut alive.
    let ctx_raw: *mut EnclaveContext = &mut kernel.enclave_contexts[enclave_idx];

    // Safety: we own the kernel singleton exclusively here.
    let ctx = unsafe { &mut *ctx_raw };

    match ctx.status {
        EnclaveState::Ready | EnclaveState::Suspended => {},
        EnclaveState::Terminated => {
            return ((enclave_id & 0xFFFF) << 16)
                 | ((EnclaveState::Terminated as u32 & 0xFF) << 8)
                 | (ctx.result & 0xFF);
        },
        EnclaveState::Faulted => {
            return ((enclave_id & 0xFFFF) << 16)
                 | ((EnclaveState::Faulted as u32 & 0xFF) << 8);
        },
        _ => return 0xFFFF_FFF2,
    }

    ctx.status = EnclaveState::Running;
    // Drop the ctx reference so we can borrow kernel freely below.
    drop(ctx);

    kernel.current_enclave_id = Some(enclave_id);

    // G3: pre-load all reachable blocks BEFORE MPU Region 5 is configured.
    // Region 5 marks the EFBC as RO+Execute (AP=0b11) which blocks ALL
    // writes, even privileged. The prefetch must write to the EFBC, so
    // it runs before the MPU locks it down.
    #[cfg(feature = "ess_miss_recovery")]
    unsafe { crate::prefetch::prefetch_reachables(enclave_id); }

    // Reconfigure MPU for this enclave (after prefetch)
    unsafe {
        let mpu_rbar = 0xE000_ED9C as *mut u32;
        let mpu_rlar = 0xE000_EDA0 as *mut u32;
        let mpu_rnr  = 0xE000_ED98 as *mut u32;

        let psp_base = kernel::common::ess::enclave_psp_top(enclave_idx)
                     - kernel::common::ess::ENCLAVE_PSP_STACK_SIZE;
        let psp_limit = kernel::common::ess::enclave_psp_top(enclave_idx) - 1;

        // Region 4: Enclave stack (RW, unprivileged, XN)
        core::ptr::write_volatile(mpu_rnr, 4);
        core::ptr::write_volatile(mpu_rbar, (psp_base & 0xFFFF_FFE0) | (0b01 << 1) | 0x01);
        core::ptr::write_volatile(mpu_rlar, (psp_limit & 0xFFFF_FFE0) | 0x01);

        // Region 5: Enclave code (RO+Execute, unprivileged)
        if let Some(le) = &kernel.ess.loaded_enclaves[enclave_idx] {
            let code_base = le.start_address | 0x1000_0000;
            let code_limit = code_base + le.descriptor.code_size - 1;
            core::ptr::write_volatile(mpu_rnr, 5);
            core::ptr::write_volatile(mpu_rbar, (code_base & 0xFFFF_FFE0) | (0b11 << 1));
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
            None => return 0xFFFF_FFF0,
        }
    };

    if enclave_idx >= MAX_ENCLAVES_CTX {
        return 0xFFFF_FFF1;
    }

    let ctx = &mut kernel.enclave_contexts[enclave_idx];

    match ctx.status {
        EnclaveState::Suspended => {
            ctx.status = EnclaveState::Terminated;
            ((enclave_id & 0xFFFF) << 16)
                | ((EnclaveState::Terminated as u32 & 0xFF) << 8)
        },
        EnclaveState::Terminated | EnclaveState::Faulted => {
            ((enclave_id & 0xFFFF) << 16)
                | ((ctx.status as u32 & 0xFF) << 8)
        },
        _ => {
            0xFFFF_FFF2
        },
    }
}

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


#[no_mangle]
#[link_section = ".umbra_api_implementation"]
pub extern "C" fn umbra_enclave_run_imp() -> u32 {
    
    let kernel = unsafe {
        match Kernel::get() {
            Some(k) => k,
            None => return 0xFFFFFFFE,
        }
    };
    
    let mut entry_point: u32 = 0;
    let mut found = false;
    
    for slot in kernel.ess.loaded_enclaves.iter() {
        if let Some(loaded) = slot {
             entry_point = loaded.descriptor.entry_point; // Use entry_point from descriptor
             found = true;
             break;
        }
    }
    
    if !found {
        return 0xFFFFFFF0; 
    }

    let result: u32;
    unsafe {
        // Ensure Thumb state
        let entry_point_thumb: u32 = entry_point | 1;
        core::arch::asm!(
            "dsb",
            "isb",
            "blx {0}",
            in(reg) entry_point_thumb,
            lateout("r0") result,
            clobber_abi("C")
        );
    }
    return result;
}

#[no_mangle]
#[link_section = ".umbra_api_implementation"]
pub extern "C" fn umbra_debug_print_imp(str_ptr: *const u8) {
    if str_ptr.is_null() { return; }

    let uart_base = crate::handlers::RAW_UART_BASE as *mut u32;

    let isr_ptr = unsafe { uart_base.add(0x1C / 4) }; 
    let tdr_ptr = unsafe { uart_base.add(0x28 / 4) };

    // Simple string loop
    let mut curr = str_ptr;
    unsafe {
        while *curr != 0 {
            // Wait for TXE (Bit 7)
            loop {
                let isr = isr_ptr.read_volatile();
                if (isr & (1 << 7)) != 0 {
                    break;
                }
            }
            // Send char
            tdr_ptr.write_volatile(*curr as u32);
            curr = curr.add(1);
        }
    }
}
