//! NSC API implementations for STM32N657.
//!
//! These `_imp` functions are called by the NSC veneers in
//! kernel/asm/arm/nsc_veneers.s. The veneers do `sg`, push the link, BL
//! into the implementation, then BXNS back to the NS host.
//!
//! Responsibilities:
//!   - `umbra_enclave_create_imp` validates the UMBR header at the supplied
//!     flash address, allocates ESS via the kernel allocator, copies block 0
//!     from flash via `kernel.load_block_n657`, UDF-fills the remaining
//!     blocks, and registers the enclave.
//!   - `umbra_enclave_enter_imp` / `_exit_imp` / `_status_imp` drive enclave
//!     execution; the kernel API is platform-agnostic now that ESS layout
//!     is feature-gated.
//!   - The UsageFault dispatcher in handlers.rs reuses
//!     `kernel.load_block_n657` to fetch a faulting (UDF-filled) block on
//!     demand.

use arm::mmio::{ICIALLU, MPU_RBAR, MPU_RLAR, MPU_RNR};
use kernel::common::enclave::{
    EnclaveContext, EnclaveDescriptor, EnclaveState, UmbraEnclaveHeader, UMBRA_HEADER_SIZE,
};
use kernel::common::ess::{
    enclave_psp_top, EfbDescriptor, ENCLAVE_PSP_STACK_SIZE, MAX_EFBS, MAX_ENCLAVES_CTX,
};

use crate::secure_kernel::{
    Kernel, BLOCK_META_OFFSET, BLOCK_META_SIZE, CODE_BLOCK_SIZE, TOTAL_BLOCK_SIZE,
};

static mut NEXT_ENCLAVE_ID: u32 = 1;

/// Chained-measurement update for a single loaded block.
///
/// Builds the per-block HMAC input as `[block_id (4) | code (256) |
/// meta (32)]` — the same layout `protect_enclave.py` uses when it
/// computes the running chain offline. The code half is read back from
/// ESS (just installed by `load_block_n657`); the meta half comes from
/// flash since we don't keep it in RAM. `chain_state = HMAC-SHA256(
/// chain_state, verify_buf)`.
fn update_chain(
    chain_state: &mut [u8; 32],
    block_idx: u32,
    ess_base: u32,
    enclave_flash_base: u32,
    hash: &mut drivers::hash::Hash,
) {
    let mut verify_buf = [0u8;
        4 + CODE_BLOCK_SIZE as usize + BLOCK_META_SIZE as usize];

    let id_bytes = block_idx.to_le_bytes();
    verify_buf[0] = id_bytes[0];
    verify_buf[1] = id_bytes[1];
    verify_buf[2] = id_bytes[2];
    verify_buf[3] = id_bytes[3];

    unsafe {
        // Code half: read back from ESS where load_block_n657 just wrote it.
        let ess_src = (ess_base + block_idx * CODE_BLOCK_SIZE) as *const u8;
        let mut i: usize = 0;
        while i < CODE_BLOCK_SIZE as usize {
            verify_buf[4 + i] = core::ptr::read_volatile(ess_src.add(i));
            i += 1;
        }
        // Meta half: read straight from flash (memory-mapped XSPI2).
        // BLOCK_META_OFFSET is feature-gated in secure_kernel (0 for
        // chained_measurement, 32 for ess_miss_recovery) so referencing it
        // here keeps the constant exercised.
        let meta_src = (enclave_flash_base
            + UMBRA_HEADER_SIZE
            + block_idx * TOTAL_BLOCK_SIZE
            + BLOCK_META_OFFSET) as *const u8;
        let mut j: usize = 0;
        while j < BLOCK_META_SIZE as usize {
            verify_buf[4 + CODE_BLOCK_SIZE as usize + j] =
                core::ptr::read_volatile(meta_src.add(j));
            j += 1;
        }
    }

    let mut output = [0u8; 32];
    hash.hmac_sha256(chain_state, &verify_buf, &mut output);
    *chain_state = output;
}

#[no_mangle]
#[link_section = ".umbra_api_implementation"]
pub extern "C" fn umbra_enclave_create_imp(base_addr: u32) -> u32 {
    let kernel = unsafe {
        match Kernel::get() {
            Some(k) => k,
            None => return 0xFFFF_FFFE,
        }
    };

    // 1. Validate flash range — XSPI2 memory-mapped at 0x70000000 (256 MB).
    if base_addr < 0x7000_0000 || base_addr >= 0x8000_0000 {
        return 0xFFFF_FFF6;
    }
    if base_addr & 0xF != 0 {
        return 0xFFFF_FFF5;
    }

    if unsafe { NEXT_ENCLAVE_ID } > MAX_ENCLAVES_CTX as u32 {
        return 0xFFFF_FFF3;
    }

    // 2. Read UMBR header from flash (memory-mapped XSPI2).
    let header = unsafe {
        match UmbraEnclaveHeader::from_address(base_addr) {
            Some(h) => h,
            None => return 0xFFFF_FFFF, // bad magic
        }
    };

    let total_blob_size = header.code_size;
    let num_blocks = total_blob_size / TOTAL_BLOCK_SIZE;
    if num_blocks == 0 || (num_blocks as usize) > MAX_EFBS {
        return 0xFFFF_FFF7;
    }

    // 3. Allocate enough ESS slots for all blocks (code only, meta lives
    //    on flash). num_blocks × CODE_BLOCK_SIZE.
    let total_ram_needed = num_blocks * CODE_BLOCK_SIZE;
    let ess_addr = match kernel.ess.allocate(total_ram_needed) {
        Some(addr) => addr,
        None => return 0xFFFF_FFFD,
    };

    // 4. Chained measurement: seed chain_state with the master key, then
    //    load each block sequentially from flash and fold its
    //    [block_id | code | meta] into the running HMAC chain.
    //    `protect_enclave.py` builds the same chain offline in numeric
    //    order and stamps the final value into header.hmac.
    kernel.begin_measurement();
    let mut hash = drivers::hash::Hash::new();

    let mut blk: u32 = 0;
    while blk < num_blocks {
        if let Err(e) = unsafe { kernel.load_block_n657(blk, ess_addr, base_addr) } {
            return e;
        }
        update_chain(&mut kernel.chain_state, blk, ess_addr, base_addr, &mut hash);
        blk += 1;
    }

    // I-cache invalidate covers the freshly loaded code for all blocks.
    unsafe {
        cortex_m::asm::dsb();
        core::ptr::write_volatile(ICIALLU, 0);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
    }

    // 5. Finalize chained measurement against header.hmac. Mismatch =
    //    the on-flash blob has been tampered with (or the host's
    //    protect_enclave.py used a different master key).
    if kernel.finalize_measurement(&header.hmac).is_err() {
        crate::raw_print::print_str(
            "[UMBRASecureBoot] chained-measurement FAIL\r\n",
        );
        return 0xFFFF_FFF6;
    }

    let assigned_id = unsafe { NEXT_ENCLAVE_ID };
    let descriptor = EnclaveDescriptor {
        id: assigned_id,
        flash_base: base_addr,
        ram_base: ess_addr,
        code_size: total_ram_needed,
        entry_point: ess_addr, // Already a Secure alias on N657 (0x34xxxxxx)
        is_loaded: true,
    };

    let mut efbs = [EfbDescriptor::default(); MAX_EFBS];
    let mut bi: u32 = 0;
    while bi < num_blocks {
        efbs[bi as usize] = EfbDescriptor {
            id: bi,
            is_loaded: true, // E.4b: all blocks pre-loaded by chain pass
            counter: 0,
            reachable: [0; kernel::common::ess::MAX_REACHABLE],
            reachable_count: 0,
        };
        bi += 1;
    }
    if !kernel.ess.register_enclave(descriptor, ess_addr, efbs, num_blocks as usize) {
        return 0xFFFF_FFF8;
    }

    // Initialize enclave context: PSP frame pre-populated with sentinel LR
    // (0xFFFFFFFF) and entry-point PC, so the first SVC #0 → exception-return
    // pops this frame and starts the enclave at the right place.
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
            core::ptr::write_volatile(frame.add(0), 0);
            core::ptr::write_volatile(frame.add(1), 0);
            core::ptr::write_volatile(frame.add(2), 0);
            core::ptr::write_volatile(frame.add(3), 0);
            core::ptr::write_volatile(frame.add(4), 0);
            core::ptr::write_volatile(frame.add(5), 0xFFFF_FFFF); // LR (sentinel)
            core::ptr::write_volatile(frame.add(6), ess_addr);     // PC = entry
            core::ptr::write_volatile(frame.add(7), 0x0100_0000);  // xPSR (Thumb)
        }

        kernel.enclave_contexts[enclave_idx] = EnclaveContext {
            r4: 0, r5: 0, r6: 0, r7: 0,
            r8: 0, r9: 0, r10: 0, r11: 0,
            psp: frame_base,
            // EXC_RETURN 0xFFFFFFFD = Thread mode, PSP, Secure, FType=1 (no FP).
            lr: 0xFFFF_FFFD,
            control: 0x03, // PRIV=0 (unprivileged), SPSEL=1 (PSP)
            status: EnclaveState::Ready,
            result: 0,
        };
    }

    unsafe { NEXT_ENCLAVE_ID += 1; }
    assigned_id
}

#[no_mangle]
#[link_section = ".umbra_api_implementation"]
pub extern "C" fn umbra_enclave_enter_imp(enclave_id: u32) -> u32 {
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

    let ctx_raw: *mut EnclaveContext = &mut kernel.enclave_contexts[enclave_idx];
    let ctx = unsafe { &mut *ctx_raw };

    match ctx.status {
        EnclaveState::Ready | EnclaveState::Suspended => {}
        EnclaveState::Terminated => {
            return ((enclave_id & 0xFFFF) << 16)
                | ((EnclaveState::Terminated as u32 & 0xFF) << 8)
                | (ctx.result & 0xFF);
        }
        EnclaveState::Faulted => {
            return ((enclave_id & 0xFFFF) << 16)
                | ((EnclaveState::Faulted as u32 & 0xFF) << 8);
        }
        _ => return 0xFFFF_FFF2,
    }

    ctx.status = EnclaveState::Running;
    let _ = ctx;

    kernel.current_enclave_id = Some(enclave_id);

    // Configure MPU regions 4 (stack) and 5 (code) for unprivileged access.
    // The enclave runs with CONTROL.PRIV=0 so the default memory map
    // (PRIVDEFENA=1) does not apply — explicit MPU regions are mandatory.
    unsafe {
        let mpu_rbar = MPU_RBAR;
        let mpu_rlar = MPU_RLAR;
        let mpu_rnr  = MPU_RNR;

        let psp_base  = enclave_psp_top(enclave_idx) - ENCLAVE_PSP_STACK_SIZE;
        let psp_limit = enclave_psp_top(enclave_idx) - 1;

        // Region 4: enclave stack — RW unprivileged, execute-never.
        core::ptr::write_volatile(mpu_rnr, 4);
        core::ptr::write_volatile(mpu_rbar, (psp_base & 0xFFFF_FFE0) | (0b01 << 1) | 0x01);
        core::ptr::write_volatile(mpu_rlar, (psp_limit & 0xFFFF_FFE0) | 0x01);

        // Region 5: enclave code — RO unprivileged + privileged, executable.
        // The UsageFault dispatcher temporarily flips this to AP=00
        // (priv RW only) when synth-loading a UDF-filled block, then
        // restores AP=11 before resuming the enclave. That keeps the code
        // genuinely RO from the enclave's perspective while still letting
        // the privileged kernel write into it during ESS-miss recovery.
        if let Some(le) = &kernel.ess.loaded_enclaves[enclave_idx] {
            let code_base  = le.start_address;
            let code_limit = code_base + le.descriptor.code_size - 1;
            core::ptr::write_volatile(mpu_rnr, 5);
            core::ptr::write_volatile(mpu_rbar, (code_base & 0xFFFF_FFE0) | (0b11 << 1));
            core::ptr::write_volatile(mpu_rlar, (code_limit & 0xFFFF_FFE0) | 0x01);
        }
        // Region 6: INPUT_SHARED (host writes 224×224×3 image, enclave
        // reads). RW unprivileged, no execute. Backed by the INPUT_SHARED
        // MEMORY entry in object_detection_n657/linker/memory.ld.
        core::ptr::write_volatile(mpu_rnr, 6);
        core::ptr::write_volatile(
            mpu_rbar,
            (0x24080000u32 & 0xFFFF_FFE0) | (0b01 << 1) | 0x01,
        );
        core::ptr::write_volatile(
            mpu_rlar,
            (0x240BFFE0u32 & 0xFFFF_FFE0) | 0x01,
        );

        // Region 7: OUTPUT_SHARED (enclave writes detections, host reads).
        // RW unprivileged, no execute.
        core::ptr::write_volatile(mpu_rnr, 7);
        core::ptr::write_volatile(
            mpu_rbar,
            (0x240C0000u32 & 0xFFFF_FFE0) | (0b01 << 1) | 0x01,
        );
        core::ptr::write_volatile(
            mpu_rlar,
            (0x240CFFE0u32 & 0xFFFF_FFE0) | 0x01,
        );

        // Region 8: NPU activations + I/O slot at 0x342E0000. The model
        // blob's hardcoded I/O and scratch addresses span the full Secure
        // AXISRAM2-6 range — a 150528-byte image copy (224×224×3) plus the
        // blob's internal scratch references reach up to ~0x343BFFFF, so
        // size the region to the full ~880 KB span. RW unprivileged, no
        // execute.
        core::ptr::write_volatile(mpu_rnr, 8);
        core::ptr::write_volatile(
            mpu_rbar,
            (0x342E0000u32 & 0xFFFF_FFE0) | (0b01 << 1) | 0x01,
        );
        core::ptr::write_volatile(
            mpu_rlar,
            (0x343BFFE0u32 & 0xFFFF_FFE0) | 0x01,
        );

        // Region 9: NPU peripheral block from base (0x580E0000) through
        // EPOCHCTRL (0x580FE000+). Covers CLKCTRL at NPU_BASE+0x10 (the
        // enclave enables the EC clock via CLKCTRL.BGATES bit 25 before
        // configuring EPOCHCTRL) as well as the EPOCHCTRL CTRL/ADDR/IRQ
        // registers. RW unprivileged, no execute, ~128 KB.
        //
        // Uses the SECURE alias (0x580E0000) not the NS alias (0x480E0000):
        // SECCFGR3 bit 10 = 1 (set by platform_impl.rs init_clocks) makes
        // RISUP 106 (NPU config port) Secure-only. NS-alias access from the
        // enclave would be silently dropped. The Secure alias forces
        // IDAU-S attribute on transactions, which RISUP 106 admits.
        core::ptr::write_volatile(mpu_rnr, 9);
        core::ptr::write_volatile(
            mpu_rbar,
            (0x580E0000u32 & 0xFFFF_FFE0) | (0b01 << 1) | 0x01,
        );
        core::ptr::write_volatile(
            mpu_rlar,
            (0x580FFFE0u32 & 0xFFFF_FFE0) | 0x01,
        );

        cortex_m::asm::dsb();
        cortex_m::asm::isb();
    }

    // SVC #0 with custom register constraints (r0 = ctx_ptr in / status out,
    // r1-r3 clobbered) — the cortex-m crate does not expose SVC with register
    // passing, so this stays as inline `core::arch::asm!`.
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
        }
        EnclaveState::Terminated | EnclaveState::Faulted => {
            ((enclave_id & 0xFFFF) << 16) | ((ctx.status as u32 & 0xFF) << 8)
        }
        _ => 0xFFFF_FFF2,
    }
}

#[no_mangle]
#[link_section = ".umbra_api_implementation"]
/// Returns the full 32-bit `ctx.result` (R0 at termination) when the enclave
/// has terminated, otherwise the state code.
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
pub extern "C" fn umbra_debug_print_imp(str_ptr: *const u8) {
    crate::raw_print::print_cstr(str_ptr);
}
