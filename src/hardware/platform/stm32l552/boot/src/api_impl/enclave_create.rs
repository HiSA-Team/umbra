//! `umbra_enclave_create_imp` NSC veneer.
//! Performs validation of the NS-supplied base address, allocates ESS RAM,
//! runs the BFS-ordered block install (chained-measurement HMAC), then —
//! under `ess_miss_recovery` — force-loads any block the BFS pass missed
//! so no enclave ever sees a UDF-filled slot at runtime.

use kernel::common::enclave::UmbraEnclaveHeader;

use crate::secure_kernel::{Kernel, CODE_BLOCK_SIZE, TOTAL_BLOCK_SIZE};
use drivers::dma::Dma;
use kernel::common::enclave::EnclaveDescriptor;
// CACHE_LIMIT_PER_ENCLAVE is read inside the ess_miss_recovery force-load
// (as a no-op marker via `let _ =...`).
use kernel::common::enclave::{EnclaveContext, EnclaveState};
#[cfg(feature = "ess_miss_recovery")]
use kernel::common::ess::CACHE_LIMIT_PER_ENCLAVE;
use kernel::common::ess::MAX_EFBS;
use kernel::common::ess::{enclave_psp_top, MAX_ENCLAVES_CTX};
use umbra_error::UmbraError;

use super::debug_print::umbra_debug_print_imp;
use super::nsc_status;

static mut NEXT_ENCLAVE_ID: u32 = 1;

// --- EFB Structure Helper ---
// [HMAC (32)] [Count (1)] [Reachable (N)] [PAD] [EncData (256)]
// We assume Block 0 is at `code_flash_addr`.

// BFS-based Recursive Loader

#[no_mangle]
#[link_section = ".umbra_api_implementation"]
pub extern "C" fn umbra_enclave_create_imp(base_addr: u32) -> u32 {
    // Secure-side DWT start. Captures the full
    // create cost (validation + BFS load + chained measurement + force-
    // load + register + context init). Only the success path records;
    // error paths bail out early and would return a meaningless 'cycles
    // until failure' value. NS-side bracket is independent and lives
    // in the Tock host.
    #[cfg(feature = "bench-eval")]
    let bench_create_start = crate::bench_eval::read_cycles();

    let enclave_flash_addr: u32 = base_addr;

    let kernel = unsafe {
        match Kernel::get() {
            Some(k) => k,
            None => return 0xFFFFFFFE,
        }
    };

    if base_addr < 0x0804_0000 || base_addr >= 0x0808_0000 {
        return nsc_status(UmbraError::NscArgInvalid {
            which: "base_addr out of NS-flash range",
        });
    }
    if base_addr & 0xFFF != 0 {
        return nsc_status(UmbraError::NscArgInvalid {
            which: "base_addr not 4KB-aligned",
        });
    }
    for slot in kernel.ess.loaded_enclaves.iter() {
        if let Some(le) = slot {
            if le.descriptor.flash_base == base_addr {
                return nsc_status(UmbraError::EnclaveAlreadyLoaded {
                    id: le.descriptor.id,
                });
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
    // CJ3 guard: cap `num_blocks` against `MAX_EFBS` BEFORE the
    // multiplication. Mirrors the equivalent bound check on the N657
    // enclave-create path. Without the upper bound, a bloated
    // `header.code_size` lets `num_blocks * CODE_BLOCK_SIZE` wrap;
    // `ess.allocate(wrapped_small)` would succeed with a region sized
    // for a few blocks while the BFS loader writes `num_blocks` blocks
    // past it → cross-enclave ESS corruption + Secure-side OOB write.
    if num_blocks == 0 || (num_blocks as usize) > MAX_EFBS {
        return 0xFFFFFFF7;
    }

    // Allocate TOTAL RAM needed (NumBlocks * 64).
    // checked_mul prevents the silent wrap that C1 documents — even
    // though MAX_EFBS already bounds num_blocks, the explicit check
    // documents the invariant + guards against future MAX_EFBS bumps.
    let total_ram_needed = match num_blocks.checked_mul(CODE_BLOCK_SIZE) {
        Some(n) => n,
        None => return nsc_status(UmbraError::OffsetOverflow),
    };
    let ess_addr = match kernel.ess.allocate(total_ram_needed) {
        Ok(addr) => addr,
        Err(e) => return nsc_status(e),
    };

    // Helper closure: release ESS slots and return the given error code. Used
    // on every FAIL path between `allocate` and `register_enclave` to avoid
    // leaking the slot run on tampered / stale / under-sized blobs. Without
    // this, every `chained-measurement FAIL` would consume a few hundred
    // bytes of ESS permanently — a slow leak that eventually starves the
    // allocator for legitimate enclaves across long boot cycles.
    // We pass `&mut kernel.ess` rather than capturing `kernel` so the closure
    // can be invoked from match arms that already hold a `&kernel` borrow.
    macro_rules! ess_fail {
        ($err:expr) => {{
            kernel.ess.release(ess_addr, total_ram_needed);
            return $err;
        }};
    }

    let scratch_addr: u32 = 0x30010000;

    // Initialize EFB tracking
    use kernel::common::ess::EfbDescriptor;
    let mut efbs = [EfbDescriptor::default(); MAX_EFBS];
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
        // Bitmap for visited blocks. MUST be wide enough to cover
        // MAX_EFBS bits — u64 covers ≤64. For larger enclaves switch
        // to a chunked bitmap.
        let mut loaded_mask: u64 = 0;
        // Queue (fixed size ring buffer or simple array)
        let mut queue = [0u8; MAX_EFBS];
        let mut head = 0;
        let mut tail = 0;

        // Push Block 0
        queue[tail] = 0;
        tail += 1;
        loaded_mask |= 1u64; // Mark 0 as visited/pending

        while head < tail {
            let curr_idx = queue[head] as u32;
            head += 1;

            // Load and Verify Block
            unsafe {
                match kernel.load_and_verify_block(
                    curr_idx,
                    ess_addr,
                    scratch_addr,
                    enclave_flash_addr,
                    &mut dma,
                ) {
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
                        // BFS enqueue runs in every config, including
                        // cache-zero-mode. The original "ESS=0" design
                        // wanted no pre-loading past block 0 so every
                        // code access faults into handle_ess_miss — but
                        // L552 has no hardware trap for data reads to
                        // unloaded slots (MPCBB only gates DMA writes and
                        // cross-alias accesses; intra-alias LDR is silent
                        // and returns whatever bytes — typically the UDF
                        // pattern 0xDEDEDEDE — land in SRAM). Benchmarks
                        // with cross-block PIC literals or GOT entries
                        // (anagram, dijkstra, cjpeg_wrbmp, …) then
                        // MemManage on a wild pointer instead of hitting
                        // handle_ess_miss. So we pre-load everything
                        // BFS-reachable here; cache-zero-mode is then
                        // realised at *runtime* via the effective_limit=1
                        // gate in secure_kernel.rs::handle_ess_miss,
                        // which forces eviction-to-1 the first time a
                        // real cache miss fires.
                        if count > 0 {
                            for i in 0..count {
                                let next_blk = *meta_ptr.add(1 + i as usize);
                                if usize::from(next_blk) < MAX_EFBS {
                                    let mask = 1u64 << next_blk;
                                    if (loaded_mask & mask) == 0 {
                                        // Found new reachable block
                                        if tail < MAX_EFBS {
                                            queue[tail] = next_blk;
                                            tail += 1;
                                            loaded_mask |= mask;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => ess_fail!(e),
                }
            }
        }
    } else {
        ess_fail!(0xFFFFFFFB);
    }

    // Fold the on-flash static-PIE reloc table into the chained measurement.
    // protect_enclave.py emits exactly this step at sign time AFTER the
    // BFS-ordered block fold: feeding the raw u32 reloc-offset bytes as a
    // final HMAC update. Doing the same here makes the kernel detect
    // on-flash tampering of the reloc list BEFORE `apply_relocs_to_block`
    // is ever called (BFS install path already trusted the offsets to
    // point at valid 32-bit slots within freshly-decrypted blocks; the
    // catch happens at finalize, the BFS work is wasted but no security
    // breach). reloc_count = 0 is the light-app case → no-op.
    #[cfg(feature = "chained_measurement")]
    {
        // Pack-misalign copy-out (avoid pack-field reference aliasing).
        let n_relocs = { header.reloc_count } as u32;
        if n_relocs > 0 {
            use kernel::common::enclave::UMBRA_HEADER_SIZE;
            let code_size = { header.code_size };
            // CJ3 + CJ2 guard: use `checked_add` / `checked_mul` on the
            // attacker-controlled offsets. Without these checks,
            // `code_size + UMBRA_HEADER_SIZE` could wrap and
            // `from_raw_parts` on the resulting pointer is UB BEFORE the
            // chained HMAC even runs. The chain detects tampering of the
            // table contents but cannot catch a wrapped pointer that
            // aliases unrelated flash regions.
            let reloc_table_flash = match enclave_flash_addr
                .checked_add(UMBRA_HEADER_SIZE)
                .and_then(|x| x.checked_add(code_size))
            {
                Some(addr) => addr,
                None => ess_fail!(nsc_status(UmbraError::OffsetOverflow)),
            };
            let reloc_len_bytes = match (n_relocs as usize).checked_mul(4) {
                Some(n) => n,
                None => ess_fail!(nsc_status(UmbraError::OffsetOverflow)),
            };
            let reloc_bytes = unsafe {
                core::slice::from_raw_parts(reloc_table_flash as *const u8, reloc_len_bytes)
            };
            if let Some(crypto_engine) = kernel.crypto.as_mut() {
                use kernel::key_storage_server::key_generator::KeyGenerator;
                let mut generator = KeyGenerator::new(*crypto_engine);
                #[cfg(feature = "bench-eval")]
                let _cg = crate::bench_eval::CryptoGuard::start();
                if generator
                    .update_chain(&mut kernel.chain_state, reloc_bytes)
                    .is_err()
                {
                    ess_fail!(0xFFFFFFFA);
                }
            } else {
                ess_fail!(0xFFFFFFF9);
            }
        }
    }

    // Finalize the chained measurement: compare against the reference HMAC in
    // the enclave header. On mismatch we emit a marker for the smoke test and
    // refuse to register the enclave.
    #[cfg(feature = "chained_measurement")]
    {
        let expected: [u8; 32] = header.hmac;
        if kernel.finalize_measurement(&expected).is_err() {
            umbra_debug_print_imp(b"[UMBRASecureBoot] chained-measurement FAIL\n\0".as_ptr());
            ess_fail!(0xFFFFFFF6);
        }
        #[cfg(feature = "boot_tests")]
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

    if !kernel
        .ess
        .register_enclave(descriptor, ess_addr, efbs, efb_count)
    {
        ess_fail!(0xFFFFFFF8);
    }

    // Force-load every block at create time so the enclave never sees
    // an UDF-filled slot at runtime. The previous design evicted all
    // non-entry blocks here, relying on Secure-alias reads to NS slots
    // raising BusFault for the handle_ess_miss recovery path. But L552
    // MPCBB has SRWILADIS=0 by default, meaning Secure reads to NS
    // slots silently return the underlying bytes (0xDEDEDEDE for
    // UDF-filled slots) without faulting. Enclaves with disconnected
    // BFS components (e.g., ndes blocks 13/14, statemate block 40 —
    // reachable only via indirect branches that parse_disassembly
    // doesn't detect) would read UDF garbage and compute wild pointers,
    // eventually MemManage'ing with `addr outside any enclave`.
    // Solution: load ANY block the BFS pass didn't visit via
    // handle_ess_miss (per-block HMAC validation, not chained-folded).
    // BFS-loaded blocks already have validated chained-measurement and
    // valid plaintext in their ESS slot, so leave them alone. This
    // gives us "all blocks loaded after create" with the same security
    // properties: chained-measurement covers BFS-reachable graph,
    // per-block HMAC covers disconnected components.
    // Force-load runs in every config, including cache-zero-mode. Same
    // reasoning as the BFS enqueue above: without a HW data-read trap
    // we cannot let any block stay UDF-filled at boot, because the first
    // cross-block PIC/GOT literal read would walk into wild-pointer
    // MemManage instead of hitting handle_ess_miss. Cache-zero-mode is
    // realised purely at runtime via effective_limit=1 in
    // secure_kernel.rs::handle_ess_miss (first real miss forces
    // eviction-to-1; benchmarks whose BFS already covers everything
    // never actually hit a runtime miss, so cache=0 collapses into
    // cache=N for them — a measurement caveat documented in the paper).
    #[cfg(feature = "ess_miss_recovery")]
    unsafe {
        let _ = CACHE_LIMIT_PER_ENCLAVE;
        // DIAGNOSTIC: confirm we reach this path (will disappear once
        // ndes/statemate are known-good).
        umbra_debug_print_imp(b"[UMBRASecureBoot] force-load start\n\0".as_ptr());
        if let Some(mut force_dma) = Dma::new() {
            force_dma.reserve_ch(0, 0);
            force_dma.reserve_ch(0, 1);
            force_dma.reserve_ch(0, 3);
            force_dma.reserve_ch(0, 4);
            force_dma.reserve_ch(0, 5);
            force_dma.reserve_ch(0, 6);
            force_dma.reserve_ch(0, 7);
            // Re-look up the freshly-registered enclave for per-block
            // is_loaded state. handle_ess_miss bounds-checks against
            // efb_count internally (won't update is_loaded for indices
            // >= efb_count) — so we ALSO bump efb_count up to num_blocks
            // here BEFORE the force-load loop, otherwise the loaded
            // blocks past the BFS-visited set get installed in SRAM but
            // remain flagged is_loaded=false and is_recoverable=false.
            if let Some(slot) = kernel
                .ess
                .loaded_enclaves
                .iter_mut()
                .flatten()
                .find(|e| e.descriptor.id == assigned_id)
            {
                if (num_blocks as usize) <= MAX_EFBS && slot.efb_count < num_blocks as usize {
                    slot.efb_count = num_blocks as usize;
                }
            }
            let mut loaded_extra: u32 = 0;
            let mut failed: u32 = 0;
            for idx in 1..(num_blocks as usize) {
                if idx >= MAX_EFBS {
                    break;
                }
                let already_loaded = kernel
                    .ess
                    .loaded_enclaves
                    .iter()
                    .flatten()
                    .find(|e| e.descriptor.id == assigned_id)
                    .map(|e| e.efbs[idx].is_loaded)
                    .unwrap_or(false);
                if !already_loaded {
                    match kernel.handle_ess_miss(assigned_id, idx as u32, &mut force_dma, false) {
                        Ok(()) => {
                            loaded_extra += 1;
                        }
                        Err(_) => {
                            failed += 1;
                        }
                    }
                }
            }
            // DIAGNOSTIC: how many extra blocks force-loaded, how many
            // failed. PASS expectations: failed=0; loaded_extra ≥ 0 for
            // every enclave (>0 only when BFS missed some).
            umbra_debug_print_imp(b"[UMBRASecureBoot] force-load done loaded=\0".as_ptr());
            crate::raw_print::print_hex(loaded_extra);
            crate::raw_print::print_str(" failed=");
            crate::raw_print::print_hex(failed);
            crate::raw_print::print_str("\n");
        } else {
            umbra_debug_print_imp(
                b"[UMBRASecureBoot] force-load: Dma::new() returned None\n\0".as_ptr(),
            );
        }
    }

    // Demand-paging eviction intentionally REMOVED. The idea was to evict
    // all-but-block-0 here so code-only enclaves demand-page at runtime and the
    // overhead-vs-ESS-size curve reappears. Hardware proved it unsafe on L552:
    // with bsort (4 blocks, 3 evicted) the runtime ESS-miss counter
    // (`bench_eval::record_miss`) read 0 — the enclave never faulted, because
    // cross-block DATA loads to evicted slots have no hardware trap and silently
    // return UDF (0xDEDEDEDE), corrupting the computation without a miss. The
    // `protect_enclave.py` reloc_count guard does NOT catch this (direct in-blob
    // data loads are not relocations). See
    // docs/superpowers/specs/2026-06-21-demand-paging-mode-design.md. The
    // `demand-paging` feature + guard are kept as scaffold; eviction is not
    // reintroducible until the target has a hardware data-read trap.
    unsafe {
        NEXT_ENCLAVE_ID += 1;
    }

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
            core::ptr::write_volatile(frame.add(0), 0); // r0
            core::ptr::write_volatile(frame.add(1), 0); // r1
            core::ptr::write_volatile(frame.add(2), 0); // r2
            core::ptr::write_volatile(frame.add(3), 0); // r3
            core::ptr::write_volatile(frame.add(4), 0); // r12
            core::ptr::write_volatile(frame.add(5), 0xFFFF_FFFF); // LR (end-of-task)
            core::ptr::write_volatile(frame.add(6), secure_entry); // PC = Secure-alias entry
            core::ptr::write_volatile(frame.add(7), 0x0100_0000); // xPSR (Thumb)
        }

        kernel.enclave_contexts[enclave_idx] = EnclaveContext {
            r4: 0,
            r5: 0,
            r6: 0,
            r7: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
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

    // Secure-side DWT end + record. Only fires
    // on the success path (assigned_id below is the implicit return).
    // u32 wrap at 110 MHz happens every ~39 s; create is well under
    // that even for the largest paper-app blobs (~60 ms = 6.6M cycles
    // for statemate per pre-Stage-A measurements).
    #[cfg(feature = "bench-eval")]
    {
        let end = crate::bench_eval::read_cycles();
        let delta = end.wrapping_sub(bench_create_start);
        crate::bench_eval::record_boot_sec_cycles(delta);
    }

    assigned_id
}
