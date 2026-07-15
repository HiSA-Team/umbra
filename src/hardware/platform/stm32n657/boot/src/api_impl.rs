//! NSC API implementations for STM32N657.
//! These `_imp` functions are called by the NSC veneers in
//! kernel/asm/arm/nsc_veneers.s. The veneers do `sg`, push the link, BL
//! into the implementation, then BXNS back to the NS host.
//! Responsibilities:
//! - `umbra_enclave_create_imp` validates the UMBR header at the supplied
//! flash address, allocates ESS via the kernel allocator, copies block 0
//! from flash via `kernel.load_block_n657`, UDF-fills the remaining
//! blocks, and registers the enclave.
//! - `umbra_enclave_enter_imp` / `_exit_imp` / `_status_imp` drive enclave
//! execution; the kernel API is platform-agnostic now that ESS layout
//! is feature-gated.
//! - The UsageFault dispatcher in handlers.rs reuses
//! `kernel.load_block_n657` to fetch a faulting (UDF-filled) block on
//! demand.

use arm::mmio::{ICIALLU, MPU_RBAR, MPU_RLAR, MPU_RNR};
use kernel::common::enclave::{
    EnclaveContext, EnclaveDescriptor, EnclaveState, UmbraEnclaveHeader, UMBRA_HEADER_SIZE,
};
use kernel::common::ess::{
    enclave_psp_top, EfbDescriptor, ENCLAVE_PSP_STACK_SIZE, MAX_EFBS, MAX_ENCLAVES_CTX,
};
// The shared 16 KB EFBC window base — both overlay enclaves live here, time-multiplexed.
#[cfg(feature = "interenclave_overlay")]
use kernel::common::ess::ESS_BASE;

use crate::secure_kernel::{
    Kernel, BLOCK_HEADER_SIZE, BLOCK_META_OFFSET, BLOCK_META_SIZE, CODE_BLOCK_SIZE,
    TOTAL_BLOCK_SIZE,
};
use umbra_error::UmbraError;

static mut NEXT_ENCLAVE_ID: u32 = 1;

/// Map a typed [`UmbraError`] onto the frozen NSC ABI `u32` status code.
/// Mirror of the L552 `api_impl::nsc_status`; the NS host only tests
/// `id >= 0xFFFF_FFF0` (`host/stm32n657/.../main.c`), so the per-variant
/// codes are for log/diagnosis clarity, not host branching.
fn nsc_status(e: UmbraError) -> u32 {
    match e {
        UmbraError::EnclaveNotFound { .. } => 0xFFFF_FFF0,
        UmbraError::EnclaveStateInvalid => 0xFFFF_FFF2,
        UmbraError::EnclaveAlreadyLoaded { .. } => 0xFFFF_FFF4,
        UmbraError::DmaTimeout => 0xFFFF_FFF5,
        UmbraError::NscArgInvalid { .. } => 0xFFFF_FFF6,
        UmbraError::OffsetOverflow => 0xFFFF_FFF7,
        UmbraError::MeasurementMismatch { .. } => 0xFFFF_FFF8,
        UmbraError::MemProtectDenied { .. } => 0xFFFF_FFF9,
        UmbraError::KeyDerivation => 0xFFFF_FFFA,
        UmbraError::LengthMismatch => 0xFFFF_FFFB,
        UmbraError::HashHardware => 0xFFFF_FFFC,
        UmbraError::EssRegionExhausted => 0xFFFF_FFFD,
        UmbraError::AesHardware => 0xFFFF_FFFE,
        UmbraError::InternalInvariant { .. } => 0xFFFF_FFFF,
    }
}

/// Chained-measurement update for a single loaded block.
/// Builds the per-block HMAC input as `[block_id (4) | code (256) |
/// meta (32)]` — the same layout `protect_enclave.py` uses when it
/// computes the running chain offline. The code half is read back from
/// ESS (just installed by `load_block_n657`); the meta half comes from
/// flash since we don't keep it in RAM. `chain_state = HMAC-SHA256(/// chain_state, verify_buf)`.
fn update_chain(
    chain_state: &mut [u8; 32],
    block_idx: u32,
    ess_base: u32,
    enclave_flash_base: u32,
    hash: &mut drivers::hash::Hash,
) -> umbra_error::UmbraResult<()> {
    let mut verify_buf = [0u8; 4 + CODE_BLOCK_SIZE as usize + BLOCK_META_SIZE as usize];

    let id_bytes = block_idx.to_le_bytes();
    verify_buf[0] = id_bytes[0];
    verify_buf[1] = id_bytes[1];
    verify_buf[2] = id_bytes[2];
    verify_buf[3] = id_bytes[3];

    unsafe {
        // Code half: read back from ESS where load_block_n657 just wrote it.
        // Checked: a corrupt block_idx must not wrap into an aliased pointer
        // fed to read_volatile inside the measurement chain (CJ2).
        let code_off = block_idx
            .checked_mul(CODE_BLOCK_SIZE)
            .ok_or(UmbraError::OffsetOverflow)?;
        let ess_src = ess_base
            .checked_add(code_off)
            .ok_or(UmbraError::OffsetOverflow)? as *const u8;
        let mut i: usize = 0;
        while i < CODE_BLOCK_SIZE as usize {
            verify_buf[4 + i] = core::ptr::read_volatile(ess_src.add(i));
            i += 1;
        }
        // Meta half: read straight from flash (memory-mapped XSPI2).
        // BLOCK_META_OFFSET is feature-gated in secure_kernel (0 for
        // chained_measurement, 32 for ess_miss_recovery) so referencing it
        // here keeps the constant exercised.
        let blk_off = block_idx
            .checked_mul(TOTAL_BLOCK_SIZE)
            .ok_or(UmbraError::OffsetOverflow)?;
        let meta_src = enclave_flash_base
            .checked_add(UMBRA_HEADER_SIZE)
            .and_then(|x| x.checked_add(blk_off))
            .and_then(|x| x.checked_add(BLOCK_META_OFFSET))
            .ok_or(UmbraError::OffsetOverflow)? as *const u8;
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
    Ok(())
}

/// Side-effect-free authentication of the enclave blob at `base_addr`: runs the SAME
/// chained measurement `umbra_enclave_create_imp` runs, then derives the version, but
/// registers NOTHING and does NOT bump the anti-rollback floor. Returns `Some(version)`
/// if the blob authenticates, `None` on any failure (bad header, over-size, measurement
/// mismatch, rollback below floor). Used by the `base_addr == 0` create-by-best-slot
/// sentinel to pick the higher authenticated of the A/B update slots, and by
/// `umbra_enclave_update_imp` to re-verify a freshly-written slot from flash.
///
/// With `enclave_version_bind` OFF every valid blob authenticates to version 0, so the
/// update path's `version > active` check can never advance (all slots tie at 0); the
/// secure-update feature is only meaningful with `enclave_version_bind` ON (ADR 013).
///
/// `kernel.chain_state` is reused as the fold accumulator: the real create re-seeds it
/// via `begin_measurement`, so clobbering it here is fine (this always runs before the
/// real create body re-measures the chosen slot).
///
/// **DMA-free / allocator-free / overlay-independent.** Blocks are folded by
/// CPU-reading the memory-mapped flash slot DIRECTLY, not by DMA-loading into ESS. The
/// A/B update slots sit outside MCE2, so the mapped bytes are the exact plaintext
/// `load_block_n657` would have DMAed into ESS — the measurement is byte-identical to the
/// real create's. This keeps the probe independent of the ESS allocator AND the shared
/// overlay window, so create-by-best-slot and the secure-update path COEXIST with
/// `interenclave_overlay` (the default feature) with no gating.
pub(crate) fn authenticated_version_at(base_addr: u32) -> Option<u32> {
    let kernel = unsafe { Kernel::get()? };

    if base_addr < 0x7000_0000 || base_addr >= 0x8000_0000 || base_addr & 0xF != 0 {
        return None;
    }

    let header = unsafe { UmbraEnclaveHeader::from_address(base_addr)? };
    let num_blocks = header.code_size / TOTAL_BLOCK_SIZE;
    if num_blocks == 0 || (num_blocks as usize) > MAX_EFBS {
        return None;
    }

    // Fold every block straight from flash (no ESS, no DMA, no overlay dependency).
    kernel.begin_measurement();
    let mut hash = drivers::hash::Hash::new();
    let mut blk: u32 = 0;
    while blk < num_blocks {
        fold_block_from_flash(&mut kernel.chain_state, blk, base_addr, &mut hash)?;
        blk += 1;
    }

    // Derive the version WITHOUT bumping the floor or registering anything.
    #[cfg(not(feature = "enclave_version_bind"))]
    let result = if kernel.finalize_measurement(&header.hmac).is_ok() {
        // All valid blobs are "version 0"; select_active_slot then picks A on a tie.
        Some(0)
    } else {
        None
    };
    #[cfg(feature = "enclave_version_bind")]
    let result = {
        // `MonotonicCounter` brings `.floor()` into scope (trait method on BackupFloorCounter).
        use kernel::key_storage_server::version_search::{search_version, MonotonicCounter};
        let bm = kernel.chain_state;
        let author_id = crate::secure_kernel::AUTHOR_ID;
        let ctr = crate::antirollback::BackupFloorCounter::new();
        let floor = ctr.floor(author_id);
        // DO NOT bump: this is a read-only probe.
        search_version(&header.hmac, floor, |v| {
            crate::secure_kernel::version_tag(&mut hash, &bm, author_id, v)
        })
    };

    result
}

/// Fold one block into the running measurement chain by reading it DIRECTLY from the
/// memory-mapped flash slot (CPU, no DMA). Builds the same `[block_id(4) | code(256) |
/// meta(32)]` preimage `update_chain` folds, but reads BOTH halves from flash: the code
/// at `base + UMBRA_HEADER_SIZE + blk*TOTAL_BLOCK_SIZE + BLOCK_HEADER_SIZE` (where
/// `load_block_n657` would have copied it from) and the meta at `... + BLOCK_META_OFFSET`.
/// Returns `None` on address overflow. Used only by the side-effect-free probe.
/// KEEP IN SYNC with `update_chain` (the ESS-backed real-create fold).
fn fold_block_from_flash(
    chain_state: &mut [u8; 32],
    blk: u32,
    enclave_flash_base: u32,
    hash: &mut drivers::hash::Hash,
) -> Option<()> {
    let mut verify_buf = [0u8; 4 + CODE_BLOCK_SIZE as usize + BLOCK_META_SIZE as usize];
    verify_buf[..4].copy_from_slice(&blk.to_le_bytes());

    let blk_off = blk.checked_mul(TOTAL_BLOCK_SIZE)?;
    let block_base = enclave_flash_base
        .checked_add(UMBRA_HEADER_SIZE)?
        .checked_add(blk_off)?;
    let code_src = block_base.checked_add(BLOCK_HEADER_SIZE)? as *const u8;
    let meta_src = block_base.checked_add(BLOCK_META_OFFSET)? as *const u8;

    // SAFETY: both addresses are inside the memory-mapped XSPI2 window for a bounded
    // block index (num_blocks ≤ MAX_EFBS at the call site); reads are read-only.
    unsafe {
        let mut i = 0usize;
        while i < CODE_BLOCK_SIZE as usize {
            verify_buf[4 + i] = core::ptr::read_volatile(code_src.add(i));
            i += 1;
        }
        let mut j = 0usize;
        while j < BLOCK_META_SIZE as usize {
            verify_buf[4 + CODE_BLOCK_SIZE as usize + j] = core::ptr::read_volatile(meta_src.add(j));
            j += 1;
        }
    }

    let mut out = [0u8; 32];
    hash.hmac_sha256(chain_state, &verify_buf, &mut out);
    *chain_state = out;
    Some(())
}

#[no_mangle]
#[link_section = ".umbra_api_implementation"]
pub extern "C" fn umbra_enclave_create_imp(base_addr: u32) -> u32 {
    // base_addr == 0 = "auto-select best enclave slot": authenticate both A/B update
    // slots and create from the highest version. The probe (`authenticated_version_at`)
    // is DMA-free and reads flash directly, so this works in BOTH the default
    // (interenclave_overlay) and non-overlay builds. The chosen concrete base then flows
    // into the create body unchanged, which RE-measures + registers + bumps the floor for
    // real (under overlay it evicts + loads at ESS_BASE like any other base). Yes this
    // measures the chosen slot twice (a few ms); acceptable for a rare create-time
    // selection. This runs BEFORE we take the &'static mut kernel borrow below, so
    // authenticated_version_at's own Kernel::get() does not alias it.
    let base_addr = if base_addr == 0 {
        use drivers::state_flash::{ENCLAVE_SLOT_A, ENCLAVE_SLOT_B};
        use kernel::key_storage_server::enclave_update::select_active_slot;
        let va = authenticated_version_at(ENCLAVE_SLOT_A);
        let vb = authenticated_version_at(ENCLAVE_SLOT_B);
        match select_active_slot(va, vb) {
            Some(0) => ENCLAVE_SLOT_A,
            Some(1) => ENCLAVE_SLOT_B,
            _ => return nsc_status(UmbraError::EnclaveNotFound { id: 0 }),
        }
    } else {
        base_addr
    };

    let kernel = unsafe {
        match Kernel::get() {
            Some(k) => k,
            None => return 0xFFFF_FFFE,
        }
    };

    // 1. Validate flash range — XSPI2 memory-mapped at 0x70000000 (256 MB).
    if base_addr < 0x7000_0000 || base_addr >= 0x8000_0000 {
        return nsc_status(UmbraError::NscArgInvalid {
            which: "base_addr out of XSPI2 range",
        });
    }
    if base_addr & 0xF != 0 {
        return nsc_status(UmbraError::NscArgInvalid {
            which: "base_addr not 16-byte-aligned",
        });
    }
    // Reject re-creating an enclave from a flash base already loaded. The
    // L552 path has always had this guard; N657 was missing it, which let a
    // second `tee_create(same_base)` install the same blob into a new slot.
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
    // on flash). num_blocks × CODE_BLOCK_SIZE. checked_mul mirrors the L552
    // guard: a bloated header.code_size must not wrap and under-allocate.
    let total_ram_needed = match num_blocks.checked_mul(CODE_BLOCK_SIZE) {
        Some(n) => n,
        None => return nsc_status(UmbraError::OffsetOverflow),
    };

    // Lazy reap: free the EFBC window + registration slot of any already-terminated
    // (or faulted) enclave before allocating. `terminate` leaves them live so the NS
    // host can read their result via `umbra_enclave_status` post-terminate; this is
    // where they are actually freed, so a fresh create can reuse the tight 16 KB /
    // 64-block N657 window (running two enclaves in one boot otherwise leaks the slots
    // → EssRegionExhausted on the 2nd create). `.as_ref().map` copies the extent so the
    // shared borrow ends before the mutable release. create re-inits the reused
    // context to `Ready` below, so a reaped slot is clean for the new enclave.
    for i in 0..MAX_ENCLAVES_CTX {
        let done = matches!(
            kernel.enclave_contexts[i].status,
            EnclaveState::Terminated | EnclaveState::Faulted
        );
        if !done {
            continue;
        }
        let extent = kernel.ess.loaded_enclaves[i]
            .as_ref()
            .map(|le| (le.start_address, le.descriptor.code_size));
        if let Some((start, size)) = extent {
            kernel.ess.release(start, size);
            kernel.ess.loaded_enclaves[i] = None;
        }
    }

    // Overlay: the two live enclaves share the ESS window (both blobs linked to ESS_BASE); the
    // 2nd enclave's `allocate` would fail (window full of the 1st), so bypass the allocator,
    // evict the currently-resident enclave's image → its SRAM backing (it survives there for a
    // restore-on-enter), and load THIS enclave fresh at ESS_BASE. Non-overlay builds keep the
    // normal per-enclave bump allocation.
    #[cfg(feature = "interenclave_overlay")]
    let ess_addr = {
        unsafe { crate::prefetch::overlay::evict_current(ESS_BASE) };
        ESS_BASE
    };
    #[cfg(not(feature = "interenclave_overlay"))]
    let ess_addr = match kernel.ess.allocate(total_ram_needed) {
        Ok(addr) => addr,
        Err(e) => return nsc_status(e),
    };

    // Helper macro: release the ESS slots reserved above and return the
    // given error code. Used on every FAIL path between `allocate` and
    // `register_enclave` to avoid leaking the slot run on tampered /
    // stale / under-sized blobs. Without this, every chained-measurement
    // FAIL would consume the run of ESS slots permanently — a slow leak
    // that eventually starves the allocator for legitimate enclaves.
    // Mirror of `ess_fail!` in stm32l552/boot/src/api_impl/enclave_create.rs:100-105.
    // boot-chain audit finding.
    macro_rules! ess_fail {
        ($err:expr) => {{
            kernel.ess.release(ess_addr, total_ram_needed);
            return $err;
        }};
    }

    // 4. Chained measurement: seed chain_state with the master key, then
    // load each block sequentially from flash and fold its
    // [block_id | code | meta] into the running HMAC chain.
    // `protect_enclave.py` builds the same chain offline in numeric
    // order and stamps the final value into header.hmac.
    // KEEP IN SYNC with `authenticated_version_at` (the side-effect-free probe
    // that runs the identical load+fold+derive for create-by-best-slot): a change
    // to the block layout, `update_chain`, or the version-derive must land in both.
    kernel.begin_measurement();
    let mut hash = drivers::hash::Hash::new();

    let mut blk: u32 = 0;
    while blk < num_blocks {
        if let Err(e) = unsafe { kernel.load_block_n657(blk, ess_addr, base_addr) } {
            ess_fail!(e);
        }
        if let Err(e) = update_chain(&mut kernel.chain_state, blk, ess_addr, base_addr, &mut hash) {
            ess_fail!(nsc_status(e));
        }
        blk += 1;
    }

    // I-cache invalidate covers the freshly loaded code for all blocks.
    unsafe {
        cortex_m::asm::dsb();
        core::ptr::write_volatile(ICIALLU, 0);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
    }

    // 5. Finalize. Default (feature off): legacy chained-measurement compare.
    // Mismatch = the on-flash blob has been tampered with (or the host's
    // protect_enclave.py used a different master key).
    #[cfg(not(feature = "enclave_version_bind"))]
    {
        if kernel.finalize_measurement(&header.hmac).is_err() {
            crate::raw_print::print_str("[UMBRASecureBoot] chained-measurement FAIL\r\n");
            ess_fail!(0xFFFF_FFF6);
        }
    }
    // Feature on: derive the enclave version from the measurement and enforce
    // anti-rollback. `kernel.chain_state` is BM (the version-independent block
    // measurement); the version is bound by the offline trailing fold and is
    // never stored in clear. Search candidates from the per-author floor; the
    // one reproducing header.hmac is the authenticated version. Below floor =>
    // below the search start => rejected (rollback). BM is MASTER_KEY-derived so
    // header.hmac is unforgeable for attacker code.
    #[cfg(feature = "enclave_version_bind")]
    {
        use kernel::key_storage_server::version_search::{search_version, MonotonicCounter};
        let bm = kernel.chain_state;
        let author_id = crate::secure_kernel::AUTHOR_ID;
        let mut ctr = crate::antirollback::BackupFloorCounter::new();
        let floor = ctr.floor(author_id);
        let derived = search_version(&header.hmac, floor, |v| {
            crate::secure_kernel::version_tag(&mut hash, &bm, author_id, v)
        });
        match derived {
            None => {
                crate::raw_print::print_str("[UMBRASecureBoot] version DENIED (rollback/tamper/out-of-window)\r\n");
                ess_fail!(0xFFFF_FFF6);
            }
            Some(v) => {
                ctr.bump(author_id, v);
                kernel.last_version = v;
                if floor == 0 {
                    crate::raw_print::print_str("[UMBRASecureBoot] rollback floor cold (0) — VBAT-trust assumed\r\n");
                }
                // Always confirm on the UART, cold or not — a silent pass on a
                // non-zero floor was indistinguishable from the feature being
                // compiled out entirely, which cost a debugging round-trip.
                crate::raw_print::print_str("[UMBRASecureBoot] enclave version OK (author=");
                crate::raw_print::print_hex(author_id);
                crate::raw_print::print_str(", version=");
                crate::raw_print::print_hex(v);
                crate::raw_print::print_str(")\r\n");
            }
        }
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
    if !kernel
        .ess
        .register_enclave(descriptor, ess_addr, efbs, num_blocks as usize)
    {
        ess_fail!(0xFFFF_FFF8);
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
    // Overlay: this enclave's image is now loaded fresh at ESS_BASE — mark it resident so the
    // next create/enter evicts it before reusing the window.
    #[cfg(feature = "interenclave_overlay")]
    crate::prefetch::overlay::set_resident(enclave_idx);
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
            core::ptr::write_volatile(frame.add(6), ess_addr); // PC = entry
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
            // EXC_RETURN 0xFFFFFFFD = Thread mode, PSP, Secure, FType=1 (no FP).
            lr: 0xFFFF_FFFD,
            control: 0x03, // PRIV=0 (unprivileged), SPSEL=1 (PSP)
            status: EnclaveState::Ready,
            result: 0,
        };

        // State-continuity restore hook: if a checkpoint for this enclave
        // survived a reset, restore it over the fresh context so the following
        // `enter` RESUMES from the yield point (its status comes back Suspended,
        // which `umbra_enclave_enter_imp` already treats as resume) instead of
        // cold-starting at the entry point. A cold anchor short-circuits with no
        // flash read; a mismatched/replayed anchor returns false -> fresh start.
        // state_root is Copy, so snapshot it to avoid borrowing kernel twice.
        let state_root = kernel.state_root;
        let decision = crate::secure_kernel::state_checkpoint::restore_enclave_decision(
            assigned_id,
            enclave_idx,
            &mut kernel.enclave_contexts[enclave_idx],
            &state_root,
        );
        // The &mut enclave_contexts[idx] borrow has ended, so recording the
        // decision on the kernel is safe. 1=Resume 2=ColdGenesis 3=Reject.
        kernel.last_restore = decision;
        if decision == 1 {
            crate::raw_print::print_str("[SC] create: resumed enclave from checkpoint\r\n");
        }
    }

    unsafe {
        NEXT_ENCLAVE_ID += 1;
    }
    assigned_id
}

/// Reprogram MPU regions 4 (enclave stack) and 5 (enclave code) for `enclave_idx` — the ONLY
/// per-enclave regions (6-9 are fixed shared/NPU windows, identical for every enclave). The
/// Phase 4.2 SysTick overlay scheduler context-switches to another enclave WITHOUT returning
/// through `umbra_enclave_enter_imp`, so its per-enclave stack region (`enclave_psp_top(idx)`)
/// and code extent (`start_address + code_size`) must be reloaded here or the exception-return
/// unstacking from the incoming enclave's PSP faults MemManage (MUNSTKERR, CFSR bit 3). Mirrors
/// the regions-4/5 block inside `umbra_enclave_enter_imp`.
#[cfg(feature = "interenclave_overlay")]
pub(crate) unsafe fn overlay_reconfigure_mpu(
    kernel: &crate::secure_kernel::Kernel,
    enclave_idx: usize,
) {
    let mpu_rbar = MPU_RBAR;
    let mpu_rlar = MPU_RLAR;
    let mpu_rnr = MPU_RNR;

    let psp_base = enclave_psp_top(enclave_idx) - ENCLAVE_PSP_STACK_SIZE;
    let psp_limit = enclave_psp_top(enclave_idx) - 1;
    core::ptr::write_volatile(mpu_rnr, 4);
    core::ptr::write_volatile(mpu_rbar, (psp_base & 0xFFFF_FFE0) | (0b01 << 1) | 0x01);
    core::ptr::write_volatile(mpu_rlar, (psp_limit & 0xFFFF_FFE0) | 0x01);

    if let Some(le) = &kernel.ess.loaded_enclaves[enclave_idx] {
        let code_base = le.start_address;
        let code_limit = code_base + le.descriptor.code_size - 1;
        core::ptr::write_volatile(mpu_rnr, 5);
        core::ptr::write_volatile(mpu_rbar, (code_base & 0xFFFF_FFE0) | (0b01 << 1));
        core::ptr::write_volatile(mpu_rlar, (code_limit & 0xFFFF_FFE0) | 0x01);
    }

    cortex_m::asm::dsb();
    cortex_m::asm::isb();
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
            None => return nsc_status(UmbraError::EnclaveNotFound { id: enclave_id }),
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
            return ((enclave_id & 0xFFFF) << 16) | ((EnclaveState::Faulted as u32 & 0xFF) << 8);
        }
        _ => return nsc_status(UmbraError::EnclaveStateInvalid),
    }

    ctx.status = EnclaveState::Running;
    let _ = ctx;

    kernel.current_enclave_id = Some(enclave_id);

    // Overlay: if this enclave is not the one currently in the shared 16 KB EFBC window, switch
    // — evict the resident enclave's image → its SRAM backing and restore THIS enclave's image ←
    // its backing (whole-window DMA). The first enter right after create is a no-op (create
    // marked it resident). Region 5 + the context frame below then resume this enclave on its
    // just-restored code. Driven per-enter by the host loop (and, later, SysTick preemption).
    #[cfg(feature = "interenclave_overlay")]
    unsafe {
        crate::prefetch::overlay::make_resident(enclave_idx, ESS_BASE, false);
    }

    // Configure MPU regions 4 (stack) and 5 (code) for unprivileged access.
    // The enclave runs with CONTROL.PRIV=0 so the default memory map
    // (PRIVDEFENA=1) does not apply — explicit MPU regions are mandatory.
    unsafe {
        let mpu_rbar = MPU_RBAR;
        let mpu_rlar = MPU_RLAR;
        let mpu_rnr = MPU_RNR;

        let psp_base = enclave_psp_top(enclave_idx) - ENCLAVE_PSP_STACK_SIZE;
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
            let code_base = le.start_address;
            let code_limit = code_base + le.descriptor.code_size - 1;
            core::ptr::write_volatile(mpu_rnr, 5);
            // Region 5: enclave code+data, AP=0b01 (RW any privilege), XN=0 (executable) —
            // mirrors L552 enclave_enter.rs. Under `-fpic -mpic-data-is-text-relative` the
            // enclave's .data/.bss are text-relative, i.e. inside this image; a RO region
            // (the old 0b11) faults any global write (DACCVIOL) — real enclaves with globals
            // (ammunition) need RW here. HARDENING TODO: split .text (RO+exec) from .data/.bss
            // (RW+XN) via a linker boundary symbol so code stays non-writable (no self-modify).
            core::ptr::write_volatile(mpu_rbar, (code_base & 0xFFFF_FFE0) | (0b01 << 1));
            core::ptr::write_volatile(mpu_rlar, (code_limit & 0xFFFF_FFE0) | 0x01);
            // Phase 2b probe: hide the entry block by shrinking region 5 — the enclave's
            // first fetch faults MemManage, and the handler restores + resumes. Proves the
            // MPU trap+restore (the sync data trap the RISAF cannot give).
            #[cfg(feature = "mpu_evict_probe")]
            crate::prefetch::mpu_evict::evict_front(code_base, code_limit, 256);
            // Inter-enclave eviction Step 1: evict A's EFBC → ESS, scramble, restore →
            // proves the round-trip preserves the enclave (the feasible eviction on N657).
            #[cfg(feature = "interenclave_evict")]
            if crate::prefetch::inter_evict::round_trip(code_base, le.descriptor.code_size) {
                crate::raw_print::print_str("[INTER-EVICT] EFBC evict->ESS->restore round-trip done\n");
            }
            // Async ESS-miss demonstrator: evict the enclave's back half to a backing +
            // MPU-hide it, then async-restore it in the BACKGROUND while the enclave runs its
            // front half. The prefetch reveals the tail (HIT) or the enclave faults into it
            // first and the fallback restores synchronously (FAULT) — either way it completes.
            #[cfg(feature = "async_ess_miss")]
            crate::prefetch::async_ess::arm(code_base, code_limit, le.descriptor.code_size);
        }
        // Region 6: INPUT_SHARED (host writes 224×224×3 image, enclave
        // reads). RW unprivileged, no execute. Backed by the INPUT_SHARED
        // MEMORY entry in host/stm32n657/object_detection/linker/memory.ld.
        core::ptr::write_volatile(mpu_rnr, 6);
        core::ptr::write_volatile(mpu_rbar, (0x24080000u32 & 0xFFFF_FFE0) | (0b01 << 1) | 0x01);
        core::ptr::write_volatile(mpu_rlar, (0x240BFFE0u32 & 0xFFFF_FFE0) | 0x01);

        // Region 7: OUTPUT_SHARED (enclave writes detections, host reads).
        // RW unprivileged, no execute.
        core::ptr::write_volatile(mpu_rnr, 7);
        core::ptr::write_volatile(mpu_rbar, (0x240C0000u32 & 0xFFFF_FFE0) | (0b01 << 1) | 0x01);
        core::ptr::write_volatile(mpu_rlar, (0x240CFFE0u32 & 0xFFFF_FFE0) | 0x01);

        // Region 8: NPU activations + I/O slot at 0x342E0000. The model
        // blob's hardcoded I/O and scratch addresses span the full Secure
        // AXISRAM2-6 range — a 150528-byte image copy (224×224×3) plus the
        // blob's internal scratch references reach up to ~0x343BFFFF, so
        // size the region to the full ~880 KB span. RW unprivileged, no
        // execute.
        core::ptr::write_volatile(mpu_rnr, 8);
        core::ptr::write_volatile(mpu_rbar, (0x342E0000u32 & 0xFFFF_FFE0) | (0b01 << 1) | 0x01);
        core::ptr::write_volatile(mpu_rlar, (0x343BFFE0u32 & 0xFFFF_FFE0) | 0x01);

        // Region 9: NPU peripheral block from base (0x580E0000) through
        // EPOCHCTRL (0x580FE000+). Covers CLKCTRL at NPU_BASE+0x10 (the
        // enclave enables the EC clock via CLKCTRL.BGATES bit 25 before
        // configuring EPOCHCTRL) as well as the EPOCHCTRL CTRL/ADDR/IRQ
        // registers. RW unprivileged, no execute, ~128 KB.
        // Uses the SECURE alias (0x580E0000) not the NS alias (0x480E0000):
        // SECCFGR3 bit 10 = 1 (set by platform_impl.rs init_clocks) makes
        // RISUP 106 (NPU config port) Secure-only. NS-alias access from the
        // enclave would be silently dropped. The Secure alias forces
        // IDAU-S attribute on transactions, which RISUP 106 admits.
        core::ptr::write_volatile(mpu_rnr, 9);
        core::ptr::write_volatile(mpu_rbar, (0x580E0000u32 & 0xFFFF_FFE0) | (0b01 << 1) | 0x01);
        core::ptr::write_volatile(mpu_rlar, (0x580FFFE0u32 & 0xFFFF_FFE0) | 0x01);

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

/// Max bytes that the NS host can ask us to print in one call.
/// Per the threat-model ADR §5, this bounds NS-pointer reads
/// from NSC veneers so a malicious `str_ptr` cannot make us read off the
/// end of valid memory. The SAU/MPCBB raises SecureFault if the pointer
/// lies in Secure-only memory; `panic_policy::handle_fault` then resets
/// (or halts with `--features debug-halt`).
const MAX_PRINT_LEN: usize = 256;

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
