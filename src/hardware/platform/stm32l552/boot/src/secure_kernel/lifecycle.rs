//! Runtime ESS-miss recovery: `handle_ess_miss` walks the full block
//! lifecycle (fetch → validate → optional evict → install → relocate)
//! when the MemManage IACCVIOL handler dispatches a cache miss.
//! Gated entirely on `feature = "ess_miss_recovery"` — without runtime
//! demand-paging the create-time BFS loader covers every reachable
//! block and this routine never runs.
//! See the `secure_kernel` module-level docs for the invariants that every
//! change in this file must preserve. In particular, the
//! `mpcbb_set_slot_secure(addr, false)` MUST precede the DMA install
//! (see the in-line landmine comment) and the per-256-B MPCBB flip loop
//! covers the full ESS slot, not just the first 256 B.

#[cfg(feature = "ess_miss_recovery")]
use arm::mmio::{DCCIMVAC, ICIALLU, MPU_RLAR, MPU_RNR};
// CryptoEngine is used only on the L552 in-place decrypt branch (L562
// decrypts via OTFDEC at the bus level — no SW crypto call needed).
#[cfg(feature = "ess_miss_recovery")]
use drivers::dma::{Dma, Request, TransferPriority, TransferSecurity, TransferSize};
#[cfg(all(feature = "ess_miss_recovery", not(feature = "stm32l562")))]
use kernel::key_storage_server::crypto::CryptoEngine;

#[cfg(feature = "ess_miss_recovery")]
use super::init::{
    apply_relocs_to_block, Kernel, BLOCK_META_OFFSET, BLOCK_META_SIZE, CODE_BLOCK_SIZE,
};

#[cfg(feature = "ess_miss_recovery")]
impl Kernel {
    /// Rust analog of the ESS miss branch in
    /// the L552 ProVerif model:
    /// ```text
    /// event CacheMiss(b);
    /// new dma_id: nonce;
    /// out(c_DMA_req, (dma_id, b));
    /// in(c_Validator_res, (=dma_id, =b, d: Dcode));
    /// insert cache(b, d);
    /// ```
    /// The `=b` pattern-match is enforced statically by the `ValidatedBlock`
    /// seal pattern in `crate::validator`: the Validator is the only producer,
    /// and the block id it stamps onto its output equals the id we passed in.
    #[inline(never)]
    pub unsafe fn handle_ess_miss(
        &mut self,
        enclave_id: u32,
        block_idx: u32,
        dma: &mut Dma,
        polling: bool,
    ) -> Result<(), u32> {
        use crate::validator::{
            validate_block, ValidationError, BLOCK_META_SIZE as V_BLOCK_META_SIZE,
            CODE_BLOCK_SIZE as V_CODE_BLOCK_SIZE,
        };

        // Count real runtime misses (not boot force-load, which passes polling=false).
        #[cfg(feature = "bench-eval")]
        if polling {
            crate::bench_eval::record_miss();
        }

        // 1. Locate the enclave in ESS and compute flash + ESS addresses.
        //
        // CJ3 guard: `block_idx` reaches this site from
        // `lookup_faulting_block((pc - base) / CODE_BLOCK_SIZE)`. The upstream
        // `num_blocks ≤ MAX_EFBS` cap at `enclave_create.rs` makes the
        // multiplication safe under nominal load; the explicit `checked_mul`
        // + `checked_add` catches a regression in that cap and surfaces it as
        // `OffsetOverflow` (`0xFFFFFFF7`) instead of a wrap into an adjacent
        // enclave's ESS slot.
        let (enclave_flash_base, ess_target_addr) = {
            let enclave = self
                .ess
                .loaded_enclaves
                .iter()
                .flatten()
                .find(|e| e.descriptor.id == enclave_id)
                .ok_or(0xFFFFFFF8u32)?;
            let ess_addr = block_idx
                .checked_mul(CODE_BLOCK_SIZE)
                .and_then(|delta| enclave.start_address.checked_add(delta))
                .ok_or(0xFFFFFFF7u32)?;
            (enclave.descriptor.flash_base, ess_addr)
        };

        const SCRATCH_ADDR: u32 = 0x30010000;

        // 2. Fetch slab from flash into scratch (DMA on L552, CPU on L562).
        // Polling mode: fault handler context, ISR can't preempt.
        let (hmac_ptr, meta_ptr, ct_ptr) = Self::fetch_block_to_scratch(
            block_idx,
            enclave_flash_base,
            SCRATCH_ADDR,
            dma,
            polling,
        )?;

        let hmac_on_flash: &[u8; 32] = &*(hmac_ptr as *const [u8; 32]);
        let metadata: &[u8; V_BLOCK_META_SIZE] = &*(meta_ptr as *const [u8; V_BLOCK_META_SIZE]);
        let ciphertext: &[u8; V_CODE_BLOCK_SIZE] = &*(ct_ptr as *const [u8; V_CODE_BLOCK_SIZE]);

        // 5. Validator call — HMAC + decrypt + block_id check.
        {
            let validated = self
                .crypto
                .as_deref_mut()
                .ok_or(ValidationError::CryptoUnavailable)
                .and_then(|crypto| {
                    validate_block(
                        crypto,
                        block_idx,
                        ciphertext,
                        metadata,
                        hmac_on_flash,
                        &self.hmac_key,
                        &self.enc_key,
                    )
                })
                .map_err(|e| match e {
                    ValidationError::HmacMismatch => 0xFFFFFFFCu32,
                    ValidationError::DecryptFailed => 0xFFFFFFFBu32,
                    ValidationError::CryptoUnavailable => 0xFFFFFFF9u32,
                })?;

            if validated.block_id != block_idx {
                return Err(0xFFFFFFFDu32);
            }
        }

        // 7. Eviction check
        // SCOPE: only at runtime ESS-miss recovery (MemManage handler context,
        // `polling == true`). At create-time force-load (`polling == false`)
        // skip eviction unconditionally — the goal of force-load is to bring
        // ALL non-BFS-visited blocks resident before the enclave first runs,
        // so evicting another block here defeats the entire purpose and
        // breaks cross-block PIC literal reads (UDF poisoning of the literal
        // pool produces wild-pointer dereferences once the enclave starts).
        // Concretely on STM32L552 with CACHE_LIMIT_PER_ENCLAVE=1: BFS visits
        // 5/6 statemate blocks; force-load handles block 5; without this
        // guard the eviction check sees `loaded_count=5 >= 1`, picks a
        // non-entry victim (e.g. block 2), UDF-fills its slot, then installs
        // block 5. Now block 1's `ldr r3, [pc, #N]` PIC literal read targets
        // block 2's slot and returns `0xDEDEDEDE` (UDF_PATTERN). `add r3, pc`
        // computes a wild address (0x0EE0EFxx in the observed instance) and
        // the next `ldrb r3, [r3, #13]` MemManages with MMFAR pointing
        // outside any enclave.
        // Once execution begins (and the MemManage handler starts dispatching
        // genuine cache misses), `polling == true` re-enables eviction so the
        // configured CACHE_LIMIT semantics still hold for the runtime
        // benchmark sweep.
        if polling {
            // Under cache-zero-mode the effective cache size is 1 (single
            // block of headroom past the entry). The configured
            // CACHE_LIMIT_PER_ENCLAVE is still 64 in the build, but every
            // additional block load past the first triggers eviction so
            // the cache never grows beyond one resident block at a time.
            // Models the paper's "ESS=0" data point — see // grilling notes on the C0-approx methodology.
            #[cfg(feature = "cache-zero-mode")]
            let effective_limit: usize = 1;
            #[cfg(not(feature = "cache-zero-mode"))]
            let effective_limit: usize = kernel::common::ess::CACHE_LIMIT_PER_ENCLAVE;

            let needs_eviction = self
                .ess
                .loaded_enclaves
                .iter()
                .flatten()
                .find(|e| e.descriptor.id == enclave_id)
                .map(|e| e.loaded_count() >= effective_limit)
                .unwrap_or(false);

            if needs_eviction {
                let victim = self
                    .ess
                    .loaded_enclaves
                    .iter()
                    .flatten()
                    .find(|e| e.descriptor.id == enclave_id)
                    .and_then(|e| e.find_eviction_victim(block_idx));

                if let Some(victim_idx) = victim {
                    self.evict_block(enclave_id, victim_idx);
                }
            }
        }

        // 8. Install: DMA ciphertext from scratch → ESS, then decrypt.
        // The MPCBB flip to Secure happens AFTER the DMA+decrypt, not
        // before. The DMA channel is Non-Secure (SECM=0 from GTZC TZSC
        // default); writing to an MPCBB-Secure block would be silently
        // dropped by GTZC when SRWILADIS=1. By keeping the block NS
        // during the DMA, the transfer succeeds. The CPU (Secure world)
        // can access NS memory through either alias for the AES decrypt.
        // For ESS-miss recovery (the runtime
        // miss path) the block was already flipped to NS by `evict_block`,
        // so the DMA worked. But FORCE-LOAD (called at create-time from
        // api_impl.rs to load blocks BFS didn't visit) calls this same
        // function on blocks that are STILL MPCBB-Secure from boot. The
        // DMA write to a Secure-marked block via NS alias was silently
        // dropped by GTZC → block stayed uninitialized → enclave read
        // garbage from.rodata literals (e.g., the iet[] permutation
        // initializer in ndes_cyfun's block 15) → wild-pointer fault.
        // Explicit flip to NS here makes the precondition unconditional.
        // Idempotent for the recovery path (already NS) and correct for
        // the force-load path.
        // SLOT_SIZE > MPCBB block size (256 B): mpcbb_set_slot_secure only
        // flips ONE 256-B MPCBB slot per call. At SLOT_SIZE=1024 each ESS
        // slot covers 4 MPCBB blocks; at SLOT_SIZE=2048, 8. Flipping just
        // the first 256 B then DMA-installing the full 1024/2048 B leaves
        // the latter 3/4 (or 7/8) of the block as MPCBB-Secure → NS DMA
        // writes there are silently dropped, leaving garbage plaintext at
        // every offset past 256. Heavy paper-apps with cross-block PIC
        // literals (cjpeg_wrbmp at SLOT=1024 — block 0 reachable=[], so
        // every block 1-9 takes the force-load path) then deref the
        // garbage as a pointer and MemManage with "addr outside any
        // enclave".
        // Flip EVERY MPCBB-block covered by this ESS slot so the entire
        // DMA target is NS-accessible.
        {
            let mut addr = ess_target_addr;
            let end = ess_target_addr + CODE_BLOCK_SIZE;
            while addr < end {
                // Checked flip: a refused flip-to-NS here makes the NS-alias
                // install DMA below silently drop (the 2026-05-24 ndes/statemate
                // landmine), so fail loud with MemProtectDenied rather than
                // corrupt the slot with stale bytes.
                if !drivers::gtzc::mpcbb_set_slot_secure_checked(addr, false) {
                    return Err(crate::api_impl::nsc_status(
                        umbra_error::UmbraError::MemProtectDenied { addr },
                    ));
                }
                addr += 256;
            }
        }
        cortex_m::asm::dsb();
        cortex_m::asm::isb();

        let ess_write_addr = ess_target_addr | 0x1000_0000;

        let mpu_rnr = MPU_RNR;
        let mpu_rlar = MPU_RLAR;
        core::ptr::write_volatile(mpu_rnr, 5);
        let saved_rlar = core::ptr::read_volatile(mpu_rlar);
        core::ptr::write_volatile(mpu_rlar, saved_rlar & !1u32);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();

        // DMA: scratch ciphertext → ESS (NS alias — block now NS)
        {
            let ct_in_scratch = SCRATCH_ADDR + BLOCK_META_OFFSET + BLOCK_META_SIZE;

            crate::reset_dma_complete();
            let mut install_req = Request::new();
            install_req.count = V_CODE_BLOCK_SIZE as u32 / 4;
            install_req.cpar = ct_in_scratch;
            install_req.cm0ar = ess_target_addr;
            install_req.ssec = TransferSecurity::Secure;
            install_req.dsec = TransferSecurity::NonSecure;
            install_req.mem2mem = true;
            install_req.minc = true;
            install_req.pinc = true;
            install_req.msize = TransferSize::Word;
            install_req.psize = TransferSize::Word;
            install_req.pl = TransferPriority::VeryHigh;

            if polling {
                install_req.tcie = false;
                install_req.teie = false;
                let dma1_ifcr = 0x50020004 as *mut u32;
                core::ptr::write_volatile(dma1_ifcr, 0xFFFFFFFF);
                dma.enqueue(&install_req);
                let dma1_isr = 0x50020000 as *const u32;
                // Bounded poll: a stuck DMA controller surfaces DmaTimeout
                // instead of hanging Secure boot. ~50M reads ≫ a 256-byte
                // mem2mem transfer (microseconds at 110 MHz).
                const DMA_POLL_LIMIT: u32 = 50_000_000;
                let mut dma_spins = 0u32;
                while (core::ptr::read_volatile(dma1_isr) & 0x22222222) == 0 {
                    dma_spins += 1;
                    if dma_spins >= DMA_POLL_LIMIT {
                        return Err(crate::api_impl::nsc_status(
                            umbra_error::UmbraError::DmaTimeout,
                        ));
                    }
                }
                core::ptr::write_volatile(dma1_ifcr, 0xFFFFFFFF);
            } else {
                install_req.tcie = true;
                install_req.teie = true;
                let ccr3 = (0x50020000 + 0x30) as *mut u32;
                *ccr3 = 0;
                dma.enqueue(&install_req);
                while !crate::is_dma_complete() {
                    cortex_m::asm::wfi();
                }
            }
        }

        cortex_m::asm::dsb();
        cortex_m::asm::isb();

        // L552: decrypt in-place in ESS via Secure alias (CPU is Secure,
        // can access NS memory through the Secure alias).
        #[cfg(not(feature = "stm32l562"))]
        {
            let crypto: &mut dyn CryptoEngine = self.crypto.as_deref_mut().ok_or(0xFFFFFFF9u32)?;
            let iv = [0u8; 16];
            let ess_slice =
                core::slice::from_raw_parts_mut(ess_write_addr as *mut u8, V_CODE_BLOCK_SIZE);
            #[cfg(feature = "bench-eval")]
            let _cg = crate::bench_eval::CryptoGuard::start();
            let _ = crypto.aes_decrypt(&self.enc_key, &iv, ess_slice);
        }

        // Static-PIE relocation fixup — same call as the BFS install path
        // in `load_and_verify_block`. Required for evicted-then-reloaded
        // blocks whose pointer slots otherwise revert to compile-time
        // values. Mirrors `apply_relocs_to_block` doc.
        // The enclave's runtime Secure-alias base is
        // `enclave.start_address | 0x1000_0000`. We compute it from the
        // descriptor here rather than re-deriving from `ess_target_addr`
        // (which is the block, not the enclave start).
        {
            let enclave_secure_base = match self
                .ess
                .loaded_enclaves
                .iter()
                .flatten()
                .find(|e| e.descriptor.id == enclave_id)
                .map(|e| e.start_address | 0x1000_0000)
            {
                Some(base) => base,
                // The enclave was registered before this ESS-miss fired, so a
                // miss here is a kernel-state invariant violation, not a
                // recoverable condition. Fail loud rather than relocate against
                // the wrong (block, not enclave-start) base via the old
                // `unwrap_or(ess_write_addr)` fallback.
                None => {
                    return Err(crate::api_impl::nsc_status(
                        umbra_error::UmbraError::InternalInvariant {
                            context: "handle_ess_miss: enclave vanished mid-recovery",
                        },
                    ))
                }
            };
            apply_relocs_to_block(
                enclave_flash_base,
                ess_write_addr,
                enclave_secure_base,
                block_idx,
            );
        }

        // MPCBB flip to Secure — AFTER data is installed and decrypted.
        // Flip every 256-B MPCBB block covered by this ESS slot (see the
        // flip-to-NS comment above for the SLOT_SIZE > 256 rationale).
        {
            let mut addr = ess_target_addr;
            let end = ess_target_addr + CODE_BLOCK_SIZE;
            while addr < end {
                drivers::gtzc::mpcbb_set_slot_secure(addr, true);
                addr += 256;
            }
        }
        cortex_m::asm::dsb();
        cortex_m::asm::isb();

        core::ptr::write_volatile(mpu_rnr, 5);
        core::ptr::write_volatile(mpu_rlar, saved_rlar);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();

        // 10. Mark descriptor loaded + increment LFU counter.
        if let Some(slot) = self
            .ess
            .loaded_enclaves
            .iter_mut()
            .flatten()
            .find(|e| e.descriptor.id == enclave_id)
        {
            if (block_idx as usize) < slot.efb_count {
                slot.efbs[block_idx as usize].is_loaded = true;
                slot.efbs[block_idx as usize].id = block_idx;
                slot.efbs[block_idx as usize].counter =
                    slot.efbs[block_idx as usize].counter.saturating_add(1);
            }
        }

        // 11. D-cache clean+invalidate, then I-cache invalidate.
        // DCCIMVAC writes dirty cache lines to RAM before invalidating;
        // DCIMVAC alone would DISCARD dirty lines, losing the plaintext
        // we just wrote.
        {
            let dccimvac = DCCIMVAC;
            let mut addr = ess_write_addr;
            let end_addr = ess_write_addr + V_CODE_BLOCK_SIZE as u32;
            while addr < end_addr {
                *dccimvac = addr;
                addr += 32;
            }
            cortex_m::asm::dsb();
            cortex_m::asm::isb();
            let iciallu = ICIALLU;
            *iciallu = 0;
            cortex_m::asm::dsb();
            cortex_m::asm::isb();
        }

        Ok(())
    }
}
