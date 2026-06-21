//! Block-into-residency entry path used at boot / enclave-create time:
//! `fetch_block_to_scratch` (L552 DMA, L562 CPU memcpy) and the BFS-based
//! `load_and_verify_block`. These are the routines that bring a slab
//! plaintext into the enclave's ESS region for the first time, before
//! the enclave starts executing.
//! See the `secure_kernel` module-level docs for the invariants that every
//! change in this file must preserve.

use arm::mmio::{DCIMVAC, ICIALLU};
use drivers::dma::Dma;
// Request/TransferSecurity/TransferSize/TransferPriority only used by the
// L552 DMA path; L562 uses CPU memcpy (OCTOSPI alias-mapped flash).
#[cfg(not(feature = "stm32l562"))]
use drivers::dma::{Request, TransferPriority, TransferSecurity, TransferSize};
use kernel::common::enclave::UMBRA_HEADER_SIZE;
use kernel::key_storage_server::key_generator::KeyGenerator;
#[cfg(not(feature = "chained_measurement"))]
use kernel::key_storage_server::key_store::Key;

use super::init::{
    apply_relocs_to_block, Kernel, BLOCK_META_OFFSET, BLOCK_META_SIZE, CODE_BLOCK_SIZE,
    TOTAL_BLOCK_SIZE,
};

impl Kernel {
    /// Transfer a single EFB slab from flash to the scratch buffer, handling
    /// L552 (DMA) vs L562 (CPU memcpy) differences and DMA wait strategy
    /// (interrupt-driven vs polling). Returns pointers into the scratch buffer
    /// for the parsed slab components, or `Err(0xFFFFFFF7)` if the per-block
    /// flash-address arithmetic overflows.
    #[inline(never)]
    pub unsafe fn fetch_block_to_scratch(
        block_idx: u32,
        enclave_flash_base: u32,
        scratch_addr: u32,
        dma: &mut Dma,
        polling: bool,
    ) -> Result<(*const u8, *const u8, *const u8), u32> {
        // CJ3 guard: `block_idx` is bounded by `num_blocks ≤ MAX_EFBS` at the
        // `enclave_create` call site (see `api_impl/enclave_create.rs`), so
        // under nominal load the arithmetic below cannot overflow. The
        // `checked_mul` + `checked_add` chain catches a regression-in-bound
        // scenario and surfaces it as `OffsetOverflow` (`0xFFFFFFF7`) rather
        // than a wrap into an adjacent enclave's ESS slot or a wild flash
        // read.
        #[cfg(feature = "stm32l562")]
        let block_flash_addr = block_idx
            .checked_mul(TOTAL_BLOCK_SIZE)
            .and_then(|delta| {
                0x9000_0000u32
                    .checked_add(UMBRA_HEADER_SIZE)
                    .and_then(|base| base.checked_add(delta))
            })
            .ok_or(0xFFFFFFF7u32)?;
        #[cfg(not(feature = "stm32l562"))]
        let block_flash_addr = block_idx
            .checked_mul(TOTAL_BLOCK_SIZE)
            .and_then(|delta| {
                enclave_flash_base
                    .checked_add(UMBRA_HEADER_SIZE)
                    .and_then(|base| base.checked_add(delta))
            })
            .ok_or(0xFFFFFFF7u32)?;
        #[cfg(feature = "stm32l562")]
        let _ = enclave_flash_base;

        let transfer_size = TOTAL_BLOCK_SIZE;

        #[cfg(feature = "stm32l562")]
        {
            let _ = (dma, polling);
            core::ptr::copy_nonoverlapping(
                block_flash_addr as *const u8,
                scratch_addr as *mut u8,
                transfer_size as usize,
            );
            cortex_m::asm::dsb();
            cortex_m::asm::isb();
        }

        #[cfg(not(feature = "stm32l562"))]
        {
            if polling {
                let dma1_ifcr = 0x50020004 as *mut u32;
                core::ptr::write_volatile(dma1_ifcr, 0xFFFFFFFF);

                let mut request = Request::new();
                request.count = transfer_size / 4;
                request.cpar = block_flash_addr;
                request.cm0ar = scratch_addr;
                request.ssec = TransferSecurity::Secure;
                request.dsec = TransferSecurity::Secure;
                request.mem2mem = true;
                request.minc = true;
                request.pinc = true;
                request.msize = TransferSize::Word;
                request.psize = TransferSize::Word;
                request.tcie = false;
                request.teie = false;
                request.pl = TransferPriority::VeryHigh;

                dma.enqueue(&request);

                let dma1_isr = 0x50020000 as *const u32;
                // Bounded poll → DmaTimeout instead of an unbounded spin if the
                // DMA controller wedges mid-fetch. ~50M reads ≫ a single-block
                // transfer at 110 MHz.
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
                crate::reset_dma_complete();

                let mut request = Request::new();
                request.count = transfer_size / 4;
                request.cpar = block_flash_addr;
                request.cm0ar = scratch_addr;
                request.ssec = TransferSecurity::Secure;
                request.dsec = TransferSecurity::Secure;
                request.mem2mem = true;
                request.minc = true;
                request.pinc = true;
                request.msize = TransferSize::Word;
                request.psize = TransferSize::Word;
                request.tcie = true;
                request.teie = true;
                request.pl = TransferPriority::VeryHigh;

                let ccr3 = (0x50020000 + 0x30) as *mut u32;
                *ccr3 = 0;

                dma.enqueue(&request);

                while !crate::is_dma_complete() {
                    cortex_m::asm::wfi();
                }
            }
        }

        let dcimvac = DCIMVAC;
        let mut addr = scratch_addr;
        let end_addr = scratch_addr + transfer_size;
        while addr < end_addr {
            *dcimvac = addr;
            addr += 32;
        }
        cortex_m::asm::dsb();
        cortex_m::asm::isb();

        let scratch_ptr = scratch_addr as *const u8;
        let hmac_ptr = scratch_ptr;
        let meta_ptr = scratch_ptr.add(BLOCK_META_OFFSET as usize);
        let ct_ptr = scratch_ptr.add((BLOCK_META_OFFSET + BLOCK_META_SIZE) as usize);
        Ok((hmac_ptr, meta_ptr, ct_ptr))
    }

    // BFS-based Recursive Loader
    #[inline(never)]
    pub unsafe fn load_and_verify_block(
        &mut self,
        block_idx: u32,
        ess_base: u32,
        scratch_addr: u32,
        enclave_flash_base: u32,
        dma: &mut Dma,
    ) -> Result<(*const u8, u8), u32> {
        // At boot, GTZC marks every EFBC slot Secure in MPCBB1. Writes must
        // use the Secure alias — NS-alias writes to Secure slots are silently
        // dropped when SRWILADIS=1.
        //
        // CJ3 guard: same regression-in-bound rationale as
        // `fetch_block_to_scratch`. The OR with `0x1000_0000` is a bit-pattern
        // (alias rewrite), not arithmetic; only the post-OR `+` needs
        // overflow protection.
        let ess_target_addr = block_idx
            .checked_mul(CODE_BLOCK_SIZE)
            .and_then(|delta| (ess_base | 0x1000_0000).checked_add(delta))
            .ok_or(0xFFFFFFF7u32)?;

        // 1. Fetch slab from flash into scratch (DMA on L552, CPU on L562).
        // Boot context: interrupt-driven DMA wait (polling=false).
        let (_hmac_ptr, meta_ptr, ct_ptr) =
            Self::fetch_block_to_scratch(block_idx, enclave_flash_base, scratch_addr, dma, false)?;

        let meta_src = meta_ptr as *mut u8;
        let ct_src = ct_ptr as *mut u8;

        // 2. Verify
        if let Some(crypto_engine) = self.crypto.as_mut() {
            let mut generator = KeyGenerator::new(*crypto_engine);

            // Build a block-binding buffer [BlockID(4) | Ciphertext | Meta] in
            // a scratch region clear of the fetched HMAC/meta/CT layout.
            // Fetch lays them out as [HMAC(32) | Meta(32) | CT(CODE_BLOCK_SIZE)]
            // starting at `scratch_addr`, ending at scratch+64+CODE_BLOCK_SIZE.
            // verify_buf must sit well past the CT region with headroom for
            // the largest swept SLOT_SIZE (8192). A small offset (e.g. 0x400)
            // overlaps CT when SLOT_SIZE ≥ 1024 — the `copy_nonoverlapping`
            // would then read its own writes once dst caught up to src,
            // corrupting the HMAC input and causing `chained-measurement FAIL`.
            const VERIFY_BUF_OFFSET: u32 = 0x4000; // 16 KB, fits SLOT_SIZE ≤ 8192
            let verify_buf = (scratch_addr + VERIFY_BUF_OFFSET) as *mut u8;
            let block_id_bytes = block_idx.to_le_bytes();
            core::ptr::copy_nonoverlapping(block_id_bytes.as_ptr(), verify_buf, 4);
            core::ptr::copy_nonoverlapping(ct_src, verify_buf.add(4), CODE_BLOCK_SIZE as usize);
            core::ptr::copy_nonoverlapping(
                meta_src,
                verify_buf.add(4 + CODE_BLOCK_SIZE as usize),
                BLOCK_META_SIZE as usize,
            );
            let verify_slice = core::slice::from_raw_parts(
                verify_buf,
                4 + (CODE_BLOCK_SIZE as usize) + (BLOCK_META_SIZE as usize),
            );

            // Per-scheme verification.
            #[cfg(not(feature = "chained_measurement"))]
            {
                let hmac_stored = core::slice::from_raw_parts(_hmac_ptr, 32);
                let base_key = Key::new(crate::master_key::MASTER_KEY);
                match generator.derive_key(&base_key, verify_slice) {
                    Ok(computed) => {
                        if !generator.verify_measurement(&computed.value, hmac_stored) {
                            return Err(0xFFFFFFFC);
                        }
                    }
                    Err(_) => return Err(0xFFFFFFFA),
                }
            }

            #[cfg(feature = "chained_measurement")]
            {
                // Fold this block into the running chain; final comparison happens
                // in `Kernel::finalize_measurement` after all blocks are loaded.
                #[cfg(feature = "bench-eval")]
                let _cg = crate::bench_eval::CryptoGuard::start();
                if generator
                    .update_chain(&mut self.chain_state, verify_slice)
                    .is_err()
                {
                    return Err(0xFFFFFFFA);
                }
            }

            // 3. Install into ESS.
            // L552: ct_src is AES-CBC ciphertext; decrypt into ESS using enc_key.
            // L562: ct_src is already plaintext (OTFDEC decrypted on the DMA read
            // through the OCTOSPI window per AN5281 §4.1). HMAC above already
            // bound `block_id || plaintext || meta` against the on-flash sig,
            // so we just copy the bytes into ESS. Keeps the ProVerif model
            // equivalence: OTFDEC replaces the Validator's AES
            // decrypt stage, and the HMAC-over-plaintext sig replaces the
            // HMAC-over-ciphertext binding.
            let ess_ptr = ess_target_addr as *mut u8;
            core::ptr::copy_nonoverlapping(ct_src, ess_ptr, CODE_BLOCK_SIZE as usize);
            #[cfg(not(feature = "stm32l562"))]
            {
                let iv = [0u8; 16];
                let ess_slice = core::slice::from_raw_parts_mut(ess_ptr, CODE_BLOCK_SIZE as usize);
                #[cfg(feature = "bench-eval")]
                let _cg = crate::bench_eval::CryptoGuard::start();
                let _ = crypto_engine.aes_decrypt(&self.enc_key, &iv, ess_slice);
            }
            #[cfg(feature = "stm32l562")]
            let _ = crypto_engine;

            // Static-PIE relocation fixup: patch every R_ARM_ABS32 pointer
            // that falls inside this freshly-decrypted block. See
            // `apply_relocs_to_block` doc for the why; in short, anagram /
            // dijkstra / huff_dec / cjpeg_wrbmp embed pointer-array
            // initialisers whose compile-time addresses would otherwise
            // alias outside the enclave's runtime EFBC slots and MemManage.
            // `ess_target_addr` here is already the Secure alias (`ess_base
            // | 0x1000_0000 + block_idx * SLOT_SIZE`), and the enclave's
            // secure-alias base is `ess_base | 0x1000_0000`.
            apply_relocs_to_block(
                enclave_flash_base,
                ess_target_addr,
                ess_base | 0x1000_0000,
                block_idx,
            );

            // Invalidate D-cache for the freshly-written ESS line, then I-cache
            // (the enclave will execute from here). Note: L552 Cortex-M33 has
            // no D-cache, so DCIMVAC is effectively a no-op — kept for
            // parity with platforms that do have one.
            let dcimvac = DCIMVAC;
            let mut addr = ess_target_addr;
            let end_addr = ess_target_addr + CODE_BLOCK_SIZE;
            while addr < end_addr {
                *dcimvac = addr;
                addr += 32;
            }
            cortex_m::asm::dsb();
            cortex_m::asm::isb();
            let iciallu = ICIALLU;
            *iciallu = 0;
            cortex_m::asm::dsb();
            cortex_m::asm::isb();

            // Return pointer to the meta block copy inside verify_buf so the
            // BFS loop can walk reachability. verify_buf survives until the
            // next block load.
            let meta_in_verify = verify_buf.add(4 + CODE_BLOCK_SIZE as usize);
            Ok((meta_in_verify, *meta_in_verify))
        } else {
            Err(0xFFFFFFF9)
        }
    }
}
