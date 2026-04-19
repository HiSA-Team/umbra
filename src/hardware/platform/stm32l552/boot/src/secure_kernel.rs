use kernel::memory_protection_server::memory_guard::MemorySecurityGuardTrait;
use kernel::common::enclave::EnclaveDescriptor;
use kernel::common::ess::EnclaveSwapSpace;
use kernel::common::enclave::EnclaveContext;
use kernel::key_storage_server::key_store::KeyStore;
use kernel::key_storage_server::crypto::CryptoEngine;

pub const MAX_ENCLAVES: usize = 8;

pub struct Kernel {
    pub guards: &'static mut [&'static mut dyn MemorySecurityGuardTrait],
    pub tees: [Option<EnclaveDescriptor>; MAX_ENCLAVES],
    pub ess: EnclaveSwapSpace,
    pub key_store: KeyStore,
    pub crypto: Option<&'static mut dyn CryptoEngine>,
    pub loader: Option<fn() -> u32>,
    /// Running HMAC-chain state for the currently-loading enclave. Seeded from
    /// `master_key::MASTER_KEY` in `begin_measurement()` and folded block-by-block
    /// in `load_and_verify_block()`. Compared against the enclave header's
    /// `hmac` field in `finalize_measurement()`.
    pub chain_state: [u8; 32],
    /// Subkeys derived from `MASTER_KEY` via `key_derivation::derive_*_key`.
    /// Populated by `init_keys()` immediately after `Kernel::init`, before any
    /// block loading or ESS-miss recovery runs. Formal-model analog:
    /// `encKey` / `hmacKey` in `docs/formal/UmbraIntegrityFixValidator.pv`.
    pub enc_key: [u8; 32],
    pub hmac_key: [u8; 32],
    pub enclave_contexts: [EnclaveContext; 4],
    pub current_enclave_id: Option<u32>,
}

static mut INSTANCE: Option<Kernel> = None;

#[no_mangle]
pub static mut CURRENT_ENCLAVE_CTX_PTR: *mut u8 = core::ptr::null_mut();

use drivers::dma::{self, Dma, Request, TransferSecurity, TransferSize, TransferPriority};
use kernel::key_storage_server::key_generator::KeyGenerator;
use kernel::key_storage_server::key_store::Key;
use kernel::common::enclave::{UmbraEnclaveHeader, UMBRA_HEADER_SIZE};

// --- CONSTANTS ---
pub const CODE_BLOCK_SIZE: u32 = 256;

pub const BLOCK_META_SIZE: u32 = 32;

// Per-block on-flash header layout. `ess_miss_recovery` adds a 32B HMAC prefix
// (used by the runtime Validator for on-demand block validation) and shifts
// the metadata to +32.
//
//   chained only:                 [Meta(32) | CT(256)]              32B header, 288B total
//   legacy (no chained):          [HMAC(32) | Meta(32) | CT(256)]   64B header, 320B total
//   chained + ess_miss_recovery:  [HMAC(32) | Meta(32) | CT(256)]   64B header, 320B total
#[cfg(all(not(feature = "chained_measurement"), not(feature = "ess_miss_recovery")))]
pub const BLOCK_META_OFFSET: u32 = 32;
#[cfg(all(not(feature = "chained_measurement"), not(feature = "ess_miss_recovery")))]
pub const BLOCK_HEADER_SIZE: u32 = 64;

#[cfg(all(feature = "chained_measurement", not(feature = "ess_miss_recovery")))]
pub const BLOCK_META_OFFSET: u32 = 0;
#[cfg(all(feature = "chained_measurement", not(feature = "ess_miss_recovery")))]
pub const BLOCK_HEADER_SIZE: u32 = 32;

#[cfg(feature = "ess_miss_recovery")]
pub const BLOCK_META_OFFSET: u32 = 32;
#[cfg(feature = "ess_miss_recovery")]
pub const BLOCK_HEADER_SIZE: u32 = 64;

pub const TOTAL_BLOCK_SIZE: u32 = CODE_BLOCK_SIZE + BLOCK_HEADER_SIZE;

impl Kernel {
    pub fn new(guards: &'static mut [&'static mut dyn MemorySecurityGuardTrait], crypto: Option<&'static mut dyn CryptoEngine>) -> Self {
        Self {
            guards,
            tees: [None; MAX_ENCLAVES],
            ess: EnclaveSwapSpace::new(),
            key_store: KeyStore::new(),
            crypto,
            loader: None,
            chain_state: [0u8; 32],
            enc_key: [0u8; 32],
            hmac_key: [0u8; 32],
            enclave_contexts: [EnclaveContext::empty(); 4],
            current_enclave_id: None,
        }
    }

    /// Populate `enc_key` and `hmac_key` from the master key via the KDF. Must
    /// be called once, immediately after `Kernel::init`, before any enclave
    /// loading. No-op if `crypto` was never installed.
    pub unsafe fn init_keys(&mut self) {
        if let Some(crypto) = self.crypto.as_mut() {
            let crypto: &mut dyn CryptoEngine = &mut **crypto;
            self.enc_key  = crate::key_derivation::derive_enc_key(crypto);
            self.hmac_key = crate::key_derivation::derive_hmac_key(crypto);
        }
    }

    /// Seed the chained-measurement state with the master key. Call once at the
    /// start of loading a new enclave, before any `load_and_verify_block`.
    pub fn begin_measurement(&mut self) {
        self.chain_state = crate::master_key::MASTER_KEY;
    }

    /// Compare the accumulated chain state against the enclave header's reference
    /// measurement. Returns `Ok(())` on match, `Err(())` on mismatch. Constant-time
    /// compare to avoid timing leaks on the 32-byte digest.
    pub fn finalize_measurement(&self, expected: &[u8; 32]) -> Result<(), ()> {
        let mut diff: u8 = 0;
        for i in 0..32 {
            diff |= self.chain_state[i] ^ expected[i];
        }
        if diff == 0 { Ok(()) } else { Err(()) }
    }

    pub const SYSTICK_RELOAD: u32 = 40_000; // ~10ms at 4MHz MSI

    pub unsafe fn enable_systick(&self) {
        let syst_rvr = 0xE000_E014 as *mut u32;
        let syst_cvr = 0xE000_E018 as *mut u32;
        let syst_csr = 0xE000_E010 as *mut u32;
        core::ptr::write_volatile(syst_rvr, Self::SYSTICK_RELOAD - 1);
        core::ptr::write_volatile(syst_cvr, 0);
        core::ptr::write_volatile(syst_csr, 0x07);
    }

    pub unsafe fn disable_systick(&self) {
        let syst_csr = 0xE000_E010 as *mut u32;
        core::ptr::write_volatile(syst_csr, 0x00);
        // Also clear any already-pending SysTick exception. Otherwise a
        // SysTick that fired mid-handler will tail-chain after our current
        // exception return, re-enter the SysTick trampoline, and clobber the
        // status word that the UsageFault / MemManage / BusFault handler
        // wrote into the SVC-entry MSP frame — turning a Faulted/Terminated
        // return into a spurious Suspended.
        let icsr = 0xE000_ED04 as *mut u32;
        core::ptr::write_volatile(icsr, 1 << 25); // PENDSTCLR
    }

    /// Resolve an executing PC to `(enclave_id, block_idx)` if it sits inside
    /// a currently-loaded enclave's ESS cache region. Used by the MemManage
    /// IACCVIOL handler to translate a stacked PC into a cache miss request.
    /// Returns `None` if the PC is outside every loaded enclave.
    pub fn lookup_faulting_block(&self, pc: u32) -> Option<(u32, u32)> {
        for slot in self.ess.loaded_enclaves.iter().flatten() {
            let base = slot.start_address;
            let top  = base + (slot.efb_count as u32) * CODE_BLOCK_SIZE;
            if pc >= base && pc < top {
                let block_idx = (pc - base) / CODE_BLOCK_SIZE;
                return Some((slot.descriptor.id, block_idx));
            }
        }
        None
    }

    /// # Safety
    ///
    /// Callers must guarantee `block_idx != 0`. Block 0 holds the enclave
    /// entry point and must remain resident; evicting it would leave
    /// `umbra_enclave_enter_imp` jumping to a UDF slot. The early return
    /// below is defence-in-depth — the real invariant is upstream at
    /// `find_eviction_victim` (loop starts at 1) and `umbra_tee_create_imp`
    /// (eviction loop starts at 1).
    #[cfg(feature = "ess_miss_recovery")]
    #[inline(never)]
    pub unsafe fn evict_block(&mut self, enclave_id: u32, block_idx: u32) {
        use kernel::common::ess::SLOT_SIZE;
        const UDF_PATTERN: u32 = 0xDEDE_DEDE;

        if block_idx == 0 {
            return;
        }

        let (slot_addr_ns, slot_addr_s) = {
            let enclave = match self.ess.loaded_enclaves.iter()
                .flatten()
                .find(|e| e.descriptor.id == enclave_id)
            {
                Some(e) => e,
                None => return,
            };
            let ns = enclave.start_address + block_idx * SLOT_SIZE;
            (ns, ns | 0x1000_0000)
        };

        let mpu_rnr  = 0xE000_ED98 as *mut u32;
        let mpu_rlar = 0xE000_EDA0 as *mut u32;
        core::ptr::write_volatile(mpu_rnr, 5);
        let saved_rlar = core::ptr::read_volatile(mpu_rlar);
        core::ptr::write_volatile(mpu_rlar, saved_rlar & !1u32);
        core::arch::asm!("dsb", "isb");

        // Write UDF via the Secure alias.  The slot is still Secure in
        // MPCBB at this point; NS-alias writes to Secure slots are
        // silently dropped when SRWILADIS=1 (see load_and_verify_block).
        let mut off = 0u32;
        while off < SLOT_SIZE {
            core::ptr::write_volatile((slot_addr_s + off) as *mut u32, UDF_PATTERN);
            off += 4;
        }

        // D-cache clean+invalidate so the UDF pattern reaches physical
        // SRAM before handle_ess_miss writes new data via the same alias.
        let dccimvac = 0xE000EF70 as *mut u32;
        let mut addr = slot_addr_s;
        while addr < slot_addr_s + SLOT_SIZE {
            core::ptr::write_volatile(dccimvac, addr);
            addr += 32;
        }
        core::arch::asm!("dsb", "isb");

        core::ptr::write_volatile(mpu_rlar, saved_rlar);
        core::arch::asm!("dsb", "isb");

        let iciallu = 0xE000EF50 as *mut u32;
        core::ptr::write_volatile(iciallu, 0);
        core::arch::asm!("dsb", "isb");

        drivers::gtzc::mpcbb_set_slot_secure(slot_addr_ns, false);
        core::arch::asm!("dsb", "isb");

        if let Some(enclave) = self.ess.loaded_enclaves.iter_mut()
            .flatten()
            .find(|e| e.descriptor.id == enclave_id)
        {
            if (block_idx as usize) < enclave.efb_count {
                enclave.efbs[block_idx as usize].is_loaded = false;
                enclave.efbs[block_idx as usize].counter = 0;
            }
        }
    }

    /// Transfer a single EFB slab from flash to the scratch buffer, handling
    /// L552 (DMA) vs L562 (CPU memcpy) differences and DMA wait strategy
    /// (interrupt-driven vs polling). Returns pointers into the scratch buffer
    /// for the parsed slab components.
    #[inline(never)]
    pub unsafe fn fetch_block_to_scratch(
        block_idx: u32,
        enclave_flash_base: u32,
        scratch_addr: u32,
        dma: &mut Dma,
        polling: bool,
    ) -> (*const u8, *const u8, *const u8) {
        #[cfg(feature = "stm32l562")]
        let block_flash_addr = 0x9000_0000u32 + UMBRA_HEADER_SIZE + (block_idx * TOTAL_BLOCK_SIZE);
        #[cfg(not(feature = "stm32l562"))]
        let block_flash_addr = enclave_flash_base + UMBRA_HEADER_SIZE + (block_idx * TOTAL_BLOCK_SIZE);
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
            core::arch::asm!("dsb", "isb");
        }

        #[cfg(not(feature = "stm32l562"))]
        {
            if polling {
                let dma1_ifcr = 0x50020004 as *mut u32;
                core::ptr::write_volatile(dma1_ifcr, 0xFFFFFFFF);

                let mut request = Request::new();
                request.count   = transfer_size / 4;
                request.cpar    = block_flash_addr;
                request.cm0ar   = scratch_addr;
                request.ssec    = TransferSecurity::Secure;
                request.dsec    = TransferSecurity::Secure;
                request.mem2mem = true;
                request.minc    = true;
                request.pinc    = true;
                request.msize   = TransferSize::Word;
                request.psize   = TransferSize::Word;
                request.tcie    = false;
                request.teie    = false;
                request.pl      = TransferPriority::VeryHigh;

                dma.enqueue(&request);

                let dma1_isr = 0x50020000 as *const u32;
                while (core::ptr::read_volatile(dma1_isr) & 0x22222222) == 0 {}
                core::ptr::write_volatile(dma1_ifcr, 0xFFFFFFFF);
            } else {
                crate::reset_dma_complete();

                let mut request = Request::new();
                request.count = transfer_size / 4;
                request.cpar  = block_flash_addr;
                request.cm0ar = scratch_addr;
                request.ssec  = TransferSecurity::Secure;
                request.dsec  = TransferSecurity::Secure;
                request.mem2mem = true;
                request.minc  = true;
                request.pinc  = true;
                request.msize = TransferSize::Word;
                request.psize = TransferSize::Word;
                request.tcie  = true;
                request.teie  = true;
                request.pl    = TransferPriority::VeryHigh;

                let ccr3 = (0x50020000 + 0x30) as *mut u32;
                *ccr3 = 0;

                dma.enqueue(&request);

                while !crate::is_dma_complete() {
                    core::arch::asm!("wfi");
                }
            }
        }

        let dcimvac = 0xE000EF5C as *mut u32;
        let mut addr = scratch_addr;
        let end_addr = scratch_addr + transfer_size;
        while addr < end_addr {
            *dcimvac = addr;
            addr += 32;
        }
        core::arch::asm!("dsb", "isb");

        let scratch_ptr = scratch_addr as *const u8;
        let hmac_ptr = scratch_ptr;
        let meta_ptr = scratch_ptr.add(BLOCK_META_OFFSET as usize);
        let ct_ptr = scratch_ptr.add((BLOCK_META_OFFSET + BLOCK_META_SIZE) as usize);
        (hmac_ptr, meta_ptr, ct_ptr)
    }

    /// Rust analog of the ESS miss branch in
    /// `docs/formal/UmbraIntegrityFixValidator.pv`:
    ///
    /// ```text
    /// event CacheMiss(b);
    /// new dma_id: nonce;
    /// out(c_DMA_req, (dma_id, b));
    /// in(c_Validator_res, (=dma_id, =b, d: Dcode));
    /// insert cache(b, d);
    /// ```
    ///
    /// The `=b` pattern-match is enforced statically by the `ValidatedBlock`
    /// seal pattern in `crate::validator`: the Validator is the only producer,
    /// and the block id it stamps onto its output equals the id we passed in.
    #[cfg(feature = "ess_miss_recovery")]
    #[inline(never)]
    pub unsafe fn handle_ess_miss(
        &mut self,
        enclave_id: u32,
        block_idx: u32,
        dma: &mut Dma,
        polling: bool,
    ) -> Result<(), u32> {
        use crate::validator::{
            validate_block, ValidationError,
            CODE_BLOCK_SIZE as V_CODE_BLOCK_SIZE,
            BLOCK_META_SIZE as V_BLOCK_META_SIZE,
        };

        // 1. Locate the enclave in ESS and compute flash + ESS addresses.
        let (enclave_flash_base, ess_target_addr) = {
            let enclave = self.ess.loaded_enclaves.iter()
                .flatten()
                .find(|e| e.descriptor.id == enclave_id)
                .ok_or(0xFFFFFFF8u32)?;
            let ess_addr = enclave.start_address + block_idx * CODE_BLOCK_SIZE;
            (enclave.descriptor.flash_base, ess_addr)
        };

        const SCRATCH_ADDR: u32 = 0x30010000;

        // 2. Fetch slab from flash into scratch (DMA on L552, CPU on L562).
        //    Polling mode: fault handler context, ISR can't preempt.
        let (hmac_ptr, meta_ptr, ct_ptr) = Self::fetch_block_to_scratch(
            block_idx, enclave_flash_base, SCRATCH_ADDR, dma, polling,
        );

        let hmac_on_flash: &[u8; 32] = &*(hmac_ptr as *const [u8; 32]);
        let metadata: &[u8; V_BLOCK_META_SIZE] = &*(meta_ptr as *const [u8; V_BLOCK_META_SIZE]);
        let ciphertext: &[u8; V_CODE_BLOCK_SIZE] = &*(ct_ptr as *const [u8; V_CODE_BLOCK_SIZE]);

        // 5. Validator call — HMAC check only, plaintext ignored (DMA install below).
        {
            let crypto: &mut dyn CryptoEngine =
                self.crypto.as_deref_mut().ok_or(0xFFFFFFF9u32)?;
            let validated = validate_block(
                crypto,
                block_idx,
                ciphertext,
                metadata,
                hmac_on_flash,
                &self.hmac_key,
                &self.enc_key,
            ).map_err(|e| match e {
                ValidationError::HmacMismatch      => 0xFFFFFFFCu32,
                ValidationError::DecryptFailed     => 0xFFFFFFFBu32,
                ValidationError::CryptoUnavailable => 0xFFFFFFF9u32,
            })?;

            if validated.block_id != block_idx {
                return Err(0xFFFFFFFDu32);
            }
        } // crypto borrow released here

        // 7. Eviction check
        {
            let needs_eviction = self.ess.loaded_enclaves.iter()
                .flatten()
                .find(|e| e.descriptor.id == enclave_id)
                .map(|e| e.loaded_count() >= kernel::common::ess::CACHE_LIMIT_PER_ENCLAVE)
                .unwrap_or(false);

            if needs_eviction {
                let victim = self.ess.loaded_enclaves.iter()
                    .flatten()
                    .find(|e| e.descriptor.id == enclave_id)
                    .and_then(|e| e.find_eviction_victim(block_idx));

                if let Some(victim_idx) = victim {
                    self.evict_block(enclave_id, victim_idx);
                }
            }
        }

        // 8. Install: DMA ciphertext from scratch → ESS, then decrypt.
        //    The MPCBB flip to Secure happens AFTER the DMA+decrypt, not
        //    before.  The DMA channel is Non-Secure (SECM=0 from GTZC TZSC
        //    default); writing to an MPCBB-Secure block would be silently
        //    dropped by GTZC when SRWILADIS=1.  By keeping the block NS
        //    during the DMA, the transfer succeeds.  The CPU (Secure world)
        //    can access NS memory through either alias for the AES decrypt.
        let ess_write_addr = ess_target_addr | 0x1000_0000;

        let mpu_rnr  = 0xE000_ED98 as *mut u32;
        let mpu_rlar = 0xE000_EDA0 as *mut u32;
        core::ptr::write_volatile(mpu_rnr, 5);
        let saved_rlar = core::ptr::read_volatile(mpu_rlar);
        core::ptr::write_volatile(mpu_rlar, saved_rlar & !1u32);
        core::arch::asm!("dsb", "isb");

        // DMA: scratch ciphertext → ESS (NS alias — block is still NS)
        {
            let ct_in_scratch = SCRATCH_ADDR + BLOCK_META_OFFSET + BLOCK_META_SIZE;

            crate::reset_dma_complete();
            let mut install_req = Request::new();
            install_req.count   = V_CODE_BLOCK_SIZE as u32 / 4;
            install_req.cpar    = ct_in_scratch;
            install_req.cm0ar   = ess_target_addr;
            install_req.ssec    = TransferSecurity::Secure;
            install_req.dsec    = TransferSecurity::NonSecure;
            install_req.mem2mem = true;
            install_req.minc    = true;
            install_req.pinc    = true;
            install_req.msize   = TransferSize::Word;
            install_req.psize   = TransferSize::Word;
            install_req.pl      = TransferPriority::VeryHigh;

            if polling {
                install_req.tcie = false;
                install_req.teie = false;
                let dma1_ifcr = 0x50020004 as *mut u32;
                core::ptr::write_volatile(dma1_ifcr, 0xFFFFFFFF);
                dma.enqueue(&install_req);
                let dma1_isr = 0x50020000 as *const u32;
                while (core::ptr::read_volatile(dma1_isr) & 0x22222222) == 0 {}
                core::ptr::write_volatile(dma1_ifcr, 0xFFFFFFFF);
            } else {
                install_req.tcie = true;
                install_req.teie = true;
                let ccr3 = (0x50020000 + 0x30) as *mut u32;
                *ccr3 = 0;
                dma.enqueue(&install_req);
                while !crate::is_dma_complete() {
                    core::arch::asm!("wfi");
                }
            }
        }

        core::arch::asm!("dsb", "isb");

        // L552: decrypt in-place in ESS via Secure alias (CPU is Secure,
        // can access NS memory through the Secure alias).
        #[cfg(not(feature = "stm32l562"))]
        {
            let crypto: &mut dyn CryptoEngine =
                self.crypto.as_deref_mut().ok_or(0xFFFFFFF9u32)?;
            let iv = [0u8; 16];
            let ess_slice = core::slice::from_raw_parts_mut(
                ess_write_addr as *mut u8, V_CODE_BLOCK_SIZE);
            let _ = crypto.aes_decrypt(&self.enc_key, &iv, ess_slice);
        }

        // MPCBB flip to Secure — AFTER data is installed and decrypted.
        drivers::gtzc::mpcbb_set_slot_secure(ess_target_addr, true);
        core::arch::asm!("dsb", "isb");

        core::ptr::write_volatile(mpu_rnr, 5);
        core::ptr::write_volatile(mpu_rlar, saved_rlar);
        core::arch::asm!("dsb", "isb");

        // 10. Mark descriptor loaded + increment LFU counter.
        if let Some(slot) = self.ess.loaded_enclaves.iter_mut()
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
        //     DCCIMVAC (0xE000EF70) writes dirty cache lines to RAM before
        //     invalidating. DCIMVAC (0xE000EF5C) would DISCARD dirty lines,
        //     losing the plaintext we just wrote.
        {
            let dccimvac = 0xE000EF70 as *mut u32;
            let mut addr = ess_write_addr;
            let end_addr = ess_write_addr + V_CODE_BLOCK_SIZE as u32;
            while addr < end_addr { *dccimvac = addr; addr += 32; }
            core::arch::asm!("dsb", "isb");
            let iciallu = 0xE000EF50 as *mut u32;
            *iciallu = 0;
            core::arch::asm!("dsb", "isb");
        }

        Ok(())
    }

    pub unsafe fn init(kernel: Kernel) {
        INSTANCE = Some(kernel);
    }

    pub unsafe fn get() -> Option<&'static mut Kernel> {
        INSTANCE.as_mut()
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
        let ess_target_addr = (ess_base | 0x1000_0000) + (block_idx * CODE_BLOCK_SIZE);

        // 1. Fetch slab from flash into scratch (DMA on L552, CPU on L562).
        //    Boot context: interrupt-driven DMA wait (polling=false).
        let (_hmac_ptr, meta_ptr, ct_ptr) = Self::fetch_block_to_scratch(
            block_idx, enclave_flash_base, scratch_addr, dma, false,
        );

        let meta_src = meta_ptr as *mut u8;
        let ct_src = ct_ptr as *mut u8;

        // 2. Verify
        if let Some(crypto_engine) = self.crypto.as_mut() {
            let mut generator = KeyGenerator::new(*crypto_engine);

            // Build a block-binding buffer [BlockID(4) | Ciphertext | Meta] in a
            // scratch region at +0x400. Used as the HMAC input for both schemes.
            let verify_buf = (scratch_addr + 0x400) as *mut u8;
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
                if generator.update_chain(&mut self.chain_state, verify_slice).is_err() {
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
                let _ = crypto_engine.aes_decrypt(&self.enc_key, &iv, ess_slice);
            }
            #[cfg(feature = "stm32l562")]
            let _ = crypto_engine;

            // Invalidate D-cache for the freshly-written ESS line, then I-cache
            // (the enclave will execute from here).
            let dcimvac = 0xE000EF5C as *mut u32;
            let mut addr = ess_target_addr;
            let end_addr = ess_target_addr + CODE_BLOCK_SIZE;
            while addr < end_addr {
                *dcimvac = addr;
                addr += 32;
            }
            core::arch::asm!("dsb", "isb");
            let iciallu = 0xE000EF50 as *mut u32;
            *iciallu = 0;
            core::arch::asm!("dsb", "isb");

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
