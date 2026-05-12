//! Kernel wrapper for STM32N657.
//!
//! Slimmer than the L5 sibling: no DMA, no GTZC/RISAF. Block loads use
//! CPU copy via `load_block_n657`; ESS-miss recovery flows through the
//! UsageFault dispatcher in handlers.rs.

use arm::mmio::{DCCMVAC, ICIALLU, SCB_ICSR, SYST_CSR, SYST_CVR, SYST_RVR};
use kernel::memory_protection_server::memory_guard::MemorySecurityGuardTrait;
use kernel::common::ess::EnclaveSwapSpace;
use kernel::common::enclave::EnclaveContext;
use kernel::key_storage_server::crypto::CryptoEngine;

use crate::boot_measurements::{
    MODEL_BYTECODE_ADDR, MODEL_BYTECODE_LEN, MODEL_BYTECODE_HMAC,
    MODEL_WEIGHTS_ADDR, MODEL_WEIGHTS_LEN, MODEL_WEIGHTS_HMAC,
};

pub struct Kernel {
    #[allow(dead_code)]
    pub guards: &'static mut [&'static mut dyn MemorySecurityGuardTrait],
    pub ess: EnclaveSwapSpace,
    pub crypto: Option<&'static mut dyn CryptoEngine>,
    pub chain_state: [u8; 32],
    pub enc_key: [u8; 32],
    pub hmac_key: [u8; 32],
    pub enclave_contexts: [EnclaveContext; 4],
    pub current_enclave_id: Option<u32>,
}

static mut INSTANCE: Option<Kernel> = None;

#[no_mangle]
pub static mut CURRENT_ENCLAVE_CTX_PTR: *mut u8 = core::ptr::null_mut();

pub const CODE_BLOCK_SIZE: u32 = 256;
pub const BLOCK_META_SIZE: u32 = 32;

#[cfg(all(feature = "chained_measurement", not(feature = "ess_miss_recovery")))]
pub const BLOCK_META_OFFSET: u32 = 0;
#[cfg(all(feature = "chained_measurement", not(feature = "ess_miss_recovery")))]
pub const BLOCK_HEADER_SIZE: u32 = 32;

#[cfg(all(not(feature = "chained_measurement"), not(feature = "ess_miss_recovery")))]
pub const BLOCK_META_OFFSET: u32 = 32;
#[cfg(all(not(feature = "chained_measurement"), not(feature = "ess_miss_recovery")))]
pub const BLOCK_HEADER_SIZE: u32 = 64;

#[cfg(feature = "ess_miss_recovery")]
pub const BLOCK_META_OFFSET: u32 = 32;
#[cfg(feature = "ess_miss_recovery")]
pub const BLOCK_HEADER_SIZE: u32 = 64;

pub const TOTAL_BLOCK_SIZE: u32 = CODE_BLOCK_SIZE + BLOCK_HEADER_SIZE;

impl Kernel {
    pub fn new(
        guards: &'static mut [&'static mut dyn MemorySecurityGuardTrait],
        crypto: Option<&'static mut dyn CryptoEngine>,
    ) -> Self {
        Self {
            guards,
            ess: EnclaveSwapSpace::new(),
            crypto,
            chain_state: [0u8; 32],
            enc_key: [0u8; 32],
            hmac_key: [0u8; 32],
            enclave_contexts: [EnclaveContext::empty(); 4],
            current_enclave_id: None,
        }
    }

    pub unsafe fn init_keys(&mut self) {
        if let Some(crypto) = self.crypto.as_mut() {
            let crypto: &mut dyn CryptoEngine = &mut **crypto;
            self.enc_key = crate::key_derivation::derive_enc_key(crypto);
            self.hmac_key = crate::key_derivation::derive_hmac_key(crypto);
        }
    }

    pub fn begin_measurement(&mut self) {
        self.chain_state = crate::master_key::MASTER_KEY;
    }

    pub fn finalize_measurement(&self, expected: &[u8; 32]) -> Result<(), ()> {
        let mut diff: u8 = 0;
        let mut i: usize = 0;
        while i < 32 { diff |= self.chain_state[i] ^ expected[i]; i += 1; }
        if diff == 0 { Ok(()) } else { Err(()) }
    }

    /// Verify NPU bytecode + weights against the boot-time chained HMAC
    /// stamped by `tools/measure_blobs.py`. Halts on mismatch — trusting an
    /// unverified blob is worse than not booting.
    ///
    /// Algorithm: state = master_key, fold 256-byte chunks via HMAC-SHA256,
    /// zero-pad the final chunk if `data_len` isn't 256-aligned. Must stay
    /// byte-for-byte aligned with `tools/measure_blobs.py`.
    pub fn measure_boot_blobs(
        &self,
        hash: &mut drivers::hash::Hash,
    ) -> Result<(), &'static str> {
        self.measure_region(
            hash,
            MODEL_BYTECODE_ADDR,
            MODEL_BYTECODE_LEN,
            &MODEL_BYTECODE_HMAC,
            "model bytecode",
        )?;
        self.measure_region(
            hash,
            MODEL_WEIGHTS_ADDR,
            MODEL_WEIGHTS_LEN,
            &MODEL_WEIGHTS_HMAC,
            "model weights",
        )?;
        Ok(())
    }

    fn measure_region(
        &self,
        hash: &mut drivers::hash::Hash,
        addr: u32,
        len: u32,
        expected: &[u8; 32],
        _label: &'static str,
    ) -> Result<(), &'static str> {
        let mut state: [u8; 32] = crate::master_key::MASTER_KEY;
        let mut chunk = [0u8; 256];
        let mut off: u32 = 0;
        while off < len {
            let mut i: u32 = 0;
            while i < 256 {
                if off + i < len {
                    unsafe {
                        chunk[i as usize] = core::ptr::read_volatile(
                            (addr + off + i) as *const u8,
                        );
                    }
                } else {
                    chunk[i as usize] = 0;
                }
                i += 1;
            }
            let mut out = [0u8; 32];
            hash.hmac_sha256(&state, &chunk, &mut out);
            state = out;
            off += 256;
        }
        let mut diff: u8 = 0;
        let mut i = 0;
        while i < 32 {
            diff |= state[i] ^ expected[i];
            i += 1;
        }
        if diff != 0 {
            return Err("HMAC mismatch");
        }
        Ok(())
    }

    /// SysTick configuration for preemptive scheduling. Not yet called from
    /// `init_security` on N657; kept here so the surface is ready for a
    /// FreeRTOS-style preemptive host.
    #[allow(dead_code)]
    pub unsafe fn enable_systick(&self) {
        let syst_rvr = SYST_RVR;
        let syst_cvr = SYST_CVR;
        let syst_csr = SYST_CSR;
        // ~10ms at 150 MHz (Boot ROM PLL clock)
        core::ptr::write_volatile(syst_rvr, 1_500_000 - 1);
        core::ptr::write_volatile(syst_cvr, 0);
        core::ptr::write_volatile(syst_csr, 0x07);
    }

    pub unsafe fn disable_systick(&self) {
        let syst_csr = SYST_CSR;
        core::ptr::write_volatile(syst_csr, 0x00);
        let icsr = SCB_ICSR;
        core::ptr::write_volatile(icsr, 1 << 25); // PENDSTCLR
    }

    pub fn lookup_faulting_block(&self, pc: u32) -> Option<(u32, u32)> {
        for slot in self.ess.loaded_enclaves.iter().flatten() {
            let base = slot.start_address;
            let top = base + (slot.efb_count as u32) * CODE_BLOCK_SIZE;
            if pc >= base && pc < top {
                return Some((slot.descriptor.id, (pc - base) / CODE_BLOCK_SIZE));
            }
        }
        None
    }

    pub unsafe fn init(kernel: Kernel) {
        INSTANCE = Some(kernel);
    }

    pub unsafe fn get() -> Option<&'static mut Kernel> {
        (*(&raw mut INSTANCE)).as_mut()
    }

    /// CPU-copy block loader from XSPI2 to ESS.
    ///
    /// Reads `CODE_BLOCK_SIZE` bytes from the protected blob on XSPI2 and
    /// copies them into the ESS slot for `block_idx`. Block layout
    /// (chained_measurement, no ess_miss_recovery): each 288-byte block is
    /// `[Meta(32) | Code(256)]`, so the code starts at
    /// `enclave_flash_base + UMBRA_HEADER_SIZE + block_idx * 288 + 32`.
    ///
    /// MCE2 transparently decrypts blocks placed inside its region 1; the
    /// current enclave lives outside that region at 0x70090000, so
    /// memory-mapped reads return plaintext.
    ///
    /// HMAC chained-measurement validation is performed by the caller
    /// (`kernel.chain_state` + `update_chain` + final `finalize_measurement`
    /// against the header HMAC).
    pub unsafe fn load_block_n657(
        &mut self,
        block_idx: u32,
        ess_base: u32,
        enclave_flash_base: u32,
    ) -> Result<(), u32> {
        use kernel::common::enclave::UMBRA_HEADER_SIZE;

        let flash_block_base = enclave_flash_base
            + UMBRA_HEADER_SIZE
            + block_idx * TOTAL_BLOCK_SIZE;
        let code_src = (flash_block_base + BLOCK_HEADER_SIZE) as *const u8;
        let ess_dst  = (ess_base + block_idx * CODE_BLOCK_SIZE) as *mut u8;

        let mut i: u32 = 0;
        while i < CODE_BLOCK_SIZE {
            let b = core::ptr::read_volatile(code_src.add(i as usize));
            core::ptr::write_volatile(ess_dst.add(i as usize), b);
            i += 1;
        }

        // Cache coherency: with D-cache enabled, the writes above sit in
        // D-cache. The enclave's instruction fetcher reads via I-cache
        // directly from RAM (separate path) and would see stale bytes,
        // faulting with MMFSR.IACCVIOL at the enclave's first PC.
        //
        // Fix: clean each just-written 32-byte cache line to PoC via DCCMVAC,
        // then invalidate I-cache (ICIALLU) so the next fetch reloads from RAM.
        // 256 B block = 8 cache lines, so 8 register writes — cheap.
        // SCB offsets: DCCMVAC = 0x268, ICIALLU = 0x250 (cm55 ARM reference).
        let dst_base = ess_base + block_idx * CODE_BLOCK_SIZE;
        let line_size: u32 = 32;
        let aligned_start = dst_base & !(line_size - 1);
        let end = dst_base + CODE_BLOCK_SIZE;
        cortex_m::asm::dsb();
        let mut a = aligned_start;
        while a < end {
            core::ptr::write_volatile(DCCMVAC, a);
            a += line_size;
        }
        cortex_m::asm::dsb();
        core::ptr::write_volatile(ICIALLU, 0);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        Ok(())
    }
}
