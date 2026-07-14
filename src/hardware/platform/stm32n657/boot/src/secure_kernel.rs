//! Kernel wrapper for STM32N657.
//! Slimmer than the L5 sibling: no DMA, no GTZC/RISAF. Block loads use
//! CPU copy via `load_block_n657`; ESS-miss recovery flows through the
//! UsageFault dispatcher in handlers.rs.
//! # Decomposition target () — currently 262 LOC
//! Mirrors L552's planned split: `init/` / `enter/` / `exit/` / `lifecycle/`.
//! The split for N657 is smaller because the DMA-driven page-load logic
//! lives on the L552 side; N657 only does CPU copy here.
//! # Invariants every change MUST preserve
//! - **CJ2 chained-measurement** — N657 uses SW SHA-256 from
//! `drivers::hash` (see that module's doc for the RIFSC history).
//! Bypassing or reordering the chain breaks the root of trust.
//! - **D-cache coherency** — `load_block_n657` DMAs the block, then INVALIDATES the
//! slot's D-cache lines + `ICIALLU` + `DSB` + `ISB`. Invalidate (not clean): the DMA
//! wrote RAM directly, so a clean would push stale lines over it. Skipping produces
//! MMFSR.IACCVIOL at the enclave's first PC.
//! - **`lookup_faulting_block` top boundary** — currently uses
//! `efb_count * CODE_BLOCK_SIZE` (BFS-visited subset). The L552 fix
//! to use `descriptor.code_size` (true ESS allocation) has not yet
//! been ported; will manifest the same trailing-data-block
//! "outside any enclave" panic when porting heavy paper-apps. Trivial
//! one-line change
//! "Open follow-ups" #1).
//! - **Panic-policy delegation** — every failure path delegates to
//! `panic_policy::handle_fault()` per ADR 2026-panic-policy.

use arm::mmio::{ICIALLU, SCB_ICSR, SYST_CSR, SYST_CVR, SYST_RVR};
use kernel::common::enclave::EnclaveContext;
use kernel::common::ess::EnclaveSwapSpace;
use kernel::key_storage_server::crypto::CryptoEngine;
use kernel::memory_protection_server::memory_guard::MemorySecurityGuardTrait;

use crate::boot_measurements::{
    MODEL_BYTECODE_ADDR, MODEL_BYTECODE_HMAC, MODEL_BYTECODE_LEN, MODEL_WEIGHTS_ADDR,
    MODEL_WEIGHTS_HMAC, MODEL_WEIGHTS_LEN,
};

/// Enclave state-continuity checkpoint/restore (runtime integration 2/4). Declared
/// here — a clean, already-linked module — so no `mod` line is added to main.rs.
#[path = "state_checkpoint.rs"]
pub mod state_checkpoint;

#[cfg(feature = "enclave_version_bind")]
include!(concat!(env!("OUT_DIR"), "/author_id.rs"));

/// Bind (author_id, version) to the block measurement `bm` by a trailing HMAC.
/// MUST equal tools/protect_enclave.py::version_tag (label 15 B + author_le +
/// version_le). Pinned by tools/test_enclave_version_guard.py.
#[cfg(feature = "enclave_version_bind")]
pub fn version_tag(
    hash: &mut drivers::hash::Hash,
    bm: &[u8; 32],
    author_id: u32,
    version: u32,
) -> [u8; 32] {
    const ENCVER_LABEL: &[u8] = b"umbra-encver-v1";
    let mut input = [0u8; 15 + 8];
    input[..15].copy_from_slice(ENCVER_LABEL);
    input[15..19].copy_from_slice(&author_id.to_le_bytes());
    input[19..].copy_from_slice(&version.to_le_bytes());
    let mut out = [0u8; 32];
    hash.hmac_sha256(bm, &input, &mut out);
    out
}

pub struct Kernel {
    #[allow(dead_code)]
    pub guards: &'static mut [&'static mut dyn MemorySecurityGuardTrait],
    pub ess: EnclaveSwapSpace,
    pub crypto: Option<&'static mut dyn CryptoEngine>,
    pub chain_state: [u8; 32],
    pub enc_key: [u8; 32],
    pub hmac_key: [u8; 32],
    /// Stable device secret that keys the state-continuity checkpoint anchor root.
    pub state_root: [u8; 32],
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

#[cfg(all(
    not(feature = "chained_measurement"),
    not(feature = "ess_miss_recovery")
))]
pub const BLOCK_META_OFFSET: u32 = 32;
#[cfg(all(
    not(feature = "chained_measurement"),
    not(feature = "ess_miss_recovery")
))]
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
            state_root: [0u8; 32],
            enclave_contexts: [EnclaveContext::empty(); 4],
            current_enclave_id: None,
        }
    }

    /// Populate `enc_key`/`hmac_key` from the master key via the KDF.
    /// Returns `Err(UmbraError::KeyDerivation)` if the HASH engine wedges; the
    /// boot boundary halts visibly rather than booting on all-zero keys (the
    /// old body swallowed the error and returned a zero key).
    pub unsafe fn init_keys(&mut self) -> umbra_error::UmbraResult<()> {
        if let Some(crypto) = self.crypto.as_mut() {
            let crypto: &mut dyn CryptoEngine = &mut **crypto;
            self.enc_key = crate::key_derivation::derive_enc_key(crypto)?;
            self.hmac_key = crate::key_derivation::derive_hmac_key(crypto)?;
            self.state_root = crate::key_derivation::derive_state_root(crypto)?;
        }
        Ok(())
    }

    pub fn begin_measurement(&mut self) {
        self.chain_state = crate::master_key::MASTER_KEY;
    }

    // Used by the legacy finalize path; the `enclave_version_bind` build derives
    // the version by search instead (api_impl.rs), leaving this unused there.
    #[cfg_attr(feature = "enclave_version_bind", allow(dead_code))]
    pub fn finalize_measurement(&self, expected: &[u8; 32]) -> Result<(), ()> {
        let mut diff: u8 = 0;
        let mut i: usize = 0;
        while i < 32 {
            diff |= self.chain_state[i] ^ expected[i];
            i += 1;
        }
        if diff == 0 {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Verify NPU bytecode + weights against the boot-time chained HMAC
    /// stamped by `tools/measure_blobs.py`. Halts on mismatch — trusting an
    /// unverified blob is worse than not booting.
    /// Algorithm: state = master_key, fold 256-byte chunks via HMAC-SHA256,
    /// zero-pad the final chunk if `data_len` isn't 256-aligned. Must stay
    /// byte-for-byte aligned with `tools/measure_blobs.py`.
    pub fn measure_boot_blobs(&self, hash: &mut drivers::hash::Hash) -> Result<(), &'static str> {
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
                        chunk[i as usize] = core::ptr::read_volatile((addr + off + i) as *const u8);
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
            // CJ3 DoS guard: a bloated `efb_count` makes
            // `base + efb_count * CODE_BLOCK_SIZE` wrap below `base`, so
            // `pc >= base && pc < top` becomes always-false for some PCs
            // — silent denial of demand-paging. `checked_mul` +
            // `checked_add` catch the wrap so we skip the broken slot and
            // keep scanning. The `enclave_create` bound caps `efb_count`
            // for newly-registered enclaves, but the per-fault lookup
            // walks `ess.loaded_enclaves` which may include slots from
            // regression-prone future code paths.
            let top = match (slot.efb_count as u32)
                .checked_mul(CODE_BLOCK_SIZE)
                .and_then(|x| base.checked_add(x))
            {
                Some(v) => v,
                None => continue,
            };
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
    /// Reads `CODE_BLOCK_SIZE` bytes from the protected blob on XSPI2 and
    /// copies them into the ESS slot for `block_idx`. Block layout
    /// (chained_measurement, no ess_miss_recovery): each 288-byte block is
    /// `[Meta(32) | Code(256)]`, so the code starts at
    /// `enclave_flash_base + UMBRA_HEADER_SIZE + block_idx * 288 + 32`.
    /// MCE2 transparently decrypts blocks placed inside its region 1; the
    /// current enclave lives outside that region at 0x70090000, so
    /// memory-mapped reads return plaintext.
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

        // CJ3 defense-in-depth guard: `block_idx` is bounded by
        // `num_blocks ≤ MAX_EFBS` at the `umbra_enclave_create_imp`
        // call site. The explicit `checked_*` chain below guards against
        // a future regression in that bound and documents the per-block
        // arithmetic invariant.
        let flash_block_base = enclave_flash_base
            .checked_add(UMBRA_HEADER_SIZE)
            .and_then(|x| {
                block_idx
                    .checked_mul(TOTAL_BLOCK_SIZE)
                    .and_then(|y| x.checked_add(y))
            })
            .ok_or(0xFFFFFFF7u32)?;
        let code_src = flash_block_base
            .checked_add(BLOCK_HEADER_SIZE)
            .ok_or(0xFFFFFFF7u32)? as *const u8;
        let ess_dst = block_idx
            .checked_mul(CODE_BLOCK_SIZE)
            .and_then(|x| ess_base.checked_add(x))
            .ok_or(0xFFFFFFF7u32)? as *mut u8;

        // Load the block via HPDMA1 (mem-to-mem, flash→ESS) instead of a CPU byte loop.
        // The source is the memory-mapped XSPI2 window (MCE-decrypted on read); the dest
        // is the ESS slot in AXISRAM, whose RISAF admits only CID 1 — `set_channel_secure`
        // presents it. Synchronous for now; this is the exact transfer the async prefetch
        // pipeline (Phase 2) reuses under a TC-IRQ + PendSV install. A dedicated channel
        // (2) keeps it clear of the crypto DMA channels (0/1).
        const PREFETCH_CH: u8 = 2;
        let dma = drivers::hpdma::Hpdma1::new();
        drivers::hpdma::enable_clock();
        dma.set_channel_secure(PREFETCH_CH);
        dma.reset_channel(PREFETCH_CH);
        dma.configure_mem_to_mem(PREFETCH_CH, code_src as u32, ess_dst as u32, CODE_BLOCK_SIZE);
        dma.enable_channel(PREFETCH_CH);
        let sr = dma.wait_complete(PREFETCH_CH, 4_000_000);
        dma.clear_flags(PREFETCH_CH);
        if (sr & drivers::hpdma::CH_TCF) == 0 {
            return Err(0xFFFFFFF6); // DMA did not complete cleanly (error/timeout)
        }

        // Cache coherency for a DMA-written CODE block. The DMA wrote the bytes straight
        // to RAM, bypassing the CPU D-cache. INVALIDATE (not clean) the slot's D-cache
        // lines: a clean would write any stale line back over the DMA's fresh bytes. Then
        // invalidate the I-cache (ICIALLU) so the enclave's next fetch reloads from RAM,
        // else it faults MMFSR.IACCVIOL at the first PC. A code slot is never CPU-written,
        // so no dirty line is lost by the invalidate.
        cortex_m::asm::dsb();
        drivers::hpdma::dcache_invalidate_range(ess_dst as usize, CODE_BLOCK_SIZE as usize);
        core::ptr::write_volatile(ICIALLU, 0);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        Ok(())
    }
}
