//! Boot-time secure-side bootstrap: struct definition, constants,
//! key-derivation, chained-measurement seeding, SysTick control, PC→block
//! lookup, and the static-PIE relocation helper.
//! See the `secure_kernel` module-level docs for the invariants that every
//! change in this file must preserve.

use arm::mmio::{SCB_ICSR, SYST_CSR, SYST_CVR, SYST_RVR};
use kernel::common::enclave::EnclaveContext;
use kernel::common::ess::{EnclaveSwapSpace, MAX_ENCLAVES_CTX};
use kernel::key_storage_server::crypto::CryptoEngine;
use kernel::memory_protection_server::memory_guard::MemorySecurityGuardTrait;

pub struct Kernel {
    #[allow(dead_code)]
    // Architectural: holds SAU/GTZC guard refs for potential runtime reconfiguration
    pub guards: &'static mut [&'static mut dyn MemorySecurityGuardTrait],
    pub ess: EnclaveSwapSpace,
    pub crypto: Option<&'static mut dyn CryptoEngine>,
    /// Running HMAC-chain state for the currently-loading enclave. Seeded from
    /// `master_key::MASTER_KEY` in `begin_measurement()` and folded block-by-block
    /// in `load_and_verify_block()`. Compared against the enclave header's
    /// `hmac` field in `finalize_measurement()`.
    pub chain_state: [u8; 32],
    /// Subkeys derived from `MASTER_KEY` via `key_derivation::derive_*_key`.
    /// Populated by `init_keys()` immediately after `Kernel::init`, before any
    /// block loading or ESS-miss recovery runs. Formal-model analog:
    /// `encKey` / `hmacKey` in the L552 ProVerif model.
    pub enc_key: [u8; 32],
    pub hmac_key: [u8; 32],
    pub enclave_contexts: [EnclaveContext; MAX_ENCLAVES_CTX],
    pub current_enclave_id: Option<u32>,
}

pub(super) static mut INSTANCE: Option<Kernel> = None;

#[no_mangle]
pub static mut CURRENT_ENCLAVE_CTX_PTR: *mut u8 = core::ptr::null_mut();

// --- CONSTANTS ---
// Alias to the single-source-of-truth SLOT_SIZE in the kernel // build-time knob via.cargo/config.toml [env]).
pub use kernel::common::ess::SLOT_SIZE as CODE_BLOCK_SIZE;

pub const BLOCK_META_SIZE: u32 = 32;

// Per-block on-flash header layout. `ess_miss_recovery` adds a 32B HMAC prefix
// (used by the runtime Validator for on-demand block validation) and shifts
// the metadata to +32.
// chained only: [Meta(32) | CT(256)] 32B header, 288B total
// legacy (no chained): [HMAC(32) | Meta(32) | CT(256)] 64B header, 320B total
// chained + ess_miss_recovery: [HMAC(32) | Meta(32) | CT(256)] 64B header, 320B total
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

#[cfg(all(feature = "chained_measurement", not(feature = "ess_miss_recovery")))]
pub const BLOCK_META_OFFSET: u32 = 0;
#[cfg(all(feature = "chained_measurement", not(feature = "ess_miss_recovery")))]
pub const BLOCK_HEADER_SIZE: u32 = 32;

#[cfg(feature = "ess_miss_recovery")]
pub const BLOCK_META_OFFSET: u32 = 32;
#[cfg(feature = "ess_miss_recovery")]
pub const BLOCK_HEADER_SIZE: u32 = 64;

pub const TOTAL_BLOCK_SIZE: u32 = CODE_BLOCK_SIZE + BLOCK_HEADER_SIZE;

/// Apply the on-flash R_ARM_ABS32 static-PIE relocation table to a
/// freshly decrypted ESS block. Adds `(enclave_runtime_secure_base -
/// 0x30)` to every 32-bit slot whose plaintext-relative offset falls
/// inside this block.
/// Why this exists: heavy paper-apps (anagram, dijkstra, huff_dec,
/// cjpeg_wrbmp) declare `char const *table[N] = {"a", "b",...}`. The
/// linker writes COMPILE-TIME absolute addresses into those slots; at
/// runtime the enclave is mapped at an arbitrary EFBC base, so a
/// `table[i]` deref would otherwise treat e.g. `0x2270` as an absolute
/// pointer and MemManage with "addr outside any enclave" on the first
/// load. `tools/protect_enclave.py` extracts every R_ARM_ABS32 from the
/// ELF (`--emit-relocs`-preserved `.rel._enclave_code`), translates the
/// offsets to plaintext-relative (subtract `_enclave_code_start` VMA =
/// 0x30), and appends a flat u32 offset table after the encrypted
/// blocks. `header.reloc_count` records how many entries the table holds.
/// We patch PER-BLOCK rather than once-globally because each block has
/// its own install lifetime: some blocks come in via BFS
/// (`load_and_verify_block`), others via boot-time force-load or
/// runtime ESS-miss recovery (`handle_ess_miss`). An evicted block
/// reloaded later must re-apply the relocations its plaintext carries.
/// Tamper resistance: `protect_enclave.py` folds the reloc-table bytes
/// into the chained measurement immediately after the BFS-ordered block
/// fold. `api_impl.rs` mirrors that on the kernel side before
/// `finalize_measurement`, so any tampering with the reloc table on
/// flash causes the measurement to mismatch BEFORE any pointer is
/// patched.
#[inline(never)]
pub(super) unsafe fn apply_relocs_to_block(
    enclave_flash_base: u32,
    block_runtime_secure_addr: u32,
    enclave_runtime_secure_base: u32,
    block_idx: u32,
) {
    use kernel::common::enclave::{UmbraEnclaveHeader, UMBRA_HEADER_SIZE};
    let hdr = match UmbraEnclaveHeader::from_address(enclave_flash_base) {
        Some(h) => h,
        None => return,
    };
    // Pack-misaligned u16 read: copy out before use so the next access
    // doesn't fault on platforms that don't permit unaligned u16 loads.
    let n_relocs = { hdr.reloc_count } as u32;
    if n_relocs == 0 {
        return;
    }
    let code_size = { hdr.code_size };
    // CJ3 guard: every block install (BFS path + ESS-miss path)
    // re-reads the reloc table from this address. Without `checked_add`
    // the wrap is silent and the volatile walk below dereferences a
    // wild flash pointer per relocation entry. The upstream bound on
    // `num_blocks` in `enclave_create.rs` limits exposure, but the
    // per-block re-fetch is a defense-in-depth surface.
    let reloc_table_flash = match enclave_flash_base
        .checked_add(UMBRA_HEADER_SIZE)
        .and_then(|x| x.checked_add(code_size))
    {
        Some(addr) => addr,
        None => return,
    };
    let block_lo = match block_idx.checked_mul(CODE_BLOCK_SIZE) {
        Some(v) => v,
        None => return,
    };
    let block_hi = match block_lo.checked_add(CODE_BLOCK_SIZE) {
        Some(v) => v,
        None => return,
    };
    let runtime_delta = enclave_runtime_secure_base.wrapping_sub(0x30);
    let table_ptr = reloc_table_flash as *const u32;
    let mut i: u32 = 0;
    while i < n_relocs {
        let off = core::ptr::read_volatile(table_ptr.add(i as usize));
        if off >= block_lo && off < block_hi {
            let intra = off - block_lo;
            let slot = (block_runtime_secure_addr + intra) as *mut u32;
            let cur = core::ptr::read_volatile(slot);
            let fixed = cur.wrapping_add(runtime_delta);
            core::ptr::write_volatile(slot, fixed);
        }
        i += 1;
    }
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
}

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
            enclave_contexts: [EnclaveContext::empty(); MAX_ENCLAVES_CTX],
            current_enclave_id: None,
        }
    }

    /// Populate `enc_key` and `hmac_key` from the master key via the KDF. Must
    /// be called once, immediately after `Kernel::init`, before any enclave
    /// loading. No-op if `crypto` was never installed.
    ///
    /// Returns `Err(UmbraError::HashHardware)` if the KDF's HASH engine wedges;
    /// the boot boundary turns that into a visible halt rather than booting on
    /// all-zero keys.
    pub unsafe fn init_keys(&mut self) -> umbra_error::UmbraResult<()> {
        if let Some(crypto) = self.crypto.as_mut() {
            let crypto: &mut dyn CryptoEngine = &mut **crypto;
            self.enc_key = crate::key_derivation::derive_enc_key(crypto)?;
            self.hmac_key = crate::key_derivation::derive_hmac_key(crypto)?;
        }
        Ok(())
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
        if diff == 0 {
            Ok(())
        } else {
            Err(())
        }
    }

    #[allow(dead_code)] // Value matches assembly constant 1099999 (SYSTICK_RELOAD-1) in startup.s _svc_enter
    pub const SYSTICK_RELOAD: u32 = 1_100_000; // ~10ms at 110 MHz SYSCLK (post-PLL)

    #[allow(dead_code)] // SysTick enabled by assembly in startup.s _svc_enter; this method exists for future Rust-side use
    pub unsafe fn enable_systick(&self) {
        let syst_rvr = SYST_RVR;
        let syst_cvr = SYST_CVR;
        let syst_csr = SYST_CSR;
        core::ptr::write_volatile(syst_rvr, Self::SYSTICK_RELOAD - 1);
        core::ptr::write_volatile(syst_cvr, 0);
        core::ptr::write_volatile(syst_csr, 0x07);
    }

    pub unsafe fn disable_systick(&self) {
        let syst_csr = SYST_CSR;
        core::ptr::write_volatile(syst_csr, 0x00);
        // Also clear any already-pending SysTick exception. Otherwise a
        // SysTick that fired mid-handler will tail-chain after our current
        // exception return, re-enter the SysTick trampoline, and clobber the
        // status word that the UsageFault / MemManage / BusFault handler
        // wrote into the SVC-entry MSP frame — turning a Faulted/Terminated
        // return into a spurious Suspended.
        let icsr = SCB_ICSR;
        core::ptr::write_volatile(icsr, 1 << 25); // PENDSTCLR
    }

    /// Resolve an executing PC to `(enclave_id, block_idx)` if it sits inside
    /// a currently-loaded enclave's ESS cache region. Used by the MemManage
    /// IACCVIOL handler to translate a stacked PC into a cache miss request.
    /// Returns `None` if the PC is outside every loaded enclave.
    /// Uses `descriptor.code_size` (= `num_blocks * CODE_BLOCK_SIZE`, set at
    /// create time from the on-flash header) rather than `efb_count`: BFS
    /// only visits blocks that have inbound branches from the entry block,
    /// so a trailing `.data`/`.bss`-only block under PIC has `efb_count`
    /// missing one entry even though it IS a part of the enclave's ESS
    /// allocation. Using `code_size` makes the boundary truthful to the
    /// kernel's ESS allocation, so the BusFault recovery path can demand-
    /// load such blocks when the enclave first writes to a global.
    pub fn lookup_faulting_block(&self, pc: u32) -> Option<(u32, u32)> {
        for slot in self.ess.loaded_enclaves.iter().flatten() {
            let base = slot.start_address;
            let top = base + slot.descriptor.code_size;
            if pc >= base && pc < top {
                let block_idx = (pc - base) / CODE_BLOCK_SIZE;
                return Some((slot.descriptor.id, block_idx));
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
}
