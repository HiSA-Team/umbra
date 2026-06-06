//! Enclave Swapping Set (ESS) — manages the loaded-EFB cache and page
//! replacement against the MPCBB (L552) / RIF+RISAF (N657) protection
//! controllers. CJ3 in the threat model (EFB confidentiality and
//! isolation) relies on every primitive in this module being correctly
//! ordered with respect to the protection controller.
//! # Three invariants that took real bugs to find
//! ## 1. Secure-alias execution would bypass MPCBB without the UDF trap
//! On STM32L5, executing from the Secure alias `0x300x_xxxx` bypasses the
//! MPCBB slot-level check that protects the NS alias `0x200x_xxxx`. The
//! handler-driven demand paging therefore traps via a UDF (`0xDEDE`)
//! pattern stamped into every non-resident slot; the `UsageFault.UNDEFINSTR`
//! handler is what kicks ESS-miss recovery. Removing the UDF stamp turns
//! the cache into a silent confidentiality bypass — see Phase 3A bring-up
//! findings. EXC_RETURN for the recovery path must be `0xFFFF_FFFD`
//! (no-FP, Thread/PSP/Secure); `0xFFFF_FFED` (FP frame) triggered NOCP.
//! ## 2. Page replacement during SysTick preemption is fragile
//! With two enclaves loaded and a SysTick interrupt landing mid-context-
//! switch, the resume path can land its PC inside a slot that has since
//! been evicted to another EFB. Mitigated today by the globals-bypass
//! pattern in Phase 2 and the `lookup_faulting_block` fix that uses
//! `descriptor.code_size` (true ESS allocation) rather than
//! `efb_count * CODE_BLOCK_SIZE` (BFS-visited subset). The MPU region 5
//! over the ESS is AP=`0b01` (RW, any privilege) — `0b11` (RO-all) caused
//! infinite MM cycles on the first enclave write to a global.
//! ## 3. DMA → MPCBB ordering (the ndes / statemate crash)
//! `handle_ess_miss` MUST call `drivers::gtzc::mpcbb_set_slot_secure(addr,
//! false)` BEFORE the DMA transfer that fetches the new page. The DMA
//! channel writes via the NS alias; if the MPCBB still classifies the
//! slot as Secure-only, GTZC silently drops the writes and the slot stays
//! filled with whatever was there at boot (typically `0xFF`s or stale
//! decryption garbage). Force-load (called at create time for blocks BFS
//! did not visit) hit this exactly: ESS-miss-recovery already had the
//! flip-to-NS because `evict_block` flipped first, but force-load did
//! not, and `ndes` was the first benchmark with > 12 force-loaded blocks
//! to expose the silent-garbage path. Tests `ndes` and `statemate` are
//! the regression oracles.

use crate::common::enclave::EnclaveDescriptor;
use umbra_error::{UmbraError, UmbraResult};

// Reject building with both platform features enabled — the cfg-gated
// constants below would conflict.
#[cfg(all(feature = "platform-l552", feature = "platform-n657"))]
compile_error!("Enable exactly ONE of kernel features platform-l552 or platform-n657");

// ── L552 platform ESS layout ─────────────────────────────────────────
// PSP stacks live just above.bss, well below the MSP. The MSP starts at
// _umb_estack (0x3003DFFC) and can grow 24 KB down to 0x30038000 before
// touching the PSP ceiling. Each enclave gets an 8 KB PSP stack: paper-
// app `ndes` uses ~5 KB (DES key schedule + two `volatile char ip[65]`
// literal-array initialisers per ndes_des() call + nested cyfun/ks
// calls), and a smaller stack causes CFSR.MUNSTKERR on exception return.
#[cfg(feature = "platform-l552")]
pub const ESS_BASE: u32 = 0x30032000; // SRAM2 (Structures, Secure alias)
#[cfg(feature = "platform-l552")]
pub const ESS_SIZE: u32 = 0x10000; // 64KB
#[cfg(feature = "platform-l552")]
pub const EFBC_BASE: u32 = 0x20020000; // SRAM1 Top 64KB (Execution) — NS alias so MPCBB per-block attribution is enforced
#[cfg(feature = "platform-l552")]
pub const ENCLAVE_PSP_BASE: u32 = 0x30034000;
#[cfg(feature = "platform-l552")]
pub const ENCLAVE_PSP_TOP: u32 = 0x30038000;

// ── N657 platform ESS layout ─────────────────────────────────────────
// AXISRAM1 (1 MB IDAU view) is split: 0x34000000-0x34063FFF is FLEXRAM
// (RISAF7), 0x34064000-0x340FFFFF is AXISRAM1 proper (RISAF2). The host runs
// in the lower portion via the NS alias (0x24000000+); enclave code lives in
// the upper portion via the Secure alias. RISAF2 region 1 must end before
// EFBC_BASE so default region 0 (Secure+CID=1+priv) governs the upper bank.
// Layout summary (Secure alias):
// 0x34064000–0x340DFFFF ~496 KB NS host (RISAF2 region 1 SEC=0)
// 0x340E0000–0x340EFFFF 64 KB EFBC — enclave code blocks (Secure)
// 0x340F0000–0x340F3FFF 16 KB PSP stacks (sized to match L552: 2 × 8 KB
// or 4 × 4 KB — ndes needs ~5 KB per enclave)
// 0x340F4000–0x340FFFFF 48 KB reserved for ESS metadata / future use
#[cfg(feature = "platform-n657")]
pub const ESS_BASE: u32 = 0x340E0000;
#[cfg(feature = "platform-n657")]
pub const ESS_SIZE: u32 = 0x10000; // 64KB EFBC region
#[cfg(feature = "platform-n657")]
pub const EFBC_BASE: u32 = 0x340E0000; // Secure alias — RISAF2 default region 0 governs (CID=1+priv)
#[cfg(feature = "platform-n657")]
pub const ENCLAVE_PSP_BASE: u32 = 0x340F0000;
#[cfg(feature = "platform-n657")]
pub const ENCLAVE_PSP_TOP: u32 = 0x340F4000;

// ── Platform-agnostic constants ──────────────────────────────────────
// Build-time knobs: SLOT_SIZE, CACHE_LIMIT_PER_ENCLAVE,
// MAX_ENCLAVES_CTX, ENCLAVE_PSP_STACK_SIZE, MAX_KEYS. Defaults live
// in.cargo/config.toml [env]; override per build:
// UMBRA_SLOT_SIZE_BYTES=2048 UMBRA_CACHE_LIMIT=8 \
// UMBRA_MAX_ENCLAVES_CTX=4 UMBRA_ENCLAVE_PSP_STACK_BYTES=4096 \
//./rebuild_all.sh
// See src/kernel/build.rs for the generation logic.
include!(concat!(env!("OUT_DIR"), "/sizes_generated.rs"));

// MAX_EFBS covers paper-app `statemate` (41 blocks). The `loaded_mask`
// bitmap in api_impl.rs is u64 — its width MUST match this ceiling.
// For larger enclaves (susan / cjpeg territory), switch to a
// `[u32; (MAX_EFBS+31)/32]` chunked bitmap. NOT moved to env: silently
// breaking the bitmap-bit-width invariant is too dangerous.
pub const MAX_EFBS: usize = 64;

// Static guard: MAX_ENCLAVES_CTX × ENCLAVE_PSP_STACK_SIZE must fit in
// the platform PSP region (ENCLAVE_PSP_TOP − ENCLAVE_PSP_BASE). This
// catches knob mis-configurations at build time instead of letting an
// out-of-region PSP top corrupt MSP at the first SVC.
const _: () = assert!(
    MAX_ENCLAVES_CTX * (ENCLAVE_PSP_STACK_SIZE as usize)
        <= (ENCLAVE_PSP_TOP - ENCLAVE_PSP_BASE) as usize,
    "UMBRA_MAX_ENCLAVES_CTX x UMBRA_ENCLAVE_PSP_STACK_BYTES exceeds the \
platform PSP region: either reduce a knob or bump the platform layout.",
);

pub fn enclave_psp_top(enclave_idx: usize) -> u32 {
    ENCLAVE_PSP_TOP - (enclave_idx as u32) * ENCLAVE_PSP_STACK_SIZE
}

#[derive(Clone, Copy)]
pub struct EnclaveSwapSpace {
    pub base_address: u32,
    pub size: u32,
    pub loaded_enclaves: [Option<LoadedEnclave>; MAX_ENCLAVES_CTX],
    pub bitmap: [u32; 8], // 256 slots (256 * 256B = 64KB)
}

pub const MAX_REACHABLE: usize = 4;

#[derive(Clone, Copy)]
pub struct EfbDescriptor {
    pub id: u32,
    pub is_loaded: bool,
    pub counter: u8,
    pub reachable: [u8; MAX_REACHABLE],
    pub reachable_count: u8,
}

impl Default for EfbDescriptor {
    fn default() -> Self {
        Self {
            id: 0,
            is_loaded: false,
            counter: 0,
            reachable: [0; MAX_REACHABLE],
            reachable_count: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub struct LoadedEnclave {
    pub descriptor: EnclaveDescriptor,
    pub start_address: u32,
    pub efbs: [EfbDescriptor; MAX_EFBS],
    pub efb_count: usize,
}

impl EnclaveSwapSpace {
    pub fn new() -> Self {
        Self {
            base_address: ESS_BASE,
            size: ESS_SIZE,
            loaded_enclaves: [None; MAX_ENCLAVES_CTX],
            bitmap: [0; 8],
        }
    }

    /// First-fit allocate a contiguous run of ESS slots for `size` bytes.
    /// Returns the EFBC base address on success, or:
    /// - `Err(UmbraError::LengthMismatch)` if `size` rounds to zero slots,
    /// - `Err(UmbraError::OffsetOverflow)` if the slot-count round-up overflows,
    /// - `Err(UmbraError::EssRegionExhausted)` if no contiguous run is free.
    pub fn allocate(&mut self, size: u32) -> UmbraResult<u32> {
        let slots_needed = size
            .checked_add(SLOT_SIZE - 1)
            .ok_or(UmbraError::OffsetOverflow)?
            / SLOT_SIZE;
        if slots_needed == 0 {
            return Err(UmbraError::LengthMismatch);
        }

        // Total ESS slots = ESS_SIZE / SLOT_SIZE. With SLOT_SIZE knob
        // (1024…8192) the value varies 8…256. The bitmap stays sized
        // for 256 slots = 8 u32 (worst case), with unused trailing
        // bits when SLOT_SIZE > 256.
        let total_slots = (ESS_SIZE / SLOT_SIZE) as usize;
        let mut found_start = 0;
        let mut found_count = 0;

        let mut i: usize = 0;
        while i < total_slots {
            let word_idx = i / 32;
            let bit_idx = i % 32;

            if (self.bitmap[word_idx] & (1 << bit_idx)) == 0 {
                if found_count == 0 {
                    found_start = i;
                }
                found_count += 1;
            } else {
                found_count = 0;
            }

            if found_count == slots_needed {
                // Mark as used
                let mut k: usize = 0;
                while k < (slots_needed as usize) {
                    let idx = found_start + k;
                    self.bitmap[idx / 32] |= 1 << (idx % 32);
                    k += 1;
                }
                // Return address from EFBC (Execution Memory)
                return Ok(EFBC_BASE + (found_start as u32 * SLOT_SIZE));
            }
            i += 1;
        }
        Err(UmbraError::EssRegionExhausted)
    }

    /// Release an allocated slot run back to the free bitmap.
    /// `address` must be the value returned by `allocate`; `size` must
    /// match the byte length passed to that allocate call.
    /// Roll-back path for `umbra_enclave_create_imp` when create bails out
    /// (chained-measurement FAIL, register_enclave failure, BFS error).
    /// Without this, a tampered or stale enclave blob silently leaks its
    /// slot run on every boot and eventually starves the allocator.
    pub fn release(&mut self, address: u32, size: u32) {
        if address < EFBC_BASE {
            return;
        }
        let slot_offset = (address - EFBC_BASE) / SLOT_SIZE;
        let slots = (size + SLOT_SIZE - 1) / SLOT_SIZE;
        let mut k: u32 = 0;
        while k < slots {
            let idx = (slot_offset + k) as usize;
            // Bound check against the bitmap capacity (8 u32 = 256 bits).
            // This is independent of the live slot count (ESS_SIZE/SLOT_SIZE)
            // — it's a guard against arithmetic mistakes by the caller.
            // The bitmap is sized for the worst case SLOT_SIZE=256;
            // larger SLOT_SIZE values use the lower bits only.
            const BITMAP_CAPACITY: usize = 256;
            if idx < BITMAP_CAPACITY {
                self.bitmap[idx / 32] &= !(1u32 << (idx % 32));
            }
            k += 1;
        }
    }

    pub fn register_enclave(
        &mut self,
        descriptor: EnclaveDescriptor,
        address: u32,
        efbs: [EfbDescriptor; MAX_EFBS],
        efb_count: usize,
    ) -> bool {
        for slot in self.loaded_enclaves.iter_mut() {
            if slot.is_none() {
                *slot = Some(LoadedEnclave {
                    descriptor,
                    start_address: address,
                    efbs,
                    efb_count,
                });
                return true;
            }
        }
        false
    }

    // Formal Model Support: "Check Cache"
    pub fn get_block_address(&self, enclave_id: u32, block_id: u32) -> Option<u32> {
        for enc in self.loaded_enclaves.iter() {
            if let Some(e) = enc {
                if e.descriptor.id == enclave_id {
                    // Check if block is loaded
                    if (block_id as usize) < e.efb_count {
                        let efb = &e.efbs[block_id as usize];
                        if efb.is_loaded && efb.id == block_id {
                            // Calculate Address: Start + (BlockID * SLOT_SIZE)
                            // CJ3 defense-in-depth guard: bounded by
                            // `efb_count` above, but the raw multiplication
                            // can still wrap if a future caller passes an
                            // unbounded `block_id` (e.g. via a re-typed
                            // `efb_count` or a wider `u32`). `checked_mul`
                            // + `checked_add` guard the return value, which
                            // is consumed as a Secure-side execution address
                            // by the "Check Cache" formal-model pathway.
                            return block_id
                                .checked_mul(SLOT_SIZE)
                                .and_then(|x| e.start_address.checked_add(x));
                        }
                    }
                }
            }
        }
        None
    }
}

impl LoadedEnclave {
    pub fn loaded_count(&self) -> usize {
        self.efbs[..self.efb_count]
            .iter()
            .filter(|e| e.is_loaded)
            .count()
    }

    pub fn find_eviction_victim(&self, exclude_idx: u32) -> Option<u32> {
        let mut best: Option<(u32, u8)> = None;

        for i in 1..self.efb_count {
            let efb = &self.efbs[i];
            if efb.is_loaded && (i as u32) != exclude_idx {
                match best {
                    None => best = Some((i as u32, efb.counter)),
                    Some((_, bc)) if efb.counter < bc => best = Some((i as u32, efb.counter)),
                    _ => {}
                }
            }
        }
        best.map(|(idx, _)| idx)
    }
}

// Property-based tests for the ESS allocator. Lives in a sibling file
// so the parent module stays under the file-size cap and proptest's
// std-only dependencies do not leak into the firmware build path.
#[cfg(test)]
#[path = "ess_proptests.rs"]
mod proptests;
