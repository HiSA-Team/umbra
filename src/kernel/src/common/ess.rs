
use crate::common::enclave::EnclaveDescriptor;

// Reject building with both platform features enabled — the cfg-gated
// constants below would conflict.
#[cfg(all(feature = "platform-l552", feature = "platform-n657"))]
compile_error!("Enable exactly ONE of kernel features platform-l552 or platform-n657");

// ── L552 platform ESS layout ─────────────────────────────────────────
//
// PSP stacks live just above .bss, well below the MSP. The MSP starts at
// _umb_estack (0x3003DFFC) and can grow 24 KB down to 0x30038000 before
// touching the PSP ceiling (was 32 KB before the 2026-05-23 expansion).
//
// PSP region expanded 2026-05-23 from 8 KB ([0x30034000, 0x30036000]) to
// 16 KB ([0x30034000, 0x30038000]) to give each enclave a 8 KB stack.
// Paper-app `ndes` uses ~5 KB of stack (DES key schedule + two
// `volatile char ip[65]` literal-array initialisers per ndes_des() call
// + nested cyfun/ks calls), overflowing the previous 2 KB ceiling and
// causing CFSR.MUNSTKERR on the next exception return. To keep the 4×
// PSP layout within the new region, MAX_ENCLAVES_CTX dropped to 2 —
// sequential paper-app testing only needs fib + 1 enclave coexistent
// at any moment, so this is fine for the §Evaluation runtime plot.
#[cfg(feature = "platform-l552")]
pub const ESS_BASE: u32 = 0x30032000;        // SRAM2 (Structures, Secure alias)
#[cfg(feature = "platform-l552")]
pub const ESS_SIZE: u32 = 0x10000;           // 64KB
#[cfg(feature = "platform-l552")]
pub const EFBC_BASE: u32 = 0x20020000;       // SRAM1 Top 64KB (Execution) — NS alias so MPCBB per-block attribution is enforced
#[cfg(feature = "platform-l552")]
pub const ENCLAVE_PSP_BASE: u32 = 0x30034000;
#[cfg(feature = "platform-l552")]
pub const ENCLAVE_PSP_TOP: u32 = 0x30038000;

// ── N657 platform ESS layout ─────────────────────────────────────────
//
// AXISRAM1 (1 MB IDAU view) is split: 0x34000000-0x34063FFF is FLEXRAM
// (RISAF7), 0x34064000-0x340FFFFF is AXISRAM1 proper (RISAF2). The host runs
// in the lower portion via the NS alias (0x24000000+); enclave code lives in
// the upper portion via the Secure alias. RISAF2 region 1 must end before
// EFBC_BASE so default region 0 (Secure+CID=1+priv) governs the upper bank.
//
// Layout summary (Secure alias):
//   0x34064000–0x340DFFFF  ~496 KB  NS host (RISAF2 region 1 SEC=0)
//   0x340E0000–0x340EFFFF   64 KB   EFBC — enclave code blocks (Secure)
//   0x340F0000–0x340F1FFF    8 KB   PSP stacks (4 enclaves × 2 KB)
//   0x340F2000–0x340FFFFF   56 KB   reserved for ESS metadata / future use
#[cfg(feature = "platform-n657")]
pub const ESS_BASE: u32 = 0x340E0000;
#[cfg(feature = "platform-n657")]
pub const ESS_SIZE: u32 = 0x10000;           // 64KB EFBC region
#[cfg(feature = "platform-n657")]
pub const EFBC_BASE: u32 = 0x340E0000;       // Secure alias — RISAF2 default region 0 governs (CID=1+priv)
#[cfg(feature = "platform-n657")]
pub const ENCLAVE_PSP_BASE: u32 = 0x340F0000;
#[cfg(feature = "platform-n657")]
pub const ENCLAVE_PSP_TOP: u32 = 0x340F2000;

// ── Platform-agnostic constants ──────────────────────────────────────
pub const SLOT_SIZE: u32 = 256;
// MAX_EFBS bumped 32 → 64 (2026-05-23) to cover paper-app `statemate`
// (41 blocks). The `loaded_mask` bitmap in api_impl.rs MUST stay wide
// enough to track every block index; u32 was only sufficient for
// ≤32 blocks. Now uses u64 — the kernel-side ceiling is 64 blocks.
// For larger enclaves (susan / cjpeg territory), switch to a
// `[u32; (MAX_EFBS+31)/32]` chunked bitmap.
pub const MAX_EFBS: usize = 64;
// MAX_ENCLAVES_CTX dropped 4 → 2 (2026-05-23) to fit the bumped
// per-enclave PSP stack (was 2 KB, now 8 KB) into the 16 KB PSP
// region — see ENCLAVE_PSP_TOP comment. Sequential paper-app testing
// only needs fib + 1 coexistent enclave; the 4-enclave round-robin
// mode in tools/test_taclebench.sh no longer fits.
pub const MAX_ENCLAVES_CTX: usize = 2;
pub const ENCLAVE_PSP_STACK_SIZE: u32 = 0x2000; // 8KB per enclave (was 2KB)
// CACHE_LIMIT_PER_ENCLAVE bumped 24 → 64 (2026-05-23) so that paper
// apps `ndes` (26 blocks under ess_miss_recovery) and `statemate`
// (41 blocks) fit entirely without eviction-induced thrashing. With
// the cap at 24, the next-block-needed-after-eviction pattern
// produces UDF reads (R0=0xDEDEDEDE in MemManage dumps) → wild
// pointer dereference → MemManage `addr outside any enclave`. EFBC
// has 256 slots total; 2 enclaves × 64 = 128 slots fits with 50%
// headroom for future workloads.
pub const CACHE_LIMIT_PER_ENCLAVE: usize = 64;

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

    pub fn allocate(&mut self, size: u32) -> Option<u32> {
        let slots_needed = (size + SLOT_SIZE - 1) / SLOT_SIZE;
        if slots_needed == 0 { return None; }

        let total_slots = 256;
        let mut found_start = 0;
        let mut found_count = 0;

        let mut i: usize = 0;
        while i < total_slots {
            let word_idx = i / 32;
            let bit_idx = i % 32;

            if (self.bitmap[word_idx] & (1 << bit_idx)) == 0 {
                if found_count == 0 { found_start = i; }
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
                return Some(EFBC_BASE + (found_start as u32 * SLOT_SIZE));
            }
            i += 1;
        }
        None
    }

    /// Release a previously-allocated slot run back to the free bitmap.
    /// `address` must be the value returned by `allocate`; `size` must be the
    /// same byte length that was originally requested.
    ///
    /// Used by `umbra_enclave_create_imp` to roll back ESS slots when the
    /// create path bails out (chained-measurement FAIL, register_enclave
    /// failure, BFS error). Without this, a tampered or stale enclave blob
    /// (`chained-measurement FAIL` line on UART) silently leaks its slot
    /// run on every boot, eventually starving the allocator for legitimate
    /// enclaves.
    pub fn release(&mut self, address: u32, size: u32) {
        if address < EFBC_BASE { return; }
        let slot_offset = (address - EFBC_BASE) / SLOT_SIZE;
        let slots = (size + SLOT_SIZE - 1) / SLOT_SIZE;
        let mut k: u32 = 0;
        while k < slots {
            let idx = (slot_offset + k) as usize;
            if idx < 256 {
                self.bitmap[idx / 32] &= !(1u32 << (idx % 32));
            }
            k += 1;
        }
    }
    
    pub fn register_enclave(&mut self, descriptor: EnclaveDescriptor, address: u32, efbs: [EfbDescriptor; MAX_EFBS], efb_count: usize) -> bool {
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
                            // Assumption: Standard linear loading for now.
                            return Some(e.start_address + (block_id * SLOT_SIZE));
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
        self.efbs[..self.efb_count].iter()
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
