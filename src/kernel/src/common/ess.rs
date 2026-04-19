
use crate::common::enclave::EnclaveDescriptor;

pub const ESS_BASE: u32 = 0x30032000; // SRAM2 (Structures)
pub const ESS_SIZE: u32 = 0x10000; // 64KB
pub const EFBC_BASE: u32 = 0x20020000; // SRAM1 Top 64KB (Execution) — NS alias so MPCBB per-block attribution is enforced
pub const SLOT_SIZE: u32 = 256;
pub const MAX_EFBS: usize = 32;

pub const MAX_ENCLAVES_CTX: usize = 4;
pub const ENCLAVE_PSP_STACK_SIZE: u32 = 0x800; // 2KB per enclave
// PSP stacks live just above .bss, well below the MSP to avoid
// overlap.  The MSP starts at _umb_estack (0x3003DFFC) and can grow
// 32 KB down to 0x30036000 before touching the PSP ceiling.
pub const ENCLAVE_PSP_BASE: u32 = 0x30034000;  // Base of PSP stack region
pub const ENCLAVE_PSP_TOP: u32 = 0x30036000;   // Top of enclave 0 stack (grows down)
pub const CACHE_LIMIT_PER_ENCLAVE: usize = 24;

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

        for i in 0..total_slots {
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
                for k in 0..slots_needed {
                    let idx = found_start + (k as usize);
                    self.bitmap[idx / 32] |= 1 << (idx % 32);
                }
                // Return address from EFBC (Execution Memory)
                return Some(EFBC_BASE + (found_start as u32 * SLOT_SIZE));
            }
        }
        None
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
