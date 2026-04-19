use crate::secure_kernel::CODE_BLOCK_SIZE;
use kernel::common::ess::MAX_REACHABLE;

const QUEUE_SIZE: usize = 16;

pub unsafe fn prefetch_reachables(enclave_id: u32) {
    let kernel = match crate::secure_kernel::Kernel::get() {
        Some(k) => k,
        None => return,
    };

    let enclave_idx = match kernel.ess.loaded_enclaves.iter()
        .enumerate()
        .find(|(_, slot)| slot.as_ref().map(|e| e.descriptor.id == enclave_id).unwrap_or(false))
        .map(|(i, _)| i)
    {
        Some(i) => i,
        None => return,
    };

    let mut queue = [0u8; QUEUE_SIZE];
    let mut head: usize = 0;
    let mut tail: usize = 0;
    let mut visited: u32 = 0;

    // Seed: enqueue reachables of all currently-loaded blocks
    {
        let enclave = match &kernel.ess.loaded_enclaves[enclave_idx] {
            Some(e) => e,
            None => return,
        };
        for i in 0..enclave.efb_count {
            if enclave.efbs[i].is_loaded {
                visited |= 1 << i;
                for r in 0..enclave.efbs[i].reachable_count as usize {
                    let target = enclave.efbs[i].reachable[r] as usize;
                    if target < enclave.efb_count && (visited & (1 << target)) == 0 {
                        if !enclave.efbs[target].is_loaded && tail < QUEUE_SIZE {
                            queue[tail] = target as u8;
                            tail += 1;
                            visited |= 1 << target;
                        }
                    }
                }
            }
        }
    }

    if head == tail {
        return;
    }

    let mut dma = match drivers::dma::Dma::new() {
        Some(d) => d,
        None => return,
    };
    dma.reserve_ch(0, 0);
    dma.reserve_ch(0, 1);
    dma.reserve_ch(0, 3);
    dma.reserve_ch(0, 4);
    dma.reserve_ch(0, 5);
    dma.reserve_ch(0, 6);
    dma.reserve_ch(0, 7);

    while head < tail {
        let block_idx = queue[head] as u32;
        head += 1;

        {
            let enclave = match &kernel.ess.loaded_enclaves[enclave_idx] {
                Some(e) => e,
                None => return,
            };
            if (block_idx as usize) < enclave.efb_count
                && enclave.efbs[block_idx as usize].is_loaded
            {
                continue;
            }
        }

        // Delegate to handle_ess_miss with polling=false (non-fault context).
        let _ = kernel.handle_ess_miss(enclave_id, block_idx, &mut dma, false);

        // Cascade: enqueue reachables of the newly-installed block
        {
            let enclave = match &kernel.ess.loaded_enclaves[enclave_idx] {
                Some(e) => e,
                None => return,
            };
            let efb = &enclave.efbs[block_idx as usize];
            for r in 0..efb.reachable_count as usize {
                let target = efb.reachable[r] as usize;
                if target < enclave.efb_count
                    && (visited & (1 << target)) == 0
                    && !enclave.efbs[target].is_loaded
                    && tail < QUEUE_SIZE
                {
                    queue[tail] = target as u8;
                    tail += 1;
                    visited |= 1 << target;
                }
            }
        }
    }
}
