//! Block-out-of-residency exit path: `evict_block` poisons an evicted
//! ESS slot with UDF and flips its MPCBB blocks back to NS so the next
//! install (DMA) can write the entire slot.
//! Gated entirely on `feature = "ess_miss_recovery"` — without runtime
//! miss recovery there is nothing to evict.
//! See the `secure_kernel` module-level docs for the invariants that every
//! change in this file must preserve. In particular, the MPCBB
//! flip-to-NS ordering and the "block 0 must remain resident" rule are
//! load-bearing.

#[cfg(feature = "ess_miss_recovery")]
use arm::mmio::{DCCIMVAC, ICIALLU, MPU_RLAR, MPU_RNR};

#[cfg(feature = "ess_miss_recovery")]
use super::init::Kernel;

#[cfg(feature = "ess_miss_recovery")]
impl Kernel {
    /// # Safety
    /// Callers must guarantee `block_idx != 0`. Block 0 holds the enclave
    /// entry point and must remain resident; evicting it would leave
    /// `umbra_enclave_enter_imp` jumping to a UDF slot. The early return
    /// below is defence-in-depth — the real invariant is upstream at
    /// `find_eviction_victim` (loop starts at 1) and `umbra_enclave_create_imp`
    /// (eviction loop starts at 1).
    #[inline(never)]
    pub unsafe fn evict_block(&mut self, enclave_id: u32, block_idx: u32) {
        use kernel::common::ess::SLOT_SIZE;
        const UDF_PATTERN: u32 = 0xDEDE_DEDE;

        if block_idx == 0 {
            return;
        }

        let (slot_addr_ns, slot_addr_s) = {
            let enclave = match self
                .ess
                .loaded_enclaves
                .iter()
                .flatten()
                .find(|e| e.descriptor.id == enclave_id)
            {
                Some(e) => e,
                None => return,
            };
            let ns = enclave.start_address + block_idx * SLOT_SIZE;
            (ns, ns | 0x1000_0000)
        };

        let mpu_rnr = MPU_RNR;
        let mpu_rlar = MPU_RLAR;
        core::ptr::write_volatile(mpu_rnr, 5);
        let saved_rlar = core::ptr::read_volatile(mpu_rlar);
        core::ptr::write_volatile(mpu_rlar, saved_rlar & !1u32);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();

        // Write UDF via the Secure alias. The slot is still Secure in
        // MPCBB at this point; NS-alias writes to Secure slots are
        // silently dropped when SRWILADIS=1 (see load_and_verify_block).
        let mut off = 0u32;
        while off < SLOT_SIZE {
            core::ptr::write_volatile((slot_addr_s + off) as *mut u32, UDF_PATTERN);
            off += 4;
        }

        // D-cache clean+invalidate so the UDF pattern reaches physical
        // SRAM before handle_ess_miss writes new data via the same alias.
        let dccimvac = DCCIMVAC;
        let mut addr = slot_addr_s;
        while addr < slot_addr_s + SLOT_SIZE {
            core::ptr::write_volatile(dccimvac, addr);
            addr += 32;
        }
        cortex_m::asm::dsb();
        cortex_m::asm::isb();

        core::ptr::write_volatile(mpu_rlar, saved_rlar);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();

        let iciallu = ICIALLU;
        core::ptr::write_volatile(iciallu, 0);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();

        // Flip every 256-B MPCBB block covered by this ESS slot to NS so the
        // next install (DMA) can write the entire slot. See SLOT_SIZE > 256
        // rationale in handle_ess_miss.
        {
            let mut addr = slot_addr_ns;
            let end = slot_addr_ns + SLOT_SIZE;
            while addr < end {
                drivers::gtzc::mpcbb_set_slot_secure(addr, false);
                addr += 256;
            }
        }
        cortex_m::asm::dsb();
        cortex_m::asm::isb();

        if let Some(enclave) = self
            .ess
            .loaded_enclaves
            .iter_mut()
            .flatten()
            .find(|e| e.descriptor.id == enclave_id)
        {
            if (block_idx as usize) < enclave.efb_count {
                enclave.efbs[block_idx as usize].is_loaded = false;
                enclave.efbs[block_idx as usize].counter = 0;
            }
        }
    }
}
