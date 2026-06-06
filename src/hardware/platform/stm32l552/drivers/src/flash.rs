// STM32L5xxxx Flash Driver (minimal)
// Exposes a single setup function used during clock bring-up to
// raise the flash wait states BEFORE switching SYSCLK to a frequency
// that the previous WS value cannot support. Under-WS access raises
// BusFault on the first secure-flash read.
// RM0438 §3.8.1 FLASH_ACR layout:
// LATENCY[3:0] bits 0-3 number of wait states (0..15)
// PRFTEN bit 8 prefetch enable
// ICEN bit 9 instruction cache enable
// DCEN bit 10 data cache enable
// VOS range 0 @ 110 MHz requires LATENCY = 5 (RM0438 Table 9).
#![allow(dead_code)]

use peripheral_regs::{MmioAccess, RealMmio};

type FlashRegisters = u32;

const FLASH_BASE_ADDR: FlashRegisters = 0x50022000; // Secure
const FLASH_ACR_OFFSET: FlashRegisters = 0x00;

// FLASH_ACR field encodings (RM0438 §3.8.1).
const LATENCY_MASK: u32 = 0xF; // bits [3:0]
const LATENCY_5WS: u32 = 0x5; // bits [3:0]
const PRFTEN_BIT: u32 = 1 << 8;
const ICEN_BIT: u32 = 1 << 9;
const DCEN_BIT: u32 = 1 << 10;

/// Generic over the MMIO backend so host
/// tests can inject [`umbra_pal_test::mmio::MmioHandle`]. Default `M = RealMmio`
/// keeps every existing `Flash::new()` call site unchanged.
pub struct Flash<M: MmioAccess = RealMmio> {
    mmio: M,
}

impl Flash<RealMmio> {
    pub fn new() -> Self {
        Self {
            mmio: RealMmio::new(FLASH_BASE_ADDR),
        }
    }
}

impl<M: MmioAccess> Flash<M> {
    /// Constructor for host-side tests — accepts any `MmioAccess` backend.
    /// On firmware build, callers use `Flash::new()` which monomorphises to
    /// `Flash<RealMmio>` and inlines the volatile accesses.
    #[allow(dead_code)]
    pub fn new_with_mmio(mmio: M) -> Self {
        Self { mmio }
    }

    /// Set FLASH_ACR for VOS range 0 @ 110 MHz SYSCLK:
    /// LATENCY = 5 WS, ICEN + DCEN + PRFTEN enabled.
    /// Polls until the read-back LATENCY field matches.
    /// Must be called BEFORE the SYSCLK source switch in
    /// `init_clocks`. The current boot LATENCY (0 WS at reset)
    /// is insufficient for any SYSCLK above ~20 MHz; without this
    /// step the first secure-flash read after the PLL switch
    /// raises BusFault.
    pub fn set_latency_5ws_enable_cache(&self) {
        // Read-modify-write: clear LATENCY field (bits [3:0]) and set our
        // bits, preserving any other ACR bits a previous boot stage may
        // have configured (e.g., RUN_PD, SLEEP_PD).
        let acr = self.mmio.read(FLASH_ACR_OFFSET);
        let new = (acr & !LATENCY_MASK) | LATENCY_5WS | PRFTEN_BIT | ICEN_BIT | DCEN_BIT;
        self.mmio.write(FLASH_ACR_OFFSET, new);
        // Poll until the L5 flash controller commits the LATENCY field.
        // Without the spin loop a fast SYSCLK switch can race ahead.
        loop {
            let got = self.mmio.read(FLASH_ACR_OFFSET);
            if (got & LATENCY_MASK) == LATENCY_5WS {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umbra_pal_test::mmio::{MmioMem, MmioOp};

    /// Verifies set_latency_5ws_enable_cache performs the documented
    /// read-modify-write on FLASH_ACR: clears LATENCY[3:0], sets LATENCY=5,
    /// and enables PRFTEN/ICEN/DCEN, preserving the other ACR bits.
    /// In-memory backend returns the new value on subsequent reads so the poll loop
    /// terminates after the first read-back.
    #[test]
    fn set_latency_clears_field_and_sets_cache_bits() {
        let mem = MmioMem::new(FLASH_BASE_ADDR);
        // Preload ACR with LATENCY=0 (reset value) plus a "previous boot
        // stage" bit (bit 14, RUN_PD) so the preservation check is observable.
        const PREVIOUS_OTHER_BIT: u32 = 1 << 14;
        mem.preload_register(FLASH_ACR_OFFSET, PREVIOUS_OTHER_BIT);

        let flash = Flash::<_>::new_with_mmio(mem.handle());
        flash.set_latency_5ws_enable_cache();

        let log = mem.write_log();
        // Expected sequence:
        // [0] Read ACR (initial)
        // [1] Write ACR (new value)
        // [2] Read ACR (poll, returns committed value, loop exits)
        assert_eq!(log.len(), 3);
        match log[0] {
            MmioOp::Read { addr, value } => {
                assert_eq!(addr, FLASH_BASE_ADDR + FLASH_ACR_OFFSET);
                assert_eq!(value, PREVIOUS_OTHER_BIT);
            }
            _ => panic!("expected initial Read, got {:?}", log[0]),
        }
        match log[1] {
            MmioOp::Write { addr, value } => {
                assert_eq!(addr, FLASH_BASE_ADDR + FLASH_ACR_OFFSET);
                // LATENCY field set to 5
                assert_eq!(value & LATENCY_MASK, LATENCY_5WS);
                // Cache/prefetch bits set
                assert_ne!(value & PRFTEN_BIT, 0);
                assert_ne!(value & ICEN_BIT, 0);
                assert_ne!(value & DCEN_BIT, 0);
                // Previously-set unrelated bit preserved
                assert_ne!(value & PREVIOUS_OTHER_BIT, 0);
            }
            _ => panic!("expected Write at position 1, got {:?}", log[1]),
        }
        match log[2] {
            MmioOp::Read { addr, .. } => {
                assert_eq!(addr, FLASH_BASE_ADDR + FLASH_ACR_OFFSET);
            }
            _ => panic!("expected poll Read at position 2, got {:?}", log[2]),
        }
    }

    /// Verifies the poll loop spins until the LATENCY field reads back as
    /// 5, modelling the documented L5 flash-controller commit delay. The
    /// mem writes the new value into the register space on Write, so the
    /// first poll read sees LATENCY=5 and the loop terminates.
    #[test]
    fn set_latency_poll_terminates_when_register_commits() {
        let mem = MmioMem::new(FLASH_BASE_ADDR);
        let flash = Flash::<_>::new_with_mmio(mem.handle());
        flash.set_latency_5ws_enable_cache();

        let log = mem.write_log();
        // Exactly one poll read after the write — mem commits synchronously.
        assert!(log.len() >= 3);
        // Last operation must be a Read whose value satisfies the loop guard.
        match log.last().unwrap() {
            MmioOp::Read { value, .. } => {
                assert_eq!(value & LATENCY_MASK, LATENCY_5WS);
            }
            other => panic!("expected final Read, got {:?}", other),
        }
    }
}
