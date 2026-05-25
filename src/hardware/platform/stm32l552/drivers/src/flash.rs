// STM32L5xxxx Flash Driver (minimal)
//
// Exposes a single setup function used during clock bring-up to
// raise the flash wait states BEFORE switching SYSCLK to a frequency
// that the previous WS value cannot support. Under-WS access raises
// BusFault on the first secure-flash read.
//
// RM0438 §3.8.1 FLASH_ACR layout:
//   LATENCY[3:0]  bits 0-3   number of wait states (0..15)
//   PRFTEN        bit 8      prefetch enable
//   ICEN          bit 9      instruction cache enable
//   DCEN          bit 10     data cache enable
//
// VOS range 0 @ 110 MHz requires LATENCY = 5 (RM0438 Table 9).
#![allow(dead_code)]

use peripheral_regs::*;

type FlashRegisters = u32;

const FLASH_BASE_ADDR: FlashRegisters = 0x50022000; // Secure
const FLASH_ACR_OFFSET: FlashRegisters = 0x00;

pub struct Flash {
    regs: &'static mut FlashRegisters,
}

impl Flash {
    pub fn new() -> Self {
        // Safety: FLASH peripheral is mapped at a fixed address and exists
        // on every STM32L5 variant supported by this driver.
        let regs = unsafe { &mut *(FLASH_BASE_ADDR as *mut FlashRegisters) };
        Self { regs }
    }

    /// Set FLASH_ACR for VOS range 0 @ 110 MHz SYSCLK:
    /// LATENCY = 5 WS, ICEN + DCEN + PRFTEN enabled.
    /// Polls until the read-back LATENCY field matches.
    ///
    /// Must be called BEFORE the SYSCLK source switch in
    /// `init_clocks`. The current boot LATENCY (0 WS at reset)
    /// is insufficient for any SYSCLK above ~20 MHz; without this
    /// step the first secure-flash read after the PLL switch
    /// raises BusFault.
    pub fn set_latency_5ws_enable_cache(&self) {
        const LATENCY_5WS: u32 = 0x5;          // bits [3:0]
        const PRFTEN_BIT:  u32 = 1 << 8;
        const ICEN_BIT:    u32 = 1 << 9;
        const DCEN_BIT:    u32 = 1 << 10;
        // Read-modify-write: clear LATENCY field (bits [3:0]) and set our
        // bits, preserving any other ACR bits a previous boot stage may
        // have configured (e.g., RUN_PD, SLEEP_PD).
        const LATENCY_MASK: u32 = 0xF;
        // Safety: FLASH_ACR is a 32-bit MMIO register. The write enables
        // additional cache/prefetch features and raises wait states; the
        // ordering invariant (set BEFORE PLL switch) is the caller's
        // responsibility — documented in init_clocks.
        unsafe {
            let acr = read_register(self.regs, FLASH_ACR_OFFSET);
            let new = (acr & !LATENCY_MASK)
                | LATENCY_5WS | PRFTEN_BIT | ICEN_BIT | DCEN_BIT;
            write_register(self.regs, FLASH_ACR_OFFSET, new);
        }
        loop {
            // Safety: same register, read-back to confirm hardware accepted
            // the new latency. The L5 flash controller takes a few cycles
            // to commit the LATENCY field; without the spin loop a fast
            // SYSCLK switch can race ahead.
            let got = unsafe { read_register(self.regs, FLASH_ACR_OFFSET) };
            if (got & 0xF) == LATENCY_5WS { break; }
        }
    }
}
