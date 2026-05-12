//! MCE (Memory Cipher Engine) driver for STM32N657.
//!
//! MCE2 sits in front of XSPI2 (memory-mapped at 0x70000000) and is the only
//! instance touched by the active boot path. This driver only exposes the
//! passthrough surface needed today: region 1 must be disabled at boot so
//! that AXI reads from 0x70080000+ return raw flash bytes (the host bin
//! already carries an encrypted enclave produced by
//! `protect_enclave.py --hmac-over-plaintext`).
//!
//! Encryption-at-rest via MCE2 is not implemented — see the design notes for
//! the OPI WREN write-path and proprietary KDF blockers.

const MCE2_BASE: usize     = 0x5802_BC00;

// Region x: offset = 0x040 + 0x10 * (x - 1), x = 1..4
const REGCR1_OFFSET: usize = 0x040;

// MCE_REGCR1 bits
const REGCR_BREN: u32      = 1 << 0;

pub struct Mce2 {
    base: usize,
}

impl Mce2 {
    pub fn new() -> Self {
        Mce2 { base: MCE2_BASE }
    }

    /// Disable region 1 (BREN=0) so AXI reads bypass MCE2 decryption.
    /// Path B-lite invariant: must be called once during boot — Boot ROM
    /// may leave the region enabled in Fast Block mode, which would garble
    /// every read from 0x70080000+ and break the host bin handoff.
    pub fn disable_region1(&self) {
        unsafe {
            let regcr1 = (self.base + REGCR1_OFFSET) as *mut u32;
            let v = core::ptr::read_volatile(regcr1);
            core::ptr::write_volatile(regcr1, v & !REGCR_BREN);
        }
    }
}
