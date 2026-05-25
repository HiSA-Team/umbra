//! SAES1 driver for STM32N657. Not on the production hot path — CRYP is
//! used directly with a SW-loaded key (see cryp.rs and project memory
//! `project_n657_aes_hw.md` for the architectural rationale). The methods
//! here are preserved for a future DHUK-wrap key-isolation path:
//!   - `load_key` — SW-load a key in normal mode (KMOD=0)
//!   - `share_key_to_cryp` — share key to CRYP via bus (needs DHUK-wrapped key per §48.4.15)
//!   - `process_block` — SAES as the AES engine (diagnostic-only; SAES is
//!     35× slower than CRYP, so production uses CRYP)
//!
//! Base address: 0x5402_1000 (Secure alias). Register layout per RM0486 §48.8.
//! Bit fields verified against the manual:
//!   - SAES_CR: EN[0], MODE[4:3], CHMOD[6:5,16], KEYSIZE[18], KMOD[25:24], KSHAREID[27:26], KEYSEL[30:28], IPRST[31]
//!   - SAES_SR: RDERRF[1], WRERRF[2], BUSY[3], KEYVALID[7]

use peripheral_regs::{read_register, write_register};

const SAES_BASE_ADDR: u32 = 0x5402_1000;

// Register offsets per RM0486 §48.8 (table starting §48.8.21)
#[allow(dead_code)] const SAES_CR_OFFSET: u32 = 0x00;
#[allow(dead_code)] const SAES_SR_OFFSET: u32 = 0x04;
#[allow(dead_code)] const SAES_DINR_OFFSET: u32 = 0x08;
#[allow(dead_code)] const SAES_DOUTR_OFFSET: u32 = 0x0C;
#[allow(dead_code)] const SAES_KEYR0_OFFSET: u32 = 0x10;
#[allow(dead_code)] const SAES_KEYR1_OFFSET: u32 = 0x14;
#[allow(dead_code)] const SAES_KEYR2_OFFSET: u32 = 0x18;
#[allow(dead_code)] const SAES_KEYR3_OFFSET: u32 = 0x1C;

// SR bit positions per §48.8.2
#[allow(dead_code)] const SR_BSY: u32 = 1 << 3;
#[allow(dead_code)] const SR_CCF: u32 = 1 << 0;
#[allow(dead_code)] const SR_KEYVALID: u32 = 1 << 7;

pub struct Saes {
    regs: *const u32,
}

impl Saes {
    pub fn new() -> Self {
        Saes { regs: SAES_BASE_ADDR as *const u32 }
    }

    #[allow(dead_code)]
    fn wait_not_busy(&self) {
        // SAFETY: self.regs is SAES_BASE_ADDR, a valid MMIO address in the Secure alias range;
        // volatile read is required to prevent the optimizer from eliding the hardware poll.
        unsafe {
            while (read_register(self.regs, SAES_SR_OFFSET) & SR_BSY) != 0 {}
        }
    }

    #[allow(dead_code)]
    fn wait_key_valid(&self) {
        // SAFETY: self.regs is SAES_BASE_ADDR, a valid MMIO address in the Secure alias range;
        // volatile read is required to prevent the optimizer from eliding the hardware poll.
        unsafe {
            while (read_register(self.regs, SAES_SR_OFFSET) & SR_KEYVALID) == 0 {}
        }
    }

    #[allow(dead_code)]
    fn wait_ccf(&self) {
        // SAFETY: self.regs is SAES_BASE_ADDR, a valid MMIO address in the Secure alias range;
        // volatile read is required to prevent the optimizer from eliding the hardware poll.
        unsafe {
            while (read_register(self.regs, SAES_SR_OFFSET) & SR_CCF) == 0 {}
        }
    }

    /// Load a 128-bit key into SAES_KEYRx in normal SW-loaded mode (KMOD=0).
    /// Per RM0486 §48.4.17, KEYRx must be written in either ascending or
    /// descending order (we use ascending: KEYR0 first, KEYR3 last).
    /// Table 409 maps: KEYR0 = KEY[31:0] (LSB word), KEYR3 = KEY[127:96] (MSB word).
    #[allow(dead_code)]   // kept for the future DHUK-wrap key-isolation path
    pub fn load_key(&mut self, key: &[u8; 16]) {
        self.wait_not_busy();
        // SAFETY: self.regs is SAES_BASE_ADDR (Secure alias MMIO); all writes are
        // bus-acknowledged register accesses, no aliasing of normal Rust memory.
        unsafe {
            // EN=0 to allow CR field writes (per §48.8.1 bit 0).
            let mut cr = read_register(self.regs, SAES_CR_OFFSET);
            cr &= !(1u32 << 0);
            write_register(self.regs, SAES_CR_OFFSET, cr);

            // KEYSIZE=0 (128-bit) at bit 18 + KMOD=0 (normal SW key) at [25:24].
            cr &= !(1 << 18);
            cr &= !(0x3 << 24);
            write_register(self.regs, SAES_CR_OFFSET, cr);

            // Ascending write: KEYR0 = KEY[31:0] (LSB word, key[12..16])
            // up to KEYR3 = KEY[127:96] (MSB word, key[0..4]). Each word is
            // big-endian per NIST/STMicro convention.
            write_register(self.regs, SAES_KEYR0_OFFSET,
                u32::from_be_bytes(key[12..16].try_into().unwrap()));
            write_register(self.regs, SAES_KEYR1_OFFSET,
                u32::from_be_bytes(key[8..12].try_into().unwrap()));
            write_register(self.regs, SAES_KEYR2_OFFSET,
                u32::from_be_bytes(key[4..8].try_into().unwrap()));
            write_register(self.regs, SAES_KEYR3_OFFSET,
                u32::from_be_bytes(key[0..4].try_into().unwrap()));

            // EN=1 — KEYVALID asserts when KEYRx writes complete in valid order.
            let cr = read_register(self.regs, SAES_CR_OFFSET);
            write_register(self.regs, SAES_CR_OFFSET, cr | 1);
        }
        self.wait_key_valid();
    }

    /// Trigger shared-key export to CRYP via internal silicon bus.
    ///
    /// IMPORTANT (RM0486 §48.4.15): the shared-key mode works ONLY when the
    /// key has been DHUK-wrapped (KEYSEL=DHUK, encrypted via SAES) — i.e. the
    /// shared bus is part of the "decrypt-and-share" flow, not a raw broadcast.
    /// Calling this with a plain SW-loaded key (KMOD=normal, KEYSEL=0) does
    /// not actually transfer the key to CRYP; CRYP raises KEIF instead.
    /// The production path bypasses this entirely; kept for the future
    /// DHUK-wrap key-isolation path.
    #[allow(dead_code)]
    pub fn share_key_to_cryp(&mut self) {
        self.wait_not_busy();
        // SAFETY: self.regs is SAES_BASE_ADDR (Secure alias MMIO); all writes are
        // bus-acknowledged register accesses, no aliasing of normal Rust memory.
        unsafe {
            // EN=0 to allow CR writes.
            let mut cr = read_register(self.regs, SAES_CR_OFFSET);
            cr &= !(1u32 << 0);
            write_register(self.regs, SAES_CR_OFFSET, cr);

            // KMOD = SHARED (2) at [25:24], MODE = key-derivation (1) at [4:3]
            // per §48.8.1. KSHAREID default 0 = CRYP target.
            cr &= !(0x3 << 24);
            cr |= 0b10 << 24;
            cr &= !(0x3 << 3);
            cr |= 0b01 << 3;
            write_register(self.regs, SAES_CR_OFFSET, cr);

            // EN=1.
            let cr = read_register(self.regs, SAES_CR_OFFSET);
            write_register(self.regs, SAES_CR_OFFSET, cr | 1);
        }
        self.wait_key_valid();
    }

    /// Process a single 16-byte block using SAES as the AES engine.
    /// Diagnostic-only path. SAES is 480 cyc/block vs CRYP's 14
    /// (per RM Table 412 / Table 426) — production uses CRYP.
    /// Requires `load_key` to have been called first.
    #[allow(dead_code)]
    pub fn process_block(&self, input: &[u8; 16], output: &mut [u8; 16]) {
        // SAFETY: self.regs is SAES_BASE_ADDR (Secure alias MMIO); FIFO writes
        // and reads go via bus-acknowledged accesses; output buffer is owned
        // mutably by caller, no aliasing concerns.
        unsafe {
            // 4 writes to DINR (MSB-first byte order, mirroring CRYP pattern)
            write_register(self.regs, SAES_DINR_OFFSET,
                u32::from_be_bytes(input[0..4].try_into().unwrap()));
            write_register(self.regs, SAES_DINR_OFFSET,
                u32::from_be_bytes(input[4..8].try_into().unwrap()));
            write_register(self.regs, SAES_DINR_OFFSET,
                u32::from_be_bytes(input[8..12].try_into().unwrap()));
            write_register(self.regs, SAES_DINR_OFFSET,
                u32::from_be_bytes(input[12..16].try_into().unwrap()));
        }
        // Wait CCF=1 (computation complete)
        self.wait_ccf();
        unsafe {
            // 4 reads from DOUTR
            let d0 = read_register(self.regs, SAES_DOUTR_OFFSET);
            let d1 = read_register(self.regs, SAES_DOUTR_OFFSET);
            let d2 = read_register(self.regs, SAES_DOUTR_OFFSET);
            let d3 = read_register(self.regs, SAES_DOUTR_OFFSET);

            output[0..4].copy_from_slice(&d0.to_be_bytes());
            output[4..8].copy_from_slice(&d1.to_be_bytes());
            output[8..12].copy_from_slice(&d2.to_be_bytes());
            output[12..16].copy_from_slice(&d3.to_be_bytes());

            // Clear CCF for next block (write 1 to clear, typical STMicro)
            let cr = read_register(self.regs, SAES_CR_OFFSET);
            write_register(self.regs, SAES_CR_OFFSET, cr | (1 << 7));
        }
    }
}
