//! CRYP1 driver for STM32N657 (SW-loaded key path).
//!
//! Base: 0x54020800 (Secure alias). Hardware AES at 14 cycles per 16-byte
//! block per RM0486 Table 426. All register layouts and field encodings
//! verified directly against RM0486 §49.8 (register reference) and
//! §49.4.16 (key registers).
//!
//! ## Architectural note: why SW-load, not SAES↔CRYP shared bus
//!
//! The SAES → CRYP shared-key bus would keep the key out of CPU registers,
//! but per RM0486 §48.4.15 this path **REQUIRES** the key to be DHUK-
//! wrapped first (encrypted via SAES with KEYSEL=DHUK). Without a wrapped
//! blob, the shared-bus mechanism produces CRYP KERF (key error). See
//! `project_n657_aes_hw.md` for the full finding.
//!
//! This driver therefore uses **SW-loaded key** directly into the CRYP
//! key registers (KMOD=normal, like L552 AesHardware does). The SAES
//! shared-bus path is preserved in `saes.rs` for future DHUK-wrap use.

use peripheral_regs::{read_register, write_register};

const CRYP_BASE_ADDR: u32 = 0x54020800;

// Register offsets (§49.8)
const CRYP_CR_OFFSET: u32 = 0x00;
const CRYP_SR_OFFSET: u32 = 0x04;
const CRYP_DIN_OFFSET: u32 = 0x08;
const CRYP_DOUT_OFFSET: u32 = 0x0C;

// Key registers (§49.4.16 Table 423). For AES-128 (KEYSIZE=0x0), the key
// goes into K2LR/K2RR/K3LR/K3RR in ascending order — writing in any other
// order sets KERF.
//   K2LR = KEY[127:96]  (MSB word, key[0..4])
//   K2RR = KEY[95:64]            (key[4..8])
//   K3LR = KEY[63:32]            (key[8..12])
//   K3RR = KEY[31:0]    (LSB word, key[12..16])
const CRYP_K2LR_OFFSET: u32 = 0x30;
const CRYP_K2RR_OFFSET: u32 = 0x34;
const CRYP_K3LR_OFFSET: u32 = 0x38;
const CRYP_K3RR_OFFSET: u32 = 0x3C;

// IV registers (§49.8.17–§49.8.20, Table 418). CTR/CBC/GCM/CCM use them;
// ECB leaves them at reset 0. Layout mirrors keys (big-endian, MSB-first):
//   IV0LR = IVI[127:96]  (MSB word, iv[0..4])
//   IV0RR = IVI[95:64]            (iv[4..8])
//   IV1LR = IVI[63:32]            (iv[8..12])
//   IV1RR = IVI[31:0]    (LSB word, iv[12..16]; HW increments this as the
//                          CTR counter on each completed block)
const CRYP_IV0LR_OFFSET: u32 = 0x40;
const CRYP_IV0RR_OFFSET: u32 = 0x44;
const CRYP_IV1LR_OFFSET: u32 = 0x48;
const CRYP_IV1RR_OFFSET: u32 = 0x4C;

// CR bits per §49.8.1
const CR_CRYPEN: u32 = 1 << 15;
const CR_FFLUSH: u32 = 1 << 14;
// ALGOMODE is bits [5:3] (with bit 19 as extension). Per §49.8.1:
//   0x4 = ECB, 0x5 = CBC, 0x6 = CTR, 0x7 = AES key prep
//   Others (including 0x0) are RESERVED — undefined behavior!
// Initial bringup had ALGOMODE=0x0 (reserved) which left CRYP unconfigured;
// no encryption happened.
const CR_ALGOMODE_ECB: u32 = 0b100 << 3;   // 0x00000020
const CR_ALGOMODE_CTR: u32 = 0b110 << 3;   // 0x00000030
// const CR_ALGOMODE_CBC: u32 = 0b101 << 3;

// SR bits per §49.8.2
const SR_OFNE: u32 = 1 << 2;
#[allow(dead_code)] const SR_BUSY: u32 = 1 << 4;   // reserved for future busy-polling across CTR blocks
const SR_KERF: u32 = 1 << 6;
const SR_KEYVALID: u32 = 1 << 7;

pub struct Cryp1 {
    regs: *const u32,
}

impl Cryp1 {
    pub fn new() -> Self {
        Cryp1 { regs: CRYP_BASE_ADDR as *const u32 }
    }

    /// Configure CRYP for AES-128-ECB encryption with a SW-loaded key.
    /// Per RM0486 §49.4.16 and §49.8.1.
    ///
    /// Sequence:
    ///   1. CRYPEN=0 (disable for config)
    ///   2. CR: KMOD=0 (normal SW key), ALGOMODE=0x4 (ECB), KEYSIZE=0
    ///      (128), DATATYPE=0 (no swap), ALGODIR=0 (encrypt)
    ///   3. Write key to K2LR → K2RR → K3LR → K3RR (ascending order
    ///      required; out-of-order writes set KERF and prevent KEYVALID)
    ///   4. Wait for SR.KEYVALID = 1 (key loaded successfully)
    ///   5. Set CRYPEN=1 (only writable while KEYVALID=1 per §49.8.2)
    pub fn configure_ecb_128_sw_key(&mut self, key: &[u8; 16]) {
        // SAFETY: self.regs is CRYP_BASE_ADDR (Secure alias MMIO); all writes
        // are bus-acknowledged register accesses, no aliasing of normal Rust memory.
        unsafe {
            // 1. Disable CRYP
            let mut cr = read_register(self.regs, CRYP_CR_OFFSET);
            cr &= !CR_CRYPEN;
            write_register(self.regs, CRYP_CR_OFFSET, cr);

            // 2. Configure fields
            //    Clear extension bit (ALGOMODE[3] at bit 19) and main field
            //    [5:3], then set ECB (0b100 at [5:3]).
            cr &= !(1 << 19);
            cr &= !(0x7 << 3);
            cr |= CR_ALGOMODE_ECB;
            cr &= !(0x3 << 8);    // KEYSIZE = 0 (128-bit)
            cr &= !(0x3 << 6);    // DATATYPE = 0 (no swap)
            cr &= !(1 << 2);      // ALGODIR = 0 (encrypt)
            cr &= !(0x3 << 24);   // KMOD = 0 (normal SW key)
            write_register(self.regs, CRYP_CR_OFFSET, cr);

            // 3. Write key in ascending order K2LR → K2RR → K3LR → K3RR.
            //    KEY[127:96] goes to K2LR — that's the MSB word, key[0..4]
            //    converted from big-endian (network byte order, matching
            //    NIST test vector convention).
            write_register(self.regs, CRYP_K2LR_OFFSET,
                u32::from_be_bytes(key[0..4].try_into().unwrap()));
            write_register(self.regs, CRYP_K2RR_OFFSET,
                u32::from_be_bytes(key[4..8].try_into().unwrap()));
            write_register(self.regs, CRYP_K3LR_OFFSET,
                u32::from_be_bytes(key[8..12].try_into().unwrap()));
            write_register(self.regs, CRYP_K3RR_OFFSET,
                u32::from_be_bytes(key[12..16].try_into().unwrap()));

            // 4. Wait KEYVALID. KERF surfaces sequence errors early.
            loop {
                let sr = read_register(self.regs, CRYP_SR_OFFSET);
                if (sr & SR_KERF) != 0 {
                    panic!("CRYP KERF asserted after key load — invalid sequence");
                }
                if (sr & SR_KEYVALID) != 0 { break; }
            }

            // 5. Enable CRYP (only after KEYVALID per §49.8.2)
            let cr = read_register(self.regs, CRYP_CR_OFFSET);
            write_register(self.regs, CRYP_CR_OFFSET, cr | CR_CRYPEN);
        }
    }

    /// Configure CRYP for AES-128-CTR with a SW-loaded key and explicit IV.
    /// Per RM0486 §49.4.10 (CTR encryption/decryption process), §49.8.17–
    /// §49.8.20 (IV registers), §49.8.1 (CR.ALGOMODE).
    ///
    /// CTR encrypt and decrypt are the same operation, so ALGODIR is left
    /// at 0 (encrypt forward cipher). The peripheral generates the
    /// keystream from `counter = IVI`, XORs it with the input stream, and
    /// increments IV1RR (the low 32 bits) big-endian after each completed
    /// block. Carry into IV1LR happens internally.
    ///
    /// Sequence (§49.4.10):
    ///   1. CRYPEN=0
    ///   2. FFLUSH=1 (clear stale FIFO contents from any prior session)
    ///   3. CR: KMOD=0, ALGOMODE=0x6 (CTR), KEYSIZE=0 (128), DATATYPE=0,
    ///      ALGODIR=0, NPBLB=0, GCM_CCMPH=0
    ///   4. Write IV to IV0LR → IV0RR → IV1LR → IV1RR (MSB-first, mirrors
    ///      key layout)
    ///   5. Write key to K2LR → K2RR → K3LR → K3RR (ascending; out-of-
    ///      order sets KERF). KEYSIZE+ALGOMODE must be set BEFORE keys.
    ///   6. Wait SR.KEYVALID=1
    ///   7. CRYPEN=1
    ///
    /// After this call, feed plaintext/ciphertext blocks through
    /// `process_block` exactly as for ECB — the FIFO protocol is identical;
    /// only the internal counter+XOR behavior differs.
    ///
    /// Suspend/resume note (§49.4.10): IV registers are HW-mutated. To
    /// resume mid-stream, callers must save IVxLR/RR before clearing
    /// CRYPEN and reload them before re-enabling. `ctr_xform` processes
    /// the whole stream under one CRYPEN, so this isn't exercised here.
    pub fn configure_ctr_128_sw_key(&mut self, key: &[u8; 16], iv: &[u8; 16]) {
        // SAFETY: self.regs is CRYP_BASE_ADDR (Secure alias MMIO); all
        // writes are bus-acknowledged register accesses, no aliasing of
        // normal Rust memory.
        unsafe {
            // 1. Disable CRYP
            let mut cr = read_register(self.regs, CRYP_CR_OFFSET);
            cr &= !CR_CRYPEN;
            write_register(self.regs, CRYP_CR_OFFSET, cr);

            // 2. FFLUSH (self-clearing per §49.8.1; safe to OR-set then
            //    follow with subsequent writes that leave bit 14 = 0).
            write_register(self.regs, CRYP_CR_OFFSET, cr | CR_FFLUSH);

            // 3. Configure fields. Re-read CR after FFLUSH (which is
            //    self-clearing) and rebuild from scratch.
            let mut cr = read_register(self.regs, CRYP_CR_OFFSET);
            cr &= !(1 << 19);             // ALGOMODE[3] = 0
            cr &= !(0x7 << 3);            // clear ALGOMODE[2:0]
            cr |= CR_ALGOMODE_CTR;        // set CTR (0b110 at [5:3])
            cr &= !(0x3 << 8);            // KEYSIZE = 0 (128-bit)
            cr &= !(0x3 << 6);            // DATATYPE = 0 (no swap)
            cr &= !(1 << 2);              // ALGODIR = 0 (forward cipher)
            cr &= !(0x3 << 24);           // KMOD = 0 (normal SW key)
            cr &= !(0xF << 20);           // NPBLB = 0 (CTR ignores it)
            cr &= !(0x3 << 16);           // GCM_CCMPH = 0 (N/A for CTR)
            write_register(self.regs, CRYP_CR_OFFSET, cr);

            // 4. Load IV. MSB-first like keys (RM Table 418).
            write_register(self.regs, CRYP_IV0LR_OFFSET,
                u32::from_be_bytes(iv[0..4].try_into().unwrap()));
            write_register(self.regs, CRYP_IV0RR_OFFSET,
                u32::from_be_bytes(iv[4..8].try_into().unwrap()));
            write_register(self.regs, CRYP_IV1LR_OFFSET,
                u32::from_be_bytes(iv[8..12].try_into().unwrap()));
            write_register(self.regs, CRYP_IV1RR_OFFSET,
                u32::from_be_bytes(iv[12..16].try_into().unwrap()));

            // 5. Write key in ascending order K2LR → K2RR → K3LR → K3RR.
            //    Same byte order as ECB path (see configure_ecb_128_sw_key
            //    docstring): K2LR receives the MSB word.
            write_register(self.regs, CRYP_K2LR_OFFSET,
                u32::from_be_bytes(key[0..4].try_into().unwrap()));
            write_register(self.regs, CRYP_K2RR_OFFSET,
                u32::from_be_bytes(key[4..8].try_into().unwrap()));
            write_register(self.regs, CRYP_K3LR_OFFSET,
                u32::from_be_bytes(key[8..12].try_into().unwrap()));
            write_register(self.regs, CRYP_K3RR_OFFSET,
                u32::from_be_bytes(key[12..16].try_into().unwrap()));

            // 6. Wait KEYVALID. KERF surfaces sequence errors early.
            loop {
                let sr = read_register(self.regs, CRYP_SR_OFFSET);
                if (sr & SR_KERF) != 0 {
                    panic!("CRYP KERF asserted after CTR key load — invalid sequence");
                }
                if (sr & SR_KEYVALID) != 0 { break; }
            }

            // 7. Enable CRYP
            let cr = read_register(self.regs, CRYP_CR_OFFSET);
            write_register(self.regs, CRYP_CR_OFFSET, cr | CR_CRYPEN);
        }
    }

    /// Process a single 16-byte block (ECB-encrypt — used as CTR keystream
    /// generator in `crypto_impl::aes_decrypt`).
    ///
    /// Per §49.8.3, write order is MSB-first: 4 successive 32-bit writes
    /// where the first is data[127:96] (input[0..4] big-endian) and the
    /// last is data[31:0] (input[12..16]).
    ///
    /// Precondition: `configure_ecb_128_sw_key` must have been called.
    pub fn process_block(&self, input: &[u8; 16], output: &mut [u8; 16]) {
        // SAFETY: self.regs is CRYP_BASE_ADDR (Secure alias MMIO); FIFO writes
        // and reads go via bus-acknowledged accesses; output buffer is owned
        // mutably by caller, no aliasing concerns.
        unsafe {
            // 4 writes to DIN (MSB-first per §49.8.3)
            write_register(self.regs, CRYP_DIN_OFFSET,
                u32::from_be_bytes(input[0..4].try_into().unwrap()));
            write_register(self.regs, CRYP_DIN_OFFSET,
                u32::from_be_bytes(input[4..8].try_into().unwrap()));
            write_register(self.regs, CRYP_DIN_OFFSET,
                u32::from_be_bytes(input[8..12].try_into().unwrap()));
            write_register(self.regs, CRYP_DIN_OFFSET,
                u32::from_be_bytes(input[12..16].try_into().unwrap()));

            // Poll OFNE=1 (4 words ready)
            while (read_register(self.regs, CRYP_SR_OFFSET) & SR_OFNE) == 0 {}

            // 4 reads from DOUT (MSB-first per §49.8.4)
            let d0 = read_register(self.regs, CRYP_DOUT_OFFSET);
            let d1 = read_register(self.regs, CRYP_DOUT_OFFSET);
            let d2 = read_register(self.regs, CRYP_DOUT_OFFSET);
            let d3 = read_register(self.regs, CRYP_DOUT_OFFSET);

            output[0..4].copy_from_slice(&d0.to_be_bytes());
            output[4..8].copy_from_slice(&d1.to_be_bytes());
            output[8..12].copy_from_slice(&d2.to_be_bytes());
            output[12..16].copy_from_slice(&d3.to_be_bytes());
        }
    }
}
