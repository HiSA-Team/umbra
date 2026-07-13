//! CRYP1 driver for STM32N657 (SW-loaded key path).
//! Base: 0x54020800 (Secure alias). Hardware AES at 14 cycles per 16-byte
//! block per RM0486 Table 426. All register layouts and field encodings
//! verified directly against RM0486 §49.8 (register reference) and
//! §49.4.16 (key registers).
//! ## Architectural note: why SW-load, not SAES↔CRYP shared bus
//! The SAES → CRYP shared-key bus would keep the key out of CPU registers,
//! but per RM0486 §48.4.15 this path **REQUIRES** the key to be DHUK-
//! wrapped first (encrypted via SAES with KEYSEL=DHUK). Without a wrapped
//! blob, the shared-bus mechanism produces CRYP KERF (key error). See
//! for the full finding.
//! This driver therefore uses **SW-loaded key** directly into the CRYP
//! key registers (KMOD=normal, like L552 AesHardware does). The SAES
//! shared-bus path is preserved in `saes.rs` for future DHUK-wrap use.

use peripheral_regs::{MmioAccess, RealMmio};

const CRYP_BASE_ADDR: u32 = 0x54020800;

// Register offsets (§49.8)
const CRYP_CR_OFFSET: u32 = 0x00;
const CRYP_SR_OFFSET: u32 = 0x04;
const CRYP_DIN_OFFSET: u32 = 0x08;
const CRYP_DOUT_OFFSET: u32 = 0x0C;
// DMA control (§49.8.3): DIEN (mem→DIN request), DOEN (DOUT→mem request). Arm-only —
// the DMA feed is firmware; host tests exercise only the polling FIFO path.
#[cfg(target_arch = "arm")]
const CRYP_DMACR_OFFSET: u32 = 0x10;
#[cfg(target_arch = "arm")]
const DMACR_DIEN: u32 = 1 << 0;
#[cfg(target_arch = "arm")]
const DMACR_DOEN: u32 = 1 << 1;

// Key registers (§49.4.16 Table 423). For AES-128 (KEYSIZE=0x0), the key
// goes into K2LR/K2RR/K3LR/K3RR in ascending order — writing in any other
// order sets KERF.
// K2LR = KEY[127:96] (MSB word, key[0..4])
// K2RR = KEY[95:64] (key[4..8])
// K3LR = KEY[63:32] (key[8..12])
// K3RR = KEY[31:0] (LSB word, key[12..16])
const CRYP_K2LR_OFFSET: u32 = 0x30;
const CRYP_K2RR_OFFSET: u32 = 0x34;
const CRYP_K3LR_OFFSET: u32 = 0x38;
const CRYP_K3RR_OFFSET: u32 = 0x3C;

// IV registers (§49.8.17–§49.8.20, Table 418). CTR/CBC/GCM/CCM use them;
// ECB leaves them at reset 0. Layout mirrors keys (big-endian, MSB-first):
// IV0LR = IVI[127:96] (MSB word, iv[0..4])
// IV0RR = IVI[95:64] (iv[4..8])
// IV1LR = IVI[63:32] (iv[8..12])
// IV1RR = IVI[31:0] (LSB word, iv[12..16]; HW increments this as the
// CTR counter on each completed block)
const CRYP_IV0LR_OFFSET: u32 = 0x40;
const CRYP_IV0RR_OFFSET: u32 = 0x44;
const CRYP_IV1LR_OFFSET: u32 = 0x48;
const CRYP_IV1RR_OFFSET: u32 = 0x4C;

// CR bits per §49.8.1
const CR_CRYPEN: u32 = 1 << 15;
const CR_FFLUSH: u32 = 1 << 14;
// ALGOMODE is bits [5:3] (with bit 19 as extension). Per §49.8.1:
// 0x4 = ECB, 0x5 = CBC, 0x6 = CTR, 0x7 = AES key prep
// Others (including 0x0) are RESERVED — leaving the field clear
// silently no-ops the engine with no encryption.
const CR_ALGOMODE_ECB: u32 = 0b100 << 3; // 0x00000020
const CR_ALGOMODE_CTR: u32 = 0b110 << 3; // 0x00000030
                                         // const CR_ALGOMODE_CBC: u32 = 0b101 << 3;

// SR bits per §49.8.2
const SR_OFNE: u32 = 1 << 2;
#[allow(dead_code)]
const SR_BUSY: u32 = 1 << 4; // reserved for future busy-polling across CTR blocks
const SR_KERF: u32 = 1 << 6;
const SR_KEYVALID: u32 = 1 << 7;

/// Generic over the MMIO backend so host
/// tests can inject [`umbra_pal_test::mmio::MmioHandle`]. Default
/// `M = RealMmio` keeps every existing `Cryp1::new()` call site unchanged at
/// the source level — the firmware build monomorphises to `Cryp1<RealMmio>`
/// and inlines the volatile accesses exactly as the pre-migration
/// `read_register`/`write_register` free functions did.
/// HW state-machine identical to L552 `AesHardware` earlier commit: the
/// ascending KEYRx write order (K2LR → K2RR → K3LR → K3RR with big-endian
/// byte reversal so K2LR holds `key[0..4]`) is the load-bearing rule —
/// writing out of order asserts SR.KERF and prevents KEYVALID from ever
/// rising. The in-memory backed tests pin this invariant by replaying the write
/// log against the expected K* offsets.
pub struct Cryp1<M: MmioAccess = RealMmio> {
    mmio: M,
}

impl Cryp1<RealMmio> {
    pub fn new() -> Self {
        Self {
            mmio: RealMmio::new(CRYP_BASE_ADDR),
        }
    }
}

impl<M: MmioAccess> Cryp1<M> {
    /// Constructor for host-side tests — accepts any `MmioAccess` backend.
    /// On firmware build, callers use `Cryp1::new()` which monomorphises to
    /// `Cryp1<RealMmio>` and inlines the volatile accesses.
    #[allow(dead_code)]
    pub fn new_with_mmio(mmio: M) -> Self {
        Self { mmio }
    }

    /// Configure CRYP for AES-128-ECB encryption with a SW-loaded key.
    /// Per RM0486 §49.4.16 and §49.8.1.
    /// Sequence:
    /// 1. CRYPEN=0 (disable for config)
    /// 2. CR: KMOD=0 (normal SW key), ALGOMODE=0x4 (ECB), KEYSIZE=0
    /// (128), DATATYPE=0 (no swap), ALGODIR=0 (encrypt)
    /// 3. Write key to K2LR → K2RR → K3LR → K3RR (ascending order
    /// required; out-of-order writes set KERF and prevent KEYVALID)
    /// 4. Wait for SR.KEYVALID = 1 (key loaded successfully)
    /// 5. Set CRYPEN=1 (only writable while KEYVALID=1 per §49.8.2)
    pub fn configure_ecb_128_sw_key(&mut self, key: &[u8; 16]) {
        // 1. Disable CRYP
        let mut cr = self.mmio.read(CRYP_CR_OFFSET);
        cr &= !CR_CRYPEN;
        self.mmio.write(CRYP_CR_OFFSET, cr);

        // 2. Configure fields
        // Clear extension bit (ALGOMODE[3] at bit 19) and main field
        // [5:3], then set ECB (0b100 at [5:3]).
        cr &= !(1 << 19);
        cr &= !(0x7 << 3);
        cr |= CR_ALGOMODE_ECB;
        cr &= !(0x3 << 8); // KEYSIZE = 0 (128-bit)
        cr &= !(0x3 << 6); // DATATYPE = 0 (no swap)
        cr &= !(1 << 2); // ALGODIR = 0 (encrypt)
        cr &= !(0x3 << 24); // KMOD = 0 (normal SW key)
        self.mmio.write(CRYP_CR_OFFSET, cr);

        // 3. Write key in ascending order K2LR → K2RR → K3LR → K3RR.
        // KEY[127:96] goes to K2LR — that's the MSB word, key[0..4]
        // converted from big-endian (network byte order, matching
        // NIST test vector convention).
        self.mmio.write(
            CRYP_K2LR_OFFSET,
            u32::from_be_bytes(key[0..4].try_into().unwrap()),
        );
        self.mmio.write(
            CRYP_K2RR_OFFSET,
            u32::from_be_bytes(key[4..8].try_into().unwrap()),
        );
        self.mmio.write(
            CRYP_K3LR_OFFSET,
            u32::from_be_bytes(key[8..12].try_into().unwrap()),
        );
        self.mmio.write(
            CRYP_K3RR_OFFSET,
            u32::from_be_bytes(key[12..16].try_into().unwrap()),
        );

        // 4. Wait KEYVALID. KERF surfaces sequence errors early.
        loop {
            let sr = self.mmio.read(CRYP_SR_OFFSET);
            if (sr & SR_KERF) != 0 {
                panic!("CRYP KERF asserted after key load — invalid sequence");
            }
            if (sr & SR_KEYVALID) != 0 {
                break;
            }
        }

        // 5. Enable CRYP (only after KEYVALID per §49.8.2)
        let cr = self.mmio.read(CRYP_CR_OFFSET);
        self.mmio.write(CRYP_CR_OFFSET, cr | CR_CRYPEN);
    }

    /// Configure CRYP for ECB using a key delivered by SAES over the shared-key
    /// bus (issue #45). `KMOD=shared`, and crucially **no KEYRx writes** —
    /// the key is loaded by SAES (`Saes::unwrap_and_share_to_cryp`), which
    /// asserts CRYP's KEYVALID. Bounded poll on KEYVALID; the orchestrator calls
    /// [`Cryp1::key_valid`] afterwards and panics fail-closed if it never set.
    #[allow(dead_code)]
    pub fn configure_ecb_shared(&mut self) {
        let mut cr = self.mmio.read(CRYP_CR_OFFSET);
        cr &= !CR_CRYPEN;
        self.mmio.write(CRYP_CR_OFFSET, cr);

        cr &= !(1 << 19);
        cr &= !(0x7 << 3);
        cr |= CR_ALGOMODE_ECB;
        cr &= !(0x3 << 8); // KEYSIZE = 0 (128-bit)
        cr &= !(0x3 << 6); // DATATYPE = 0
        cr &= !(1 << 2); // ALGODIR = 0 (encrypt)
        cr &= !(0x3 << 24);
        cr |= 0b10 << 24; // KMOD = shared (key from SAES bus)
        self.mmio.write(CRYP_CR_OFFSET, cr);

        // No KEYRx writes — the key arrives over the SAES shared bus.
        let mut budget = 1_000_000u32;
        while self.mmio.read(CRYP_SR_OFFSET) & SR_KEYVALID == 0 {
            budget -= 1;
            if budget == 0 {
                break;
            }
        }

        let cr = self.mmio.read(CRYP_CR_OFFSET);
        self.mmio.write(CRYP_CR_OFFSET, cr | CR_CRYPEN);
    }

    /// Configure CRYP for AES-128-CTR with the SAES-shared key (no KEYRx writes) + the
    /// byte-swap DATATYPE the DMA feed needs: HPDMA reads little-endian words from memory
    /// and CRYP expects MSB-first AES data, so DATATYPE=0b10 swaps the bytes inside CRYP.
    /// The DMA feed is the only CTR path now — the CPU polling loop was removed. If the
    /// SAES-shared key does not survive the ECB→CTR switch, the orchestrator re-shares
    /// before calling this.
    #[cfg(target_arch = "arm")]
    pub fn configure_ctr_shared_for_dma(&mut self, iv: &[u8; 16]) {
        let mut cr = self.mmio.read(CRYP_CR_OFFSET);
        cr &= !CR_CRYPEN;
        self.mmio.write(CRYP_CR_OFFSET, cr);
        self.mmio.write(CRYP_CR_OFFSET, cr | CR_FFLUSH);

        let mut cr = self.mmio.read(CRYP_CR_OFFSET);
        cr &= !(1 << 19);
        cr &= !(0x7 << 3);
        cr |= CR_ALGOMODE_CTR;
        cr &= !(0x3 << 8);
        cr &= !(0x3 << 6); // clear DATATYPE
        cr |= 0b10 << 6; // byte-swap for the DMA word feed
        cr &= !(1 << 2);
        cr &= !(0x3 << 24);
        cr |= 0b10 << 24; // KMOD = shared
        cr &= !(0xF << 20); // NPBLB = 0
        cr &= !(0x3 << 16); // GCM_CCMPH = 0
        self.mmio.write(CRYP_CR_OFFSET, cr);

        // IV, MSB-first (mirrors configure_ctr_128_sw_key).
        self.mmio.write(
            CRYP_IV0LR_OFFSET,
            u32::from_be_bytes(iv[0..4].try_into().unwrap()),
        );
        self.mmio.write(
            CRYP_IV0RR_OFFSET,
            u32::from_be_bytes(iv[4..8].try_into().unwrap()),
        );
        self.mmio.write(
            CRYP_IV1LR_OFFSET,
            u32::from_be_bytes(iv[8..12].try_into().unwrap()),
        );
        self.mmio.write(
            CRYP_IV1RR_OFFSET,
            u32::from_be_bytes(iv[12..16].try_into().unwrap()),
        );

        let mut budget = 1_000_000u32;
        while self.mmio.read(CRYP_SR_OFFSET) & SR_KEYVALID == 0 {
            budget -= 1;
            if budget == 0 {
                break;
            }
        }

        let cr = self.mmio.read(CRYP_CR_OFFSET);
        self.mmio.write(CRYP_CR_OFFSET, cr | CR_CRYPEN);
    }

    /// Enable CRYP's DMA request lines — DMACR.DIEN (mem→DIN) + DOEN (DOUT→mem). Call
    /// after `configure_ctr_shared_for_dma`, before arming the HPDMA channels.
    #[cfg(target_arch = "arm")]
    pub fn enable_dma(&mut self) {
        self.mmio.write(CRYP_DMACR_OFFSET, DMACR_DIEN | DMACR_DOEN);
    }

    /// Clear CRYP's DMA request lines (return to the CPU polling FIFO path).
    #[cfg(target_arch = "arm")]
    pub fn disable_dma(&mut self) {
        self.mmio.write(CRYP_DMACR_OFFSET, 0);
    }

    /// True if CRYP holds a valid key (`SR.KEYVALID`). Used by the DHUK
    /// provisioning orchestrator for the fail-closed check after the SAES share.
    #[allow(dead_code)]
    pub fn key_valid(&self) -> bool {
        self.mmio.read(CRYP_SR_OFFSET) & SR_KEYVALID != 0
    }

    /// Configure CRYP for AES-128-CTR with a SW-loaded key and explicit IV.
    /// Per RM0486 §49.4.10 (CTR encryption/decryption process), §49.8.17–
    /// §49.8.20 (IV registers), §49.8.1 (CR.ALGOMODE).
    /// CTR encrypt and decrypt are the same operation, so ALGODIR is left
    /// at 0 (encrypt forward cipher). The peripheral generates the
    /// keystream from `counter = IVI`, XORs it with the input stream, and
    /// increments IV1RR (the low 32 bits) big-endian after each completed
    /// block. Carry into IV1LR happens internally.
    /// Sequence (§49.4.10):
    /// 1. CRYPEN=0
    /// 2. FFLUSH=1 (clear stale FIFO contents from any prior session)
    /// 3. CR: KMOD=0, ALGOMODE=0x6 (CTR), KEYSIZE=0 (128), DATATYPE=0,
    /// ALGODIR=0, NPBLB=0, GCM_CCMPH=0
    /// 4. Write IV to IV0LR → IV0RR → IV1LR → IV1RR (MSB-first, mirrors
    /// key layout)
    /// 5. Write key to K2LR → K2RR → K3LR → K3RR (ascending; out-of-
    /// order sets KERF). KEYSIZE+ALGOMODE must be set BEFORE keys.
    /// 6. Wait SR.KEYVALID=1
    /// 7. CRYPEN=1
    /// After this call, feed plaintext/ciphertext blocks through
    /// `process_block` exactly as for ECB — the FIFO protocol is identical;
    /// only the internal counter+XOR behavior differs.
    /// Suspend/resume note (§49.4.10): IV registers are HW-mutated. To
    /// resume mid-stream, callers must save IVxLR/RR before clearing
    /// CRYPEN and reload them before re-enabling. `ctr_xform` processes
    /// the whole stream under one CRYPEN, so this isn't exercised here.
    pub fn configure_ctr_128_sw_key(&mut self, key: &[u8; 16], iv: &[u8; 16]) {
        // 1. Disable CRYP
        let mut cr = self.mmio.read(CRYP_CR_OFFSET);
        cr &= !CR_CRYPEN;
        self.mmio.write(CRYP_CR_OFFSET, cr);

        // 2. FFLUSH (self-clearing per §49.8.1; safe to OR-set then
        // follow with subsequent writes that leave bit 14 = 0).
        self.mmio.write(CRYP_CR_OFFSET, cr | CR_FFLUSH);

        // 3. Configure fields. Re-read CR after FFLUSH (which is
        // self-clearing) and rebuild from scratch.
        let mut cr = self.mmio.read(CRYP_CR_OFFSET);
        cr &= !(1 << 19); // ALGOMODE[3] = 0
        cr &= !(0x7 << 3); // clear ALGOMODE[2:0]
        cr |= CR_ALGOMODE_CTR; // set CTR (0b110 at [5:3])
        cr &= !(0x3 << 8); // KEYSIZE = 0 (128-bit)
        cr &= !(0x3 << 6); // DATATYPE = 0 (no swap)
        cr &= !(1 << 2); // ALGODIR = 0 (forward cipher)
        cr &= !(0x3 << 24); // KMOD = 0 (normal SW key)
        cr &= !(0xF << 20); // NPBLB = 0 (CTR ignores it)
        cr &= !(0x3 << 16); // GCM_CCMPH = 0 (N/A for CTR)
        self.mmio.write(CRYP_CR_OFFSET, cr);

        // 4. Load IV. MSB-first like keys (RM Table 418).
        self.mmio.write(
            CRYP_IV0LR_OFFSET,
            u32::from_be_bytes(iv[0..4].try_into().unwrap()),
        );
        self.mmio.write(
            CRYP_IV0RR_OFFSET,
            u32::from_be_bytes(iv[4..8].try_into().unwrap()),
        );
        self.mmio.write(
            CRYP_IV1LR_OFFSET,
            u32::from_be_bytes(iv[8..12].try_into().unwrap()),
        );
        self.mmio.write(
            CRYP_IV1RR_OFFSET,
            u32::from_be_bytes(iv[12..16].try_into().unwrap()),
        );

        // 5. Write key in ascending order K2LR → K2RR → K3LR → K3RR.
        // Same byte order as ECB path (see configure_ecb_128_sw_key
        // docstring): K2LR receives the MSB word.
        self.mmio.write(
            CRYP_K2LR_OFFSET,
            u32::from_be_bytes(key[0..4].try_into().unwrap()),
        );
        self.mmio.write(
            CRYP_K2RR_OFFSET,
            u32::from_be_bytes(key[4..8].try_into().unwrap()),
        );
        self.mmio.write(
            CRYP_K3LR_OFFSET,
            u32::from_be_bytes(key[8..12].try_into().unwrap()),
        );
        self.mmio.write(
            CRYP_K3RR_OFFSET,
            u32::from_be_bytes(key[12..16].try_into().unwrap()),
        );

        // 6. Wait KEYVALID. KERF surfaces sequence errors early.
        loop {
            let sr = self.mmio.read(CRYP_SR_OFFSET);
            if (sr & SR_KERF) != 0 {
                panic!("CRYP KERF asserted after CTR key load — invalid sequence");
            }
            if (sr & SR_KEYVALID) != 0 {
                break;
            }
        }

        // 7. Enable CRYP
        let cr = self.mmio.read(CRYP_CR_OFFSET);
        self.mmio.write(CRYP_CR_OFFSET, cr | CR_CRYPEN);
    }

    /// Process a single 16-byte block (ECB-encrypt — used as CTR keystream
    /// generator in `crypto_impl::aes_decrypt`).
    /// Per §49.8.3, write order is MSB-first: 4 successive 32-bit writes
    /// where the first is data[127:96] (input[0..4] big-endian) and the
    /// last is data[31:0] (input[12..16]).
    /// Precondition: `configure_ecb_128_sw_key` must have been called.
    pub fn process_block(&self, input: &[u8; 16], output: &mut [u8; 16]) {
        // 4 writes to DIN (MSB-first per §49.8.3)
        self.mmio.write(
            CRYP_DIN_OFFSET,
            u32::from_be_bytes(input[0..4].try_into().unwrap()),
        );
        self.mmio.write(
            CRYP_DIN_OFFSET,
            u32::from_be_bytes(input[4..8].try_into().unwrap()),
        );
        self.mmio.write(
            CRYP_DIN_OFFSET,
            u32::from_be_bytes(input[8..12].try_into().unwrap()),
        );
        self.mmio.write(
            CRYP_DIN_OFFSET,
            u32::from_be_bytes(input[12..16].try_into().unwrap()),
        );

        // Poll OFNE=1 (4 words ready)
        while (self.mmio.read(CRYP_SR_OFFSET) & SR_OFNE) == 0 {}

        // 4 reads from DOUT (MSB-first per §49.8.4)
        let d0 = self.mmio.read(CRYP_DOUT_OFFSET);
        let d1 = self.mmio.read(CRYP_DOUT_OFFSET);
        let d2 = self.mmio.read(CRYP_DOUT_OFFSET);
        let d3 = self.mmio.read(CRYP_DOUT_OFFSET);

        output[0..4].copy_from_slice(&d0.to_be_bytes());
        output[4..8].copy_from_slice(&d1.to_be_bytes());
        output[8..12].copy_from_slice(&d2.to_be_bytes());
        output[12..16].copy_from_slice(&d3.to_be_bytes());
    }
}

#[cfg(test)]
#[path = "cryp_tests.rs"]
mod tests;
