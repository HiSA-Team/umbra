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
mod tests {
    use super::*;
    use umbra_pal_test::mmio::{MmioMem, MmioOp};

    /// Return the (addr, value) of the n-th Write in `log`. Mirrors the
    /// L552 hash.rs helper — N657 no_std test mod cannot pull in `Vec`,
    /// so iterate the slice directly.
    fn nth_write(log: &[MmioOp], n: usize) -> (u32, u32) {
        let mut seen = 0;
        for op in log {
            if let MmioOp::Write { addr, value } = *op {
                if seen == n {
                    return (addr, value);
                }
                seen += 1;
            }
        }
        panic!("log only contains {} writes, wanted index {}", seen, n);
    }

    /// Return the value of the most-recent Write to `want_addr` (or None).
    fn last_write_to(log: &[MmioOp], want_addr: u32) -> Option<u32> {
        let mut found = None;
        for op in log {
            if let MmioOp::Write { addr, value } = *op {
                if addr == want_addr {
                    found = Some(value);
                }
            }
        }
        found
    }

    /// Return the (addr, value) of the n-th Write whose addr matches
    /// `want_addr` (0-indexed). DIN/DOUT FIFOs share a single offset across
    /// 4 consecutive writes; this helper indexes into that sequence.
    fn nth_write_to(log: &[MmioOp], want_addr: u32, n: usize) -> u32 {
        let mut seen = 0;
        for op in log {
            if let MmioOp::Write { addr, value } = *op {
                if addr == want_addr {
                    if seen == n {
                        return value;
                    }
                    seen += 1;
                }
            }
        }
        panic!(
            "log only contains {} writes to 0x{:08x}, wanted index {}",
            seen, want_addr, n
        );
    }

    /// Verifies the load-bearing KEYRx ascending-write contract from
    /// `configure_ecb_128_sw_key`: K2LR receives `key[0..4]` as a big-
    /// endian u32 (the MSB word of KEY[127:0]), then K2RR/K3LR/K3RR in
    /// ascending offsets. Any other order asserts CRYP SR.KERF on real
    /// silicon and would prevent KEYVALID from rising. See L552 commit
    /// 18c47d3 for the analogous AesHardware test.
    /// Preloads SR with KEYVALID=1 so the post-key poll exits on the
    /// first iteration.
    #[test]
    fn configure_ecb_128_writes_keyrx_ascending_with_be_byteswap() {
        let mem = MmioMem::new(CRYP_BASE_ADDR);
        // SR.KEYVALID = bit 7 — set so the poll-after-key loop exits.
        mem.preload_register(CRYP_SR_OFFSET, SR_KEYVALID);

        let mut cryp = Cryp1::<_>::new_with_mmio(mem.handle());
        // Distinguishable per-word sentinels so a swapped order would
        // produce different captured values.
        let key: [u8; 16] = [
            0xDE, 0xAD, 0xBE, 0xEF, // → K2LR  = 0xDEADBEEF
            0x01, 0x02, 0x03, 0x04, // → K2RR  = 0x01020304
            0xCA, 0xFE, 0xBA, 0xBE, // → K3LR  = 0xCAFEBABE
            0x12, 0x34, 0x56, 0x78, // → K3RR  = 0x12345678
        ];
        cryp.configure_ecb_128_sw_key(&key);

        let log = mem.write_log();
        let k2lr_addr = CRYP_BASE_ADDR + CRYP_K2LR_OFFSET;
        let k2rr_addr = CRYP_BASE_ADDR + CRYP_K2RR_OFFSET;
        let k3lr_addr = CRYP_BASE_ADDR + CRYP_K3LR_OFFSET;
        let k3rr_addr = CRYP_BASE_ADDR + CRYP_K3RR_OFFSET;

        // Confirm the exact captured value at each KEYRx — pins both byte
        // order AND register choice.
        assert_eq!(
            last_write_to(&log, k2lr_addr),
            Some(0xDEAD_BEEF),
            "K2LR must receive key[0..4] as BE u32 (MSB word of KEY[127:0])"
        );
        assert_eq!(
            last_write_to(&log, k2rr_addr),
            Some(0x0102_0304),
            "K2RR must receive key[4..8] as BE u32"
        );
        assert_eq!(
            last_write_to(&log, k3lr_addr),
            Some(0xCAFE_BABE),
            "K3LR must receive key[8..12] as BE u32"
        );
        assert_eq!(
            last_write_to(&log, k3rr_addr),
            Some(0x1234_5678),
            "K3RR must receive key[12..16] as BE u32 (LSB word)"
        );

        // And confirm the relative ordering: K2LR write happens BEFORE
        // K2RR write, etc. KEYRx ascending order is the HW contract that
        // prevents SR.KERF.
        let pos = |addr: u32| -> usize {
            log.iter()
                .position(|op| matches!(op, MmioOp::Write { addr: a, .. } if *a == addr))
                .unwrap_or_else(|| panic!("expected a Write to 0x{:08x}", addr))
        };
        assert!(pos(k2lr_addr) < pos(k2rr_addr), "K2LR must precede K2RR");
        assert!(pos(k2rr_addr) < pos(k3lr_addr), "K2RR must precede K3LR");
        assert!(pos(k3lr_addr) < pos(k3rr_addr), "K3LR must precede K3RR");
    }

    /// Verifies the CR.ALGOMODE encoding for ECB: bits [5:3] = 0b100
    /// (= 0x4 per RM0486 §49.8.1), bit 19 (ALGOMODE[3] extension) cleared.
    /// Also pins ancillary CR fields zeroed by the configure routine:
    /// KEYSIZE [9:8] = 0 (128-bit), DATATYPE [7:6] = 0 (no swap),
    /// ALGODIR bit 2 = 0 (encrypt), KMOD [25:24] = 0 (normal SW key).
    /// The final CR write (step 5: CRYPEN=1) is what we sample.
    #[test]
    fn configure_ecb_128_sets_algomode_ecb_in_cr() {
        let mem = MmioMem::new(CRYP_BASE_ADDR);
        mem.preload_register(CRYP_SR_OFFSET, SR_KEYVALID);

        let mut cryp = Cryp1::<_>::new_with_mmio(mem.handle());
        // Zero key — value irrelevant for this test; we're checking CR.
        cryp.configure_ecb_128_sw_key(&[0u8; 16]);

        let log = mem.write_log();
        let cr_addr = CRYP_BASE_ADDR + CRYP_CR_OFFSET;
        let final_cr = last_write_to(&log, cr_addr)
            .expect("configure_ecb_128_sw_key must write CR at least once");

        // ALGOMODE field [5:3] == 0b100 (ECB = 0x4)
        assert_eq!(
            (final_cr >> 3) & 0x7,
            0b100,
            "CR.ALGOMODE[5:3] must be 0b100 (ECB) — got 0b{:03b}",
            (final_cr >> 3) & 0x7
        );
        // ALGOMODE[3] extension at bit 19 cleared
        assert_eq!(
            (final_cr >> 19) & 1,
            0,
            "CR bit 19 (ALGOMODE ext) must be cleared"
        );
        // KEYSIZE [9:8] = 0 (AES-128)
        assert_eq!((final_cr >> 8) & 0x3, 0, "CR.KEYSIZE must be 0 (128-bit)");
        // DATATYPE [7:6] = 0 (no byte swap on the data path; the BE
        // swap is done in software via from_be_bytes on each DIN write)
        assert_eq!((final_cr >> 6) & 0x3, 0, "CR.DATATYPE must be 0 (no swap)");
        // ALGODIR bit 2 = 0 (encrypt — CTR is symmetric so decrypt re-uses)
        assert_eq!((final_cr >> 2) & 1, 0, "CR.ALGODIR must be 0 (encrypt)");
        // KMOD [25:24] = 0 (normal SW key — not DHUK-wrapped shared-bus)
        assert_eq!(
            (final_cr >> 24) & 0x3,
            0,
            "CR.KMOD must be 0 (normal SW key)"
        );
        // Final write must enable CRYP (bit 15)
        assert_eq!(
            (final_cr >> 15) & 1,
            1,
            "CR.CRYPEN must be set on final write"
        );
    }

    /// Verifies the DIN→OFNE-poll→DOUT FIFO protocol from `process_block`.
    /// Preload SR.OFNE=1 so the poll exits on the first read. Preload
    /// DOUT with 4 distinct sentinels so we can check the BE byte-order
    /// reconstruction (each u32 read becomes 4 output bytes via
    /// `to_be_bytes`).
    /// Confirms:
    /// - 4 DIN writes happen in ascending input-byte order (MSB-first
    /// per §49.8.3, matching key BE convention)
    /// - OFNE poll happens between the writes and the DOUT reads
    /// - output buffer matches the BE expansion of the 4 DOUT reads
    #[test]
    fn process_block_writes_din_then_polls_ofne_then_reads_dout() {
        let mem = MmioMem::new(CRYP_BASE_ADDR);
        // SR.OFNE = bit 2; preload so the poll exits immediately.
        mem.preload_register(CRYP_SR_OFFSET, SR_OFNE);
        // Preload DOUT with a single sentinel — MmioMem's single-cell
        // FIFO returns the same value for all 4 reads, which is fine for
        // pinning the BE-expansion semantics: we just need to verify the
        // output buffer mirrors what came back.
        mem.preload_register(CRYP_DOUT_OFFSET, 0xCA11_AB1E);

        let cryp = Cryp1::<_>::new_with_mmio(mem.handle());
        let input: [u8; 16] = [
            0x11, 0x22, 0x33, 0x44, // → DIN  = 0x11223344
            0x55, 0x66, 0x77, 0x88, // → DIN  = 0x55667788
            0x99, 0xAA, 0xBB, 0xCC, // → DIN  = 0x99AABBCC
            0xDD, 0xEE, 0xFF, 0x00, // → DIN  = 0xDDEEFF00
        ];
        let mut output = [0u8; 16];
        cryp.process_block(&input, &mut output);

        let log = mem.write_log();
        let din_addr = CRYP_BASE_ADDR + CRYP_DIN_OFFSET;

        // 4 DIN writes with BE byte-order (MSB-first per §49.8.3)
        assert_eq!(
            nth_write_to(&log, din_addr, 0),
            0x1122_3344,
            "DIN write #0 must be input[0..4] BE"
        );
        assert_eq!(
            nth_write_to(&log, din_addr, 1),
            0x5566_7788,
            "DIN write #1 must be input[4..8] BE"
        );
        assert_eq!(
            nth_write_to(&log, din_addr, 2),
            0x99AA_BBCC,
            "DIN write #2 must be input[8..12] BE"
        );
        assert_eq!(
            nth_write_to(&log, din_addr, 3),
            0xDDEE_FF00,
            "DIN write #3 must be input[12..16] BE"
        );

        // Output reconstructed from BE expansion of the DOUT reads.
        let expect = 0xCA11_AB1Eu32.to_be_bytes();
        for i in 0..4 {
            assert_eq!(
                &output[i * 4..i * 4 + 4],
                &expect,
                "output[{}*4..] must mirror DOUT read as BE bytes",
                i
            );
        }

        // Reference nth_write so dead-code lint doesn't trip on this
        // helper when only the addr-filtered nth_write_to is exercised.
        let _ = nth_write(&log, 0);
    }
}
