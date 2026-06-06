//! SAES1 driver for STM32N657. Not on the production hot path — CRYP is
//! used directly with a SW-loaded key (see cryp.rs and project memory
//! for the architectural rationale). The methods
//! here are preserved for a future DHUK-wrap key-isolation path:
//! - `load_key` — SW-load a key in normal mode (KMOD=0)
//! - `share_key_to_cryp` — share key to CRYP via bus (needs DHUK-wrapped key per §48.4.15)
//! - `process_block` — SAES as the AES engine (diagnostic-only; SAES is
//! 35× slower than CRYP, so production uses CRYP)
//! Base address: 0x5402_1000 (Secure alias). Register layout per RM0486 §48.8.
//! Bit fields verified against the manual:
//! - SAES_CR: EN[0], MODE[4:3], CHMOD[6:5,16], KEYSIZE[18], KMOD[25:24], KSHAREID[27:26], KEYSEL[30:28], IPRST[31]
//! - SAES_SR: RDERRF[1], WRERRF[2], BUSY[3], KEYVALID[7]
//! # extended — `MmioAccess` generic
//! `Saes` is generic over the MMIO backend so host tests can inject
//! [`umbra_pal_test::mmio::MmioHandle`]. Default `M = RealMmio` keeps the
//! existing `Saes::new()` call site in `aes/keyreg.rs` unchanged at the
//! source level — the firmware build monomorphises to `Saes<RealMmio>` and
//! inlines the volatile accesses exactly as before.
//! ## State-machine ordering — DO NOT REORDER
//! The SAES peripheral state machine is sensitive to register-write order;
//! the original write sequence is preserved verbatim:
//! - CR.EN cleared before KEYSIZE/KMOD are programmed,
//! - KEYR0..KEYR3 written in ascending offset order with the big-endian
//! key reversal (KEYR0 = BE(key[12..16]) = LSB word; KEYR3 = BE(key[0..4]) = MSB word)
//! per RM0486 §48.4.17 and Table 409,
//! - CR.EN set last so KEYVALID asserts only after the full sequence,
//! - DINR written 4× per block (MSB-first byte order, mirroring CRYP),
//! - DOUTR read 4× after CCF=1; CCF cleared via the documented write-1-to-CR[7] handshake.

use peripheral_regs::{MmioAccess, RealMmio};

const SAES_BASE_ADDR: u32 = 0x5402_1000;

// Register offsets per RM0486 §48.8 (table starting §48.8.21)
#[allow(dead_code)]
const SAES_CR_OFFSET: u32 = 0x00;
#[allow(dead_code)]
const SAES_SR_OFFSET: u32 = 0x04;
#[allow(dead_code)]
const SAES_DINR_OFFSET: u32 = 0x08;
#[allow(dead_code)]
const SAES_DOUTR_OFFSET: u32 = 0x0C;
#[allow(dead_code)]
const SAES_KEYR0_OFFSET: u32 = 0x10;
#[allow(dead_code)]
const SAES_KEYR1_OFFSET: u32 = 0x14;
#[allow(dead_code)]
const SAES_KEYR2_OFFSET: u32 = 0x18;
#[allow(dead_code)]
const SAES_KEYR3_OFFSET: u32 = 0x1C;

// SR bit positions per §48.8.2
#[allow(dead_code)]
const SR_BSY: u32 = 1 << 3;
#[allow(dead_code)]
const SR_CCF: u32 = 1 << 0;
#[allow(dead_code)]
const SR_KEYVALID: u32 = 1 << 7;

/// SAES driver. Generic over the MMIO backend — default `M = RealMmio`
/// preserves every existing firmware call site (`Saes::new()` in
/// `aes/keyreg.rs`).
pub struct Saes<M: MmioAccess = RealMmio> {
    mmio: M,
}

impl Saes<RealMmio> {
    pub fn new() -> Self {
        Saes {
            mmio: RealMmio::new(SAES_BASE_ADDR),
        }
    }
}

impl<M: MmioAccess> Saes<M> {
    /// Constructor for host-side tests — accepts any `MmioAccess` backend.
    /// On firmware build, callers use `Saes::new()` which monomorphises to
    /// `Saes<RealMmio>` and inlines the volatile accesses.
    #[allow(dead_code)]
    pub fn new_with_mmio(mmio: M) -> Self {
        Self { mmio }
    }

    #[allow(dead_code)]
    fn wait_not_busy(&self) {
        while (self.mmio.read(SAES_SR_OFFSET) & SR_BSY) != 0 {}
    }

    #[allow(dead_code)]
    fn wait_key_valid(&self) {
        while (self.mmio.read(SAES_SR_OFFSET) & SR_KEYVALID) == 0 {}
    }

    #[allow(dead_code)]
    fn wait_ccf(&self) {
        while (self.mmio.read(SAES_SR_OFFSET) & SR_CCF) == 0 {}
    }

    /// Load a 128-bit key into SAES_KEYRx in normal SW-loaded mode (KMOD=0).
    /// Per RM0486 §48.4.17, KEYRx must be written in either ascending or
    /// descending order (we use ascending: KEYR0 first, KEYR3 last).
    /// Table 409 maps: KEYR0 = KEY[31:0] (LSB word), KEYR3 = KEY[127:96] (MSB word).
    #[allow(dead_code)] // kept for the future DHUK-wrap key-isolation path
    pub fn load_key(&mut self, key: &[u8; 16]) {
        self.wait_not_busy();

        // EN=0 to allow CR field writes (per §48.8.1 bit 0).
        let mut cr = self.mmio.read(SAES_CR_OFFSET);
        cr &= !(1u32 << 0);
        self.mmio.write(SAES_CR_OFFSET, cr);

        // KEYSIZE=0 (128-bit) at bit 18 + KMOD=0 (normal SW key) at [25:24].
        cr &= !(1 << 18);
        cr &= !(0x3 << 24);
        self.mmio.write(SAES_CR_OFFSET, cr);

        // Ascending write: KEYR0 = KEY[31:0] (LSB word, key[12..16])
        // up to KEYR3 = KEY[127:96] (MSB word, key[0..4]). Each word is
        // big-endian per NIST/STMicro convention.
        self.mmio.write(
            SAES_KEYR0_OFFSET,
            u32::from_be_bytes(key[12..16].try_into().unwrap()),
        );
        self.mmio.write(
            SAES_KEYR1_OFFSET,
            u32::from_be_bytes(key[8..12].try_into().unwrap()),
        );
        self.mmio.write(
            SAES_KEYR2_OFFSET,
            u32::from_be_bytes(key[4..8].try_into().unwrap()),
        );
        self.mmio.write(
            SAES_KEYR3_OFFSET,
            u32::from_be_bytes(key[0..4].try_into().unwrap()),
        );

        // EN=1 — KEYVALID asserts when KEYRx writes complete in valid order.
        let cr = self.mmio.read(SAES_CR_OFFSET);
        self.mmio.write(SAES_CR_OFFSET, cr | 1);

        self.wait_key_valid();
    }

    /// Trigger shared-key export to CRYP via internal silicon bus.
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

        // EN=0 to allow CR writes.
        let mut cr = self.mmio.read(SAES_CR_OFFSET);
        cr &= !(1u32 << 0);
        self.mmio.write(SAES_CR_OFFSET, cr);

        // KMOD = SHARED (2) at [25:24], MODE = key-derivation (1) at [4:3]
        // per §48.8.1. KSHAREID default 0 = CRYP target.
        cr &= !(0x3 << 24);
        cr |= 0b10 << 24;
        cr &= !(0x3 << 3);
        cr |= 0b01 << 3;
        self.mmio.write(SAES_CR_OFFSET, cr);

        // EN=1.
        let cr = self.mmio.read(SAES_CR_OFFSET);
        self.mmio.write(SAES_CR_OFFSET, cr | 1);

        self.wait_key_valid();
    }

    /// Process a single 16-byte block using SAES as the AES engine.
    /// Diagnostic-only path. SAES is 480 cyc/block vs CRYP's 14
    /// (per RM Table 412 / Table 426) — production uses CRYP.
    /// Requires `load_key` to have been called first.
    #[allow(dead_code)]
    pub fn process_block(&self, input: &[u8; 16], output: &mut [u8; 16]) {
        // 4 writes to DINR (MSB-first byte order, mirroring CRYP pattern)
        self.mmio.write(
            SAES_DINR_OFFSET,
            u32::from_be_bytes(input[0..4].try_into().unwrap()),
        );
        self.mmio.write(
            SAES_DINR_OFFSET,
            u32::from_be_bytes(input[4..8].try_into().unwrap()),
        );
        self.mmio.write(
            SAES_DINR_OFFSET,
            u32::from_be_bytes(input[8..12].try_into().unwrap()),
        );
        self.mmio.write(
            SAES_DINR_OFFSET,
            u32::from_be_bytes(input[12..16].try_into().unwrap()),
        );

        // Wait CCF=1 (computation complete)
        self.wait_ccf();

        // 4 reads from DOUTR
        let d0 = self.mmio.read(SAES_DOUTR_OFFSET);
        let d1 = self.mmio.read(SAES_DOUTR_OFFSET);
        let d2 = self.mmio.read(SAES_DOUTR_OFFSET);
        let d3 = self.mmio.read(SAES_DOUTR_OFFSET);

        output[0..4].copy_from_slice(&d0.to_be_bytes());
        output[4..8].copy_from_slice(&d1.to_be_bytes());
        output[8..12].copy_from_slice(&d2.to_be_bytes());
        output[12..16].copy_from_slice(&d3.to_be_bytes());

        // Clear CCF for next block (write 1 to clear, typical STMicro)
        let cr = self.mmio.read(SAES_CR_OFFSET);
        self.mmio.write(SAES_CR_OFFSET, cr | (1 << 7));
    }
}

#[cfg(test)]
mod tests {
    //! Host-side tests for the `Saes` MMIO recipe.
    //! We do NOT exercise the real SAES state machine here — the host mem
    //! has no AES math; CCF/KEYVALID never set on their own. Tests below
    //! preload SR with KEYVALID=1 so `wait_key_valid` exits, then verify the
    //! issued MMIO sequence matches the documented register-write recipe
    //! (KEYRx ascending + BE word reversal, CR.EN gated around KEYRx).
    //! Block-data transforms (encrypt/decrypt) are out of scope — the L562
    //! `AesHardware` tests and on-target boot_tests cover those paths.
    use super::*;
    use umbra_pal_test::mmio::{MmioMem, MmioOp};

    /// `load_key(key)` must write KEYR0..KEYR3 in ascending offset order
    /// with the documented big-endian word reversal:
    /// KEYR0 = BE(key[12..16]) (LSB word, per RM0486 Table 409)
    /// KEYR1 = BE(key[8..12])
    /// KEYR2 = BE(key[4..8])
    /// KEYR3 = BE(key[0..4]) (MSB word)
    /// Out-of-order writes set RDERRF/WRERRF and prevent KEYVALID, so this
    /// recipe is load-bearing on real silicon.
    #[test]
    fn load_key_writes_keyrx_in_ascending_order_with_be_reversal() {
        let mem = MmioMem::new(SAES_BASE_ADDR);
        // Preload SR.KEYVALID (bit 7) so wait_key_valid exits immediately.
        // SR.BSY (bit 3) starts low so wait_not_busy exits without spinning.
        mem.preload_register(SAES_SR_OFFSET, SR_KEYVALID);

        let mut saes = Saes::<_>::new_with_mmio(mem.handle());

        // Distinct bytes per key word so we can assert the reversal.
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, // becomes KEYR3 (MSB word)
            0x04, 0x05, 0x06, 0x07, // becomes KEYR2
            0x08, 0x09, 0x0A, 0x0B, // becomes KEYR1
            0x0C, 0x0D, 0x0E, 0x0F, // becomes KEYR0 (LSB word)
        ];
        saes.load_key(&key);

        // Walk the log; record each Write to a KEYRx in issue order. The
        // crate is no_std (no alloc::Vec), so we use a fixed-size array
        // and a manual counter — same hand-rolled pattern as L562 aes/hw.rs.
        let log = mem.write_log();
        let mut keyr_writes: [(u32, u32); 4] = [(0, 0); 4];
        let mut n: usize = 0;
        for op in log.iter() {
            if let MmioOp::Write { addr, value } = *op {
                let off = addr - SAES_BASE_ADDR;
                if off == SAES_KEYR0_OFFSET
                    || off == SAES_KEYR1_OFFSET
                    || off == SAES_KEYR2_OFFSET
                    || off == SAES_KEYR3_OFFSET
                {
                    assert!(n < 4, "more than 4 KEYRx writes");
                    keyr_writes[n] = (addr, value);
                    n += 1;
                }
            }
        }
        assert_eq!(n, 4, "expected exactly 4 KEYRx writes, got {}", n);

        // Ascending offset order:
        assert_eq!(keyr_writes[0].0, SAES_BASE_ADDR + SAES_KEYR0_OFFSET);
        assert_eq!(keyr_writes[1].0, SAES_BASE_ADDR + SAES_KEYR1_OFFSET);
        assert_eq!(keyr_writes[2].0, SAES_BASE_ADDR + SAES_KEYR2_OFFSET);
        assert_eq!(keyr_writes[3].0, SAES_BASE_ADDR + SAES_KEYR3_OFFSET);

        // BE word reversal — KEYR0 = key[12..16] BE, KEYR3 = key[0..4] BE
        // (per RM0486 Table 409).
        assert_eq!(keyr_writes[0].1, 0x0C0D_0E0F, "KEYR0 = BE(key[12..16])");
        assert_eq!(keyr_writes[1].1, 0x0809_0A0B, "KEYR1 = BE(key[8..12])");
        assert_eq!(keyr_writes[2].1, 0x0405_0607, "KEYR2 = BE(key[4..8])");
        assert_eq!(keyr_writes[3].1, 0x0001_0203, "KEYR3 = BE(key[0..4])");
    }

    /// `load_key(key)` must, BEFORE the KEYRx writes, perform CR
    /// read-modify-writes that:
    /// - clear CR.EN (bit 0) so the engine accepts new config,
    /// - clear CR.KEYSIZE (bit 18) to select 128-bit keys,
    /// - clear CR.KMOD (bits [25:24]) to select normal SW-loaded mode.
    /// And, AFTER the KEYRx writes, must set CR.EN (bit 0) so KEYVALID
    /// asserts on a complete, in-order sequence. We preload CR with all-1s
    /// so each clear-step is observable distinctly from a zero-initial state.
    #[test]
    fn load_key_clears_en_keysize_kmod_then_sets_en_around_keyrx() {
        let mem = MmioMem::new(SAES_BASE_ADDR);
        mem.preload_register(SAES_CR_OFFSET, 0xFFFF_FFFF);
        // SR.KEYVALID=1 so wait_key_valid exits; SR.BSY=0 so wait_not_busy
        // exits — both flagged in one preload (bits don't overlap).
        mem.preload_register(SAES_SR_OFFSET, SR_KEYVALID);

        let mut saes = Saes::<_>::new_with_mmio(mem.handle());
        let key = [0xAAu8; 16];
        saes.load_key(&key);

        let log = mem.write_log();

        // Capture CR writes flanking the first KEYRx write.
        // last_cr_before = the CR write that immediately precedes KEYR0 —
        // it must have EN=0, KEYSIZE=0, KMOD=00.
        // first_cr_after = the first CR write after the last KEYRx (KEYR3) —
        // it must have EN=1.
        let mut last_cr_before: Option<u32> = None;
        let mut first_cr_after: Option<u32> = None;
        let mut saw_keyr0 = false;
        let mut saw_keyr3 = false;
        for op in log.iter() {
            match *op {
                MmioOp::Write { addr, value } => {
                    let off = addr - SAES_BASE_ADDR;
                    if !saw_keyr0 && off == SAES_CR_OFFSET {
                        last_cr_before = Some(value);
                    }
                    if off == SAES_KEYR0_OFFSET {
                        saw_keyr0 = true;
                    }
                    if off == SAES_KEYR3_OFFSET {
                        saw_keyr3 = true;
                    } else if saw_keyr3 && off == SAES_CR_OFFSET && first_cr_after.is_none() {
                        first_cr_after = Some(value);
                    }
                }
                _ => {}
            }
        }

        let pre = last_cr_before.expect("expected a CR write before KEYR0");
        assert_eq!(pre & 1, 0, "CR.EN not cleared before KEYRx");
        assert_eq!((pre >> 18) & 1, 0, "CR.KEYSIZE not cleared (128-bit)");
        assert_eq!((pre >> 24) & 0x3, 0, "CR.KMOD not cleared (normal SW key)");

        let post = first_cr_after.expect("expected a CR write after KEYR3");
        assert_eq!(post & 1, 1, "CR.EN not set after KEYRx");
    }
}
