//! SAES1 driver for STM32N657 — DHUK key-wrap / share-to-CRYP path (issue #45).
//!
//! Production use: the AES key reaches CRYP over the SAES→CRYP silicon
//! shared-key bus under DHUK, instead of a software key load. SAES is not used
//! as the bulk AES engine here (CRYP is ~35× faster); it only wraps the key and
//! decrypts+shares it. Procedure mirrors the STM32Cube HAL
//! (`HAL_CRYPEx_EncryptSharedKey`/`DecryptSharedKey`) — see `wrap_under_dhuk`
//! and `unwrap_and_share_to_cryp`.
//!
//! Base address: 0x5402_1000 (Secure alias). Register layout per RM0486 §48.8 /
//! CMSIS `stm32n657xx.h`: SAES_CR EN[0], MODE[4:3], KEYSIZE[18], KMOD[25:24],
//! KSHAREID[27:26], KEYSEL[30:28]; SAES_SR CCF[0], KEYVALID[7]; SAES_ICR[0]
//! clears CCF. The CCF wait is interrupt-driven via [`crate::crypto_wait`].
//!
//! `Saes` is generic over the MMIO backend so host tests can inject
//! [`umbra_pal_test::mmio::MmioHandle`]; the firmware build monomorphises to
//! `Saes<RealMmio>` and inlines the volatile accesses.

use peripheral_regs::{MmioAccess, RealMmio};

const SAES_BASE_ADDR: u32 = 0x5402_1000;

const SAES_CR_OFFSET: u32 = 0x00;
const SAES_SR_OFFSET: u32 = 0x04;
const SAES_DINR_OFFSET: u32 = 0x08;
const SAES_DOUTR_OFFSET: u32 = 0x0C;
// Only KEYR0 is referenced (host tests assert the wrap/share path writes no
// KEYRx — the key flows through DINR/DOUTR, not the key registers).
#[allow(dead_code)] // test-only
const SAES_KEYR0_OFFSET: u32 = 0x10;

// SR_CCF / SAES_ICR / ICR_CCF are used only by the host (non-ARM) branch of
// wait_ccf; on ARM the CCF wait is interrupt-driven via crypto_wait.
#[allow(dead_code)]
const SR_CCF: u32 = 1 << 0;
const SR_KEYVALID: u32 = 1 << 7;
// SAES_ICR @ 0x308 (CMSIS): write CCF bit to clear the computation-complete
// flag (mirrors HAL __HAL_CRYP_CLEAR_FLAG).
#[allow(dead_code)]
const SAES_ICR_OFFSET: u32 = 0x308;
#[allow(dead_code)]
const ICR_CCF: u32 = 1 << 0;

/// SAES driver. Generic over the MMIO backend — default `M = RealMmio`
/// preserves the firmware call site (`Saes::new()` in `dhuk_provision.rs`).
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
    #[allow(dead_code)]
    pub fn new_with_mmio(mmio: M) -> Self {
        Self { mmio }
    }

    /// Bounded poll: spin on `SAES_SR & mask` until set or the budget runs out.
    fn wait_sr_bounded(&self, mask: u32) {
        let mut budget = 1_000_000u32;
        while self.mmio.read(SAES_SR_OFFSET) & mask == 0 {
            budget -= 1;
            if budget == 0 {
                break;
            }
        }
    }

    /// Clear the computation-complete flag via SAES_ICR (HAL convention).
    /// Used only by the host (non-ARM) `wait_ccf` branch — on ARM the ISR
    /// clears CCF.
    #[allow(dead_code)]
    fn clear_ccf(&self) {
        self.mmio.write(SAES_ICR_OFFSET, ICR_CCF);
    }

    /// Wait for the SAES computation-complete (CCF) event.
    /// On firmware: interrupt-driven via [`crate::crypto_wait`] — arm the SAES
    /// CCF IRQ (36), `WFI` until the ISR posts (low power + the future
    /// preemption/yield seam), disarm; the ISR clears CCF. On host tests: a
    /// bounded SR poll + ICR clear (the IRQ path does raw NVIC/SAES MMIO that
    /// would fault under `MmioMem`).
    fn wait_ccf(&self) {
        #[cfg(target_arch = "arm")]
        {
            crate::crypto_wait::arm();
            let r = crate::crypto_wait::block_until_done(1_000_000);
            crate::crypto_wait::disarm();
            // Fail closed: a stalled SAES op (e.g. the VBAT backup domain is
            // unpowered, so DHUK never derives) must panic, not silently
            // continue on a broken crypto path or hang the boot forever.
            if r.is_err() {
                panic!("SAES CCF timeout (crypto op stalled — check VBAT/backup domain)");
            }
            // CCF was cleared by the ISR.
        }
        #[cfg(not(target_arch = "arm"))]
        {
            self.wait_sr_bounded(SR_CCF);
            self.clear_ccf();
        }
    }

    /// Wrap a 128-bit key under DHUK for later sharing to CRYP (issue #45).
    /// Mirrors STM32Cube HAL `HAL_CRYPEx_EncryptSharedKey`/`CRYPEx_KeyEncrypt`:
    /// `KMOD=SHARED`, `KSHAREID=0` (CRYP), `KEYSEL=DHUK`, `MODE=ENCRYPT`; wait
    /// KEYVALID (DHUK derivation), enable, feed the key via **DINR**, wait CCF,
    /// read the wrapped blob from **DOUTR**. All polls bounded — never hangs.
    pub fn wrap_under_dhuk(&mut self, key: &[u8; 16]) -> [u8; 16] {
        // EN=0 to program CR.
        let mut cr = self.mmio.read(SAES_CR_OFFSET);
        cr &= !(1u32 << 0);
        self.mmio.write(SAES_CR_OFFSET, cr);
        // KEYSIZE=128 (bit18=0); KEYSEL=DHUK(0b001<<28); KMOD=SHARED(0b10<<24);
        // KSHAREID=0(CRYP, [27:26]); MODE=ENCRYPT(0, [4:3]).
        cr &= !(1 << 18);
        cr &= !(0x7 << 28);
        cr |= 0b001 << 28;
        cr &= !(0x3 << 24);
        cr |= 0b10 << 24;
        cr &= !(0x3 << 26);
        cr &= !(0x3 << 3);
        self.mmio.write(SAES_CR_OFFSET, cr);
        // Wait for the DHUK key to be valid before enabling + feeding data.
        self.wait_sr_bounded(SR_KEYVALID);
        // EN=1.
        let cr = self.mmio.read(SAES_CR_OFFSET);
        self.mmio.write(SAES_CR_OFFSET, cr | 1);
        // Feed the key as 4 BIG-endian words to DINR so the key delivered to
        // CRYP matches the NIST byte order (MSB = key[0]) — the same order the
        // legacy SW key-load used. Little-endian here byte-reverses the
        // effective key per word and the AES output diverges from
        // AesEmulated(key) (caught by the boot self-consistency KAT).
        for w in 0..4 {
            self.mmio.write(
                SAES_DINR_OFFSET,
                u32::from_be_bytes(key[w * 4..w * 4 + 4].try_into().unwrap()),
            );
        }
        self.wait_ccf();
        // Read the wrapped blob from DOUTR (4 little-endian words).
        let mut blob = [0u8; 16];
        for w in 0..4 {
            let d = self.mmio.read(SAES_DOUTR_OFFSET);
            blob[w * 4..w * 4 + 4].copy_from_slice(&d.to_le_bytes());
        }
        // EN=0.
        let cr = self.mmio.read(SAES_CR_OFFSET);
        self.mmio.write(SAES_CR_OFFSET, cr & !1);
        blob
    }

    /// Decrypt a DHUK-wrapped blob and broadcast the key to CRYP over the
    /// silicon shared-key bus (issue #45). Mirrors STM32Cube HAL
    /// `HAL_CRYPEx_DecryptSharedKey`/`CRYPEx_KeyDecrypt`: `KMOD=SHARED`,
    /// `KSHAREID=0` (CRYP), `KEYSEL=DHUK`, then TWO phases —
    /// (1) `MODE=KEY_DERIVATION` + EN + wait CCF (derive DHUK), then
    /// (2) `MODE=DECRYPT` + EN + feed the blob via **DINR** + wait CCF. The
    /// decrypted key is delivered to CRYP. All polls bounded. After this, CRYP
    /// holds the shared key (configure CRYP `KMOD=shared`, then `key_valid`).
    pub fn unwrap_and_share_to_cryp(&mut self, blob: &[u8; 16]) {
        // EN=0; KEYSIZE=128; KEYSEL=DHUK; KMOD=SHARED; KSHAREID=0 (CRYP).
        let mut cr = self.mmio.read(SAES_CR_OFFSET);
        cr &= !(1u32 << 0);
        self.mmio.write(SAES_CR_OFFSET, cr);
        cr &= !(1 << 18);
        cr &= !(0x7 << 28);
        cr |= 0b001 << 28; // KEYSEL=DHUK
        cr &= !(0x3 << 24);
        cr |= 0b10 << 24; // KMOD=SHARED
        cr &= !(0x3 << 26); // KSHAREID=0 (CRYP)
                            // Phase 1: MODE=KEY_DERIVATION (0b01<<3).
        cr &= !(0x3 << 3);
        cr |= 0b01 << 3;
        self.mmio.write(SAES_CR_OFFSET, cr);
        // EN=1, wait CCF (DHUK derivation complete).
        let cr1 = self.mmio.read(SAES_CR_OFFSET);
        self.mmio.write(SAES_CR_OFFSET, cr1 | 1);
        self.wait_ccf();
        // Phase 2: MODE=DECRYPT (0b10<<3). HAL keeps EN across the MODE change
        // and re-enables; mirror that.
        let mut cr = self.mmio.read(SAES_CR_OFFSET);
        cr &= !(0x3 << 3);
        cr |= 0b10 << 3;
        self.mmio.write(SAES_CR_OFFSET, cr);
        let cr = self.mmio.read(SAES_CR_OFFSET);
        self.mmio.write(SAES_CR_OFFSET, cr | 1);
        // Feed the wrapped blob as 4 little-endian words to DINR.
        for w in 0..4 {
            self.mmio.write(
                SAES_DINR_OFFSET,
                u32::from_le_bytes(blob[w * 4..w * 4 + 4].try_into().unwrap()),
            );
        }
        self.wait_ccf();
        // EN=0.
        let cr = self.mmio.read(SAES_CR_OFFSET);
        self.mmio.write(SAES_CR_OFFSET, cr & !1);
    }
}

#[cfg(test)]
mod tests {
    //! Host tests verify the issued MMIO recipe (CR field selection + the key/
    //! blob flowing through DINR, never KEYRx). The host has no AES math, so
    //! SR.CCF/KEYVALID are preloaded to let the bounded waits exit; block-data
    //! correctness is covered on-target by the boot self-consistency KAT.
    use super::*;
    use umbra_pal_test::mmio::{MmioMem, MmioOp};

    /// `wrap_under_dhuk` (HAL EncryptSharedKey): KEYSEL=DHUK, KMOD=SHARED
    /// (0b10), MODE=ENCRYPT (0b00); key fed via DINR, NOT KEYRx.
    #[test]
    fn wrap_under_dhuk_selects_dhuk_shared_encrypt_via_dinr() {
        let mem = MmioMem::new(SAES_BASE_ADDR);
        // KEYVALID + CCF preset so both bounded waits exit immediately.
        mem.preload_register(SAES_SR_OFFSET, SR_KEYVALID | SR_CCF);
        let mut saes = Saes::<_>::new_with_mmio(mem.handle());
        let _ = saes.wrap_under_dhuk(&[0x11u8; 16]);

        let log = mem.write_log();
        let cfg = log
            .iter()
            .find_map(|op| match op {
                MmioOp::Write { addr, value }
                    if *addr == SAES_BASE_ADDR + SAES_CR_OFFSET
                        && (*value >> 28) & 0x7 == 0b001 =>
                {
                    Some(*value)
                }
                _ => None,
            })
            .expect("a CR write with KEYSEL=DHUK");
        assert_eq!((cfg >> 24) & 0x3, 0b10, "KMOD=SHARED");
        assert_eq!((cfg >> 3) & 0x3, 0b00, "MODE=ENCRYPT");
        assert!(
            log.iter().any(|op| matches!(op,
                MmioOp::Write { addr, .. } if *addr == SAES_BASE_ADDR + SAES_DINR_OFFSET)),
            "key must be fed via DINR"
        );
        assert!(
            !log.iter().any(|op| matches!(op,
                MmioOp::Write { addr, .. } if *addr == SAES_BASE_ADDR + SAES_KEYR0_OFFSET)),
            "wrap must NOT write KEYRx"
        );
    }

    /// `unwrap_and_share_to_cryp` (HAL DecryptSharedKey): KEYSEL=DHUK,
    /// KMOD=SHARED (0b10), KSHAREID=CRYP (0b00); blob fed via DINR, NOT KEYRx.
    #[test]
    fn unwrap_and_share_selects_dhuk_shared_via_dinr() {
        let mem = MmioMem::new(SAES_BASE_ADDR);
        mem.preload_register(SAES_SR_OFFSET, SR_CCF);
        let mut saes = Saes::<_>::new_with_mmio(mem.handle());
        saes.unwrap_and_share_to_cryp(&[0x22u8; 16]);

        let log = mem.write_log();
        let cfg = log
            .iter()
            .find_map(|op| match op {
                MmioOp::Write { addr, value }
                    if *addr == SAES_BASE_ADDR + SAES_CR_OFFSET
                        && (*value >> 28) & 0x7 == 0b001 =>
                {
                    Some(*value)
                }
                _ => None,
            })
            .expect("a CR write with KEYSEL=DHUK");
        assert_eq!((cfg >> 24) & 0x3, 0b10, "KMOD=SHARED");
        assert_eq!((cfg >> 26) & 0x3, 0b00, "KSHAREID=CRYP");
        assert!(
            log.iter().any(|op| matches!(op,
                MmioOp::Write { addr, .. } if *addr == SAES_BASE_ADDR + SAES_DINR_OFFSET)),
            "blob must be fed via DINR"
        );
        assert!(
            !log.iter().any(|op| matches!(op,
                MmioOp::Write { addr, .. } if *addr == SAES_BASE_ADDR + SAES_KEYR0_OFFSET)),
            "unwrap must NOT write KEYRx"
        );
    }
}
