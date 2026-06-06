// Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>

//! Hardware AES Driver for STM32L562.
//! L552 has **no AES peripheral** — this entire module is gated on the
//! `stm32l562` feature. See the parent module docs and memory note
//! for why this gate must not be widened.
//! # `MmioAccess` generic
//! `AesHardware` is generic over the MMIO backend so host tests can inject
//! [`umbra_pal_test::mmio::MmioHandle`]. Default `M = RealMmio` keeps every
//! existing `AesHardware::new()` call site (crypto_impl, benchmark,
//! platform_impl/boot) unchanged. The trait impl mirrors the GPIO / DMA
//!
//! ## State-machine ordering — DO NOT REORDER
//! The L562 AES peripheral state machine is sensitive to register-write
//! order; the original write sequence is preserved verbatim:
//! - CR.MODE/ALGO/DATATYPE cleared before CR.EN is set,
//! - KEYR0..KEYR3 are written in ascending offset order with the
//! big-endian key reversal that matches RM0438 §27.4 (KEYR0 holds the
//! LSB word, KEYR3 the MSB word),
//! - DINR is written 4× per block (MSB-first byte order),
//! - DOUTR is read 4× after CCF set; CCFC clears the flag.

use crate::rcc::{self, Rcc};
use peripheral_regs::{MmioAccess, RealMmio};

use super::engine::AesEngine;

const AES_BASE_ADDR: u32 = 0x520C0000; // Secure AES base address for STM32L562

// Registers
const AES_CR_BASE_OFFSET: u32 = 0x00;
const AES_SR_BASE_OFFSET: u32 = 0x04;
const AES_DINR_BASE_OFFSET: u32 = 0x08;
const AES_DOUTR_BASE_OFFSET: u32 = 0x0C;
const AES_KEYR0_BASE_OFFSET: u32 = 0x10;
const AES_KEYR1_BASE_OFFSET: u32 = 0x14;
const AES_KEYR2_BASE_OFFSET: u32 = 0x18;
const AES_KEYR3_BASE_OFFSET: u32 = 0x1C;
#[allow(dead_code)]
const AES_IVR0_BASE_OFFSET: u32 = 0x20;
#[allow(dead_code)]
const AES_IVR1_BASE_OFFSET: u32 = 0x24;
#[allow(dead_code)]
const AES_IVR2_BASE_OFFSET: u32 = 0x28;
#[allow(dead_code)]
const AES_IVR3_BASE_OFFSET: u32 = 0x2C;

/// Hardware AES Driver for STM32L562.
/// Generic over the MMIO backend — default `M = RealMmio` preserves every
/// existing firmware call site (`AesHardware::new()`).
pub struct AesHardware<M: MmioAccess = RealMmio> {
    mmio: M,
    key: [u8; 16],
}

impl AesHardware<RealMmio> {
    pub fn new() -> Self {
        let rcc = Rcc::new();
        rcc.enable_clock(rcc::peripherals::AES);

        Self {
            mmio: RealMmio::new(AES_BASE_ADDR),
            key: [0; 16],
        }
    }
}

impl<M: MmioAccess> AesHardware<M> {
    /// Host-test constructor — accepts any `MmioAccess` backend. On
    /// firmware build, callers use `AesHardware::new()` which monomorphises
    /// to `AesHardware<RealMmio>` and inlines the volatile accesses.
    /// Skips the RCC clock-enable (that path constructs an Rcc HW
    /// singleton, which is firmware-only).
    #[allow(dead_code)]
    pub fn new_with_mmio(mmio: M) -> Self {
        Self { mmio, key: [0; 16] }
    }

    fn wait_for_ccf(&self) {
        loop {
            let sr = self.mmio.read(AES_SR_BASE_OFFSET);
            if (sr & 0x1) != 0 {
                break;
            } // CCF: Computation Complete Flag
        }
    }

    fn clear_ccf(&self) {
        self.mmio.set_bit(AES_CR_BASE_OFFSET, 7); // CCFC: Computation Complete Flag Clear
    }
}

impl<M: MmioAccess> AesEngine for AesHardware<M> {
    fn init(&mut self, key: &[u8], iv: Option<&[u8]>) {
        if key.len() != 16 {
            panic!("AesHardware: Only 128-bit keys supported for now");
        }

        self.key.copy_from_slice(key);

        self.mmio.clear_bit(AES_CR_BASE_OFFSET, 0); // EN bit

        // Set Mode to Encryption by default (00)
        let mut cr = self.mmio.read(AES_CR_BASE_OFFSET);
        cr &= !((3 << 5) | (3 << 1)); // Clear CHMOD and DATATYPE
        cr &= !(3 << 3); // Encryption Mode
        self.mmio.write(AES_CR_BASE_OFFSET, cr);

        // Write Key Initial — KEYR0..KEYR3 ascending, RM0438 §27.4 byte order
        self.mmio.write(
            AES_KEYR0_BASE_OFFSET,
            u32::from_be_bytes(key[12..16].try_into().unwrap()),
        );
        self.mmio.write(
            AES_KEYR1_BASE_OFFSET,
            u32::from_be_bytes(key[8..12].try_into().unwrap()),
        );
        self.mmio.write(
            AES_KEYR2_BASE_OFFSET,
            u32::from_be_bytes(key[4..8].try_into().unwrap()),
        );
        self.mmio.write(
            AES_KEYR3_BASE_OFFSET,
            u32::from_be_bytes(key[0..4].try_into().unwrap()),
        );

        if let Some(_iv_bytes) = iv {
            // TODO: IV support
        }

        self.mmio.set_bit(AES_CR_BASE_OFFSET, 0); // EN bit
    }

    fn encrypt_block(&self, input: &[u8; 16], output: &mut [u8; 16]) {
        // Set Mode to Encryption (00).
        let mut cr = self.mmio.read(AES_CR_BASE_OFFSET);

        // Always ensure Encryption Mode and Key are loaded (previous Decrypt might have dirtied them)
        // Ideally we check if mode changed, but Mode 11 overwrites key, so safe to reload.

        self.mmio.clear_bit(AES_CR_BASE_OFFSET, 0); // Disable
        cr &= !(3 << 3); // Mode 00
        self.mmio.write(AES_CR_BASE_OFFSET, cr);

        // Reload Key (because Decryption Mode 11 overwrites it)
        self.mmio.write(
            AES_KEYR0_BASE_OFFSET,
            u32::from_be_bytes(self.key[12..16].try_into().unwrap()),
        );
        self.mmio.write(
            AES_KEYR1_BASE_OFFSET,
            u32::from_be_bytes(self.key[8..12].try_into().unwrap()),
        );
        self.mmio.write(
            AES_KEYR2_BASE_OFFSET,
            u32::from_be_bytes(self.key[4..8].try_into().unwrap()),
        );
        self.mmio.write(
            AES_KEYR3_BASE_OFFSET,
            u32::from_be_bytes(self.key[0..4].try_into().unwrap()),
        );

        self.mmio.set_bit(AES_CR_BASE_OFFSET, 0); // Enable

        // DINR is written 4× MSB-first per block (RM0438 §27.4).
        self.mmio.write(
            AES_DINR_BASE_OFFSET,
            u32::from_be_bytes(input[0..4].try_into().unwrap()),
        );
        self.mmio.write(
            AES_DINR_BASE_OFFSET,
            u32::from_be_bytes(input[4..8].try_into().unwrap()),
        );
        self.mmio.write(
            AES_DINR_BASE_OFFSET,
            u32::from_be_bytes(input[8..12].try_into().unwrap()),
        );
        self.mmio.write(
            AES_DINR_BASE_OFFSET,
            u32::from_be_bytes(input[12..16].try_into().unwrap()),
        );

        self.wait_for_ccf();

        let d0 = self.mmio.read(AES_DOUTR_BASE_OFFSET); // MSB
        let d1 = self.mmio.read(AES_DOUTR_BASE_OFFSET);
        let d2 = self.mmio.read(AES_DOUTR_BASE_OFFSET);
        let d3 = self.mmio.read(AES_DOUTR_BASE_OFFSET); // LSB

        self.clear_ccf();

        output[0..4].copy_from_slice(&d0.to_be_bytes());
        output[4..8].copy_from_slice(&d1.to_be_bytes());
        output[8..12].copy_from_slice(&d2.to_be_bytes());
        output[12..16].copy_from_slice(&d3.to_be_bytes());
    }

    fn decrypt_block(&self, input: &[u8; 16], output: &mut [u8; 16]) {
        // Use Mode 11 (Key Derivation + Decryption)
        // This mode expects the ENCRYPTION KEY in the registers.
        // It derives automatically and then decrypts.
        // Warning: Overwrites registers with Derived Key.

        let mut cr = self.mmio.read(AES_CR_BASE_OFFSET);

        self.mmio.clear_bit(AES_CR_BASE_OFFSET, 0); // Disable
        cr &= !(3 << 3);
        cr |= 3 << 3; // Set Mode 11 (Key Derivation + Decryption)
        self.mmio.write(AES_CR_BASE_OFFSET, cr);

        // Reload original Encryption Key (Critical for Mode 11)
        self.mmio.write(
            AES_KEYR0_BASE_OFFSET,
            u32::from_be_bytes(self.key[12..16].try_into().unwrap()),
        );
        self.mmio.write(
            AES_KEYR1_BASE_OFFSET,
            u32::from_be_bytes(self.key[8..12].try_into().unwrap()),
        );
        self.mmio.write(
            AES_KEYR2_BASE_OFFSET,
            u32::from_be_bytes(self.key[4..8].try_into().unwrap()),
        );
        self.mmio.write(
            AES_KEYR3_BASE_OFFSET,
            u32::from_be_bytes(self.key[0..4].try_into().unwrap()),
        );

        self.mmio.set_bit(AES_CR_BASE_OFFSET, 0); // Enable

        // DINR ciphertext is written 4× MSB-first per block (RM0438 §27.4).
        self.mmio.write(
            AES_DINR_BASE_OFFSET,
            u32::from_be_bytes(input[0..4].try_into().unwrap()),
        );
        self.mmio.write(
            AES_DINR_BASE_OFFSET,
            u32::from_be_bytes(input[4..8].try_into().unwrap()),
        );
        self.mmio.write(
            AES_DINR_BASE_OFFSET,
            u32::from_be_bytes(input[8..12].try_into().unwrap()),
        );
        self.mmio.write(
            AES_DINR_BASE_OFFSET,
            u32::from_be_bytes(input[12..16].try_into().unwrap()),
        );

        // Single CCF assertion at end of Mode 11 (key derivation + decrypt).
        self.wait_for_ccf();

        let d0 = self.mmio.read(AES_DOUTR_BASE_OFFSET); // MSB
        let d1 = self.mmio.read(AES_DOUTR_BASE_OFFSET);
        let d2 = self.mmio.read(AES_DOUTR_BASE_OFFSET);
        let d3 = self.mmio.read(AES_DOUTR_BASE_OFFSET); // LSB

        self.clear_ccf();

        output[0..4].copy_from_slice(&d0.to_be_bytes());
        output[4..8].copy_from_slice(&d1.to_be_bytes());
        output[8..12].copy_from_slice(&d2.to_be_bytes());
        output[12..16].copy_from_slice(&d3.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    //! Host-side tests for the `AesHardware` MMIO recipe.
    //! We do NOT fire the real AES state machine here — the host mem has
    //! no AES math; CCF never sets, DOUTR is always 0. Instead we verify
    //! the configure step emits the right CR.MODE/ALGO bits in order, and
    //! that key loading writes KEYR0..KEYR3 in ascending offset order
    //! with the documented big-endian word reversal.
    //! Block-data transforms are covered by `emulated::tests` (NIST KAT)
    //! and by on-target boot_tests; here we only care about the MMIO
    //! transaction recipe.
    use super::*;
    use umbra_pal_test::mmio::{MmioMem, MmioOp};

    /// Helper: preload SR.CCF = 1 so `wait_for_ccf` (if exercised) would
    /// terminate; tests below avoid the data-path so this is unused, but
    /// kept here for any future test that wants to drive a block through.
    #[allow(dead_code)]
    fn preload_ccf(mem: &MmioMem) {
        mem.preload_register(AES_SR_BASE_OFFSET, 0x1);
    }

    /// `init(key, None)` must:
    /// 1. clear CR.EN (bit 0),
    /// 2. clear CR.CHMOD/DATATYPE/Mode bits via a CR read-modify-write,
    /// 3. write KEYR0..KEYR3 in ascending offset order with the BE word
    /// reversal (KEYR0 = BE(key[12..16]), KEYR3 = BE(key[0..4])),
    /// 4. set CR.EN (bit 0).
    #[test]
    fn init_writes_keyrx_in_ascending_order_with_be_reversal() {
        let mem = MmioMem::new(AES_BASE_ADDR);
        // Preload CR with all-1s so the CR.MODE clear step is observable
        // distinctly from the "register starts at 0" case.
        mem.preload_register(AES_CR_BASE_OFFSET, 0xFFFF_FFFF);

        let mut aes = AesHardware::<_>::new_with_mmio(mem.handle());

        // Distinct bytes per key word so we can assert the reversal.
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, // becomes KEYR3 (MSB word)
            0x04, 0x05, 0x06, 0x07, // becomes KEYR2
            0x08, 0x09, 0x0A, 0x0B, // becomes KEYR1
            0x0C, 0x0D, 0x0E, 0x0F, // becomes KEYR0 (LSB word)
        ];
        aes.init(&key, None);

        // Walk the log; record each Write to a KEYRx in issue order. The
        // crate is no_std (no alloc::Vec), so we use a fixed-size array
        // and a manual counter — same hand-rolled pattern as dma.rs tests.
        let log = mem.write_log();
        let mut keyr_writes: [(u32, u32); 4] = [(0, 0); 4];
        let mut n: usize = 0;
        for op in log.iter() {
            if let MmioOp::Write { addr, value } = *op {
                let off = addr - AES_BASE_ADDR;
                if off == AES_KEYR0_BASE_OFFSET
                    || off == AES_KEYR1_BASE_OFFSET
                    || off == AES_KEYR2_BASE_OFFSET
                    || off == AES_KEYR3_BASE_OFFSET
                {
                    assert!(n < 4, "more than 4 KEYRx writes");
                    keyr_writes[n] = (addr, value);
                    n += 1;
                }
            }
        }
        assert_eq!(n, 4, "expected exactly 4 KEYRx writes, got {}", n);

        // Ascending offset order:
        assert_eq!(keyr_writes[0].0, AES_BASE_ADDR + AES_KEYR0_BASE_OFFSET);
        assert_eq!(keyr_writes[1].0, AES_BASE_ADDR + AES_KEYR1_BASE_OFFSET);
        assert_eq!(keyr_writes[2].0, AES_BASE_ADDR + AES_KEYR2_BASE_OFFSET);
        assert_eq!(keyr_writes[3].0, AES_BASE_ADDR + AES_KEYR3_BASE_OFFSET);

        // BE word reversal — KEYR0 = key[12..16] BE, KEYR3 = key[0..4] BE.
        assert_eq!(keyr_writes[0].1, 0x0C0D_0E0F, "KEYR0 = BE(key[12..16])");
        assert_eq!(keyr_writes[1].1, 0x0809_0A0B, "KEYR1 = BE(key[8..12])");
        assert_eq!(keyr_writes[2].1, 0x0405_0607, "KEYR2 = BE(key[4..8])");
        assert_eq!(keyr_writes[3].1, 0x0001_0203, "KEYR3 = BE(key[0..4])");
    }

    /// `init(key, None)` must clear CR.MODE (bits [4:3]), CR.CHMOD (bits
    /// [6:5]) and CR.DATATYPE (bits [2:1]) in the CR read-modify-write
    /// preceding the KEYRx writes. We preload CR with all-1s and inspect
    /// the CR write that follows the initial CR read.
    #[test]
    fn init_clears_cr_mode_chmod_datatype_bits_before_keyrx() {
        let mem = MmioMem::new(AES_BASE_ADDR);
        mem.preload_register(AES_CR_BASE_OFFSET, 0xFFFF_FFFF);

        let mut aes = AesHardware::<_>::new_with_mmio(mem.handle());
        let key = [0xAAu8; 16];
        aes.init(&key, None);

        let log = mem.write_log();

        // Walk the log until the first KEYRx write. Among writes to
        // CR_OFFSET before that point, the LAST one is the read-modify-write
        // that init issues (CR &= !mask; write CR). That value must have
        // bits [6:5], [4:3], [2:1] cleared, and bit 0 cleared by the
        // preceding clear_bit (EN disable).
        let mut last_cr_write: Option<u32> = None;
        for op in log.iter() {
            match *op {
                MmioOp::Write { addr, value } => {
                    if addr == AES_BASE_ADDR + AES_KEYR0_BASE_OFFSET {
                        break;
                    }
                    if addr == AES_BASE_ADDR + AES_CR_BASE_OFFSET {
                        last_cr_write = Some(value);
                    }
                }
                _ => {}
            }
        }

        let cr = last_cr_write.expect("expected at least one CR write before KEYRx");
        // CHMOD [6:5], MODE [4:3], DATATYPE [2:1] must all be zero.
        assert_eq!((cr >> 5) & 0b11, 0, "CR.CHMOD not cleared");
        assert_eq!((cr >> 3) & 0b11, 0, "CR.MODE not cleared (encrypt = 00)");
        assert_eq!((cr >> 1) & 0b11, 0, "CR.DATATYPE not cleared");
    }
}
