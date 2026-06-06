// ────────────────────────────────────────────────────────────────────────────
// umbra-hal::Aes adapter.
// Mirror of the L552 adapter — same shape so the kernel call site
// looks identical across platforms (the only difference is which
// underlying `AesEngine` it owns: SW T-table on L552 default, HW CRYP1
// on N657 default with `n657_aes_hw` feature, or SW fallback otherwise).
// N657's `AesEngine` includes a `ctr_xform` default method that
// `AesHardware` overrides to drive CRYP1 in native CTR mode. The
// adapter calls `encrypt_block` directly for ECB and uses the
// big-endian counter increment for CTR — matching what the existing
// `aes_decrypt` in N657 crypto_impl does today.
// ────────────────────────────────────────────────────────────────────────────

use super::ecb::AesEngine;

/// AES-128 engine implementing `umbra_hal::Aes`. Generic over the
/// underlying single-block primitive (`AesEmulated` for SW path or
/// `AesHardware` for HW CRYP1 with the `n657_aes_hw` feature).
pub struct Aes128Engine<E: AesEngine> {
    engine: E,
    mode: Option<umbra_hal::AesMode>,
    iv: [u8; 16],
}

impl<E: AesEngine> Aes128Engine<E> {
    /// Adopt an externally-constructed `AesEngine`.
    pub fn from_engine(engine: E) -> Self {
        Self {
            engine,
            mode: None,
            iv: [0u8; 16],
        }
    }

    /// Borrow the underlying single-block engine.
    pub fn inner_mut(&mut self) -> &mut E {
        &mut self.engine
    }
}

#[derive(Debug)]
pub enum Aes128Error {
    /// `process` called before `configure`.
    NotConfigured,
    /// AES-256 was requested; only AES-128 is wired here.
    Aes256NotSupported,
    /// ECB length not a multiple of 16.
    EcbLengthNotMultipleOf16,
    /// `output.len() < input.len()`.
    OutputTooShort,
}

impl<E: AesEngine> umbra_hal::Aes for Aes128Engine<E> {
    type Error = Aes128Error;

    fn configure(
        &mut self,
        key: umbra_hal::AesKey<'_>,
        mode: umbra_hal::AesMode,
    ) -> Result<(), Self::Error> {
        let key_bytes: &[u8] = match key {
            umbra_hal::AesKey::Bits128(k) => &k[..],
            umbra_hal::AesKey::Bits256(_) => return Err(Aes128Error::Aes256NotSupported),
        };
        self.engine.init(key_bytes, None);
        self.mode = Some(mode);
        Ok(())
    }

    fn set_iv(&mut self, iv: &[u8; 16]) -> Result<(), Self::Error> {
        self.iv = *iv;
        Ok(())
    }

    fn process(&mut self, input: &[u8], output: &mut [u8]) -> Result<(), Self::Error> {
        let mode = self.mode.ok_or(Aes128Error::NotConfigured)?;
        if output.len() < input.len() {
            return Err(Aes128Error::OutputTooShort);
        }
        match mode {
            umbra_hal::AesMode::EcbEncrypt | umbra_hal::AesMode::EcbDecrypt => {
                if input.len() % 16 != 0 {
                    return Err(Aes128Error::EcbLengthNotMultipleOf16);
                }
                let mut in_block = [0u8; 16];
                let mut out_block = [0u8; 16];
                let mut off = 0;
                while off < input.len() {
                    in_block.copy_from_slice(&input[off..off + 16]);
                    if mode == umbra_hal::AesMode::EcbEncrypt {
                        self.engine.encrypt_block(&in_block, &mut out_block);
                    } else {
                        self.engine.decrypt_block(&in_block, &mut out_block);
                    }
                    output[off..off + 16].copy_from_slice(&out_block);
                    off += 16;
                }
            }
            umbra_hal::AesMode::CtrEncrypt => {
                let mut counter = self.iv;
                let mut keystream = [0u8; 16];
                let mut off = 0;
                while off < input.len() {
                    self.engine.encrypt_block(&counter, &mut keystream);
                    let n = core::cmp::min(16, input.len() - off);
                    for i in 0..n {
                        output[off + i] = input[off + i] ^ keystream[i];
                    }
                    for k in (0..16).rev() {
                        counter[k] = counter[k].wrapping_add(1);
                        if counter[k] != 0 {
                            break;
                        }
                    }
                    off += n;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Host-side tests for the `umbra_hal::Aes` adapter on top of
    //! `AesEmulated`. `AesHardware` cannot be instantiated host-side
    //! (MMIO), but the adapter is generic — the SW engine exercises
    //! every adapter code path (configure/set_iv/process for ECB+CTR
    //! and every error variant) without touching CRYP1.
    use super::super::ecb::AesEmulated;
    use super::*;
    use umbra_hal::Aes;

    fn nist_key() -> [u8; 16] {
        [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ]
    }

    /// `process` before `configure` must error with `NotConfigured`.
    /// This is the lifecycle contract that protects against an
    /// uninitialised-engine cryptography call.
    #[test]
    fn process_before_configure_errors() {
        let mut aes = Aes128Engine::from_engine(AesEmulated::new());
        let input = [0u8; 16];
        let mut output = [0u8; 16];
        let err = aes.process(&input, &mut output).unwrap_err();
        assert!(matches!(err, Aes128Error::NotConfigured));
    }

    /// AES-256 must be rejected — the N657 hardware path is AES-128 only.
    #[test]
    fn aes256_rejected() {
        let mut aes = Aes128Engine::from_engine(AesEmulated::new());
        let key256 = [0u8; 32];
        let err = aes
            .configure(
                umbra_hal::AesKey::Bits256(&key256),
                umbra_hal::AesMode::EcbEncrypt,
            )
            .unwrap_err();
        assert!(matches!(err, Aes128Error::Aes256NotSupported));
    }

    /// ECB rejects non-multiple-of-16 input lengths.
    #[test]
    fn ecb_rejects_unaligned_length() {
        let key = nist_key();
        let mut aes = Aes128Engine::from_engine(AesEmulated::new());
        aes.configure(
            umbra_hal::AesKey::Bits128(&key),
            umbra_hal::AesMode::EcbEncrypt,
        )
        .unwrap();
        let input = [0u8; 15];
        let mut output = [0u8; 16];
        let err = aes.process(&input, &mut output).unwrap_err();
        assert!(matches!(err, Aes128Error::EcbLengthNotMultipleOf16));
    }

    /// `output.len() < input.len()` must error before any crypto runs.
    #[test]
    fn output_too_short_errors() {
        let key = nist_key();
        let mut aes = Aes128Engine::from_engine(AesEmulated::new());
        aes.configure(
            umbra_hal::AesKey::Bits128(&key),
            umbra_hal::AesMode::EcbEncrypt,
        )
        .unwrap();
        let input = [0u8; 16];
        let mut output = [0u8; 8];
        let err = aes.process(&input, &mut output).unwrap_err();
        assert!(matches!(err, Aes128Error::OutputTooShort));
    }

    /// End-to-end NIST KAT through the adapter: configure(EcbEncrypt) +
    /// process must produce the FIPS-197 ciphertext, then EcbDecrypt
    /// must invert it. Exercises the full adapter glue + AesEmulated.
    #[test]
    fn ecb_round_trip_through_adapter() {
        let key = nist_key();
        let plaintext: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let expected_ct: [u8; 16] = [
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66,
            0xef, 0x97,
        ];

        let mut aes = Aes128Engine::from_engine(AesEmulated::new());
        aes.configure(
            umbra_hal::AesKey::Bits128(&key),
            umbra_hal::AesMode::EcbEncrypt,
        )
        .unwrap();
        let mut ct = [0u8; 16];
        aes.process(&plaintext, &mut ct).unwrap();
        assert_eq!(
            ct, expected_ct,
            "adapter ECB encrypt diverged from NIST KAT"
        );

        aes.configure(
            umbra_hal::AesKey::Bits128(&key),
            umbra_hal::AesMode::EcbDecrypt,
        )
        .unwrap();
        let mut pt = [0u8; 16];
        aes.process(&ct, &mut pt).unwrap();
        assert_eq!(pt, plaintext, "adapter ECB decrypt did not invert encrypt");
    }

    /// CTR is XOR-symmetric: encrypt-then-encrypt with the same IV must
    /// restore the original. Exercises the adapter CTR path (counter
    /// increment + partial-block tail), 33 bytes to hit the partial path.
    #[test]
    fn ctr_xor_symmetry_through_adapter() {
        let key = nist_key();
        let iv = [
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
            0xfe, 0xff,
        ];
        let plaintext = [0xAAu8; 33];
        let mut ct = [0u8; 33];

        let mut aes = Aes128Engine::from_engine(AesEmulated::new());
        aes.configure(
            umbra_hal::AesKey::Bits128(&key),
            umbra_hal::AesMode::CtrEncrypt,
        )
        .unwrap();
        aes.set_iv(&iv).unwrap();
        aes.process(&plaintext, &mut ct).unwrap();
        assert_ne!(ct, plaintext, "CTR did not mutate plaintext");

        // Reconfigure (CTR is symmetric, but the counter has advanced —
        // need to reset IV) and run again.
        aes.configure(
            umbra_hal::AesKey::Bits128(&key),
            umbra_hal::AesMode::CtrEncrypt,
        )
        .unwrap();
        aes.set_iv(&iv).unwrap();
        let mut pt2 = [0u8; 33];
        aes.process(&ct, &mut pt2).unwrap();
        assert_eq!(pt2, plaintext, "CTR round-trip failed");
    }
}
