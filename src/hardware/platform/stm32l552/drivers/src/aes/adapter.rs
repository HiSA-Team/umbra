// Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>

// ────────────────────────────────────────────────────────────────────────────
// umbra-hal::Aes adapter.
// Wraps any `AesEngine` impl (AesEmulated or AesHardware) and lifts the
// single-block ECB primitive to the trait's multi-byte `process` API.
// Mode + IV state lives in the adapter so callers don't have to manage
// counter increment loops or ECB chunking themselves. Mirror of the
// Sha256Engine pattern from.
// ────────────────────────────────────────────────────────────────────────────

use super::engine::AesEngine;

/// AES-128 engine implementing `umbra_hal::Aes`. Generic over the
/// underlying single-block primitive (`AesEmulated` for L552 default,
/// `AesHardware` when the `stm32l562` feature is on).
pub struct Aes128Engine<E: AesEngine> {
    engine: E,
    mode: Option<umbra_hal::AesMode>,
    iv: [u8; 16],
}

impl<E: AesEngine> Aes128Engine<E> {
    /// Adopt an externally-constructed `AesEngine`. Matches the
    /// `Sha256Engine::from_hash` pattern.
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
                // AES-CTR keystream-XOR. Mirrors the loop already in
                // L552 crypto_impl::aes_decrypt (which IS encrypt + XOR;
                // CTR is symmetric). Counter block starts from IV,
                // increments big-endian by 1 each block.
                let mut counter = self.iv;
                let mut keystream = [0u8; 16];
                let mut off = 0;
                while off < input.len() {
                    self.engine.encrypt_block(&counter, &mut keystream);
                    let n = core::cmp::min(16, input.len() - off);
                    for i in 0..n {
                        output[off + i] = input[off + i] ^ keystream[i];
                    }
                    // Increment counter big-endian.
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
    //! Host-side tests for the `umbra_hal::Aes` adapter glue.
    //! We do NOT re-exercise the AES math here — that is tested in
    //! `emulated::tests` against NIST KAT. These tests verify the
    //! ADAPTER routing: configure dispatches the right mode, ECB length
    //! is validated, CTR counter increments big-endian, OutputTooShort
    //! fires, and the ECB encrypt/decrypt branches call the correct
    //! engine method.
    use super::super::engine::AesEngine;
    use super::*;
    use umbra_hal::Aes;

    /// Trivial deterministic mem engine. `encrypt_block` and
    /// `decrypt_block` apply different transforms so the test can prove
    /// which path the adapter selected.
    /// - encrypt: out[i] = in[i] XOR key[i] XOR 0xAA
    /// - decrypt: out[i] = in[i] XOR key[i] XOR 0x55
    struct TestEngine {
        key: [u8; 16],
    }
    impl TestEngine {
        fn new() -> Self {
            Self { key: [0u8; 16] }
        }
    }
    impl AesEngine for TestEngine {
        fn init(&mut self, key: &[u8], _iv: Option<&[u8]>) {
            self.key.copy_from_slice(key);
        }
        fn encrypt_block(&self, input: &[u8; 16], output: &mut [u8; 16]) {
            for i in 0..16 {
                output[i] = input[i] ^ self.key[i] ^ 0xAA;
            }
        }
        fn decrypt_block(&self, input: &[u8; 16], output: &mut [u8; 16]) {
            for i in 0..16 {
                output[i] = input[i] ^ self.key[i] ^ 0x55;
            }
        }
    }

    fn key128() -> [u8; 16] {
        [0x01; 16]
    }

    #[test]
    fn process_without_configure_returns_not_configured() {
        let mut aes = Aes128Engine::from_engine(TestEngine::new());
        let inp = [0u8; 16];
        let mut out = [0u8; 16];
        match aes.process(&inp, &mut out) {
            Err(Aes128Error::NotConfigured) => {}
            other => panic!("expected NotConfigured, got {:?}", other),
        }
    }

    #[test]
    fn aes256_not_supported() {
        let mut aes = Aes128Engine::from_engine(TestEngine::new());
        let k256 = [0u8; 32];
        let res = aes.configure(
            umbra_hal::AesKey::Bits256(&k256),
            umbra_hal::AesMode::EcbEncrypt,
        );
        match res {
            Err(Aes128Error::Aes256NotSupported) => {}
            other => panic!("expected Aes256NotSupported, got {:?}", other),
        }
    }

    #[test]
    fn ecb_rejects_non_multiple_of_16() {
        let mut aes = Aes128Engine::from_engine(TestEngine::new());
        let k = key128();
        aes.configure(
            umbra_hal::AesKey::Bits128(&k),
            umbra_hal::AesMode::EcbEncrypt,
        )
        .unwrap();
        let inp = [0u8; 15];
        let mut out = [0u8; 16];
        match aes.process(&inp, &mut out) {
            Err(Aes128Error::EcbLengthNotMultipleOf16) => {}
            other => panic!("expected EcbLengthNotMultipleOf16, got {:?}", other),
        }
    }

    #[test]
    fn output_too_short_rejected() {
        let mut aes = Aes128Engine::from_engine(TestEngine::new());
        let k = key128();
        aes.configure(
            umbra_hal::AesKey::Bits128(&k),
            umbra_hal::AesMode::CtrEncrypt,
        )
        .unwrap();
        let inp = [0u8; 16];
        let mut out = [0u8; 8];
        match aes.process(&inp, &mut out) {
            Err(Aes128Error::OutputTooShort) => {}
            other => panic!("expected OutputTooShort, got {:?}", other),
        }
    }

    /// ECB-encrypt dispatch: calls `encrypt_block` (XOR 0xAA), NOT
    /// `decrypt_block` (XOR 0x55). Two-block input verifies the chunking
    /// loop.
    #[test]
    fn ecb_encrypt_routes_to_encrypt_block() {
        let mut aes = Aes128Engine::from_engine(TestEngine::new());
        let k = key128();
        aes.configure(
            umbra_hal::AesKey::Bits128(&k),
            umbra_hal::AesMode::EcbEncrypt,
        )
        .unwrap();
        let inp = [0x00u8; 32];
        let mut out = [0u8; 32];
        aes.process(&inp, &mut out).unwrap();
        // 0x00 ^ 0x01 (key) ^ 0xAA (encrypt tag) == 0xAB
        for b in out.iter() {
            assert_eq!(*b, 0xAB, "ECB encrypt did not route to encrypt_block");
        }
    }

    /// ECB-decrypt dispatch: calls `decrypt_block` (XOR 0x55).
    #[test]
    fn ecb_decrypt_routes_to_decrypt_block() {
        let mut aes = Aes128Engine::from_engine(TestEngine::new());
        let k = key128();
        aes.configure(
            umbra_hal::AesKey::Bits128(&k),
            umbra_hal::AesMode::EcbDecrypt,
        )
        .unwrap();
        let inp = [0x00u8; 16];
        let mut out = [0u8; 16];
        aes.process(&inp, &mut out).unwrap();
        // 0x00 ^ 0x01 (key) ^ 0x55 (decrypt tag) == 0x54
        for b in out.iter() {
            assert_eq!(*b, 0x54, "ECB decrypt did not route to decrypt_block");
        }
    }

    /// CTR mode uses the encrypt path for keystream, big-endian counter,
    /// XOR keystream into input. Verify counter increment by encrypting
    /// 2 blocks of zero input with a known IV and checking the second
    /// keystream block differs from the first by the counter delta.
    #[test]
    fn ctr_mode_keystream_xor_and_counter_increment() {
        let mut aes = Aes128Engine::from_engine(TestEngine::new());
        let k = [0u8; 16];
        aes.configure(
            umbra_hal::AesKey::Bits128(&k),
            umbra_hal::AesMode::CtrEncrypt,
        )
        .unwrap();
        // IV = all-zero; counter block 0 = 0..0, counter block 1 = 0..0,01.
        let iv = [0u8; 16];
        aes.set_iv(&iv).unwrap();
        // Input all-zero → output == keystream.
        let inp = [0u8; 32];
        let mut out = [0u8; 32];
        aes.process(&inp, &mut out).unwrap();
        // In-memory backend keystream[block 0] = 0 ^ 0 ^ 0xAA = 0xAA in every byte.
        for i in 0..16 {
            assert_eq!(out[i], 0xAA, "CTR block 0 byte {} wrong", i);
        }
        // In-memory backend keystream[block 1] = counter ^ key ^ 0xAA, counter has
        // only byte 15 set to 1 → out[16..31] == 0xAA except out[31] == 0xAB.
        for i in 0..15 {
            assert_eq!(out[16 + i], 0xAA, "CTR block 1 byte {} wrong", i);
        }
        assert_eq!(out[31], 0xAB, "CTR counter did not increment big-endian");
    }

    /// CTR with a non-multiple-of-16 length must still succeed
    /// (partial-block tail XOR). 17-byte input → 16-byte block + 1
    /// keystream byte.
    #[test]
    fn ctr_partial_tail_block_ok() {
        let mut aes = Aes128Engine::from_engine(TestEngine::new());
        let k = [0u8; 16];
        aes.configure(
            umbra_hal::AesKey::Bits128(&k),
            umbra_hal::AesMode::CtrEncrypt,
        )
        .unwrap();
        let iv = [0u8; 16];
        aes.set_iv(&iv).unwrap();
        let inp = [0u8; 17];
        let mut out = [0u8; 17];
        aes.process(&inp, &mut out).unwrap();
        // First 16 = block 0 keystream = 0xAA.
        // Byte 16 = block 1 keystream byte 0 = 0xAA.
        for b in out.iter() {
            assert_eq!(*b, 0xAA);
        }
    }
}
