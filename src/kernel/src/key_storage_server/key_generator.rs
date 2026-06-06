use crate::key_storage_server::crypto::CryptoEngine;
use crate::key_storage_server::key_store::{Key, KEY_SIZE};
use umbra_error::{UmbraError, UmbraResult};

pub struct KeyGenerator<'a> {
    crypto: &'a mut dyn CryptoEngine,
}

impl<'a> KeyGenerator<'a> {
    pub fn new(crypto: &'a mut dyn CryptoEngine) -> Self {
        Self { crypto }
    }

    pub fn derive_key(&mut self, base_key: &Key, context: &[u8]) -> UmbraResult<Key> {
        let mut new_key_bytes = [0u8; KEY_SIZE];
        // For simplicity, using HMAC as KDF: HMAC(base_key, context)
        self.crypto
            .hmac(&base_key.value, context, &mut new_key_bytes)?;
        Ok(Key::new(new_key_bytes))
    }

    /// Constant-time tag comparison. Mirrors the XOR-fold pattern at
    /// `src/hardware/platform/stm32l552/boot/src/validator.rs:62-65`.
    /// The length-mismatch branch leaks only `len() != len()`, which is
    /// always public (both lengths are known constants at every call
    /// site — currently 32 bytes for the HMAC-SHA-256 measurement tag).
    pub fn verify_measurement(&self, measured_hash: &[u8], expected_hash: &[u8]) -> bool {
        if measured_hash.len() != expected_hash.len() {
            return false;
        }
        let mut diff: u8 = 0;
        for i in 0..measured_hash.len() {
            diff |= measured_hash[i] ^ expected_hash[i];
        }
        diff == 0
    }

    /// Fold one more block into an in-progress HMAC chain.
    /// `current_key` is both the input key (from the previous block, or the master
    /// key for block 0) and, on success, the output key `HMAC(current_key, block)`.
    /// Lets the caller stream the design's chained measurement one block at a time
    /// as DMA completes, without buffering all blocks in memory.
    pub fn update_chain(
        &mut self,
        current_key: &mut [u8; KEY_SIZE],
        block: &[u8],
    ) -> UmbraResult<()> {
        let mut output = [0u8; KEY_SIZE];
        self.crypto.hmac(current_key, block, &mut output)?;
        *current_key = output;
        Ok(())
    }

    // Logic to chain HMACs for EFB validation as per design
    pub fn compute_measurement(
        &mut self,
        blocks: &[&[u8]],
        initial_key: &Key,
    ) -> UmbraResult<[u8; KEY_SIZE]> {
        let mut current_key = initial_key.value;
        let mut output = [0u8; KEY_SIZE];

        for block in blocks {
            self.crypto.hmac(&current_key, block, &mut output)?;
            current_key = output;
        }
        Ok(output)
    }

    /// Authenticates the encrypted binary using HMAC and then decrypts it in-place.
    /// # Arguments
    /// * `key` - The root key (encryption key).
    /// * `data` - The encrypted data (ciphertext). Modified in-place to plaintext.
    /// * `expected_hmac` - The expected HMAC signature of the ciphertext.
    pub fn authenticate_and_decrypt(
        &mut self,
        key: &Key,
        data: &mut [u8],
        expected_hmac: &[u8],
    ) -> UmbraResult<()> {
        // 1. Verify Measurement (HMAC of Ciphertext)
        let measurement_key = self.derive_key(key, data)?;

        if !self.verify_measurement(&measurement_key.value, expected_hmac) {
            // MeasurementMismatch carries the first 8 bytes of each side for
            // diagnostic visibility without leaking the full digest off-chip.
            let mut expected = [0u8; 8];
            let mut got = [0u8; 8];
            let elen = core::cmp::min(8, expected_hmac.len());
            expected[..elen].copy_from_slice(&expected_hmac[..elen]);
            let glen = core::cmp::min(8, measurement_key.value.len());
            got[..glen].copy_from_slice(&measurement_key.value[..glen]);
            return Err(UmbraError::MeasurementMismatch { expected, got });
        }

        // 2. Decrypt (AES-CTR)
        // Using 0-IV as per current protocol (or derived).
        let iv = [0u8; 16];
        self.crypto.aes_decrypt(&key.value, &iv, data)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! first kernel host-side tests.
    //! Covers `verify_measurement` (constant-time tag compare). The
    //! `NoopCrypto` stub is local — `KeyGenerator::new` needs a
    //! `&mut dyn CryptoEngine` even though `verify_measurement` doesn't
    //! touch it. A full `TestCryptoEngine` in `umbra-pal-test` lands
    //! when expands driver coverage.
    use super::*;

    struct NoopCrypto;
    impl CryptoEngine for NoopCrypto {
        fn hmac(&mut self, _: &[u8], _: &[u8], _: &mut [u8]) -> UmbraResult<()> {
            Ok(())
        }
        fn hash(&mut self, _: &[u8], _: &mut [u8]) -> UmbraResult<()> {
            Ok(())
        }
        fn aes_decrypt(&mut self, _: &[u8], _: &[u8], _: &mut [u8]) -> UmbraResult<()> {
            Ok(())
        }
    }

    #[test]
    fn verify_measurement_identical_arrays_return_true() {
        let mut crypto = NoopCrypto;
        let gen = KeyGenerator::new(&mut crypto);
        let a = [0xABu8; 32];
        let b = [0xABu8; 32];
        assert!(gen.verify_measurement(&a, &b));
    }

    #[test]
    fn verify_measurement_one_bit_difference_returns_false() {
        let mut crypto = NoopCrypto;
        let gen = KeyGenerator::new(&mut crypto);
        let a = [0xABu8; 32];
        let mut b = [0xABu8; 32];
        b[15] ^= 1;
        assert!(!gen.verify_measurement(&a, &b));
    }

    #[test]
    fn verify_measurement_length_mismatch_returns_false() {
        let mut crypto = NoopCrypto;
        let gen = KeyGenerator::new(&mut crypto);
        let a = [0xABu8; 32];
        let b = [0xABu8; 16];
        assert!(!gen.verify_measurement(&a, &b));
    }
}

// CJ2 chained-measurement property tests live in a sibling file. They
// require a `Vec`-backed test crypto mock; keeping them out of the
// parent module avoids cluttering the production file with std-only
// scaffolding.
#[cfg(test)]
#[path = "key_generator_proptests.rs"]
mod proptests;
