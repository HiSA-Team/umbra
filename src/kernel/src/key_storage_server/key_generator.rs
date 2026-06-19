use crate::key_storage_server::crypto::CryptoEngine;
use crate::key_storage_server::key_store::{Key, KEY_SIZE};
use umbra_error::UmbraResult;

pub struct KeyGenerator<'a> {
    crypto: &'a mut dyn CryptoEngine,
}

impl<'a> KeyGenerator<'a> {
    pub fn new(crypto: &'a mut dyn CryptoEngine) -> Self {
        Self { crypto }
    }

    pub fn derive_key(&mut self, base_key: &Key, context: &[u8]) -> UmbraResult<Key> {
        umbra_rot_core::derive_key(&mut *self.crypto, base_key, context)
    }

    /// Constant-time tag comparison (proved sound: T1). Returns `true` iff the
    /// tags are byte-for-byte equal.
    pub fn verify_measurement(&self, measured_hash: &[u8], expected_hash: &[u8]) -> bool {
        umbra_rot_core::verify_measurement(measured_hash, expected_hash)
    }

    /// Fold one more block into the in-progress HMAC chain.
    pub fn update_chain(
        &mut self,
        current_key: &mut [u8; KEY_SIZE],
        block: &[u8],
    ) -> UmbraResult<()> {
        umbra_rot_core::update_chain(&mut *self.crypto, current_key, block)
    }

    /// Closed-form chained measurement — the streaming [`Self::update_chain`]
    /// folded over a block list. The `&[&[u8]]` shape is not Aeneas-extractable
    /// (slice of borrows), so the oracle stays here as a loop over the proved
    /// `update_chain`; the firmware itself streams via `update_chain`.
    pub fn compute_measurement(
        &mut self,
        blocks: &[&[u8]],
        initial_key: &Key,
    ) -> UmbraResult<[u8; KEY_SIZE]> {
        let mut current_key = initial_key.value;
        for block in blocks {
            umbra_rot_core::update_chain(&mut *self.crypto, &mut current_key, block)?;
        }
        Ok(current_key)
    }

    /// Authenticate the ciphertext against `expected_hmac`, then decrypt in
    /// place. Returns `Ok` only if the measurement matched.
    /// Delegates to the proved `umbra_rot_core::authenticate_and_decrypt`.
    pub fn authenticate_and_decrypt(
        &mut self,
        key: &Key,
        data: &mut [u8],
        expected_hmac: &[u8],
    ) -> UmbraResult<()> {
        umbra_rot_core::authenticate_and_decrypt(&mut *self.crypto, key, data, expected_hmac)
    }

    /// Validate a single block against its expected measurement (proved sound:
    /// T4). Returns `true` only if the block's derived measurement matches.
    pub fn validate_block(&mut self, data: &[u8], expected_measurement: &Key) -> bool {
        umbra_rot_core::validate_block(&mut *self.crypto, data, expected_measurement)
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
