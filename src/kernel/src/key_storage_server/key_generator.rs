
use crate::key_storage_server::crypto::CryptoEngine;
use crate::key_storage_server::key_store::{Key, KEY_SIZE};

pub struct KeyGenerator<'a> {
    crypto: &'a mut dyn CryptoEngine,
}

impl<'a> KeyGenerator<'a> {
    pub fn new(crypto: &'a mut dyn CryptoEngine) -> Self {
        Self { crypto }
    }

    pub fn derive_key(&mut self, base_key: &Key, context: &[u8]) -> Result<Key, ()> {
        let mut new_key_bytes = [0u8; KEY_SIZE];
        // For simplicity, using HMAC as KDF: HMAC(base_key, context)
        self.crypto.hmac(&base_key.value, context, &mut new_key_bytes)?;
        Ok(Key::new(new_key_bytes))
    }

    pub fn verify_measurement(&self, measured_hash: &[u8], expected_hash: &[u8]) -> bool {
         measured_hash == expected_hash
    }
    
    /// Fold one more block into an in-progress HMAC chain.
    ///
    /// `current_key` is both the input key (from the previous block, or the master
    /// key for block 0) and, on success, the output key `HMAC(current_key, block)`.
    /// Lets the caller stream the design's chained measurement one block at a time
    /// as DMA completes, without buffering all blocks in memory.
    pub fn update_chain(&mut self, current_key: &mut [u8; KEY_SIZE], block: &[u8]) -> Result<(), ()> {
        let mut output = [0u8; KEY_SIZE];
        self.crypto.hmac(current_key, block, &mut output)?;
        *current_key = output;
        Ok(())
    }

    // Logic to chain HMACs for EFB validation as per design
    pub fn compute_measurement(&mut self, blocks: &[&[u8]], initial_key: &Key) -> Result<[u8; KEY_SIZE], ()> {
        let mut current_key = initial_key.value;
        let mut output = [0u8; KEY_SIZE];

        for block in blocks {
            self.crypto.hmac(&current_key, block, &mut output)?;
            current_key = output;
        }
        Ok(output)
    }

    /// Authenticates the encrypted binary using HMAC and then decrypts it in-place.
    /// 
    /// # Arguments
    /// * `key` - The root key (encryption key).
    /// * `data` - The encrypted data (ciphertext). Modified in-place to plaintext.
    /// * `expected_hmac` - The expected HMAC signature of the ciphertext.
    pub fn authenticate_and_decrypt(&mut self, key: &Key, data: &mut [u8], expected_hmac: &[u8]) -> Result<(), ()> {
        // 1. Verify Measurement (HMAC of Ciphertext)
        let measurement_key = self.derive_key(key, data)?;
        
        if !self.verify_measurement(&measurement_key.value, expected_hmac) {
            return Err(());
        }
        
        // 2. Decrypt (AES-CTR)
        // Using 0-IV as per current protocol (or derived).
        let iv = [0u8; 16];
        self.crypto.aes_decrypt(&key.value, &iv, data)?;
        
        Ok(())
    }
}
