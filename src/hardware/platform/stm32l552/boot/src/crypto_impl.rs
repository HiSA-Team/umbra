use kernel::key_storage_server::crypto::CryptoEngine;
use drivers::hash::{Hash, Algorithm, DataType};

#[cfg(feature = "stm32l562")]
use drivers::aes::AesHardware as AesImpl;
#[cfg(not(feature = "stm32l562"))]
use drivers::aes::AesEmulated as AesImpl;
use drivers::aes::AesEngine;

pub struct UmbraCryptoEngine {
    hash: Hash,
    aes: AesImpl,
}

impl UmbraCryptoEngine {

    pub fn new(hash: Hash, aes: AesImpl) -> Self {
        Self { hash, aes }
    }
}

impl CryptoEngine for UmbraCryptoEngine {
    fn hmac(&mut self, key: &[u8], data: &[u8], output: &mut [u8]) -> Result<(), ()> {
        // Using SHA256 for HMAC
        let mut ctx = self.hash.start(Algorithm::SHA256, DataType::Width8, Some(key));
        self.hash.update(&mut ctx, data);
        self.hash.finish(ctx, output);
        Ok(())
    }

    fn hash(&mut self, data: &[u8], output: &mut [u8]) -> Result<(), ()> {
        // Using SHA256 for Hash
        let mut ctx = self.hash.start(Algorithm::SHA256, DataType::Width8, None);
        self.hash.update(&mut ctx, data);
        self.hash.finish(ctx, output);
        Ok(())
    }
    
    fn aes_decrypt(&mut self, key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<(), ()> {
        // AES-128-CTR: encrypt the counter block to produce keystream, then XOR.
        // 32-byte subkeys (from HMAC-KDF) are truncated to 16 bytes for AES-128.
        let mut output_block = [0u8; 16];
        let chunks = data.len() / 16;

        let mut counter_block = [0u8; 16];
        counter_block.copy_from_slice(iv);

        if key.len() < 16 {
             return Err(());
        }
        let aes_key: [u8; 16] = key[0..16].try_into().expect("Key too short");

        self.aes.init(&aes_key, None);

        for i in 0..chunks {
             self.aes.encrypt_block(&counter_block, &mut output_block);

             for j in 0..16 {
                 data[i*16 + j] ^= output_block[j];
             }

             // Increment counter (big-endian)
             for k in (0..16).rev() {
                 counter_block[k] = counter_block[k].wrapping_add(1);
                 if counter_block[k] != 0 { break; }
             }
        }

        Ok(())
    }
}
