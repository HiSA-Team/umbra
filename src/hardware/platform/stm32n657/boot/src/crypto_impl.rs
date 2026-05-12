use kernel::key_storage_server::crypto::CryptoEngine;
use drivers::hash::Hash;
use drivers::aes::{AesEmulated, AesEngine};

pub struct UmbraCryptoEngine {
    hash: Hash,
    aes: AesEmulated,
}

impl UmbraCryptoEngine {
    pub fn new(hash: Hash, aes: AesEmulated) -> Self {
        Self { hash, aes }
    }
}

impl CryptoEngine for UmbraCryptoEngine {
    fn hmac(&mut self, key: &[u8], data: &[u8], output: &mut [u8]) -> Result<(), ()> {
        self.hash.hmac_sha256(key, data, output);
        Ok(())
    }

    fn hash(&mut self, data: &[u8], output: &mut [u8]) -> Result<(), ()> {
        self.hash.sha256(data, output);
        Ok(())
    }

    fn aes_decrypt(&mut self, key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<(), ()> {
        let mut output_block = [0u8; 16];
        let chunks = data.len() / 16;
        let mut counter_block = [0u8; 16];
        counter_block.copy_from_slice(iv);
        if key.len() < 16 { return Err(()); }
        let mut aes_key = [0u8; 16];
        let mut k: usize = 0;
        while k < 16 { aes_key[k] = key[k]; k += 1; }
        self.aes.init(&aes_key, None);
        let mut i: usize = 0;
        while i < chunks {
            self.aes.encrypt_block(&counter_block, &mut output_block);
            let mut j: usize = 0;
            while j < 16 { data[i*16 + j] ^= output_block[j]; j += 1; }
            // Increment counter (big-endian)
            let mut c: usize = 15;
            loop {
                counter_block[c] = counter_block[c].wrapping_add(1);
                if counter_block[c] != 0 || c == 0 { break; }
                c -= 1;
            }
            i += 1;
        }
        Ok(())
    }
}
