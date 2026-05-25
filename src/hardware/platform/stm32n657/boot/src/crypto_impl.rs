use kernel::key_storage_server::crypto::CryptoEngine;
use drivers::hash::Hash;
use drivers::aes::AesEngine;

// `n657_aes_hw` ON  → CRYP1 + SAES1 hardware path
// `n657_aes_hw` OFF → T-table software fallback
#[cfg(feature = "n657_aes_hw")]
type ActiveAes = drivers::aes::AesHardware;
#[cfg(not(feature = "n657_aes_hw"))]
type ActiveAes = drivers::aes::AesEmulated;

pub struct UmbraCryptoEngine {
    hash: Hash,
    aes: ActiveAes,
}

impl UmbraCryptoEngine {
    pub fn new(hash: Hash, aes: ActiveAes) -> Self {
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
        if key.len() < 16 || iv.len() < 16 { return Err(()); }
        let mut aes_key = [0u8; 16];
        let mut iv_block = [0u8; 16];
        let mut k: usize = 0;
        while k < 16 { aes_key[k] = key[k]; iv_block[k] = iv[k]; k += 1; }
        // init() configures the engine in ECB (or "key-loaded") state.
        // CTR-specific config (counter/IV, ALGOMODE swap for HW path) lives
        // in ctr_xform so engines that override it own their state machine.
        self.aes.init(&aes_key, None);
        self.aes.ctr_xform(&iv_block, data);
        Ok(())
    }
}
