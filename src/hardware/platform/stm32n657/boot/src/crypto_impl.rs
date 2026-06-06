use drivers::aes::AesEngine;
use drivers::hash::{Hash, Sha256Engine};
use kernel::key_storage_server::crypto::CryptoEngine;
//: bring the trait into scope so the `hash()` method
// below dispatches through `umbra_hal::Hash::{init,update,finalize}`.
// HMAC stays on the inherent `Hash::hmac_sha256` (HW HMAC path) — the
// trait does not model keyed hashing.
use umbra_hal::Hash as HashTrait;
//: typed errors on the kernel boundary.
use umbra_error::{UmbraError, UmbraResult};

// `n657_aes_hw` ON → CRYP1 + SAES1 hardware path
// `n657_aes_hw` OFF → T-table software fallback
#[cfg(feature = "n657_aes_hw")]
type ActiveAes = drivers::aes::AesHardware;
#[cfg(not(feature = "n657_aes_hw"))]
type ActiveAes = drivers::aes::AesEmulated;

pub struct UmbraCryptoEngine {
    /// HW HASH peripheral handle — kept for the HMAC path (HW HMAC at
    /// 0x5402_0400) which the trait can't express (no keyed hashing).
    /// Unit struct on N657, so this costs zero bytes.
    hash: Hash,
    /// SHA-256 engine implementing `umbra_hal::Hash`. Backed by the
    /// file-local SW SHA-256 today; can move to HW SHA-256 transparently
    /// when that path lands.
    sha256: Sha256Engine,
    aes: ActiveAes,
}

impl UmbraCryptoEngine {
    pub fn new(hash: Hash, aes: ActiveAes) -> Self {
        Self {
            hash,
            sha256: Sha256Engine::new(),
            aes,
        }
    }
}

impl CryptoEngine for UmbraCryptoEngine {
    fn hmac(&mut self, key: &[u8], data: &[u8], output: &mut [u8]) -> UmbraResult<()> {
        self.hash.hmac_sha256(key, data, output);
        Ok(())
    }

    fn hash(&mut self, data: &[u8], output: &mut [u8]) -> UmbraResult<()> {
        // Trait dispatch path — same byte-for-byte SHA-256 output as the
        // pre-earlier `Hash::sha256()` shortcut, now flowing through
        // `umbra_hal::Hash`.
        self.sha256.init().map_err(|_| UmbraError::HashHardware)?;
        self.sha256
            .update(data)
            .map_err(|_| UmbraError::HashHardware)?;
        let mut digest = [0u8; 32];
        self.sha256
            .finalize(&mut digest)
            .map_err(|_| UmbraError::HashHardware)?;
        let n = core::cmp::min(output.len(), digest.len());
        output[..n].copy_from_slice(&digest[..n]);
        Ok(())
    }

    fn aes_decrypt(&mut self, key: &[u8], iv: &[u8], data: &mut [u8]) -> UmbraResult<()> {
        if key.len() < 16 || iv.len() < 16 {
            return Err(UmbraError::LengthMismatch);
        }
        let mut aes_key = [0u8; 16];
        let mut iv_block = [0u8; 16];
        let mut k: usize = 0;
        while k < 16 {
            aes_key[k] = key[k];
            iv_block[k] = iv[k];
            k += 1;
        }
        // init() configures the engine in ECB (or "key-loaded") state.
        // CTR-specific config (counter/IV, ALGOMODE swap for HW path) lives
        // in ctr_xform so engines that override it own their state machine.
        self.aes.init(&aes_key, None);
        self.aes.ctr_xform(&iv_block, data);
        Ok(())
    }
}
