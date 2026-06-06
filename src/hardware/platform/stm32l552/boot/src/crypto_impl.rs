use drivers::hash::{Algorithm, DataType, Hash, Sha256Engine};
use kernel::key_storage_server::crypto::CryptoEngine;
//: bring the trait into scope so the `hash()` method
// below dispatches through `umbra_hal::Hash::{init,update,finalize}`
// instead of the inherent `Hash::start/update/finish` API directly.
// HMAC stays on the inherent API (the trait does not model keyed hashing).
use umbra_hal::Hash as HashTrait;
//: typed errors on the kernel boundary.
use umbra_error::{UmbraError, UmbraResult};

#[cfg(not(feature = "stm32l562"))]
use drivers::aes::AesEmulated as AesImpl;
use drivers::aes::AesEngine;
#[cfg(feature = "stm32l562")]
use drivers::aes::AesHardware as AesImpl;

pub struct UmbraCryptoEngine {
    sha256: Sha256Engine,
    aes: AesImpl,
}

impl UmbraCryptoEngine {
    pub fn new(hash: Hash, aes: AesImpl) -> Self {
        // Adopt the externally-constructed `Hash` driver into the engine.
        // Call sites (platform_impl.rs) keep passing `Hash::new()` — no
        // construction-side churn.
        Self {
            sha256: Sha256Engine::from_hash(hash),
            aes,
        }
    }
}

impl CryptoEngine for UmbraCryptoEngine {
    fn hmac(&mut self, key: &[u8], data: &[u8], output: &mut [u8]) -> UmbraResult<()> {
        // HMAC needs the keyed `start(.., Some(key))` API — borrow the
        // underlying `Hash` directly via the engine's accessor.
        let hw = self.sha256.inner_mut();
        let mut ctx = hw
            .start(Algorithm::SHA256, DataType::Width8, Some(key))
            .map_err(|_| UmbraError::HashHardware)?;
        hw.update(&mut ctx, data)
            .map_err(|_| UmbraError::HashHardware)?;
        hw.finish(ctx, output)
            .map_err(|_| UmbraError::HashHardware)?;
        Ok(())
    }

    fn hash(&mut self, data: &[u8], output: &mut [u8]) -> UmbraResult<()> {
        // Trait dispatch path — same byte-for-byte SHA-256 output as the
        // pre-earlier code, now flowing through `umbra_hal::Hash`.
        self.sha256.init().map_err(|_| UmbraError::HashHardware)?;
        self.sha256
            .update(data)
            .map_err(|_| UmbraError::HashHardware)?;
        let mut digest = [0u8; 32];
        self.sha256
            .finalize(&mut digest)
            .map_err(|_| UmbraError::HashHardware)?;
        // CryptoEngine::hash's output slice may be wider than 32 bytes
        // (kernel currently always passes exactly 32). Copy what fits.
        let n = core::cmp::min(output.len(), digest.len());
        output[..n].copy_from_slice(&digest[..n]);
        Ok(())
    }

    fn aes_decrypt(&mut self, key: &[u8], iv: &[u8], data: &mut [u8]) -> UmbraResult<()> {
        // AES-128-CTR: encrypt the counter block to produce keystream, then XOR.
        // 32-byte subkeys (from HMAC-KDF) are truncated to 16 bytes for AES-128.
        let mut output_block = [0u8; 16];
        let chunks = data.len() / 16;

        let mut counter_block = [0u8; 16];
        counter_block.copy_from_slice(iv);

        if key.len() < 16 {
            return Err(UmbraError::LengthMismatch);
        }
        let aes_key: [u8; 16] = key[0..16].try_into().expect("Key too short");

        self.aes.init(&aes_key, None);

        for i in 0..chunks {
            self.aes.encrypt_block(&counter_block, &mut output_block);

            for j in 0..16 {
                data[i * 16 + j] ^= output_block[j];
            }

            // Increment counter (big-endian)
            for k in (0..16).rev() {
                counter_block[k] = counter_block[k].wrapping_add(1);
                if counter_block[k] != 0 {
                    break;
                }
            }
        }

        Ok(())
    }
}
