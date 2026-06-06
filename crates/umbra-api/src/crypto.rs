//! `CryptoEngine` trait — kernel's boundary to per-platform crypto.
//! Moved here () from
//! `src/kernel/src/key_storage_server/crypto.rs`. The kernel crate
//! re-exports it for backwards compatibility during the migration.
//!: error variants come from `umbra_error::UmbraResult`.
//! Each method's `?`-propagation surface lives there, not on the trait.

use umbra_error::UmbraResult;

pub trait CryptoEngine {
    /// HMAC-SHA256 over `data` with `key`, output to `output` (must be
    /// 32 bytes). Returns `UmbraError::HashHardware` on HW failure.
    fn hmac(&mut self, key: &[u8], data: &[u8], output: &mut [u8]) -> UmbraResult<()>;

    /// SHA-256 over `data`, output to `output` (must be 32 bytes).
    /// Returns `UmbraError::HashHardware` on HW failure.
    fn hash(&mut self, data: &[u8], output: &mut [u8]) -> UmbraResult<()>;

    /// AES-128-CTR decrypt-in-place. `key` must be 16 bytes (only the
    /// first 16 are used if longer); `iv` must be 16 bytes. Returns
    /// `UmbraError::AesHardware` on HW failure or
    /// `UmbraError::LengthMismatch` if key/iv are too short.
    fn aes_decrypt(&mut self, key: &[u8], iv: &[u8], data: &mut [u8]) -> UmbraResult<()>;
}
