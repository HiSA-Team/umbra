//! KDF derivation of independent `enc_key` and `hmac_key` from `MASTER_KEY`.
//! Labels must stay byte-for-byte in sync with `tools/protect_enclave.py`.

use crate::master_key::MASTER_KEY;
use kernel::key_storage_server::crypto::CryptoEngine;
use umbra_error::{UmbraError, UmbraResult};

pub const ENC_KEY_LABEL: &[u8] = b"umbra-enc-v1";
pub const HMAC_KEY_LABEL: &[u8] = b"umbra-hmac-v1";

/// Derive the enclave encryption subkey from `MASTER_KEY`. Propagates
/// `UmbraError::KeyDerivation` on HASH failure — previously the error was
/// swallowed (`let _ =`), which would silently boot on an all-zero key.
pub fn derive_enc_key(crypto: &mut dyn CryptoEngine) -> UmbraResult<[u8; 32]> {
    let mut out = [0u8; 32];
    crypto
        .hmac(&MASTER_KEY, ENC_KEY_LABEL, &mut out)
        .map_err(|_| UmbraError::KeyDerivation)?;
    Ok(out)
}

/// Derive the chained-measurement HMAC subkey from `MASTER_KEY`. Same
/// error-propagation contract as [`derive_enc_key`].
pub fn derive_hmac_key(crypto: &mut dyn CryptoEngine) -> UmbraResult<[u8; 32]> {
    let mut out = [0u8; 32];
    crypto
        .hmac(&MASTER_KEY, HMAC_KEY_LABEL, &mut out)
        .map_err(|_| UmbraError::KeyDerivation)?;
    Ok(out)
}
