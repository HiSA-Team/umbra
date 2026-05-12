//! KDF derivation of independent `enc_key` and `hmac_key` from `MASTER_KEY`.
//! Labels must stay byte-for-byte in sync with `tools/protect_enclave.py`.

use kernel::key_storage_server::crypto::CryptoEngine;
use crate::master_key::MASTER_KEY;

pub const ENC_KEY_LABEL:  &[u8] = b"umbra-enc-v1";
pub const HMAC_KEY_LABEL: &[u8] = b"umbra-hmac-v1";

pub fn derive_enc_key(crypto: &mut dyn CryptoEngine) -> [u8; 32] {
    let mut out = [0u8; 32];
    let _ = crypto.hmac(&MASTER_KEY, ENC_KEY_LABEL, &mut out);
    out
}

pub fn derive_hmac_key(crypto: &mut dyn CryptoEngine) -> [u8; 32] {
    let mut out = [0u8; 32];
    let _ = crypto.hmac(&MASTER_KEY, HMAC_KEY_LABEL, &mut out);
    out
}
