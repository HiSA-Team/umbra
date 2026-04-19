//! KDF derivation of independent `enc_key` and `hmac_key` from `MASTER_KEY`.
//!
//! Formal-model cross-ref: `docs/formal/UmbraIntegrityFixValidator.pv` declares
//! `new encKey: key;` and `new hmacKey: key;` as two fresh, independent keys.
//! Using a single secret for both domains would collapse that distinction and
//! break the model's soundness argument, so we derive two subkeys via HMAC.
//!
//! The label strings must stay byte-for-byte in sync with `tools/protect_enclave.py`.
//!
//! Kept out of `master_key.rs` because that file is overwritten verbatim by
//! `tools/gen_key.py` on every key regen.

use kernel::key_storage_server::crypto::CryptoEngine;
use crate::master_key::MASTER_KEY;

pub const ENC_KEY_LABEL:    &[u8] = b"umbra-enc-v1";
pub const HMAC_KEY_LABEL:   &[u8] = b"umbra-hmac-v1";
pub const OTFDEC_KEY_LABEL: &[u8] = b"umbra-otfdec-v1";

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

/// Derive 32 bytes of raw keying material for OTFDEC region 1 from
/// `MASTER_KEY`. Caller slices: `[0..16] = key`, `[16..24] = nonce`,
/// `[24..32]` discarded.
pub fn derive_otfdec_raw(crypto: &mut dyn CryptoEngine) -> [u8; 32] {
    let mut out = [0u8; 32];
    let _ = crypto.hmac(&MASTER_KEY, OTFDEC_KEY_LABEL, &mut out);
    out
}
