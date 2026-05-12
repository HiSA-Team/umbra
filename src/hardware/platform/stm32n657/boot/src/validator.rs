//! Rust analog of the ProVerif Validator process.
//! `validate_block` is the ONLY producer of `ValidatedBlock`.

use kernel::key_storage_server::crypto::CryptoEngine;

pub const CODE_BLOCK_SIZE: usize = 256;
pub const BLOCK_META_SIZE: usize = 32;

pub struct ValidatedBlock {
    pub block_id: u32,
    #[allow(dead_code)]
    pub plaintext: [u8; CODE_BLOCK_SIZE],
    #[allow(dead_code)]
    pub metadata: [u8; BLOCK_META_SIZE],
    _seal: (),
}

#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
pub enum ValidationError {
    HmacMismatch,
    DecryptFailed,
    CryptoUnavailable,
}

pub fn validate_block(
    crypto: &mut dyn CryptoEngine,
    expected_block_id: u32,
    ciphertext: &[u8; CODE_BLOCK_SIZE],
    metadata: &[u8; BLOCK_META_SIZE],
    hmac_on_flash: &[u8; 32],
    hmac_key: &[u8; 32],
    enc_key: &[u8; 32],
) -> Result<ValidatedBlock, ValidationError> {
    let mut input = [0u8; 4 + CODE_BLOCK_SIZE + BLOCK_META_SIZE];
    input[0..4].copy_from_slice(&expected_block_id.to_le_bytes());
    input[4..4 + CODE_BLOCK_SIZE].copy_from_slice(ciphertext);
    input[4 + CODE_BLOCK_SIZE..].copy_from_slice(metadata);

    let mut computed = [0u8; 32];
    crypto.hmac(hmac_key, &input, &mut computed)
          .map_err(|_| ValidationError::HmacMismatch)?;

    let mut diff: u8 = 0;
    let mut i: usize = 0;
    while i < 32 { diff |= computed[i] ^ hmac_on_flash[i]; i += 1; }
    if diff != 0 { return Err(ValidationError::HmacMismatch); }

    // N657 always uses AES decrypt (no OTFDEC path).
    let mut plaintext = *ciphertext;
    let iv = [0u8; 16];
    crypto.aes_decrypt(enc_key, &iv, &mut plaintext)
          .map_err(|_| ValidationError::DecryptFailed)?;

    Ok(ValidatedBlock {
        block_id: expected_block_id,
        plaintext,
        metadata: *metadata,
        _seal: (),
    })
}
